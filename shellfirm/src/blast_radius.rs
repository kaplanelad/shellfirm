//! Blast radius — runtime impact computation for matched checks.
//!
//! Severity tells users **how dangerous** a command is, but not **how wide the
//! damage spreads**. This module computes real metrics at runtime (file counts,
//! sizes, commit counts) so users see concrete impact before confirming.
//!
//! # Design principle: graceful degradation
//!
//! Blast radius must **never** interfere with the core safety flow. Every
//! computation returns `Option` — on any failure (timeout, missing command,
//! permission error, unexpected output) the result is `None`, and the user
//! simply sees the challenge prompt without the extra line.
//!
//! # Time budget
//!
//! All the work for one command (`find` / `du` per path, `git` and `docker`
//! queries) shares one total budget (`blast_radius_budget_ms`, default
//! 400 ms; `0` skips the blast radius). A subprocess gets at most the time
//! that is left; when it runs out, the process group is killed, the rest is
//! skipped and the description says so (`size not computed: took too long`).
//! In the interactive shell hook a computation that passes 200 ms shows a
//! transient `shellfirm: checking impact…` line on the terminal, erased
//! before the banner.

use std::io::{IsTerminal as _, Write as _};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use regex::Regex;
use serde_derive::{Deserialize, Serialize};
use tracing::debug;

use crate::env::{CommandOutcome, Environment};

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// The scope of potential damage.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum BlastScope {
    /// Single file, branch, container.
    Resource,
    /// Repository, database, application.
    Project,
    /// Kubernetes namespace, resource group.
    Namespace,
    /// Entire local host.
    Machine,
}

impl std::fmt::Display for BlastScope {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Resource => write!(f, "RESOURCE"),
            Self::Project => write!(f, "PROJECT"),
            Self::Namespace => write!(f, "NAMESPACE"),
            Self::Machine => write!(f, "MACHINE"),
        }
    }
}

/// Runtime-computed blast radius for a matched check.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlastRadiusInfo {
    pub scope: BlastScope,
    /// Human-readable impact description, e.g. "Deletes 347 files (12.4 MB) in ./src".
    pub description: String,
}

/// Upper limit (ms) for one blast-radius subprocess.
///
/// Every subprocess also shares the command's total budget
/// (`blast_radius_budget_ms`, default 400 ms, see [`budget_ms`]): it
/// gets at most the time that is left, so the wait before a prompt is
/// bounded by the budget, not by this per-step limit times the step count.
const TIMEOUT_MS: u64 = 3000;

// ---------------------------------------------------------------------------
// Time budget
// ---------------------------------------------------------------------------

/// Whether a slow computation shows a transient "checking impact…" line on
/// the terminal (the interactive shell hook only).
static PROGRESS_NOTICE: AtomicBool = AtomicBool::new(false);

/// The total blast-radius time budget (ms) for the command being evaluated.
///
/// It is the budget of the active [`crate::env::CommandScope`] (entered by
/// every caller with the settings it really uses, e.g. `check --config-dir
/// DIR`), else the built-in default.
#[must_use]
pub fn budget_ms() -> u64 {
    crate::env::scope_budget_ms().unwrap_or(crate::config::DEFAULT_BLAST_RADIUS_BUDGET_MS)
}

/// Show (`true`) a transient `shellfirm: checking impact…` line on the
/// terminal when the blast radius takes longer than
/// [`PROGRESS_NOTICE_AFTER_MS`]. Only the interactive shell hook turns it on.
pub fn set_progress_notice(on: bool) {
    PROGRESS_NOTICE.store(on, Ordering::Relaxed);
}

/// After this long (ms) a still-running blast-radius computation shows the
/// transient progress line (when [`set_progress_notice`] is on).
pub const PROGRESS_NOTICE_AFTER_MS: u64 = 200;

/// Marks a file count that stopped before the end (a lower bound).
const STOPPED_COUNTING: &str = "(stopped counting)";

/// The text of the transient progress line.
#[must_use]
pub fn progress_notice_text() -> String {
    format!(
        "shellfirm: checking impact{} (Ctrl-C cancels)",
        crate::config::glyph("…", "...")
    )
}

/// Why a blast-radius subprocess gave no (full) answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Miss {
    /// Started, then stopped when the time ran out.
    TimedOut,
    /// Not started: the budget was already spent by earlier work.
    Skipped,
}

/// An [`Environment`] that shares one deadline across every subprocess it
/// runs. Each command gets at most the time that is left (and at most its
/// own timeout); once the deadline has passed nothing else is started.
/// `misses` lists the commands that were killed or skipped for lack of time.
///
/// Inside a [`crate::env::CommandScope`] the deadline is counted from the
/// start of the scope (so the context lookups before it count too), and an
/// answer an earlier evaluation of the same command got is reused.
struct BudgetEnv<'a> {
    inner: &'a dyn Environment,
    deadline: Instant,
    misses: Mutex<Vec<(String, Miss)>>,
}

impl<'a> BudgetEnv<'a> {
    fn new(inner: &'a dyn Environment, budget: Duration) -> Self {
        let start = crate::env::scope_start().unwrap_or_else(Instant::now);
        Self {
            inner,
            deadline: start + budget,
            misses: Mutex::new(Vec::new()),
        }
    }

    fn miss(&self, cmd: &str, kind: Miss) {
        if let Ok(mut m) = self.misses.lock() {
            m.push((cmd.to_string(), kind));
        }
    }

    fn miss_count(&self) -> usize {
        self.misses.lock().map_or(0, |m| m.len())
    }

    fn misses_since(&self, from: usize) -> Vec<(String, Miss)> {
        self.misses
            .lock()
            .map(|m| m.get(from..).map(<[_]>::to_vec).unwrap_or_default())
            .unwrap_or_default()
    }
}

impl Environment for BudgetEnv<'_> {
    fn var(&self, key: &str) -> Option<String> {
        self.inner.var(key)
    }

    fn current_dir(&self) -> crate::error::Result<std::path::PathBuf> {
        self.inner.current_dir()
    }

    fn path_exists(&self, path: &std::path::Path) -> bool {
        self.inner.path_exists(path)
    }

    fn home_dir(&self) -> Option<std::path::PathBuf> {
        self.inner.home_dir()
    }

    fn run_command(&self, cmd: &str, args: &[&str], timeout_ms: u64) -> Option<String> {
        self.run_command_outcome(cmd, args, timeout_ms).output()
    }

    fn run_command_outcome(&self, cmd: &str, args: &[&str], timeout_ms: u64) -> CommandOutcome {
        self.run_command_partial(cmd, args, timeout_ms).0
    }

    fn run_command_partial(
        &self,
        cmd: &str,
        args: &[&str],
        timeout_ms: u64,
    ) -> (CommandOutcome, Option<String>) {
        // Another view of the same command already asked: same answer.
        if crate::env::scope_budget_skipped(cmd, args) {
            self.miss(cmd, Miss::Skipped);
            return (CommandOutcome::Skipped, None);
        }
        if let Some(hit) = crate::env::scope_lookup(cmd, args) {
            if hit.0 == CommandOutcome::TimedOut {
                self.miss(cmd, Miss::TimedOut);
            }
            return hit;
        }
        let left = self.deadline.saturating_duration_since(Instant::now());
        let left_ms = u64::try_from(left.as_millis()).unwrap_or(u64::MAX);
        if left_ms == 0 {
            self.miss(cmd, Miss::Skipped);
            crate::env::scope_mark_budget_skipped(cmd, args);
            debug!("blast_radius: budget spent, skipping `{cmd}`");
            return (CommandOutcome::Skipped, None);
        }
        let result = self
            .inner
            .run_command_partial(cmd, args, timeout_ms.min(left_ms));
        if result.0 == CommandOutcome::TimedOut {
            self.miss(cmd, Miss::TimedOut);
            debug!("blast_radius: `{cmd}` stopped, out of time");
        }
        crate::env::scope_store(cmd, args, &result);
        result
    }

    fn effective_uid(&self) -> Option<u32> {
        self.inner.effective_uid()
    }

    fn read_file(&self, path: &std::path::Path) -> crate::error::Result<String> {
        self.inner.read_file(path)
    }

    fn find_file_upward(
        &self,
        start: &std::path::Path,
        filename: &str,
    ) -> Option<std::path::PathBuf> {
        self.inner.find_file_upward(start, filename)
    }
}

/// Mark `info` (or its absence) as cut short by the time budget.
///
/// The note says what is missing (the size, the file count, or part of the
/// measurement) and why: `took too long` when a step was stopped, `skipped,
/// no time left` when the budget was already spent by earlier work. A file
/// count that stopped early already says so (`more than N files (stopped
/// counting)`), so a stopped `find` alone adds no note.
fn mark_not_measured(
    check_id: &str,
    info: Option<BlastRadiusInfo>,
    misses: &[(String, Miss)],
) -> BlastRadiusInfo {
    let Some(mut br) = info else {
        let why = if misses.iter().any(|(_, m)| *m == Miss::TimedOut) {
            "took too long"
        } else {
            "skipped: no time left"
        };
        return BlastRadiusInfo {
            scope: BlastScope::Resource,
            description: format!("Impact not measured ({why})"),
        };
    };
    let stopped = br.description.contains(STOPPED_COUNTING);
    let missing: Vec<&(String, Miss)> = misses
        .iter()
        // After a stopped count, a skipped `find` / `test -d` only means the
        // lower bound is lower: it is still true.
        .filter(|(cmd, _)| !(stopped && (cmd == "find" || cmd == "test")))
        .collect();
    if missing.is_empty() {
        return br;
    }
    let what = if check_id.starts_with("fs") {
        // `test -d` and `find` only serve the file count; `du` the size.
        let counting = |c: &str| c == "find" || c == "test";
        let no_count = missing.iter().any(|(c, _)| counting(c));
        let no_size = missing.iter().any(|(c, _)| !counting(c));
        if no_count && !no_size {
            "file count not computed"
        } else if no_count && !stopped {
            "size and file count not computed"
        } else {
            "size not computed"
        }
    } else {
        "not fully measured"
    };
    let why = if missing.iter().any(|(_, m)| *m == Miss::TimedOut) {
        ": took too long"
    } else {
        ": skipped, no time left"
    };
    // One bracket, not two: `more than N files (stopped counting; size not
    // computed: took too long)`.
    br.description = match br.description.strip_suffix(')') {
        Some(head) if br.description.ends_with(STOPPED_COUNTING) => {
            format!("{head}; {what}{why})")
        }
        _ => format!("{} ({what}{why})", br.description),
    };
    br
}

/// Run `compute` for one check against the shared budget and note a
/// measurement that ran out of time.
fn budgeted(
    check_id: &str,
    benv: &BudgetEnv<'_>,
    compute: impl FnOnce(&dyn Environment) -> Option<BlastRadiusInfo>,
) -> Option<BlastRadiusInfo> {
    let before = benv.miss_count();
    let info = compute(benv);
    let misses = benv.misses_since(before);
    if misses.is_empty() {
        info
    } else {
        Some(mark_not_measured(check_id, info, &misses))
    }
}

/// A transient progress line on the terminal ("checking impact…").
///
/// It is shown when the computation outlives [`PROGRESS_NOTICE_AFTER_MS`],
/// and erased (cursor back where it was) when the guard is dropped, before
/// the banner is drawn.
#[must_use = "the line is erased when the guard is dropped"]
pub struct ProgressNotice {
    done: Option<mpsc::Sender<()>>,
    handle: Option<thread::JoinHandle<()>>,
}

/// Show `text` as a transient line on the terminal while the guard lives.
///
/// The line appears once the work outlasts [`PROGRESS_NOTICE_AFTER_MS`]
/// (only when [`set_progress_notice`] is on, on a terminal that can erase
/// it again). Dropping the guard erases the line before anything else is
/// printed.
#[must_use = "the line is erased when the guard is dropped"]
pub fn start_progress_notice(text: String) -> ProgressNotice {
    ProgressNotice::start_with(text)
}

impl ProgressNotice {
    fn start() -> Self {
        Self::start_with(progress_notice_text())
    }

    fn start_with(text: String) -> Self {
        let idle = Self {
            done: None,
            handle: None,
        };
        // A dumb terminal cannot erase the line again: show nothing there.
        let dumb = std::env::var("TERM").is_ok_and(|t| t == "dumb");
        if !PROGRESS_NOTICE.load(Ordering::Relaxed) || !std::io::stderr().is_terminal() || dumb {
            return idle;
        }
        let color = console::colors_enabled_stderr();
        let (tx, rx) = mpsc::channel::<()>();
        let handle = thread::spawn(move || {
            if rx.recv_timeout(Duration::from_millis(PROGRESS_NOTICE_AFTER_MS))
                != Err(mpsc::RecvTimeoutError::Timeout)
            {
                return;
            }
            let Ok(mut tty) = std::fs::OpenOptions::new().write(true).open("/dev/tty") else {
                return;
            };
            let text = if color {
                format!("\x1b[2m{text}\x1b[0m")
            } else {
                text
            };
            let _ = write!(tty, "\r\n{text}");
            let _ = tty.flush();
            // Until the computation is over (or the guard is dropped).
            let _ = rx.recv();
            // Erase the line and go back up, so the banner (which starts
            // with a newline) lands where it would have without the notice.
            let _ = write!(tty, "\r\x1b[2K\x1b[1A");
            let _ = tty.flush();
        });
        Self {
            done: Some(tx),
            handle: Some(handle),
        }
    }
}

impl Drop for ProgressNotice {
    fn drop(&mut self) {
        if let Some(tx) = self.done.take() {
            let _ = tx.send(());
        }
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

// ---------------------------------------------------------------------------
// Dispatch
// ---------------------------------------------------------------------------

/// Compute blast radius for a single matched check.
///
/// Returns `None` for checks that don't support blast radius or when
/// computation fails for any reason (timeout, missing command, etc.).
#[must_use]
pub fn compute(
    check_id: &str,
    check_regex: &Regex,
    command: &str,
    env: &dyn Environment,
) -> Option<BlastRadiusInfo> {
    let result = match check_id {
        // fs group
        "fs:recursively_delete" => compute_fs_recursive_delete(check_regex, command, env),
        "fs:move_to_dev_null" => compute_fs_move_to_dev_null(check_regex, command, env),
        "fs:flush_file_content" => compute_fs_flush_file(check_regex, command, env),
        "fs:recursively_chmod" => compute_fs_recursive_chmod(check_regex, command, env),
        "fs:delete_find_files" | "fs:delete_find_files_dir" => compute_fs_delete_find(command, env),
        "fs-strict:any_deletion"
        | "fs-strict:recursive_deletion"
        | "fs:recursive_delete_unknown_target"
        | "fs:delete_unknown_target" => compute_fs_strict_any_deletion(check_regex, command, env),
        "fs-strict:folder_deletion" => compute_fs_strict_folder_deletion(check_regex, command, env),
        "fs-strict:change_permissions" => compute_fs_strict_change_permissions(command, env),
        // git group
        "git:reset" => compute_git_reset(command, env),
        "git:delete_all" => compute_git_delete_all(env),
        "git:clean_force" => compute_git_clean_force(command, env),
        "git:force_push" => compute_git_force_push(command, env),
        "git:force_delete_branch" => compute_git_force_delete_branch(command, env),
        "git:force_checkout" => compute_git_force_checkout(env),
        "git:filter_branch" => compute_git_filter_branch(env),
        "git-strict:add_all" => compute_git_strict_add_all(env),
        "git-strict:commit_all" => compute_git_strict_commit_all(env),
        // docker group
        "docker:system_prune_all" => compute_docker_system_prune(command, env),
        "docker:force_remove_all_containers" => {
            compute_docker_force_remove_containers(command, env)
        }
        "docker:volume_prune" => compute_docker_volume_prune(command, env),
        "docker:stop_all_containers" => compute_docker_stop_all(env),
        // kubernetes group
        "kubernetes:delete_namespace" => {
            compute_kubernetes_delete_namespace(check_regex, command, env)
        }
        _ => None,
    };

    if result.is_none() {
        debug!("blast_radius: no result for check {check_id}");
    }
    result
}

/// Compute blast radius for all matched checks in a pipeline.
///
/// Returns a vec of `(check_id, BlastRadiusInfo)` pairs for checks that have
/// computable blast radius. Checks without blast radius are silently skipped.
#[must_use]
pub fn compute_for_matches(
    checks: &[crate::checks::Check],
    command_parts: &[String],
    stripped_command: &str,
    env: &dyn Environment,
) -> Vec<(String, BlastRadiusInfo)> {
    let budget = budget_ms();
    if budget == 0 {
        return Vec::new();
    }
    let benv = BudgetEnv::new(env, Duration::from_millis(budget));
    let _notice = ProgressNotice::start();
    checks
        .iter()
        .filter_map(|c| {
            let segment = command_parts
                .iter()
                .find(|seg| c.test.is_match(seg))
                .map_or(stripped_command, String::as_str);
            // Normalized segments carry the intra-word whitespace sentinel:
            // it keeps `rm -rf "my dir"` one operand; each operand is
            // restored to real text where it is used.
            budgeted(&c.id, &benv, |e| compute(&c.id, &c.test, segment, e))
                .map(|br| (c.id.clone(), br))
        })
        .collect()
}

/// Like [`compute_for_matches`], but aware of remote segments.
///
/// Segments that run on another host or in a container (`remote_parts`,
/// from [`crate::parser::Parsed::remote_segments`]) are not measured on the
/// local machine (that would count the wrong files / cluster); they get a
/// "runs remotely" description instead.
///
/// k8s blast-radius queries reuse the command's own `--context` /
/// `--kubeconfig` / `KUBECONFIG=` so they count the targeted cluster.
#[must_use]
pub fn compute_for_matches_remote_aware(
    checks: &[crate::checks::Check],
    command_parts: &[String],
    remote_parts: &[String],
    stripped_command: &str,
    env: &dyn Environment,
) -> Vec<(String, BlastRadiusInfo)> {
    compute_for_matches_within(
        checks,
        command_parts,
        remote_parts,
        stripped_command,
        env,
        budget_ms(),
    )
}

/// [`compute_for_matches_remote_aware`] with an explicit total budget (ms).
fn compute_for_matches_within(
    checks: &[crate::checks::Check],
    command_parts: &[String],
    remote_parts: &[String],
    stripped_command: &str,
    env: &dyn Environment,
    budget_ms: u64,
) -> Vec<(String, BlastRadiusInfo)> {
    if budget_ms == 0 || checks.is_empty() {
        return Vec::new();
    }
    let benv = BudgetEnv::new(env, Duration::from_millis(budget_ms));
    let _notice = ProgressNotice::start();
    let is_remote = |s: &str| remote_parts.binary_search_by(|r| r.as_str().cmp(s)).is_ok();
    let targets = crate::context::parse_command_targets(stripped_command);
    checks
        .iter()
        .filter_map(|c| {
            let matching: Vec<&String> = command_parts
                .iter()
                .filter(|seg| c.test.is_match(seg))
                .collect();
            let local = matching.iter().find(|s| !is_remote(s));
            if local.is_none() && !matching.is_empty() {
                return Some((
                    c.id.clone(),
                    BlastRadiusInfo {
                        scope: BlastScope::Resource,
                        description: "Runs on another host or in a container; its impact \
                                      is not measured locally"
                            .to_string(),
                    },
                ));
            }
            let segment = local.map_or(stripped_command, |s| s.as_str());
            let info = budgeted(&c.id, &benv, |env| {
                if c.id == "kubernetes:delete_namespace" {
                    compute_kubernetes_delete_namespace_in(
                        &c.test,
                        segment,
                        env,
                        &kube_flags(&targets),
                    )
                } else if c.id == "git:reset" {
                    // `git checkout main && git reset --hard origin/main` resets
                    // main, not the branch checked out now.
                    let switched = targets
                        .segments
                        .iter()
                        .find(|s| s.git && s.text.split_whitespace().any(|w| w == "reset"))
                        .and_then(|s| s.git_branch_switch.clone());
                    compute_git_reset_on(segment, env, switched.as_deref())
                } else if c.id == "git:force_push" {
                    // `git checkout feature/x && git push -f` pushes feature/x.
                    let switched = targets
                        .segments
                        .iter()
                        .find(|s| s.git && s.text.split_whitespace().any(|w| w == "push"))
                        .and_then(|s| s.git_branch_switch.clone());
                    compute_git_force_push_on(segment, env, switched.as_deref())
                } else {
                    compute(&c.id, &c.test, segment, env)
                }
            });
            info.map(|mut br| {
                br.description = readable_targets(&br.description, stripped_command);
                (c.id.clone(), br)
            })
        })
        .collect()
}

/// Replace the analysis placeholders in a description with what the user
/// wrote: the unknown target `{}` with the substitution / input it comes
/// from, the `mktemp` placeholder path with words.
fn readable_targets(description: &str, command: &str) -> String {
    let mut out = description.replace(
        "/tmp/shellfirm-mktemp.XXXXXX",
        "a new temporary path (mktemp)",
    );
    if out.contains("{}") {
        let expr = first_substitution(command).unwrap_or_else(|| {
            if command.contains("xargs") {
                "the names xargs reads".to_string()
            } else if command.contains("find") {
                "the files find matches".to_string()
            } else {
                "a run-time value".to_string()
            }
        });
        out = out.replace("{}", &expr);
    }
    out
}

/// The first `$(…)` or `` `…` `` command substitution written in `command`.
fn first_substitution(command: &str) -> Option<String> {
    let bytes = command.as_bytes();
    let start = command.find("$(").or_else(|| command.find('`'))?;
    if bytes[start] == b'`' {
        let end = command[start + 1..].find('`')? + start + 1;
        return Some(command[start..=end].to_string());
    }
    let mut depth = 0usize;
    for (i, &b) in bytes.iter().enumerate().skip(start + 1) {
        match b {
            b'(' => depth += 1,
            b')' => {
                depth -= 1;
                if depth == 0 {
                    return Some(command[start..=i].to_string());
                }
            }
            _ => {}
        }
    }
    None
}

/// The `--context` / `--kubeconfig` flags a k8s query must reuse.
fn kube_flags(targets: &crate::context::CommandTargets) -> Vec<String> {
    let mut out = Vec::new();
    if let Some(ref c) = targets.k8s_context {
        out.push("--context".to_string());
        out.push(c.clone());
    }
    if let Some(ref k) = targets.kubeconfig {
        out.push("--kubeconfig".to_string());
        out.push(k.split(':').next().unwrap_or(k).to_string());
    }
    out
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Parse human-readable size from `du -sh` output (e.g. "12M\t/path" → "12M").
fn parse_du_output(output: &str) -> Option<String> {
    let first_line = output.lines().next()?;
    let size = first_line.split_whitespace().next()?;
    if size.is_empty() {
        return None;
    }
    // `du -sh` prints a bare `0` for an empty file: say it is zero bytes,
    // not "(0)" (which reads like a count).
    if size == "0" {
        return Some("0 B".to_string());
    }
    Some(size.to_string())
}

/// Count non-empty lines in command output.
fn count_lines(output: &str) -> usize {
    output.lines().filter(|l| !l.trim().is_empty()).count()
}

/// Format a count with a noun, e.g. `format_count(1, "file")` → `"1 file"`,
/// `format_count(5629, "file")` → `"5,629 files"`.
fn format_count(n: usize, noun: &str) -> String {
    let num = format_number(n);
    if n == 1 {
        format!("{num} {noun}")
    } else {
        format!("{num} {noun}s")
    }
}

/// Format a file count from `count_files_at`: `1,234 files`, or a lower
/// bound when counting stopped early (`more than 100,000 files (stopped
/// counting)`).
fn format_file_count(count: usize, capped: bool) -> String {
    format_count_capped(count, capped, "file")
}

/// Format a number with comma separators, e.g. `1234567` → `"1,234,567"`.
fn format_number(n: usize) -> String {
    let s = n.to_string();
    let mut result = String::with_capacity(s.len() + s.len() / 3);
    for (i, ch) in s.chars().enumerate() {
        if i > 0 && (s.len() - i).is_multiple_of(3) {
            result.push(',');
        }
        result.push(ch);
    }
    result
}

/// Extract capture group 1 from regex match on command.
fn capture_group(regex: &Regex, command: &str, group: usize) -> Option<String> {
    let caps = regex.captures(command)?;
    let m = caps.get(group)?;
    let val = m.as_str().trim();
    if val.is_empty() {
        return None;
    }
    Some(crate::parser::desentinel(val))
}

/// Words of a (normalized) command with each word's own whitespace restored
/// (`rm -rf "my dir"` → `rm`, `-rf`, `my dir`).
fn words_of(command: &str) -> Vec<String> {
    command
        .split_whitespace()
        .map(crate::parser::desentinel)
        .collect()
}

/// A path in a description: quoted when it contains whitespace. The text
/// stays raw (the audit log keeps the real characters); invisible
/// characters are escaped where it is displayed.
fn shown(path: &str) -> String {
    if path.chars().any(char::is_whitespace) {
        format!("\"{path}\"")
    } else {
        path.to_string()
    }
}

/// Determine blast scope for a filesystem path.
fn fs_scope_for_path(path: &str) -> BlastScope {
    if path == "/" || path == "/*" {
        BlastScope::Machine
    } else {
        BlastScope::Project
    }
}

/// Top-level system directories that are never traversed for blast radius.
const SYSTEM_DIRS: &[&str] = &[
    "/home",
    "/etc",
    "/usr",
    "/var",
    "/bin",
    "/sbin",
    "/lib",
    "/lib64",
    "/boot",
    "/opt",
    "/root",
    "/srv",
    "/sys",
    "/proc",
    "/dev",
    "/System",
    "/Users",
    "/Library",
    "/Applications",
];

/// Expand `~`, `$HOME` and `${HOME}` at the start of a path.
fn expand_home(path: &str, env: &dyn Environment) -> String {
    for prefix in ["${HOME}", "$HOME", "~"] {
        if path == prefix || path.starts_with(&format!("{prefix}/")) {
            if let Some(home) = env.home_dir() {
                return path.replacen(prefix, &home.display().to_string(), 1);
            }
        }
    }
    path.to_string()
}

/// A path whose deletion is catastrophic and which must not be traversed
/// (counting files under `/` or `$HOME` is slow and pointless).
/// Returns `(scope, human description)`.
fn protected_target(path: &str, env: &dyn Environment) -> Option<(BlastScope, String)> {
    let normalized = crate::parser::normalize_path(path);
    let bare = normalized.trim_end_matches("/*");
    if bare == "/" || bare.is_empty() || normalized == "/*" {
        return Some((BlastScope::Machine, "the entire filesystem (/)".to_string()));
    }
    let home = env.home_dir().map(|h| h.display().to_string());
    let expanded = expand_home(bare, env);
    if bare == "~" || bare == "$HOME" || home.as_deref() == Some(expanded.as_str()) {
        let shown = home.unwrap_or_else(|| "~".to_string());
        return Some((
            BlastScope::Machine,
            format!("your home directory ({shown})"),
        ));
    }
    if SYSTEM_DIRS.contains(&bare) {
        return Some((BlastScope::Machine, format!("system directory {bare}")));
    }
    None
}

/// Operands of an `rm`-like command: words after the program that are not
/// flags (unless after `--`), stopping at a redirection.
fn command_operands(command: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut after_dashdash = false;
    for (i, tok) in words_of(command).iter().enumerate() {
        if i == 0 {
            continue;
        }
        let bare = tok.trim_start_matches(|c: char| c.is_ascii_digit());
        if bare.starts_with('>') || bare.starts_with('<') || bare.starts_with("&>") {
            break;
        }
        if !after_dashdash && *tok == "--" {
            after_dashdash = true;
            continue;
        }
        if !after_dashdash && tok.starts_with('-') {
            continue;
        }
        out.push(tok.clone());
    }
    out
}

/// Describe the deletion of a set of operands. Protected targets are
/// reported without traversal; other targets are counted (capped).
fn describe_deletion(
    operands: &[String],
    env: &dyn Environment,
    default_scope: BlastScope,
) -> Option<BlastRadiusInfo> {
    if operands.is_empty() {
        return None;
    }
    // Protected targets dominate.
    let protected: Vec<(BlastScope, String)> = operands
        .iter()
        .filter_map(|p| protected_target(p, env))
        .collect();
    if !protected.is_empty() {
        let names: Vec<String> = protected.iter().map(|(_, d)| d.clone()).collect();
        return Some(BlastRadiusInfo {
            scope: BlastScope::Machine,
            description: format!("Deletes {}", names.join(", ")),
        });
    }

    let mut total_files = 0usize;
    let mut any_capped = false;
    let mut counted = false;
    let mut dirs = 0usize;
    for op in operands {
        let path = expand_home(op, env);
        if path.contains('*') || path.contains('?') {
            continue; // globs are reported by count of operands below
        }
        if is_directory(env, &path) {
            dirs += 1;
            if let Some((count, capped)) = count_files_at(env, &path) {
                total_files += count;
                any_capped |= capped;
                counted = true;
            }
        }
    }

    let names: Vec<String> = operands.iter().map(|o| shown(o)).collect();
    let what = if names.len() == 1 {
        names[0].clone()
    } else {
        format!("{} paths ({})", names.len(), names.join(", "))
    };
    let description = if counted {
        format!(
            "Deletes {what} with {}",
            format_file_count(total_files, any_capped)
        )
    } else if dirs > 0 && names.len() == 1 {
        format!("Deletes directory {what}")
    } else if dirs > 0 {
        format!("Deletes {what}")
    } else if operands.iter().any(|o| o.contains('*') || o.contains('?')) {
        format!("Deletes everything matching {what}")
    } else {
        format!("Deletes {what}")
    };
    Some(BlastRadiusInfo {
        scope: default_scope,
        description,
    })
}

/// Maximum number of files to count before returning a capped estimate.
/// Prevents `find` from consuming excessive memory/time on huge directories.
const MAX_FILE_COUNT: usize = 100_000;

/// Count files under a path using `find`.
///
/// Returns `(count, capped)` where `capped` is true if the count hit the
/// `MAX_FILE_COUNT` limit (meaning the real count is at least that many).
///
/// A `find` stopped by the time budget still counts what it listed so
/// far, as a lower bound (`capped`), so a big tree shows "more than N
/// files" instead of no count at all.
fn count_files_at(env: &dyn Environment, path: &str) -> Option<(usize, bool)> {
    let (outcome, partial) =
        env.run_command_partial("find", &[path, "-maxdepth", "20", "-type", "f"], TIMEOUT_MS);
    match outcome {
        CommandOutcome::Output(output) => {
            let count = count_lines(&output);
            if count >= MAX_FILE_COUNT {
                Some((MAX_FILE_COUNT, true))
            } else {
                Some((count, false))
            }
        }
        CommandOutcome::TimedOut => {
            // The last line may be cut: count only complete ones.
            let listed = partial.map_or(0, |p| {
                p.rsplit_once('\n')
                    .map_or(0, |(complete, _)| count_lines(complete))
            });
            (listed > 0).then(|| (listed.min(MAX_FILE_COUNT), true))
        }
        CommandOutcome::Failed | CommandOutcome::Skipped => None,
    }
}

/// Get human-readable size of a path using `du -sh`.
fn get_size(env: &dyn Environment, path: &str) -> Option<String> {
    let output = env.run_command("du", &["-sh", path], TIMEOUT_MS)?;
    parse_du_output(&output)
}

/// Check if a path is a directory.
fn is_directory(env: &dyn Environment, path: &str) -> bool {
    env.run_command("test", &["-d", path], TIMEOUT_MS).is_some()
}

// ---------------------------------------------------------------------------
// fs group computations
// ---------------------------------------------------------------------------

fn compute_fs_recursive_delete(
    regex: &Regex,
    command: &str,
    env: &dyn Environment,
) -> Option<BlastRadiusInfo> {
    let path = capture_group(regex, command, 1)?;

    // Root, home and system directories: report the scope without traversing.
    let operands = command_operands(command);
    if let Some(info) = describe_protected(&operands, env) {
        return Some(info);
    }

    let scope = fs_scope_for_path(&path);
    let target = expand_home(&path, env);
    let file_count = count_files_at(env, &target);
    let size = get_size(env, &target);

    let where_ = if operands.len() > 1 {
        format!("{} (and {} other paths)", shown(&path), operands.len() - 1)
    } else {
        shown(&path)
    };
    let description = match (file_count, size) {
        (Some((count, capped)), Some(sz)) => {
            format!(
                "Deletes {} ({sz}) in {where_}",
                format_file_count(count, capped)
            )
        }
        (Some((count, capped)), None) => {
            format!("Deletes {} in {where_}", format_file_count(count, capped))
        }
        (None, Some(sz)) => format!("Deletes ({sz}) in {where_}"),
        (None, None) => format!("Deletes everything in {where_}"),
    };

    Some(BlastRadiusInfo { scope, description })
}

/// Report protected targets (root/home/system dirs) among operands, if any.
fn describe_protected(operands: &[String], env: &dyn Environment) -> Option<BlastRadiusInfo> {
    let names: Vec<String> = operands
        .iter()
        .filter_map(|p| protected_target(p, env).map(|(_, d)| d))
        .collect();
    if names.is_empty() {
        None
    } else {
        Some(BlastRadiusInfo {
            scope: BlastScope::Machine,
            description: format!("Deletes {}", names.join(", ")),
        })
    }
}

fn compute_fs_move_to_dev_null(
    regex: &Regex,
    command: &str,
    env: &dyn Environment,
) -> Option<BlastRadiusInfo> {
    let path = capture_group(regex, command, 1)?;
    let size = get_size(env, &path);
    Some(BlastRadiusInfo {
        scope: BlastScope::Resource,
        description: size.map_or_else(
            || "Destroys file".to_string(),
            |sz| format!("Destroys file ({sz})"),
        ),
    })
}

fn compute_fs_flush_file(
    regex: &Regex,
    command: &str,
    env: &dyn Environment,
) -> Option<BlastRadiusInfo> {
    let path = capture_group(regex, command, 1)?;
    let size = get_size(env, path.trim());
    Some(BlastRadiusInfo {
        scope: BlastScope::Resource,
        description: size.map_or_else(
            || "Flushes 1 file".to_string(),
            |sz| format!("Flushes 1 file ({sz})"),
        ),
    })
}

fn compute_fs_recursive_chmod(
    regex: &Regex,
    command: &str,
    env: &dyn Environment,
) -> Option<BlastRadiusInfo> {
    // Capture group 1 is the target (group 2 never existed).
    let path = capture_group(regex, command, 1)?;
    if let Some((scope, what)) = protected_target(&path, env) {
        return Some(BlastRadiusInfo {
            scope,
            description: format!("Changes permissions on {what}"),
        });
    }
    let scope = fs_scope_for_path(&path);
    let (file_count, capped) = count_files_at(env, &expand_home(&path, env))?;
    Some(BlastRadiusInfo {
        scope,
        description: format!(
            "Affects permissions on {}",
            format_file_count(file_count, capped)
        ),
    })
}

/// `find` tests that narrow what is selected by name, time, size, owner or
/// emptiness (options such as `-maxdepth` and `-type` do not count).
const FIND_FILTERS: &[&str] = &[
    "-name",
    "-iname",
    "-path",
    "-ipath",
    "-wholename",
    "-iwholename",
    "-regex",
    "-iregex",
    "-newer",
    "-anewer",
    "-cnewer",
    "-newermt",
    "-mtime",
    "-mmin",
    "-atime",
    "-amin",
    "-ctime",
    "-cmin",
    "-size",
    "-user",
    "-group",
    "-uid",
    "-gid",
    "-perm",
    "-empty",
    "-links",
    "-inum",
    "-samefile",
    "-lname",
    "-ilname",
    "-used",
];

/// `find` actions that must never be run while measuring a blast radius.
const FIND_ACTIONS: &[&str] = &[
    "-delete", "-exec", "-execdir", "-ok", "-okdir", "-fprint", "-fprint0", "-fprintf", "-fls",
];

fn compute_fs_delete_find(command: &str, env: &dyn Environment) -> Option<BlastRadiusInfo> {
    let owned = words_of(command);
    let parts: Vec<&str> = owned.iter().map(String::as_str).collect();
    let find_idx = parts.iter().position(|p| *p == "find")?;
    let args = &parts[find_idx + 1..];
    let search_path = args
        .first()
        .filter(|p| !p.starts_with('-'))
        .copied()
        .unwrap_or(".");
    // Never traverse the filesystem root or the home directory.
    if let Some((scope, what)) = protected_target(search_path, env) {
        return Some(BlastRadiusInfo {
            scope,
            description: format!("Deletes matching files anywhere under {what}"),
        });
    }
    let start = expand_home(search_path, env);
    // Expression tokens after the start point(s).
    let expr: Vec<&str> = args
        .iter()
        .skip_while(|a| !a.starts_with('-') && **a != "(" && **a != "!")
        .copied()
        .collect();
    let delete_pos = expr.iter().position(|a| *a == "-delete");
    // find evaluates left to right: what `-delete` acts on is selected by the
    // tokens before it (a filter after it, or in another `-o` branch, does
    // not narrow it).
    let before: &[&str] = delete_pos.map_or(&[], |p| &expr[..p]);
    let has_or = before.iter().any(|a| matches!(*a, "-o" | "-or"));
    let filters_before_delete = !before.is_empty() && !has_or;
    let scoped = before.iter().any(|a| FIND_FILTERS.contains(a));
    let other_actions = expr
        .iter()
        .any(|a| FIND_ACTIONS.contains(a) && *a != "-delete");
    let (count, capped, filtered) = if filters_before_delete && !other_actions {
        // Count what is selected: the expression up to `-delete` (find then
        // only prints the matches).
        let mut q: Vec<&str> = vec![start.as_str()];
        q.extend(before.iter().copied());
        let output = env.run_command("find", &q, TIMEOUT_MS);
        match output {
            Some(o) => {
                let n = count_lines(&o);
                (n.min(MAX_FILE_COUNT), n >= MAX_FILE_COUNT, true)
            }
            None => {
                return Some(BlastRadiusInfo {
                    scope: BlastScope::Project,
                    description: format!(
                        "Deletes the files matching the filters under {search_path} (count unknown)"
                    ),
                })
            }
        }
    } else if !filters_before_delete && delete_pos.is_some() {
        // `-delete` before any filter acts on everything under the start.
        let (c, cap) = count_files_at(env, &start)?;
        (c, cap, false)
    } else {
        return Some(BlastRadiusInfo {
            scope: BlastScope::Project,
            description: format!(
                "Deletes the files matching the filters under {search_path} (count unknown)"
            ),
        });
    };
    Some(BlastRadiusInfo {
        scope: BlastScope::Project,
        description: if filtered && scoped {
            format!(
                "Deletes {} matching the filters under {search_path}",
                format_count_capped(count, capped, "path")
            )
        } else if filtered {
            // Only options such as `-maxdepth 1` / `-type f` before `-delete`.
            format!(
                "Deletes {} under {search_path}",
                format_count_capped(count, capped, "path")
            )
        } else {
            format!(
                "Deletes everything under {search_path}: {}",
                format_file_count(count, capped)
            )
        },
    })
}

/// `N <noun>s`, or `more than N <noun>s (stopped counting)` when the
/// count is a lower bound (capped, or cut short by the time budget).
fn format_count_capped(count: usize, capped: bool, noun: &str) -> String {
    if capped {
        format!("more than {} {STOPPED_COUNTING}", format_count(count, noun))
    } else {
        format_count(count, noun)
    }
}

fn compute_fs_strict_any_deletion(
    regex: &Regex,
    command: &str,
    env: &dyn Environment,
) -> Option<BlastRadiusInfo> {
    // The check must have matched; operands are taken from the whole command
    // so multiple targets (`rm -rf a b`) are all reported.
    capture_group(regex, command, 1)?;
    let operands = command_operands(command);
    if operands.len() == 1 {
        // Single operand: keep the detailed file/directory wording.
        let path = expand_home(&operands[0], env);
        let op = &shown(&operands[0]);
        if protected_target(&operands[0], env).is_none() && !path.contains('*') {
            // A variable / placeholder target is only known when it runs.
            if path.contains('$') || path.contains("{}") {
                return Some(BlastRadiusInfo {
                    scope: BlastScope::Resource,
                    description: format!("Deletes {op} (target is not known until it runs)"),
                });
            }
            // `test -d` first: it is instant. Then the file count, then the
            // size: `du` on a big tree may use up the time budget, and a
            // stopped count is still a lower bound ("more than N files").
            let is_dir = is_directory(env, &path);
            if !is_dir {
                let size = get_size(env, &path);
                return Some(BlastRadiusInfo {
                    scope: BlastScope::Resource,
                    description: size.map_or_else(
                        || format!("Deletes {op}"),
                        |sz| format!("Deletes file {op} ({sz})"),
                    ),
                });
            }
            let file_count = count_files_at(env, &path);
            let size = get_size(env, &path);
            let desc = match (file_count, &size) {
                (Some((0, _)), _) => format!("Deletes empty directory {op}"),
                (Some((count, capped)), Some(sz)) => format!(
                    "Deletes directory {op} with {} ({sz})",
                    format_file_count(count, capped)
                ),
                (Some((count, capped)), None) => format!(
                    "Deletes directory {op} with {}",
                    format_file_count(count, capped)
                ),
                (None, Some(sz)) => format!("Deletes directory {op} ({sz})"),
                (None, None) => format!("Deletes directory {op}"),
            };
            return Some(BlastRadiusInfo {
                scope: BlastScope::Resource,
                description: desc,
            });
        }
    }
    describe_deletion(&operands, env, BlastScope::Resource)
}

fn compute_fs_strict_folder_deletion(
    regex: &Regex,
    command: &str,
    env: &dyn Environment,
) -> Option<BlastRadiusInfo> {
    let path = capture_group(regex, command, 1)?;
    let path = path.trim();
    if path.is_empty() {
        return None;
    }
    let file_count = count_files_at(env, path);
    let size = get_size(env, path);
    let desc = match (file_count, size) {
        (Some((count, capped)), Some(sz)) => {
            format!(
                "Deletes directory with {} ({sz})",
                format_file_count(count, capped)
            )
        }
        (Some((count, capped)), None) => {
            format!(
                "Deletes directory with {}",
                format_file_count(count, capped)
            )
        }
        (None, Some(sz)) => format!("Deletes directory ({sz})"),
        (None, None) => return None,
    };
    Some(BlastRadiusInfo {
        scope: BlastScope::Resource,
        description: desc,
    })
}

fn compute_fs_strict_change_permissions(
    command: &str,
    env: &dyn Environment,
) -> Option<BlastRadiusInfo> {
    // Parse the last argument as the target path
    let owned = words_of(command);
    let parts: Vec<&str> = owned.iter().map(String::as_str).collect();
    let target = parts.last()?;
    if target.starts_with('-') || *target == "chmod" {
        return None;
    }
    if is_directory(env, target) {
        let (count, capped) = count_files_at(env, target)?;
        Some(BlastRadiusInfo {
            scope: BlastScope::Resource,
            description: format!(
                "Changes permissions on {} in {}",
                format_file_count(count, capped),
                shown(target)
            ),
        })
    } else {
        Some(BlastRadiusInfo {
            scope: BlastScope::Resource,
            description: "Changes permissions on 1 file".to_string(),
        })
    }
}

// ---------------------------------------------------------------------------
// git group computations
// ---------------------------------------------------------------------------

/// Up to three names from `list`, plus "and N more".
fn sample_names(list: &[String]) -> String {
    let shown: Vec<&str> = list.iter().take(3).map(String::as_str).collect();
    if list.len() > 3 {
        format!("{}, and {} more", shown.join(", "), list.len() - 3)
    } else {
        shown.join(", ")
    }
}

fn compute_git_reset(command: &str, env: &dyn Environment) -> Option<BlastRadiusInfo> {
    compute_git_reset_on(command, env, None)
}

/// [`compute_git_reset`] for a reset that runs on `branch` (checked out
/// earlier in the line: `git checkout main && git reset --hard origin/main`)
/// instead of the current `HEAD`.
fn compute_git_reset_on(
    command: &str,
    env: &dyn Environment,
    branch: Option<&str>,
) -> Option<BlastRadiusInfo> {
    let head = branch.unwrap_or("HEAD");
    let lines = |args: &[&str]| -> Vec<String> {
        env.run_command("git", args, TIMEOUT_MS)
            .map(|o| {
                o.lines()
                    .map(str::trim)
                    .filter(|l| !l.is_empty())
                    .map(str::to_string)
                    .collect()
            })
            .unwrap_or_default()
    };
    // A conflicted (unmerged) file is listed once per stage: count it once.
    let mut files: Vec<String> = Vec::new();
    for f in lines(&["diff", "--name-only"]).into_iter().chain(lines(&[
        "diff",
        "--cached",
        "--name-only",
    ])) {
        if !files.contains(&f) {
            files.push(f);
        }
    }
    // `git reset --hard <rev>` also drops the commits after <rev>.
    let words: Vec<&str> = command.split_whitespace().collect();
    let rev_at = words.iter().position(|w| *w == "reset").and_then(|i| {
        words[i + 1..]
            .iter()
            .take_while(|w| **w != "--")
            .position(|w| !w.starts_with('-'))
            .map(|p| i + 1 + p)
    });
    // A command substitution (`$(git rev-parse HEAD~1)`) spans several words.
    let rev: Option<String> = rev_at
        .map(|at| {
            if words[at].starts_with("$(") && !words[at].ends_with(')') {
                let end = words[at..]
                    .iter()
                    .position(|w| w.ends_with(')'))
                    .map_or(words.len(), |p| at + p + 1);
                words[at..end].join(" ")
            } else {
                words[at].to_string()
            }
        })
        .filter(|r| r != "HEAD" && r != "@");
    let dropped = rev
        .as_deref()
        .filter(|r| !r.contains('$') && !r.contains('`'))
        .and_then(|r| {
            env.run_command(
                "git",
                &["rev-list", "--count", &format!("{r}..{head}")],
                TIMEOUT_MS,
            )
            .and_then(|o| o.trim().parse::<usize>().ok())
        });
    let rev = rev.as_deref();
    let mut parts = Vec::new();
    match (rev, dropped) {
        (Some(r), Some(n)) if n > 0 => {
            let commits = format_count(n, "commit");
            parts.push(branch.map_or_else(
                || format!("Drops {commits} (moves the branch to {r})"),
                |b| format!("Drops {commits} of {b} (moves it to {r})"),
            ));
        }
        (Some(r), None) => parts.push(format!(
            "Moves the branch to {r} (commits after it are dropped)"
        )),
        _ => {}
    }
    if !files.is_empty() {
        parts.push(format!(
            "discards changes in {} ({})",
            format_count(files.len(), "modified file"),
            sample_names(&files)
        ));
    }
    if parts.is_empty() {
        return None;
    }
    let mut description = parts.join("; ");
    if let Some(first) = description.get_mut(0..1) {
        first.make_ascii_uppercase();
    }
    Some(BlastRadiusInfo {
        scope: BlastScope::Project,
        description,
    })
}

fn compute_git_delete_all(env: &dyn Environment) -> Option<BlastRadiusInfo> {
    let output = env.run_command("git", &["ls-files"], TIMEOUT_MS)?;
    let count = count_lines(&output);
    if count == 0 {
        return None;
    }
    Some(BlastRadiusInfo {
        scope: BlastScope::Project,
        description: format!("Deletes {}", format_count(count, "tracked file")),
    })
}

/// `git clean` with the user's own `-d` / `-x` / `-X` flags, as a dry run
/// (`git clean -f` alone does not remove directories, `-X` only ignored
/// files, …).
fn compute_git_clean_force(command: &str, env: &dyn Environment) -> Option<BlastRadiusInfo> {
    let words: Vec<&str> = command.split_whitespace().collect();
    let after = words
        .iter()
        .position(|w| *w == "clean")
        .map_or(&words[..0], |i| &words[i + 1..]);
    let (mut dirs, mut all, mut ignored) = (false, false, false);
    // The pathspec limits what is removed (`git clean -f build`).
    let mut paths: Vec<String> = Vec::new();
    // `-e .env` / `--exclude=.env`: kept, so the banner leaves them out.
    let mut excludes: Vec<String> = Vec::new();
    let mut after_dashdash = false;
    let mut k = 0;
    while let Some(w) = after.get(k) {
        if after_dashdash || !w.starts_with('-') {
            paths.push(crate::parser::desentinel(w));
        } else if *w == "--" {
            after_dashdash = true;
        } else if matches!(*w, "-e" | "--exclude") {
            if let Some(p) = after.get(k + 1) {
                excludes.push(format!("--exclude={}", crate::parser::desentinel(p)));
            }
            k += 1;
        } else if let Some(p) = w.strip_prefix("--exclude=") {
            excludes.push(format!("--exclude={}", crate::parser::desentinel(p)));
        } else if let Some(p) = w.strip_prefix("-e").filter(|p| !p.is_empty()) {
            excludes.push(format!("--exclude={}", crate::parser::desentinel(p)));
        } else if let Some(cluster) = w.strip_prefix('-').filter(|c| !c.starts_with('-')) {
            dirs |= cluster.contains('d');
            all |= cluster.contains('x');
            ignored |= cluster.contains('X');
        }
        k += 1;
    }
    let mut args = vec!["clean", "-n"];
    if dirs {
        args.push("-d");
    }
    if ignored {
        args.push("-X");
    } else if all {
        args.push("-x");
    }
    args.extend(excludes.iter().map(String::as_str));
    if !paths.is_empty() {
        args.push("--");
        args.extend(paths.iter().map(String::as_str));
    }
    let output = env.run_command("git", &args, TIMEOUT_MS)?;
    let mut names: Vec<String> = output
        .lines()
        .filter_map(|l| {
            let l = l.trim();
            let n = l.strip_prefix("Would remove ").unwrap_or(l);
            (!n.is_empty()).then(|| n.to_string())
        })
        .collect();
    if names.is_empty() {
        return None;
    }
    // Dotfiles (`.env`, credentials) first: they are the costly ones.
    names.sort_by_key(|n| !n.starts_with('.'));
    let kind = if ignored { "ignored" } else { "untracked" };
    let what = match (names.len(), dirs) {
        (1, true) => format!("1 {kind} file or directory"),
        (1, false) => format!("1 {kind} file"),
        (n, true) => format!("{} {kind} files or directories", format_number(n)),
        (n, false) => format!("{} {kind} files", format_number(n)),
    };
    Some(BlastRadiusInfo {
        scope: BlastScope::Project,
        description: format!("Removes {what} ({})", sample_names(&names)),
    })
}

fn compute_git_force_push(command: &str, env: &dyn Environment) -> Option<BlastRadiusInfo> {
    compute_git_force_push_on(command, env, None)
}

/// [`compute_git_force_push`] when an earlier `git checkout|switch` of the
/// line switched to `switched`: that branch is pushed, not the one checked
/// out now.
fn compute_git_force_push_on(
    command: &str,
    env: &dyn Environment,
    switched: Option<&str>,
) -> Option<BlastRadiusInfo> {
    let words: Vec<&str> = command.split_whitespace().collect();
    if words
        .iter()
        .any(|w| matches!(*w, "--all" | "--mirror" | "--branches"))
    {
        let mirror = words.contains(&"--mirror");
        return Some(BlastRadiusInfo {
            scope: BlastScope::Project,
            description: if mirror {
                "Force-pushes every local ref (branches and tags) and deletes remote refs that do not exist locally".to_string()
            } else {
                "Force-pushes all local branches, overwriting each remote branch".to_string()
            },
        });
    }
    // Try to extract branch from command, else the switched-to / current branch
    let explicit = extract_git_push_branch(command);
    let local = switched.map_or_else(|| "HEAD".to_string(), ToString::to_string);
    let branch = explicit
        .clone()
        .or_else(|| switched.map(ToString::to_string))
        .or_else(|| env.run_command("git", &["rev-parse", "--abbrev-ref", "HEAD"], TIMEOUT_MS))?;
    let local = if explicit.is_some() && switched.is_none() {
        "HEAD".to_string()
    } else {
        local
    };

    let remote_ref = format!("origin/{branch}..{local}");
    let Some(output) = env.run_command("git", &["rev-list", "--count", &remote_ref], TIMEOUT_MS)
    else {
        return switched.map(|b| BlastRadiusInfo {
            scope: BlastScope::Project,
            description: format!(
                "Force-pushes {b} (switched to in this command; origin/{branch} does not exist yet)"
            ),
        });
    };
    let count: usize = output.trim().parse().ok()?;
    if count == 0 {
        return Some(BlastRadiusInfo {
            scope: BlastScope::Project,
            description: format!("Force-pushes to origin/{branch}"),
        });
    }
    Some(BlastRadiusInfo {
        scope: BlastScope::Project,
        description: format!(
            "Force-pushes {} to origin/{branch}",
            format_count(count, "commit")
        ),
    })
}

/// Extract the branch from a `git push` command.
/// Looks for the token after a remote name (or after --force/-f).
fn extract_git_push_branch(command: &str) -> Option<String> {
    let parts: Vec<&str> = command.split_whitespace().collect();
    // Find "push" and skip flags to find remote + branch
    let push_idx = parts.iter().position(|p| *p == "push")?;
    let args: Vec<&&str> = parts[push_idx + 1..]
        .iter()
        .filter(|p| !p.starts_with('-'))
        .collect();
    // args[0] = remote, args[1] = refspec (may contain ':')
    if args.len() >= 2 {
        let refspec = args[1];
        // Handle "local:remote" refspec
        let branch = refspec.split(':').next_back().unwrap_or(refspec);
        Some(branch.to_string())
    } else {
        None
    }
}

fn compute_git_force_delete_branch(
    command: &str,
    env: &dyn Environment,
) -> Option<BlastRadiusInfo> {
    // Parse the branch name — word after -D
    let parts: Vec<&str> = command.split_whitespace().collect();
    let d_idx = parts
        .iter()
        .position(|p| *p == "-D" || *p == "--delete" || *p == "-df" || *p == "-fd")?;
    let branch = parts.get(d_idx + 1).filter(|b| !b.starts_with('-'))?;
    let full = format!("refs/heads/{branch}");
    // A branch that does not exist loses nothing.
    env.run_command(
        "git",
        &["rev-parse", "--verify", "--quiet", &full],
        TIMEOUT_MS,
    )?;
    let unmerged = env
        .run_command(
            "git",
            &["rev-list", "--count", &format!("HEAD..{full}")],
            TIMEOUT_MS,
        )
        .and_then(|o| o.trim().parse::<usize>().ok());
    Some(BlastRadiusInfo {
        scope: BlastScope::Resource,
        description: match unmerged {
            Some(n) if n > 0 => format!(
                "Deletes branch '{branch}' with {} not merged into the current branch",
                format_count(n, "commit")
            ),
            _ => format!("Deletes branch '{branch}'"),
        },
    })
}

fn compute_git_force_checkout(env: &dyn Environment) -> Option<BlastRadiusInfo> {
    let output = env.run_command("git", &["diff", "--name-only"], TIMEOUT_MS)?;
    let count = count_lines(&output);
    if count == 0 {
        return None;
    }
    Some(BlastRadiusInfo {
        scope: BlastScope::Resource,
        description: format!("Discards changes in {}", format_count(count, "file")),
    })
}

fn compute_git_filter_branch(env: &dyn Environment) -> Option<BlastRadiusInfo> {
    let output = env.run_command("git", &["rev-list", "--count", "HEAD"], TIMEOUT_MS)?;
    let count: usize = output.trim().parse().ok()?;
    if count == 0 {
        return None;
    }
    Some(BlastRadiusInfo {
        scope: BlastScope::Project,
        description: format!("Rewrites history of {}", format_count(count, "commit")),
    })
}

fn compute_git_strict_add_all(env: &dyn Environment) -> Option<BlastRadiusInfo> {
    let output = env.run_command("git", &["status", "--short"], TIMEOUT_MS)?;
    let count = count_lines(&output);
    if count == 0 {
        return None;
    }
    Some(BlastRadiusInfo {
        scope: BlastScope::Project,
        description: format!("Stages {}", format_count(count, "file")),
    })
}

fn compute_git_strict_commit_all(env: &dyn Environment) -> Option<BlastRadiusInfo> {
    let output = env.run_command("git", &["status", "--short"], TIMEOUT_MS)?;
    let count = count_lines(&output);
    if count == 0 {
        return None;
    }
    Some(BlastRadiusInfo {
        scope: BlastScope::Project,
        description: format!("Commits all changes across {}", format_count(count, "file")),
    })
}

// ---------------------------------------------------------------------------
// docker group computations
// ---------------------------------------------------------------------------

/// Whether a docker command narrows what it prunes with `--filter`.
fn has_docker_filter(command: &str) -> bool {
    command
        .split_whitespace()
        .any(|w| w == "--filter" || w.starts_with("--filter="))
}

/// The note added to a prune count when `--filter` keeps some of them.
const FILTER_NOTE: &str = " (fewer: --filter keeps some of them)";

fn compute_docker_system_prune(command: &str, env: &dyn Environment) -> Option<BlastRadiusInfo> {
    let images = env
        .run_command("docker", &["images", "-q"], TIMEOUT_MS)
        .map_or(0, |o| count_lines(&o));
    let containers = env
        .run_command("docker", &["ps", "-aq"], TIMEOUT_MS)
        .map_or(0, |o| count_lines(&o));
    // `docker system prune` removes volumes only with `--volumes`.
    let with_volumes = command
        .split_whitespace()
        .any(|w| w == "--volumes" || w == "--volumes=true");
    let volumes = if with_volumes {
        env.run_command(
            "docker",
            &["volume", "ls", "-q", "--filter", "dangling=true"],
            TIMEOUT_MS,
        )
        .map_or(0, |o| count_lines(&o))
    } else {
        0
    };
    if images == 0 && containers == 0 && volumes == 0 {
        return None;
    }
    let mut parts = vec![
        format_count(images, "image"),
        format_count(containers, "container"),
    ];
    if with_volumes {
        parts.push(format_count(volumes, "unused volume"));
    }
    let mut description = format!("Prunes up to {}", parts.join(", "));
    if has_docker_filter(command) {
        description.push_str(FILTER_NOTE);
    }
    Some(BlastRadiusInfo {
        scope: BlastScope::Machine,
        description,
    })
}

fn compute_docker_force_remove_containers(
    command: &str,
    env: &dyn Environment,
) -> Option<BlastRadiusInfo> {
    // `docker ps -aq` / `-qa` / `-a -q` / `--all` lists stopped ones too.
    let all = command
        .split_whitespace()
        .any(|w| w == "--all" || (w.starts_with('-') && !w.starts_with("--") && w.contains('a')));
    let args: &[&str] = if all { &["ps", "-aq"] } else { &["ps", "-q"] };
    let output = env.run_command("docker", args, TIMEOUT_MS)?;
    let count = count_lines(&output);
    if count == 0 {
        return None;
    }
    let noun = if all {
        "container"
    } else {
        "running container"
    };
    let mut description = format!("Removes {}", format_count(count, noun));
    if all {
        description.push_str(" (running and stopped)");
    }
    Some(BlastRadiusInfo {
        scope: BlastScope::Machine,
        description,
    })
}

fn compute_docker_volume_prune(command: &str, env: &dyn Environment) -> Option<BlastRadiusInfo> {
    // Only volumes no container uses are pruned.
    let output = env.run_command(
        "docker",
        &["volume", "ls", "-q", "--filter", "dangling=true"],
        TIMEOUT_MS,
    )?;
    let count = count_lines(&output);
    if count == 0 {
        return None;
    }
    let description = if has_docker_filter(command) {
        format!(
            "Prunes up to {}{FILTER_NOTE}",
            format_count(count, "unused volume")
        )
    } else {
        format!("Prunes {}", format_count(count, "unused volume"))
    };
    Some(BlastRadiusInfo {
        scope: BlastScope::Machine,
        description,
    })
}

fn compute_docker_stop_all(env: &dyn Environment) -> Option<BlastRadiusInfo> {
    let output = env.run_command("docker", &["ps", "-q"], TIMEOUT_MS)?;
    let count = count_lines(&output);
    if count == 0 {
        return None;
    }
    Some(BlastRadiusInfo {
        scope: BlastScope::Machine,
        description: format!("Stops {}", format_count(count, "running container")),
    })
}

// ---------------------------------------------------------------------------
// kubernetes group computations
// ---------------------------------------------------------------------------

fn compute_kubernetes_delete_namespace(
    regex: &Regex,
    command: &str,
    env: &dyn Environment,
) -> Option<BlastRadiusInfo> {
    compute_kubernetes_delete_namespace_in(regex, command, env, &[])
}

/// `kubectl delete ns X`, counting the resources with `extra` flags
/// (`--context`, `--kubeconfig`) so the targeted cluster is queried.
fn compute_kubernetes_delete_namespace_in(
    regex: &Regex,
    command: &str,
    env: &dyn Environment,
    extra: &[String],
) -> Option<BlastRadiusInfo> {
    // Parse the namespace name — word after ns/namespace in the command
    let parts: Vec<&str> = command.split_whitespace().collect();
    let ns_idx = parts
        .iter()
        .position(|p| *p == "ns" || *p == "namespace" || *p == "namespaces")?;
    // Closing punctuation of the code around the command (`arr1);`, `x')`,
    // `y]`) is not part of the name.
    let namespace = parts
        .get(ns_idx + 1)?
        .trim_end_matches([')', ']', '}', ';', '\'', '"', ','])
        .trim_start_matches(['\'', '"']);
    if namespace.is_empty() || namespace.starts_with('-') {
        return None;
    }
    // A name only known when it runs (`$n`, `{}`): nothing to probe.
    if !namespace
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '.' | '_'))
    {
        return Some(BlastRadiusInfo {
            scope: BlastScope::Namespace,
            description: format!(
                "Deletes namespace '{}' (the name is only known when it runs)",
                crate::context::escape_invisible(namespace)
            ),
        });
    }
    let mut args: Vec<&str> = extra.iter().map(String::as_str).collect();
    args.extend(["get", "all", "-n", namespace, "--no-headers"]);
    let program = match capture_group(regex, command, 1).as_deref() {
        // `k` / `kubecolor` / `oc` are normalized to kubectl by the parser.
        Some("oc") => "oc".to_string(),
        _ => "kubectl".to_string(),
    };
    let output = env.run_command(&program, &args, TIMEOUT_MS)?;
    let count = count_lines(&output);
    if count == 0 {
        return Some(BlastRadiusInfo {
            scope: BlastScope::Namespace,
            description: format!("Deletes namespace '{namespace}'"),
        });
    }
    Some(BlastRadiusInfo {
        scope: BlastScope::Namespace,
        description: format!(
            "Deletes namespace '{namespace}' with {}",
            format_count(count, "resource")
        ),
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::env::MockEnvironment;
    use std::collections::HashMap;

    fn mock_env_with_commands(commands: Vec<(&str, &str)>) -> MockEnvironment {
        let mut command_outputs = HashMap::new();
        for (cmd, output) in commands {
            command_outputs.insert(cmd.to_string(), output.to_string());
        }
        MockEnvironment {
            cwd: "/tmp/test".into(),
            command_outputs,
            ..Default::default()
        }
    }

    // -- Helper tests --

    #[test]
    fn test_parse_du_output() {
        assert_eq!(parse_du_output("12M\t/tmp/foo"), Some("12M".to_string()));
        assert_eq!(parse_du_output("4.0K /tmp/foo"), Some("4.0K".to_string()));
        assert_eq!(parse_du_output(""), None);
    }

    #[test]
    fn test_count_lines() {
        assert_eq!(count_lines("a\nb\nc"), 3);
        assert_eq!(count_lines("a\n\nb"), 2);
        assert_eq!(count_lines(""), 0);
    }

    #[test]
    fn test_format_count() {
        assert_eq!(format_count(1, "file"), "1 file");
        assert_eq!(format_count(5, "file"), "5 files");
        assert_eq!(format_count(0, "file"), "0 files");
        assert_eq!(format_count(1234, "file"), "1,234 files");
        assert_eq!(format_count(5629, "file"), "5,629 files");
        assert_eq!(format_count(47236, "file"), "47,236 files");
        assert_eq!(format_count(1234567, "commit"), "1,234,567 commits");
    }

    #[test]
    fn test_format_number() {
        assert_eq!(format_number(0), "0");
        assert_eq!(format_number(1), "1");
        assert_eq!(format_number(999), "999");
        assert_eq!(format_number(1000), "1,000");
        assert_eq!(format_number(12345), "12,345");
        assert_eq!(format_number(1000000), "1,000,000");
    }

    // -- fs group tests --

    #[test]
    fn test_fs_recursive_delete() {
        let regex = Regex::new(
            r"rm\s{1,}(?:-R|-r|-f|-fR|-fr|-Rf|-rf|-v|--force|--verbose|--preserve-root)\s*(?:-R|-r|-f|-fR|-fr|-Rf|-rf|-v|--force|--verbose|--preserve-root)?(?:\s+\S+)*?\s+(\*|\.{1,}|/)(?:\s|$)",
        ).unwrap();
        let env = mock_env_with_commands(vec![
            ("find / -maxdepth 20 -type f", "file1\nfile2\nfile3"),
            ("du -sh /", "1.2G\t/"),
        ]);
        let result = compute_fs_recursive_delete(&regex, "rm -rf /", &env);
        assert!(result.is_some());
        let info = result.unwrap();
        assert_eq!(info.scope, BlastScope::Machine);
        // Intended change: the filesystem root is reported without running
        // `find /` / `du /`.
        assert!(
            info.description.contains("entire filesystem"),
            "{}",
            info.description
        );
    }

    fn home_env() -> MockEnvironment {
        MockEnvironment {
            cwd: "/tmp/test".into(),
            home: Some("/home/dev".into()),
            ..Default::default()
        }
    }

    #[test]
    fn test_protected_targets_are_not_traversed() {
        let env = home_env();
        for (target, needle) in [
            ("/", "entire filesystem"),
            ("/*", "entire filesystem"),
            ("//", "entire filesystem"),
            ("/home/..", "entire filesystem"),
            ("~", "home directory (/home/dev)"),
            ("~/", "home directory (/home/dev)"),
            ("$HOME", "home directory (/home/dev)"),
            ("${HOME}", "home directory (/home/dev)"),
            ("/home/dev", "home directory (/home/dev)"),
            ("/etc", "system directory /etc"),
            ("/usr/", "system directory /usr"),
        ] {
            let (scope, desc) = protected_target(target, &env)
                .unwrap_or_else(|| panic!("{target} should be protected"));
            assert_eq!(scope, BlastScope::Machine, "{target}");
            assert!(desc.contains(needle), "{target}: {desc}");
        }
        assert!(protected_target("build", &env).is_none());
        assert!(protected_target("/usr/local/lib/foo", &env).is_none());
    }

    #[test]
    fn test_recursive_delete_multiple_protected_targets() {
        let regex = Regex::new(r"^rm\s+(?:\S+\s+)*?-rf\s+(?:\S+\s+)*?(/\S*)(?:\s|$)").unwrap();
        let env = home_env();
        let info = compute_fs_recursive_delete(&regex, "rm -rf /etc /usr", &env).unwrap();
        assert_eq!(info.scope, BlastScope::Machine);
        assert!(info.description.contains("/etc"), "{}", info.description);
        assert!(info.description.contains("/usr"), "{}", info.description);
    }

    #[test]
    fn test_recursive_delete_home_expands() {
        let regex = Regex::new(r"^rm\s+-rf\s+(\S+)").unwrap();
        let env = home_env();
        let info = compute_fs_recursive_delete(&regex, "rm -rf $HOME", &env).unwrap();
        assert!(
            info.description.contains("/home/dev"),
            "{}",
            info.description
        );
    }

    #[test]
    fn test_strict_deletion_multiple_operands() {
        let regex = Regex::new(r"^rm\s+(.+)$").unwrap();
        let mut env = mock_env_with_commands(vec![
            ("test -d a", ""),
            ("find a -maxdepth 20 -type f", "a/1\na/2"),
        ]);
        env.home = Some("/home/dev".into());
        let info = compute_fs_strict_any_deletion(&regex, "rm -rf a b.txt", &env).unwrap();
        assert!(info.description.contains("2 paths"), "{}", info.description);
        assert!(info.description.contains("2 files"), "{}", info.description);
    }

    #[test]
    fn test_path_with_spaces_is_one_operand() {
        let regex = Regex::new(r"^rm\s+(.+)$").unwrap();
        let env = mock_env_with_commands(vec![]);
        // The parser keeps a quoted word's spaces as the sentinel.
        let info = compute_fs_strict_any_deletion(&regex, "rm -rf my\u{1}dir", &env).unwrap();
        assert_eq!(info.description, "Deletes \"my dir\"");
        // The description keeps the real characters (the audit log stores
        // them); the banner escapes them when it displays the text.
        let info = compute_fs_strict_any_deletion(&regex, "rm -rf a\u{202e}b c", &env).unwrap();
        assert!(
            info.description.contains("a\u{202e}b"),
            "{}",
            info.description
        );
        assert!(crate::context::escape_invisible(&info.description).contains("a\\u{202e}b"));
    }

    #[test]
    fn test_strict_deletion_directory_not_called_file() {
        let regex = Regex::new(r"^rm\s+(.+)$").unwrap();
        let env = mock_env_with_commands(vec![
            ("test -d data", ""),
            ("find data -maxdepth 20 -type f", "data/1\ndata/2\ndata/3"),
        ]);
        let info = compute_fs_strict_any_deletion(&regex, "rm -rf data", &env).unwrap();
        assert!(
            info.description.contains("directory"),
            "{}",
            info.description
        );
        assert!(info.description.contains("3 files"), "{}", info.description);
    }

    #[test]
    fn test_chmod_uses_capture_group_one() {
        let regex = Regex::new(r"chmod\s+-R\s+\S+\s+(\S+)").unwrap();
        let env = home_env();
        let info = compute_fs_recursive_chmod(&regex, "chmod -R 777 ~", &env).unwrap();
        assert_eq!(info.scope, BlastScope::Machine);
        assert!(
            info.description.contains("home directory"),
            "{}",
            info.description
        );
    }

    #[test]
    fn test_find_delete_on_root_is_not_traversed() {
        let env = home_env();
        let info = compute_fs_delete_find("find / -name '*.log' -delete", &env).unwrap();
        assert_eq!(info.scope, BlastScope::Machine);
        assert!(
            info.description.contains("entire filesystem"),
            "{}",
            info.description
        );
    }

    #[test]
    fn test_command_operands() {
        assert_eq!(
            command_operands("rm -rf -- a b > /dev/null"),
            vec!["a", "b"]
        );
        assert_eq!(command_operands("rm -rf -- -weird"), vec!["-weird"]);
        assert!(command_operands("rm -rf").is_empty());
    }

    #[test]
    fn test_fs_recursive_delete_project_scope() {
        let regex = Regex::new(
            r"rm\s{1,}(?:-R|-r|-f|-fR|-fr|-Rf|-rf|-v|--force|--verbose|--preserve-root)\s*(?:-R|-r|-f|-fR|-fr|-Rf|-rf|-v|--force|--verbose|--preserve-root)?(?:\s+\S+)*?\s+(\*|\.{1,}|/)(?:\s|$)",
        ).unwrap();
        let env = mock_env_with_commands(vec![
            ("find . -maxdepth 20 -type f", "a\nb"),
            ("du -sh .", "500K\t."),
        ]);
        let result = compute_fs_recursive_delete(&regex, "rm -rf .", &env);
        assert!(result.is_some());
        let info = result.unwrap();
        assert_eq!(info.scope, BlastScope::Project);
    }

    #[test]
    fn test_fs_recursive_delete_no_match() {
        let regex = Regex::new(
            r"rm\s{1,}(?:-R|-r|-f|-fR|-fr|-Rf|-rf|-v|--force|--verbose|--preserve-root)\s*(?:-R|-r|-f|-fR|-fr|-Rf|-rf|-v|--force|--verbose|--preserve-root)?(?:\s+\S+)*?\s+(\*|\.{1,}|/)(?:\s|$)",
        ).unwrap();
        let env = MockEnvironment::default();
        let result = compute_fs_recursive_delete(&regex, "echo hello", &env);
        assert!(result.is_none());
    }

    #[test]
    fn test_fs_recursive_delete_hidden_slash() {
        let regex = Regex::new(
            r"rm\s{1,}(?:-R|-r|-f|-fR|-fr|-Rf|-rf|-v|--force|--verbose|--preserve-root)\s*(?:-R|-r|-f|-fR|-fr|-Rf|-rf|-v|--force|--verbose|--preserve-root)?(?:\s+\S+)*?\s+(\*|\.{1,}|/)(?:\s|$)",
        ).unwrap();
        let env = mock_env_with_commands(vec![
            ("find / -maxdepth 20 -type f", "file1\nfile2\nfile3"),
            ("du -sh /", "1.2G\t/"),
        ]);
        let result = compute_fs_recursive_delete(&regex, "rm -rf / node_modules", &env);
        assert!(result.is_some());
        let info = result.unwrap();
        assert_eq!(info.scope, BlastScope::Machine);
    }

    #[test]
    fn test_fs_recursive_delete_hidden_slash_middle() {
        let regex = Regex::new(
            r"rm\s{1,}(?:-R|-r|-f|-fR|-fr|-Rf|-rf|-v|--force|--verbose|--preserve-root)\s*(?:-R|-r|-f|-fR|-fr|-Rf|-rf|-v|--force|--verbose|--preserve-root)?(?:\s+\S+)*?\s+(\*|\.{1,}|/)(?:\s|$)",
        ).unwrap();
        let env = mock_env_with_commands(vec![
            ("find / -maxdepth 20 -type f", "file1\nfile2"),
            ("du -sh /", "500M\t/"),
        ]);
        let result = compute_fs_recursive_delete(&regex, "rm -rf node_modules / pkg", &env);
        assert!(result.is_some());
        let info = result.unwrap();
        assert_eq!(info.scope, BlastScope::Machine);
    }

    #[test]
    fn test_fs_recursive_delete_no_false_positive_on_path() {
        let regex = Regex::new(
            r"rm\s{1,}(?:-R|-r|-f|-fR|-fr|-Rf|-rf|-v|--force|--verbose|--preserve-root)\s*(?:-R|-r|-f|-fR|-fr|-Rf|-rf|-v|--force|--verbose|--preserve-root)?(?:\s+\S+)*?\s+(\*|\.{1,}|/)(?:\s|$)",
        ).unwrap();
        let env = MockEnvironment::default();
        let result = compute_fs_recursive_delete(&regex, "rm -rf /usr/local", &env);
        assert!(result.is_none());
    }

    // -- git group tests --

    #[test]
    fn test_git_reset() {
        let env = mock_env_with_commands(vec![
            ("git diff --name-only", "file1.rs\nfile2.rs"),
            ("git diff --cached --name-only", "file3.rs"),
        ]);
        let result = compute_git_reset("git reset --hard", &env);
        assert!(result.is_some());
        let info = result.unwrap();
        assert_eq!(info.scope, BlastScope::Project);
        assert!(info.description.contains("3 modified files"), "{info:?}");
        assert!(info.description.contains("file1.rs"), "{info:?}");
    }

    #[test]
    fn test_git_reset_to_older_commit_mentions_dropped_commits() {
        let env = mock_env_with_commands(vec![
            ("git diff --name-only", "README.md"),
            ("git rev-list --count HEAD~1..HEAD", "1"),
        ]);
        let info = compute_git_reset("git reset --hard HEAD~1", &env).unwrap();
        assert!(info.description.starts_with("Drops 1 commit"), "{info:?}");
        assert!(info.description.contains("HEAD~1"), "{info:?}");
        assert!(info.description.contains("README.md"), "{info:?}");
    }

    #[test]
    fn test_git_reset_no_changes() {
        let env = mock_env_with_commands(vec![
            ("git diff --name-only", ""),
            ("git diff --cached --name-only", ""),
        ]);
        let result = compute_git_reset("git reset --hard", &env);
        assert!(result.is_none());
    }

    #[test]
    fn test_git_force_push() {
        let env = mock_env_with_commands(vec![
            ("git rev-parse --abbrev-ref HEAD", "main"),
            ("git rev-list --count origin/main..HEAD", "5"),
        ]);
        let result = compute_git_force_push("git push --force", &env);
        assert!(result.is_some());
        let info = result.unwrap();
        assert_eq!(info.scope, BlastScope::Project);
        assert!(info.description.contains("5 commits"));
        assert!(info.description.contains("origin/main"));
    }

    #[test]
    fn test_git_force_push_with_branch() {
        let env = mock_env_with_commands(vec![("git rev-list --count origin/feature..HEAD", "3")]);
        let result = compute_git_force_push("git push -f origin feature", &env);
        assert!(result.is_some());
        let info = result.unwrap();
        assert!(info.description.contains("3 commits"));
        assert!(info.description.contains("origin/feature"));
    }

    #[test]
    fn test_git_delete_all() {
        let env = mock_env_with_commands(vec![(
            "git ls-files",
            "src/main.rs\nsrc/lib.rs\nCargo.toml",
        )]);
        let result = compute_git_delete_all(&env);
        assert!(result.is_some());
        let info = result.unwrap();
        assert!(info.description.contains("3 tracked files"));
    }

    #[test]
    fn test_git_clean_force() {
        let env = mock_env_with_commands(vec![
            ("git clean -n -d", "Would remove foo.tmp\nWould remove bar/"),
            ("git clean -n", "Would remove foo.tmp"),
            ("git clean -n -d -X", ""),
        ]);
        let info = compute_git_clean_force("git clean -f", &env).unwrap();
        assert!(
            info.description.contains("1 untracked file (foo.tmp)"),
            "{info:?}"
        );
        assert!(compute_git_clean_force("git clean -fdX", &env).is_none());
        let result = compute_git_clean_force("git clean -fd", &env);
        assert!(result.is_some());
        let info = result.unwrap();
        assert!(
            info.description
                .contains("2 untracked files or directories (foo.tmp, bar/)"),
            "{info:?}"
        );
        assert!(!info.description.contains("directorys"));
        // `-e .env` / `--exclude=.env` keep `.env`: the probe is asked the
        // same, and the banner leaves it out.
        let env = mock_env_with_commands(vec![
            (
                "git clean -n -d -x",
                "Would remove .env\nWould remove app.log",
            ),
            ("git clean -n -d -x --exclude=.env", "Would remove app.log"),
        ]);
        for cmd in [
            "git clean -fdx -e .env",
            "git clean -fdx --exclude=.env",
            "git clean -fdx -e.env",
        ] {
            let info = compute_git_clean_force(cmd, &env).unwrap();
            assert!(
                info.description
                    .contains("1 untracked file or directory (app.log)"),
                "{cmd}: {info:?}"
            );
        }
    }

    #[test]
    fn test_git_force_delete_branch() {
        let env = mock_env_with_commands(vec![
            ("git rev-parse --verify --quiet refs/heads/feature-x", "abc"),
            ("git rev-list --count HEAD..refs/heads/feature-x", "2"),
        ]);
        let result = compute_git_force_delete_branch("git branch -D feature-x", &env);
        assert!(result.is_some());
        let info = result.unwrap();
        assert_eq!(info.scope, BlastScope::Resource);
        assert!(info.description.contains("feature-x"));
        assert!(
            info.description.contains("2 commits not merged"),
            "{info:?}"
        );
        // A branch that does not exist loses nothing.
        let none = mock_env_with_commands(vec![]);
        assert!(compute_git_force_delete_branch("git branch -D nothere", &none).is_none());
    }

    #[test]
    fn test_git_force_push_all_branches() {
        let env = mock_env_with_commands(vec![]);
        let info = compute_git_force_push("git push --all --force", &env).unwrap();
        assert!(info.description.contains("all local branches"), "{info:?}");
        assert!(!info.description.contains("origin/main"));
    }

    #[test]
    fn test_docker_ps_aq_counts_all_containers() {
        let env = mock_env_with_commands(vec![("docker ps -aq", "a\nb\nc"), ("docker ps -q", "a")]);
        let info =
            compute_docker_force_remove_containers("docker rm -f $(docker ps -aq)", &env).unwrap();
        assert!(
            info.description
                .contains("3 containers (running and stopped)"),
            "{info:?}"
        );
        let info =
            compute_docker_force_remove_containers("docker rm -f $(docker ps -q)", &env).unwrap();
        assert!(info.description.contains("1 running container"), "{info:?}");
    }

    #[test]
    fn test_find_delete_honours_filters() {
        let env = mock_env_with_commands(vec![
            ("find . -name *.log", "./a.log"),
            ("find . -maxdepth 20 -type f", "a\nb\nc\nd"),
        ]);
        let info = compute_fs_delete_find("find . -name *.log -delete", &env).unwrap();
        assert!(
            info.description.contains("1 path matching the filters"),
            "{info:?}"
        );
        // `-delete` before the filter deletes everything.
        let info = compute_fs_delete_find("find . -delete -name *.log", &env).unwrap();
        assert!(info.description.contains("everything under ."), "{info:?}");
        // Other actions are never run: the count is unknown.
        let info = compute_fs_delete_find("find . -name x -exec rm {} ; -delete", &env).unwrap();
        assert!(info.description.contains("count unknown"), "{info:?}");
    }

    #[test]
    fn test_remote_segments_are_not_measured_locally() {
        let checks = crate::checks::get_all().unwrap();
        let check = checks
            .iter()
            .find(|c| c.id == "fs-strict:recursive_deletion")
            .unwrap()
            .clone();
        let env = mock_env_with_commands(vec![("test -d /data", "")]);
        let parts = vec!["rm -rf /data".to_string()];
        let out = compute_for_matches_remote_aware(
            &[check],
            &parts,
            &parts,
            "ssh host rm -rf /data",
            &env,
        );
        assert_eq!(out.len(), 1);
        assert!(out[0].1.description.contains("another host"), "{out:?}");
    }

    #[test]
    fn test_namespace_count_uses_command_context() {
        let checks = crate::checks::get_all().unwrap();
        let check = checks
            .iter()
            .find(|c| c.id == "kubernetes:delete_namespace")
            .unwrap()
            .clone();
        let env = mock_env_with_commands(vec![(
            "kubectl --context prod-eu get all -n payments --no-headers",
            "a\nb",
        )]);
        let parts = vec!["kubectl delete ns payments".to_string()];
        let out = compute_for_matches_remote_aware(
            &[check],
            &parts,
            &[],
            "kubectl --context prod-eu delete ns payments",
            &env,
        );
        assert!(out[0].1.description.contains("2 resources"), "{out:?}");
    }

    #[test]
    fn test_git_force_checkout() {
        let env = mock_env_with_commands(vec![(
            "git diff --name-only",
            "file1.rs\nfile2.rs\nfile3.rs",
        )]);
        let result = compute_git_force_checkout(&env);
        assert!(result.is_some());
        let info = result.unwrap();
        assert!(info.description.contains("3 files"));
    }

    #[test]
    fn test_git_filter_branch() {
        let env = mock_env_with_commands(vec![("git rev-list --count HEAD", "1203")]);
        let result = compute_git_filter_branch(&env);
        assert!(result.is_some());
        let info = result.unwrap();
        assert!(info.description.contains("1,203 commits"));
    }

    #[test]
    fn test_git_strict_add_all() {
        let env = mock_env_with_commands(vec![(
            "git status --short",
            " M file1.rs\n?? file2.rs\n M file3.rs",
        )]);
        let result = compute_git_strict_add_all(&env);
        assert!(result.is_some());
        let info = result.unwrap();
        assert!(info.description.contains("3 files"));
    }

    // -- docker group tests --

    #[test]
    fn test_docker_system_prune() {
        let env = mock_env_with_commands(vec![
            ("docker images -q", "abc\ndef\nghi"),
            ("docker ps -aq", "111\n222"),
            ("docker volume ls -q --filter dangling=true", "vol1"),
        ]);
        // Without --volumes, volumes are not pruned and not counted.
        let info = compute_docker_system_prune("docker system prune -af", &env).unwrap();
        assert_eq!(info.scope, BlastScope::Machine);
        assert!(info.description.contains("3 images"));
        assert!(info.description.contains("2 containers"));
        assert!(!info.description.contains("volume"), "{}", info.description);
        let info = compute_docker_system_prune("docker system prune -af --volumes", &env).unwrap();
        assert!(
            info.description.contains("1 unused volume"),
            "{}",
            info.description
        );
        let info = compute_docker_system_prune("docker system prune -af --filter until=24h", &env)
            .unwrap();
        assert!(
            info.description.contains("--filter"),
            "{}",
            info.description
        );
    }

    #[test]
    fn test_docker_volume_prune_counts_unused_and_names_the_filter() {
        let env = mock_env_with_commands(vec![(
            "docker volume ls -q --filter dangling=true",
            "v1\nv2",
        )]);
        let info = compute_docker_volume_prune("docker volume prune -f", &env).unwrap();
        assert_eq!(info.description, "Prunes 2 unused volumes");
        let info =
            compute_docker_volume_prune("docker volume prune -f --filter label=keep!=1", &env)
                .unwrap();
        assert!(info
            .description
            .starts_with("Prunes up to 2 unused volumes"));
        assert!(
            info.description.contains("--filter"),
            "{}",
            info.description
        );
    }

    #[test]
    fn test_docker_stop_all() {
        let env = mock_env_with_commands(vec![("docker ps -q", "abc\ndef")]);
        let result = compute_docker_stop_all(&env);
        assert!(result.is_some());
        let info = result.unwrap();
        assert!(info.description.contains("2 running containers"));
    }

    // -- kubernetes group tests --

    #[test]
    fn test_kubernetes_delete_namespace() {
        let regex = Regex::new(r"(kubectl|k)\s+delete\s+(ns|namespace)").unwrap();
        let env = mock_env_with_commands(vec![(
            "kubectl get all -n staging --no-headers",
            "pod/web-1\npod/web-2\nsvc/web",
        )]);
        let result = compute_kubernetes_delete_namespace(&regex, "kubectl delete ns staging", &env);
        assert!(result.is_some());
        let info = result.unwrap();
        assert_eq!(info.scope, BlastScope::Namespace);
        assert!(info.description.contains("staging"));
        assert!(info.description.contains("3 resources"));
    }

    // -- dispatch tests --

    #[test]
    fn test_unsupported_check_returns_none() {
        let regex = Regex::new("test").unwrap();
        let env = MockEnvironment::default();
        assert!(compute("base:fork_bomb", &regex, ":(){ :|:& };:", &env).is_none());
    }

    #[test]
    fn test_compute_for_matches_empty() {
        let env = MockEnvironment::default();
        let result = compute_for_matches(&[], &["echo hello".to_string()], "echo hello", &env);
        assert!(result.is_empty());
    }

    #[test]
    fn test_extract_git_push_branch() {
        assert_eq!(
            extract_git_push_branch("git push -f origin main"),
            Some("main".to_string())
        );
        assert_eq!(
            extract_git_push_branch("git push --force origin feature:feature"),
            Some("feature".to_string())
        );
        assert_eq!(extract_git_push_branch("git push --force"), None);
    }

    #[test]
    fn test_blast_scope_ordering() {
        assert!(BlastScope::Resource < BlastScope::Project);
        assert!(BlastScope::Project < BlastScope::Namespace);
        assert!(BlastScope::Namespace < BlastScope::Machine);
    }

    /// Every subprocess takes `delay_ms` (or is "killed" at its timeout).
    struct SlowEnv {
        inner: MockEnvironment,
        delay_ms: u64,
    }

    impl Environment for SlowEnv {
        fn var(&self, key: &str) -> Option<String> {
            self.inner.var(key)
        }
        fn current_dir(&self) -> crate::error::Result<std::path::PathBuf> {
            self.inner.current_dir()
        }
        fn path_exists(&self, path: &std::path::Path) -> bool {
            self.inner.path_exists(path)
        }
        fn home_dir(&self) -> Option<std::path::PathBuf> {
            self.inner.home_dir()
        }
        fn run_command(&self, cmd: &str, args: &[&str], timeout_ms: u64) -> Option<String> {
            self.run_command_outcome(cmd, args, timeout_ms).output()
        }
        fn run_command_outcome(&self, cmd: &str, args: &[&str], timeout_ms: u64) -> CommandOutcome {
            if self.delay_ms > timeout_ms {
                thread::sleep(Duration::from_millis(timeout_ms));
                return CommandOutcome::TimedOut;
            }
            thread::sleep(Duration::from_millis(self.delay_ms));
            self.inner.run_command_outcome(cmd, args, timeout_ms)
        }
        fn read_file(&self, path: &std::path::Path) -> crate::error::Result<String> {
            self.inner.read_file(path)
        }
        fn find_file_upward(
            &self,
            start: &std::path::Path,
            filename: &str,
        ) -> Option<std::path::PathBuf> {
            self.inner.find_file_upward(start, filename)
        }
    }

    fn check(id: &str) -> crate::checks::Check {
        crate::checks::get_all()
            .unwrap()
            .into_iter()
            .find(|c| c.id == id)
            .unwrap()
    }

    #[test]
    fn total_budget_bounds_the_wait_and_marks_the_description() {
        // Three slow paths used to cost 3 s each (find + du per path, one
        // after another). One total budget now caps it.
        let env = SlowEnv {
            inner: mock_env_with_commands(vec![
                ("test -d /data/a", ""),
                ("test -d /data/b", ""),
                ("test -d /data/c", ""),
            ]),
            delay_ms: 2_000,
        };
        let cmd = "rm -rf /data/a /data/b /data/c";
        let parts = vec![cmd.to_string()];
        let started = Instant::now();
        let out = compute_for_matches_within(
            &[check("fs-strict:recursive_deletion")],
            &parts,
            &[],
            cmd,
            &env,
            150,
        );
        let took = started.elapsed();
        assert!(took < Duration::from_millis(600), "took {took:?}");
        assert_eq!(out.len(), 1, "{out:?}");
        assert!(
            out[0].1.description.contains("not computed: took too long"),
            "{out:?}"
        );
    }

    #[test]
    fn budget_zero_skips_the_blast_radius() {
        let env = mock_env_with_commands(vec![("git status --porcelain", " M a")]);
        let parts = vec!["git reset --hard".to_string()];
        let out =
            compute_for_matches_within(&[check("git:reset")], &parts, &[], &parts[0], &env, 0);
        assert!(out.is_empty(), "{out:?}");
    }

    #[test]
    fn fast_work_within_the_budget_is_not_marked() {
        let env = SlowEnv {
            inner: mock_env_with_commands(vec![("git status --porcelain", " M README.md")]),
            delay_ms: 1,
        };
        let parts = vec!["git reset --hard".to_string()];
        let out =
            compute_for_matches_within(&[check("git:reset")], &parts, &[], &parts[0], &env, 2_000);
        assert!(
            out.iter()
                .all(|(_, br)| !br.description.contains("took too long")),
            "{out:?}"
        );
    }

    #[test]
    fn a_slow_git_query_is_marked_not_fully_measured() {
        let env = SlowEnv {
            inner: mock_env_with_commands(vec![("git status --porcelain", " M README.md")]),
            delay_ms: 5_000,
        };
        let parts = vec!["git reset --hard".to_string()];
        let started = Instant::now();
        let out =
            compute_for_matches_within(&[check("git:reset")], &parts, &[], &parts[0], &env, 100);
        assert!(started.elapsed() < Duration::from_millis(600));
        assert_eq!(out.len(), 1, "{out:?}");
        assert!(out[0].1.description.contains("took too long"), "{out:?}");
    }

    #[cfg(unix)]
    #[test]
    fn a_timed_out_command_and_its_children_are_killed() {
        // A wrapper script that leaves a grandchild holding stdout must not
        // keep shellfirm waiting, and nothing it started may outlive it.
        let dir = std::env::temp_dir().join(format!("sf-br-kill-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let marker = dir.join("still-running");
        let script = format!("sleep 3; touch {}", marker.display());
        let env = crate::env::RealEnvironment;
        let started = Instant::now();
        let out = env.run_command_outcome("sh", &["-c", &script], 200);
        assert_eq!(out, CommandOutcome::TimedOut);
        assert!(started.elapsed() < Duration::from_millis(1_500));
        thread::sleep(Duration::from_millis(3_300));
        assert!(!marker.exists(), "the grandchild survived the timeout");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Like [`SlowEnv`], counting the subprocesses it is asked to run.
    struct CountingEnv {
        slow: SlowEnv,
        calls: std::sync::atomic::AtomicUsize,
    }

    impl Environment for CountingEnv {
        fn var(&self, key: &str) -> Option<String> {
            self.slow.var(key)
        }
        fn current_dir(&self) -> crate::error::Result<std::path::PathBuf> {
            self.slow.current_dir()
        }
        fn path_exists(&self, path: &std::path::Path) -> bool {
            self.slow.path_exists(path)
        }
        fn home_dir(&self) -> Option<std::path::PathBuf> {
            self.slow.home_dir()
        }
        fn run_command(&self, cmd: &str, args: &[&str], timeout_ms: u64) -> Option<String> {
            self.run_command_outcome(cmd, args, timeout_ms).output()
        }
        fn run_command_outcome(&self, cmd: &str, args: &[&str], timeout_ms: u64) -> CommandOutcome {
            self.calls
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            self.slow.run_command_outcome(cmd, args, timeout_ms)
        }
        fn read_file(&self, path: &std::path::Path) -> crate::error::Result<String> {
            self.slow.read_file(path)
        }
        fn find_file_upward(
            &self,
            start: &std::path::Path,
            filename: &str,
        ) -> Option<std::path::PathBuf> {
            self.slow.find_file_upward(start, filename)
        }
    }

    #[test]
    fn one_scope_spends_the_budget_once_and_every_view_reads_the_same() {
        // `check` evaluates a command up to three times; inside one scope
        // the wait is one budget and the text is the same each time.
        let env = CountingEnv {
            slow: SlowEnv {
                inner: mock_env_with_commands(vec![("git status --porcelain", " M a")]),
                delay_ms: 5_000,
            },
            calls: std::sync::atomic::AtomicUsize::new(0),
        };
        let parts = vec!["git reset --hard".to_string()];
        let started = Instant::now();
        let _scope = crate::env::CommandScope::enter(200);
        let first =
            compute_for_matches_remote_aware(&[check("git:reset")], &parts, &[], &parts[0], &env);
        let calls = env.calls.load(std::sync::atomic::Ordering::Relaxed);
        let second =
            compute_for_matches_remote_aware(&[check("git:reset")], &parts, &[], &parts[0], &env);
        let third =
            compute_for_matches_remote_aware(&[check("git:reset")], &parts, &[], &parts[0], &env);
        let took = started.elapsed();
        assert!(took < Duration::from_millis(600), "took {took:?}");
        assert_eq!(
            env.calls.load(std::sync::atomic::Ordering::Relaxed),
            calls,
            "the later views ran no subprocess"
        );
        assert_eq!(first[0].1.description, second[0].1.description);
        assert_eq!(first[0].1.description, third[0].1.description);
        assert!(
            first[0].1.description.contains("took too long"),
            "{first:?}"
        );
    }

    #[test]
    fn time_spent_before_the_blast_radius_counts_against_the_scope() {
        // The context lookups (git branch, kube context) run first: their
        // time is part of the same budget.
        let env = SlowEnv {
            inner: mock_env_with_commands(vec![("git status --porcelain", " M a")]),
            delay_ms: 5_000,
        };
        let parts = vec!["git reset --hard".to_string()];
        let started = Instant::now();
        let _scope = crate::env::CommandScope::enter(300);
        thread::sleep(Duration::from_millis(300));
        let out =
            compute_for_matches_remote_aware(&[check("git:reset")], &parts, &[], &parts[0], &env);
        assert!(
            started.elapsed() < Duration::from_millis(450),
            "{:?}",
            started.elapsed()
        );
        assert_eq!(
            out[0].1.description, "Impact not measured (skipped: no time left)",
            "{out:?}"
        );
    }

    #[test]
    fn scope_budget_is_capped() {
        let _scope = crate::env::CommandScope::enter(600_000);
        assert_eq!(
            budget_ms(),
            crate::config::MAX_BLAST_RADIUS_BUDGET_MS,
            "a huge setting is used as the cap"
        );
        // A nested scope keeps the outer one.
        let _inner = crate::env::CommandScope::enter(0);
        assert_eq!(budget_ms(), crate::config::MAX_BLAST_RADIUS_BUDGET_MS);
    }

    #[test]
    fn without_a_scope_the_default_budget_applies() {
        assert_eq!(budget_ms(), crate::config::DEFAULT_BLAST_RADIUS_BUDGET_MS);
    }

    /// `find` "times out" after listing `listed` files.
    struct PartialFindEnv {
        inner: MockEnvironment,
        listed: usize,
    }

    impl Environment for PartialFindEnv {
        fn var(&self, key: &str) -> Option<String> {
            self.inner.var(key)
        }
        fn current_dir(&self) -> crate::error::Result<std::path::PathBuf> {
            self.inner.current_dir()
        }
        fn path_exists(&self, path: &std::path::Path) -> bool {
            self.inner.path_exists(path)
        }
        fn home_dir(&self) -> Option<std::path::PathBuf> {
            self.inner.home_dir()
        }
        fn run_command(&self, cmd: &str, args: &[&str], timeout_ms: u64) -> Option<String> {
            self.run_command_outcome(cmd, args, timeout_ms).output()
        }
        fn run_command_outcome(&self, cmd: &str, args: &[&str], timeout_ms: u64) -> CommandOutcome {
            self.run_command_partial(cmd, args, timeout_ms).0
        }
        fn run_command_partial(
            &self,
            cmd: &str,
            args: &[&str],
            timeout_ms: u64,
        ) -> (CommandOutcome, Option<String>) {
            if cmd == "find" {
                let mut out: String = (0..self.listed).map(|i| format!("./f{i}\n")).collect();
                out.push_str("./cut-in-the-mid");
                return (CommandOutcome::TimedOut, Some(out));
            }
            (self.inner.run_command_outcome(cmd, args, timeout_ms), None)
        }
        fn read_file(&self, path: &std::path::Path) -> crate::error::Result<String> {
            self.inner.read_file(path)
        }
        fn find_file_upward(
            &self,
            start: &std::path::Path,
            filename: &str,
        ) -> Option<std::path::PathBuf> {
            self.inner.find_file_upward(start, filename)
        }
    }

    #[test]
    fn a_stopped_count_is_a_stated_lower_bound_for_one_and_many_paths() {
        for (cmd, id, shown) in [
            ("rm -rf /data/a", "fs-strict:recursive_deletion", "1,234"),
            (
                "rm -rf /data/a /data/b",
                "fs-strict:recursive_deletion",
                "2,468",
            ),
        ] {
            let env = PartialFindEnv {
                inner: mock_env_with_commands(vec![
                    ("test -d /data/a", ""),
                    ("test -d /data/b", ""),
                    ("du -sh /data/a", "1004K\t/data/a"),
                ]),
                listed: 1234,
            };
            let parts = vec![cmd.to_string()];
            let out = compute_for_matches_within(&[check(id)], &parts, &[], cmd, &env, 2_000);
            let d = &out[0].1.description;
            assert!(
                d.contains(&format!("more than {shown} files (stopped counting)")),
                "{d}"
            );
            assert!(!d.contains("not computed"), "no contradicting note: {d}");
            assert!(!d.contains('~') && !d.contains("files+"), "{d}");
        }
    }

    #[test]
    fn only_the_count_missing_says_so() {
        // `du` finished, `find` timed out with nothing listed.
        let env = PartialFindEnv {
            inner: mock_env_with_commands(vec![
                ("test -d /data/a", ""),
                ("du -sh /data/a", "1004K\t/data/a"),
            ]),
            listed: 0,
        };
        let cmd = "rm -rf /data/a";
        let parts = vec![cmd.to_string()];
        let out = compute_for_matches_within(
            &[check("fs-strict:recursive_deletion")],
            &parts,
            &[],
            cmd,
            &env,
            2_000,
        );
        let d = &out[0].1.description;
        assert!(d.contains("(1004K)"), "{d}");
        assert!(
            d.contains("(file count not computed: took too long)"),
            "{d}"
        );
        assert!(!d.contains("size not computed"), "{d}");
    }

    #[test]
    fn an_empty_file_is_zero_bytes() {
        assert_eq!(parse_du_output("0\t/tmp/e0"), Some("0 B".to_string()));
    }

    #[test]
    fn progress_line_says_ctrl_c_cancels() {
        let t = progress_notice_text();
        assert!(t.starts_with("shellfirm: checking impact"), "{t}");
        assert!(t.ends_with(" (Ctrl-C cancels)"), "{t}");
    }
}
