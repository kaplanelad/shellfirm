//! Environment abstraction for testability.
//!
//! Provides the [`Environment`] trait to abstract all external I/O
//! (env vars, filesystem, subprocesses), enabling fully sandboxed testing.

use std::{
    cell::RefCell,
    collections::{HashMap, HashSet},
    io::{BufReader, Read as _},
    marker::PhantomData,
    path::{Path, PathBuf},
    process,
    sync::atomic::{AtomicBool, Ordering},
    thread,
    time::{Duration, Instant},
};

use crate::error::Result;
use wait_timeout::ChildExt;

/// Abstracts all interaction with the operating system.
///
/// The real application uses [`RealEnvironment`]; tests inject
/// [`MockEnvironment`] so that nothing touches the real system.
pub trait Environment: Send + Sync {
    /// Read an environment variable.
    fn var(&self, key: &str) -> Option<String>;

    /// Get the current working directory.
    ///
    /// # Errors
    /// Returns an error if the working directory cannot be determined.
    fn current_dir(&self) -> Result<PathBuf>;

    /// Check if a path exists (file or directory).
    fn path_exists(&self, path: &Path) -> bool;

    /// Get the user's home directory.
    fn home_dir(&self) -> Option<PathBuf>;

    /// Run a command and return its stdout, or `None` on failure/timeout.
    fn run_command(&self, cmd: &str, args: &[&str], timeout_ms: u64) -> Option<String>;

    /// Run a command and report *why* it produced no output.
    ///
    /// Unlike [`Self::run_command`], this distinguishes a timeout (the answer
    /// is unknown) from a clean failure (the answer is "nothing"). The
    /// default implementation is built on [`Self::run_command`] and can only
    /// report [`CommandOutcome::Failed`] for the `None` case.
    fn run_command_outcome(&self, cmd: &str, args: &[&str], timeout_ms: u64) -> CommandOutcome {
        self.run_command(cmd, args, timeout_ms)
            .map_or(CommandOutcome::Failed, CommandOutcome::Output)
    }

    /// Like [`Self::run_command_outcome`], but a command that timed out also
    /// returns what it printed before it was stopped (when known), so a
    /// file count can say "more than N files" instead of nothing. The
    /// default reports no partial output.
    fn run_command_partial(
        &self,
        cmd: &str,
        args: &[&str],
        timeout_ms: u64,
    ) -> (CommandOutcome, Option<String>) {
        (self.run_command_outcome(cmd, args, timeout_ms), None)
    }

    /// The effective user id of the current process (`geteuid(2)`), or
    /// `None` when it cannot be determined (non-unix platforms, mocks).
    ///
    /// Used for root detection. Shell variables such as `$EUID` are *not*
    /// exported to child processes, so they cannot be used for this.
    fn effective_uid(&self) -> Option<u32> {
        None
    }

    /// Read a file's contents.
    ///
    /// # Errors
    /// Returns an error if the file cannot be read.
    fn read_file(&self, path: &Path) -> Result<String>;

    /// Walk up directories from `start` looking for `filename`.
    /// Returns the full path to the first match, or `None`.
    fn find_file_upward(&self, start: &Path, filename: &str) -> Option<PathBuf>;
}

/// The outcome of [`Environment::run_command_outcome`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CommandOutcome {
    /// The command succeeded; trimmed stdout.
    Output(String),
    /// The command could not be spawned or exited with a non-zero status.
    Failed,
    /// The command did not finish within the timeout (it was killed).
    TimedOut,
    /// The command was not run at all (`--no-context`, see
    /// [`NoContextEnvironment`]).
    Skipped,
}

impl CommandOutcome {
    /// The output, if the command succeeded.
    #[must_use]
    pub fn output(self) -> Option<String> {
        match self {
            Self::Output(o) => Some(o),
            Self::Failed | Self::TimedOut | Self::Skipped => None,
        }
    }
}

// ---------------------------------------------------------------------------
// Real implementation (used in production)
// ---------------------------------------------------------------------------

/// Production [`Environment`] backed by the real OS.
pub struct RealEnvironment;

impl Environment for RealEnvironment {
    fn var(&self, key: &str) -> Option<String> {
        std::env::var(key).ok()
    }

    fn current_dir(&self) -> Result<PathBuf> {
        std::env::current_dir().map_err(Into::into)
    }

    fn path_exists(&self, path: &Path) -> bool {
        path.exists()
    }

    fn home_dir(&self) -> Option<PathBuf> {
        dirs::home_dir()
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
        // Inside a command scope each program is asked once: the shell view,
        // the agent view and the target repository's policy reuse the answer.
        if let Some(hit) = scope_lookup(cmd, args) {
            return hit;
        }
        let result = run_real_command(cmd, args, timeout_ms);
        scope_store(cmd, args, &result);
        result
    }
    fn effective_uid(&self) -> Option<u32> {
        #[cfg(unix)]
        {
            // SAFETY: geteuid(2) has no preconditions and cannot fail.
            Some(unsafe { libc::geteuid() })
        }
        #[cfg(not(unix))]
        {
            None
        }
    }

    fn read_file(&self, path: &Path) -> Result<String> {
        Ok(std::fs::read_to_string(path)?)
    }

    fn find_file_upward(&self, start: &Path, filename: &str) -> Option<PathBuf> {
        let mut current = start.to_path_buf();
        loop {
            let candidate = current.join(filename);
            if candidate.is_file() {
                return Some(candidate);
            }
            if !current.pop() {
                return None;
            }
        }
    }
}

/// Run `cmd` in its own process group, killing the group on a timeout.
/// A command that timed out also returns what it wrote before it was
/// stopped (see [`Environment::run_command_partial`]).
fn run_real_command(cmd: &str, args: &[&str], timeout_ms: u64) -> (CommandOutcome, Option<String>) {
    run_cancellable_command(cmd, args, timeout_ms, &CANCEL)
}

/// [`run_real_command`] that also stops (as a timeout) as soon as `cancel`
/// is set.
fn run_cancellable_command(
    cmd: &str,
    args: &[&str],
    timeout_ms: u64,
    cancel: &AtomicBool,
) -> (CommandOutcome, Option<String>) {
    // Ctrl-C during the measurement: nothing new is started.
    if cancel.load(Ordering::SeqCst) {
        return (CommandOutcome::TimedOut, None);
    }
    let mut command = process::Command::new(cmd);
    // shellfirm only reads the repository: `git status` must not take (and,
    // when stopped by the budget, leave behind) the optional `index.lock`.
    if is_git_program(cmd) {
        command.arg("--no-optional-locks");
    }
    command
        .args(args)
        .env("GIT_OPTIONAL_LOCKS", "0")
        .stdin(process::Stdio::null())
        .stdout(process::Stdio::piped())
        .stderr(process::Stdio::null());
    // Its own process group, so a timeout kills everything it started
    // (a wrapper script's `sleep`, `find` under `xargs`): no orphans,
    // and no grandchild keeps the stdout pipe (and us) waiting.
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt as _;
        command.process_group(0);
    }
    let Ok(mut child) = command.spawn() else {
        return (CommandOutcome::Failed, None);
    };

    // Read stdout in a separate thread to prevent pipe buffer deadlock.
    // Without this, processes producing >64KB of stdout (e.g. `find` on
    // large directories) block on write, causing wait_timeout to fire
    // even though the process hasn't finished computing.
    let Some(stdout) = child.stdout.take() else {
        return (CommandOutcome::Failed, None);
    };
    let reader_handle = thread::spawn(move || {
        let mut output = Vec::new();
        let mut reader = BufReader::new(stdout);
        let _ = reader.read_to_end(&mut output);
        String::from_utf8_lossy(&output).into_owned()
    });

    match wait_cancellable(&mut child, Duration::from_millis(timeout_ms), cancel) {
        Ok(Some(status)) => {
            // Anything the command left running in the background would
            // hold the pipe open: end it before reading to EOF.
            kill_process_group(&child);
            let output = reader_handle.join().ok();
            if status.success() {
                (
                    output.map_or(CommandOutcome::Failed, |o| {
                        CommandOutcome::Output(o.trim().to_string())
                    }),
                    None,
                )
            } else {
                (CommandOutcome::Failed, None)
            }
        }
        Ok(None) => {
            // Timeout (or Ctrl-C): end the whole group (closes the pipe,
            // unblocks the reader) and reap the child. SIGTERM first, so
            // git removes its lock files; SIGKILL whatever is left.
            terminate_process_group(&mut child);
            let _ = child.kill();
            let _ = child.wait();
            let partial = reader_handle.join().ok().filter(|o| !o.is_empty());
            (CommandOutcome::TimedOut, partial)
        }
        Err(_) => {
            kill_process_group(&child);
            let _ = child.kill();
            let _ = child.wait();
            (CommandOutcome::Failed, None)
        }
    }
}

/// Whether `cmd` runs git (`git`, `/usr/bin/git`).
fn is_git_program(cmd: &str) -> bool {
    Path::new(cmd).file_name().is_some_and(|n| n == "git")
}

/// How often a running subprocess is checked for Ctrl-C (see
/// [`request_cancel`]).
const CANCEL_POLL: Duration = Duration::from_millis(10);

/// Wait for `child` up to `timeout`, but stop early (as if it timed out)
/// when `cancel` is set (see [`request_cancel`]). `Ok(None)` means it is still running.
fn wait_cancellable(
    child: &mut process::Child,
    timeout: Duration,
    cancel: &AtomicBool,
) -> std::io::Result<Option<process::ExitStatus>> {
    let deadline = Instant::now() + timeout;
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() || cancel.load(Ordering::SeqCst) {
            return child.try_wait();
        }
        if let Some(status) = child.wait_timeout(left.min(CANCEL_POLL))? {
            return Ok(Some(status));
        }
    }
}

/// How long a process group gets to exit after `SIGTERM` before `SIGKILL`.
const TERM_GRACE: Duration = Duration::from_millis(50);

/// End the process group `child` leads: `SIGTERM`, up to [`TERM_GRACE`] for
/// the leader to exit (git removes its `index.lock` on `SIGTERM`), then
/// `SIGKILL` for anything left.
fn terminate_process_group(child: &mut process::Child) {
    #[cfg(unix)]
    {
        if let Ok(pid) = libc::pid_t::try_from(child.id()) {
            // SAFETY: kill(2) with a negative pid signals that process group;
            // it has no memory-safety preconditions.
            unsafe {
                libc::kill(-pid, libc::SIGTERM);
            }
            let _ = child.wait_timeout(TERM_GRACE);
        }
    }
    kill_process_group(child);
}

static CANCEL: AtomicBool = AtomicBool::new(false);

/// Ask every running and future subprocess of this process to stop now
/// (Ctrl-C while the impact is measured). Only stores to an atomic, so it
/// may be called from a signal handler.
pub fn request_cancel() {
    CANCEL.store(true, Ordering::SeqCst);
}

/// Undo [`request_cancel`] (before measuring the next command).
pub fn reset_cancel() {
    CANCEL.store(false, Ordering::SeqCst);
}

/// Whether [`request_cancel`] was called.
#[must_use]
pub fn cancel_requested() -> bool {
    CANCEL.load(Ordering::SeqCst)
}

/// `SIGKILL` the process group `child` leads (see `process_group(0)` in
/// [`RealEnvironment::run_command_outcome`]). A group that is already gone
/// is not an error.
fn kill_process_group(child: &process::Child) {
    #[cfg(unix)]
    {
        if let Ok(pid) = libc::pid_t::try_from(child.id()) {
            // SAFETY: kill(2) with a negative pid signals that process group;
            // it has no memory-safety preconditions.
            unsafe {
                libc::kill(-pid, libc::SIGKILL);
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = child;
    }
}

// ---------------------------------------------------------------------------
// Command scope: one time budget and one answer per program for a command
// ---------------------------------------------------------------------------

type ScopeKey = (String, Vec<String>);

struct ScopeState {
    start: Instant,
    budget_ms: u64,
    /// Answers of the external programs run in this scope.
    outcomes: HashMap<ScopeKey, (CommandOutcome, Option<String>)>,
    /// Programs the blast radius skipped because the budget was spent.
    budget_skips: HashSet<ScopeKey>,
}

thread_local! {
    static SCOPE: RefCell<Option<ScopeState>> = const { RefCell::new(None) };
}

/// Everything shellfirm does to evaluate **one** command shares one time
/// budget and asks each external program once.
///
/// `check` evaluates a command up to three times (the agent view, the
/// target repository's policy and the shell view), an agent hook twice.
/// Inside a scope the clock starts when the scope is entered, so the
/// context lookups (git branch, kube context) count against the budget, and
/// every later evaluation reuses the answers of the first one: the wait is
/// one budget, and every view shows the same impact text.
///
/// The scope belongs to the current thread. Entering a scope while one is
/// active keeps the outer one (the returned guard does nothing).
#[must_use = "the scope ends when the guard is dropped"]
pub struct CommandScope {
    owner: bool,
    _not_send: PhantomData<*const ()>,
}

impl CommandScope {
    /// Start a scope whose blast-radius work may take `budget_ms` in total
    /// (capped at [`crate::config::MAX_BLAST_RADIUS_BUDGET_MS`]; `0` skips the blast radius).
    pub fn enter(budget_ms: u64) -> Self {
        let owner = SCOPE.with(|s| {
            let mut s = s.borrow_mut();
            if s.is_some() {
                return false;
            }
            *s = Some(ScopeState {
                start: Instant::now(),
                budget_ms: budget_ms.min(crate::config::MAX_BLAST_RADIUS_BUDGET_MS),
                outcomes: HashMap::new(),
                budget_skips: HashSet::new(),
            });
            true
        });
        Self {
            owner,
            _not_send: PhantomData,
        }
    }
}

impl Drop for CommandScope {
    fn drop(&mut self) {
        if self.owner {
            SCOPE.with(|s| *s.borrow_mut() = None);
        }
    }
}

fn scope_key(cmd: &str, args: &[&str]) -> ScopeKey {
    (
        cmd.to_string(),
        args.iter().map(|a| (*a).to_string()).collect(),
    )
}

/// The budget (ms) of the active [`CommandScope`], if any.
#[must_use]
pub fn scope_budget_ms() -> Option<u64> {
    SCOPE.with(|s| s.borrow().as_ref().map(|s| s.budget_ms))
}

/// When the active [`CommandScope`] started, if any.
#[must_use]
pub fn scope_start() -> Option<Instant> {
    SCOPE.with(|s| s.borrow().as_ref().map(|s| s.start))
}

/// The answer an earlier evaluation in this scope got from `cmd args`.
#[must_use]
pub fn scope_lookup(cmd: &str, args: &[&str]) -> Option<(CommandOutcome, Option<String>)> {
    SCOPE.with(|s| {
        s.borrow()
            .as_ref()
            .and_then(|s| s.outcomes.get(&scope_key(cmd, args)).cloned())
    })
}

/// Remember the answer of `cmd args` for the rest of the scope.
pub fn scope_store(cmd: &str, args: &[&str], result: &(CommandOutcome, Option<String>)) {
    SCOPE.with(|s| {
        if let Some(s) = s.borrow_mut().as_mut() {
            s.outcomes.insert(scope_key(cmd, args), result.clone());
        }
    });
}

/// Whether the blast radius already skipped `cmd args` in this scope
/// because the budget was spent (a later view skips it too).
#[must_use]
pub fn scope_budget_skipped(cmd: &str, args: &[&str]) -> bool {
    SCOPE.with(|s| {
        s.borrow()
            .as_ref()
            .is_some_and(|s| s.budget_skips.contains(&scope_key(cmd, args)))
    })
}

/// Note that the blast radius skipped `cmd args` (no time left).
pub fn scope_mark_budget_skipped(cmd: &str, args: &[&str]) {
    SCOPE.with(|s| {
        if let Some(s) = s.borrow_mut().as_mut() {
            s.budget_skips.insert(scope_key(cmd, args));
        }
    });
}

// ---------------------------------------------------------------------------
// No-context wrapper (`--no-context`): never runs external commands
// ---------------------------------------------------------------------------

/// An [`Environment`] that never runs a subprocess.
///
/// Everything is delegated to `inner` **except** subprocesses:
/// [`Environment::run_command`] always returns `None` and
/// [`Environment::run_command_outcome`] returns [`CommandOutcome::Skipped`].
///
/// Used for side-effect-free dry checks (`--no-context`): no `git`,
/// `kubectl`, `docker`, `du` or `find` is executed. Context that can be read
/// from files (the git `HEAD` file, a kubeconfig) is still used, and
/// blast-radius computations that need a subprocess are simply omitted.
pub struct NoContextEnvironment<'a> {
    inner: &'a dyn Environment,
}

impl<'a> NoContextEnvironment<'a> {
    /// Wrap `inner`, disabling every subprocess.
    #[must_use]
    pub fn new(inner: &'a dyn Environment) -> Self {
        Self { inner }
    }
}

/// Whether `SHELLFIRM_NO_CONTEXT` asks for [`NoContextEnvironment`]
/// (`1`, `true`, `yes`, `on`; case-insensitive).
#[must_use]
pub fn no_context_requested(env: &dyn Environment) -> bool {
    env.var("SHELLFIRM_NO_CONTEXT").is_some_and(|v| {
        matches!(
            v.trim().to_ascii_lowercase().as_str(),
            "1" | "true" | "yes" | "on"
        )
    })
}

impl Environment for NoContextEnvironment<'_> {
    fn var(&self, key: &str) -> Option<String> {
        self.inner.var(key)
    }
    fn current_dir(&self) -> Result<PathBuf> {
        self.inner.current_dir()
    }
    fn path_exists(&self, path: &Path) -> bool {
        self.inner.path_exists(path)
    }
    fn home_dir(&self) -> Option<PathBuf> {
        self.inner.home_dir()
    }
    fn run_command(&self, _cmd: &str, _args: &[&str], _timeout_ms: u64) -> Option<String> {
        None
    }
    fn run_command_outcome(&self, _cmd: &str, _args: &[&str], _timeout_ms: u64) -> CommandOutcome {
        CommandOutcome::Skipped
    }
    fn effective_uid(&self) -> Option<u32> {
        self.inner.effective_uid()
    }
    fn read_file(&self, path: &Path) -> Result<String> {
        self.inner.read_file(path)
    }
    fn find_file_upward(&self, start: &Path, filename: &str) -> Option<PathBuf> {
        self.inner.find_file_upward(start, filename)
    }
}

// ---------------------------------------------------------------------------
// Mock implementation (used in tests — zero real I/O)
// ---------------------------------------------------------------------------

/// A fully in-memory [`Environment`] for sandboxed testing.
///
/// Every field is public so tests can construct scenarios declaratively.
#[derive(Debug, Clone, Default)]
pub struct MockEnvironment {
    pub env_vars: HashMap<String, String>,
    pub cwd: PathBuf,
    pub existing_paths: HashSet<PathBuf>,
    pub home: Option<PathBuf>,
    /// Maps `"cmd arg1 arg2"` → stdout output.
    pub command_outputs: HashMap<String, String>,
    /// Virtual filesystem: path → file contents.
    pub files: HashMap<PathBuf, String>,
    /// Effective uid returned by [`Environment::effective_uid`]
    /// (`Some(0)` simulates a root process).
    pub euid: Option<u32>,
    /// Commands (`"cmd arg1 arg2"`) that simulate a timeout.
    pub timed_out_commands: HashSet<String>,
}

impl Environment for MockEnvironment {
    fn var(&self, key: &str) -> Option<String> {
        self.env_vars.get(key).cloned()
    }

    fn current_dir(&self) -> Result<PathBuf> {
        Ok(self.cwd.clone())
    }

    fn path_exists(&self, path: &Path) -> bool {
        self.existing_paths.contains(path) || self.files.contains_key(path)
    }

    fn home_dir(&self) -> Option<PathBuf> {
        self.home.clone()
    }

    fn run_command(&self, cmd: &str, args: &[&str], timeout_ms: u64) -> Option<String> {
        self.run_command_outcome(cmd, args, timeout_ms).output()
    }

    fn run_command_outcome(&self, cmd: &str, args: &[&str], _timeout_ms: u64) -> CommandOutcome {
        let key = format!("{} {}", cmd, args.join(" "));
        if self.timed_out_commands.contains(&key) {
            return CommandOutcome::TimedOut;
        }
        self.command_outputs
            .get(&key)
            .cloned()
            .map_or(CommandOutcome::Failed, CommandOutcome::Output)
    }

    fn effective_uid(&self) -> Option<u32> {
        self.euid
    }

    fn read_file(&self, path: &Path) -> Result<String> {
        self.files.get(path).cloned().ok_or_else(|| {
            crate::error::Error::Other(format!("mock file not found: {}", path.display()))
        })
    }

    fn find_file_upward(&self, start: &Path, filename: &str) -> Option<PathBuf> {
        let mut current = start.to_path_buf();
        loop {
            let candidate = current.join(filename);
            if self.files.contains_key(&candidate) {
                return Some(candidate);
            }
            if !current.pop() {
                return None;
            }
        }
    }
}

#[cfg(all(test, unix))]
mod real_command_tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt as _;

    /// A temporary folder with an executable script `name`.
    fn script(name: &str, body: &str) -> (tree_fs::Tree, String) {
        let tree = tree_fs::TreeBuilder::default().create().expect("tree");
        let path = tree.root.join(name);
        std::fs::write(&path, format!("#!/bin/sh\n{body}\n")).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        (tree, path.display().to_string())
    }

    #[test]
    fn git_runs_without_optional_locks() {
        let (_t, git) = script("git", r#"echo "$* lock=$GIT_OPTIONAL_LOCKS""#);
        let (out, _) = run_cancellable_command(&git, &["status"], 5000, &AtomicBool::new(false));
        assert_eq!(
            out,
            CommandOutcome::Output("--no-optional-locks status lock=0".into())
        );
        // Other programs get their arguments unchanged.
        let (_t2, other) = script("du", r#"echo "$*""#);
        let (out, _) =
            run_cancellable_command(&other, &["-sh", "x"], 5000, &AtomicBool::new(false));
        assert_eq!(out, CommandOutcome::Output("-sh x".into()));
    }

    #[test]
    fn a_timeout_sends_sigterm_before_sigkill() {
        let (t, _) = script("x", "");
        let mark = t.root.join("got-term");
        let body = format!(
            "trap 'touch {}; exit 0' TERM\nwhile :; do sleep 0.01; done",
            mark.display()
        );
        let (_t, slow) = script("slow", &body);
        let (out, _) = run_cancellable_command(&slow, &[], 150, &AtomicBool::new(false));
        assert_eq!(out, CommandOutcome::TimedOut);
        assert!(mark.exists(), "the command was not given SIGTERM first");
    }

    #[test]
    fn cancel_stops_a_running_command_at_once() {
        let cancel = std::sync::Arc::new(AtomicBool::new(false));
        let c = std::sync::Arc::clone(&cancel);
        let setter = thread::spawn(move || {
            thread::sleep(Duration::from_millis(100));
            c.store(true, Ordering::SeqCst);
        });
        let start = Instant::now();
        let (out, _) = run_cancellable_command("sleep", &["5"], 5000, &cancel);
        setter.join().unwrap();
        assert_eq!(out, CommandOutcome::TimedOut);
        assert!(
            start.elapsed() < Duration::from_millis(1500),
            "{:?}",
            start.elapsed()
        );
        // Once cancelled, nothing new is started.
        let start = Instant::now();
        let (out, _) = run_cancellable_command("sleep", &["5"], 5000, &cancel);
        assert_eq!(out, CommandOutcome::TimedOut);
        assert!(start.elapsed() < Duration::from_millis(100));
    }
}
