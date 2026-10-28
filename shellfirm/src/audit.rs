//! Audit trail — optional local log of every intercepted command.
//!
//! Records are JSON Lines (one JSON object per line). Each record contains
//! the [`AuditEvent`] fields written by the caller, plus metadata collected
//! automatically at write time ([`AuditMeta`]: user, host, cwd, git repo and
//! branch, schema version) and optional caller-provided details
//! ([`AuditExtra`]: policy sources, effective challenge, deny reason).
//!
//! Writes are safe under concurrency: each record is serialized into one
//! buffer and written with a single `write()` on an `O_APPEND` descriptor,
//! under an exclusive `flock` on Unix, so lines from parallel writers never
//! interleave. The file is created with mode `0600`. When the log grows past
//! [`DEFAULT_MAX_AUDIT_BYTES`] it is rotated: `audit.log` becomes
//! `audit.log.1`, `.1` becomes `.2`, … and only the newest
//! [`DEFAULT_MAX_AUDIT_FILES`] generations are kept (configurable with the
//! `audit_max_files` setting of the log's configuration directory, see
//! [`max_files_for`]). `audit show` reads
//! every generation.
//!
//! A stored command is capped at [`MAX_STORED_COMMAND_BYTES`]; longer
//! commands are truncated and the record carries `command_bytes` and the
//! `command_sha256` of the full command, so a few huge commands can never
//! flush the history.
//!
//! Secrets are redacted before a command is stored (see [`redact_secrets`]):
//! `mysql -pSECRET`, `--password=…`, `PGPASSWORD=…` and other
//! `*_PASSWORD` / `*_TOKEN` / `*_SECRET` / `*_KEY` assignments, `user:pass@`
//! in URLs, `Authorization:` headers, `curl -u user:pass` and well-known
//! token formats (AWS `AKIA…`, GitHub `ghp_…`, Slack `xox…-`) become `***`.
//! A redacted record carries `command_redacted: true`, and its
//! `command_sha256` is computed over the **original** command, so a known
//! command can still be matched against the log without storing the secret.
//!
//! Identity: `user` is the account name of the real uid (from the password
//! database, falling back to `$USER`), `uid` is the numeric uid, and
//! `env_user` records `$USER` when it differs from `user`.
//!
//! Older records (without the newer fields) are still readable through
//! [`AuditEntry`].

use std::{
    fs::{self, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
};

use crate::error::{Error, Result};
use serde_derive::{Deserialize, Serialize};

use crate::checks::Severity;

/// Version of the on-disk record format written by this build.
/// - 1 (implicit, no field): original format
/// - 2: adds `schema_version`, `user`, `hostname`, `cwd`, `git_repo`,
///   `git_branch` and the optional [`AuditExtra`] fields.
/// - 3: `user` comes from the uid (not `$USER`); adds `uid`, `env_user`,
///   `escalation_reasons`, `command_bytes`, `command_sha256`,
///   `command_truncated`, `command_redacted` and the `NoTerminal` outcome.
/// - 4: adds `version` (the shellfirm version that wrote the record).
pub const AUDIT_SCHEMA_VERSION: u32 = 4;

/// Size after which `audit.log` is rotated to `audit.log.1` (10 MiB).
pub const DEFAULT_MAX_AUDIT_BYTES: u64 = 10 * 1024 * 1024;

/// Rotated generations kept by default (`audit.log.1` … `audit.log.5`).
pub const DEFAULT_MAX_AUDIT_FILES: usize = 5;

/// Longest command stored verbatim in a record (8 KiB). Longer commands are
/// truncated (at a character boundary) and hashed.
pub const MAX_STORED_COMMAND_BYTES: usize = 8 * 1024;

/// How many rotated generations are kept for the log at `audit_path`.
///
/// It is the `audit_max_files` setting of the configuration directory the
/// log lives in (`settings.yaml` next to `audit.log`), so `--config-dir DIR`
/// and `SHELLFIRM_CONFIG_DIR` rotate with DIR's own setting. The file is
/// read only when a rotation is due. The value is clamped to `1..=100`: at
/// least one rotated generation is always kept, so rotation never deletes
/// the history it just rotated (`0`, which the settings parser rejects,
/// means the default). Unset or unreadable: [`DEFAULT_MAX_AUDIT_FILES`].
#[must_use]
pub fn max_files_for(audit_path: &Path) -> usize {
    let configured = audit_path
        .parent()
        .map(|d| d.join("settings.yaml"))
        .and_then(|p| fs::read_to_string(p).ok())
        .and_then(|c| serde_yaml::from_str::<serde_yaml::Value>(&c).ok())
        .and_then(|v| v.get("audit_max_files").and_then(serde_yaml::Value::as_u64))
        .and_then(|n| usize::try_from(n).ok())
        .filter(|n| *n > 0)
        .unwrap_or(DEFAULT_MAX_AUDIT_FILES);
    clamp_max_files(configured)
}

const fn clamp_max_files(n: usize) -> usize {
    if n == 0 {
        1
    } else if n > MAX_AUDIT_FILES_LIMIT {
        MAX_AUDIT_FILES_LIMIT
    } else {
        n
    }
}

/// Largest accepted `audit_max_files`.
pub const MAX_AUDIT_FILES_LIMIT: usize = 100;

/// The number of rotated generations kept for an `audit_max_files`
/// setting (clamped like [`max_files_for`]).
#[must_use]
pub const fn max_files(setting: usize) -> usize {
    clamp_max_files(setting)
}

/// The outcome of a challenge interaction.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AuditOutcome {
    Allowed,
    Denied,
    /// The check matched but was skipped because its severity was below
    /// the configured `min_severity` threshold.
    Skipped,
    /// The challenge was declined or aborted by a human (Esc, Ctrl-C, a
    /// wrong answer given up on). The record is written once, after the
    /// prompt ends; a process killed with `SIGKILL` while the prompt is
    /// shown writes no record (the command does not run either).
    Cancelled,
    /// The decision was handed back to a human (e.g. an AI-agent hook
    /// returned "ask" so the tool's own permission prompt is shown).
    Asked,
    /// Blocked without asking because no terminal was available to answer
    /// the challenge (fail closed). Distinct from `Cancelled`, which is a
    /// human declining or aborting.
    NoTerminal,
}

impl std::fmt::Display for AuditOutcome {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Allowed => write!(f, "ALLOWED"),
            Self::Denied => write!(f, "DENIED"),
            Self::Skipped => write!(f, "SKIPPED"),
            Self::Cancelled => write!(f, "CANCELLED"),
            Self::Asked => write!(f, "ASKED"),
            Self::NoTerminal => write!(f, "NO-TTY"),
        }
    }
}

/// The outcome names accepted by [`AuditOutcome::parse`] (for help texts).
pub const OUTCOME_VALUES: &str = "allowed, denied, skipped, cancelled, asked, no-terminal";

impl AuditOutcome {
    /// Parse an outcome name (case-insensitive).
    ///
    /// # Errors
    /// Returns an error listing the valid values.
    pub fn parse(s: &str) -> Result<Self> {
        match s.to_lowercase().as_str() {
            "allowed" => Ok(Self::Allowed),
            "denied" => Ok(Self::Denied),
            "skipped" => Ok(Self::Skipped),
            "cancelled" | "canceled" => Ok(Self::Cancelled),
            "asked" | "ask" => Ok(Self::Asked),
            "noterminal" | "no-terminal" | "no_terminal" | "no-tty" | "notty" => {
                Ok(Self::NoTerminal)
            }
            _ => Err(Error::Config(format!(
                "invalid outcome '{s}'. Valid values: {OUTCOME_VALUES}"
            ))),
        }
    }
}

/// A single audit log entry, as written by the interception paths.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEvent {
    /// Unique identifier of the decision. Older versions wrote a
    /// pre-challenge record and a final record with the same id;
    /// `audit show` still collapses those pairs.
    pub event_id: String,
    pub timestamp: String,
    pub command: String,
    pub matched_ids: Vec<String>,
    pub challenge_type: String,
    pub outcome: AuditOutcome,
    pub context_labels: Vec<String>,
    /// The highest severity among the matched checks.
    pub severity: Severity,
    /// Name of the AI agent that originated this command (if any).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_name: Option<String>,
    /// Session ID of the AI agent (if any).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_session_id: Option<String>,
    /// Blast radius scope (e.g. "PROJECT", "MACHINE").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub blast_radius_scope: Option<String>,
    /// Blast radius detail description.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub blast_radius_detail: Option<String>,
    /// Number of challenge attempts made before the outcome (if tracked).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attempts: Option<u32>,
}

/// Metadata collected automatically by [`log_event`] for every record.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuditMeta {
    pub schema_version: u32,
    /// The shellfirm version that wrote the record (schema 4 and later).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    /// Account name of the real uid (password database), or `$USER` when
    /// the lookup fails.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,
    /// Numeric real uid (Unix).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uid: Option<u32>,
    /// `$USER` / `$LOGNAME`, recorded only when it differs from `user`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub env_user: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hostname: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cwd: Option<String>,
    /// Top-level directory of the git repository containing `cwd`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub git_repo: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub git_branch: Option<String>,
}

/// Optional details a caller can attach with [`log_event_with`].
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuditExtra {
    /// Paths of the policy files (org or `.shellfirm.yaml`) that enforce
    /// the matched checks (for a policy deny: the files that deny them).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub policy_sources: Vec<String>,
    /// The challenge actually presented (after all escalation layers), as
    /// opposed to `challenge_type` (the configured base challenge).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub effective_challenge: Option<String>,
    /// Why the command was denied: `"policy_deny"` (a policy `deny` entry),
    /// `"user_deny"` (the personal `deny_patterns_ids`), or a caller-set
    /// reason such as `"agent_auto_deny"`, `"no_tty"`, `"cancelled"` or
    /// `"fail_closed"` (see [`deny_reason`]).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deny_reason: Option<String>,
    /// Ids of matched checks that are enforced by the project policy.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub policy_check_ids: Vec<String>,
    /// Why the challenge was raised above the base challenge (e.g.
    /// "protected branch `main`", "severity High").
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub escalation_reasons: Vec<String>,
    /// The agent's id for the tool call (Claude Code `tool_use_id`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool_use_id: Option<String>,
}

/// The values of [`AuditExtra::deny_reason`].
pub mod deny_reason {
    use super::AuditOutcome;

    /// A matched id is in a policy `deny` list (org or `.shellfirm.yaml`).
    pub const POLICY_DENY: &str = "policy_deny";
    /// A matched id is in the personal `deny_patterns_ids`.
    pub const USER_DENY: &str = "user_deny";
    /// An AI-agent hook denied it because the severity reached
    /// `agent.auto_deny_severity`.
    pub const AGENT_AUTO_DENY: &str = "agent_auto_deny";
    /// No terminal was available to answer the challenge (fail closed).
    pub const NO_TTY: &str = "no_tty";
    /// A human cancelled the challenge (Esc, Ctrl-C, Ctrl-D / end of
    /// input). The interactive prompt keeps asking after a wrong answer,
    /// so a shell-hook challenge only ever ends unanswered this way.
    pub const CANCELLED: &str = "cancelled";
    /// The challenge was answered wrongly and given up. Written by older
    /// versions for every cancelled challenge (they could not tell a
    /// cancel from a wrong answer); read it as "not passed".
    pub const CHALLENGE_FAILED: &str = "challenge_failed";

    /// The deny reason implied by an outcome on its own (`NoTerminal` →
    /// [`NO_TTY`], `Cancelled` → [`CANCELLED`]); `None` for the others.
    #[must_use]
    pub const fn for_outcome(outcome: &AuditOutcome) -> Option<&'static str> {
        match outcome {
            AuditOutcome::NoTerminal => Some(NO_TTY),
            AuditOutcome::Cancelled => Some(CANCELLED),
            _ => None,
        }
    }
}

impl AuditExtra {
    /// Build the extra fields for one decision.
    ///
    /// - `merged`: the merged project policy of the pipeline run.
    /// - `user_deny`: the user's personal `deny_patterns_ids`.
    /// - `matched_ids`: ids of the active matches.
    /// - `denied`: whether the command was denied by a deny list.
    /// - `effective_challenge` / `escalation_reasons`: from the challenge
    ///   display.
    ///
    /// `deny_reason` is `policy_deny` when a matched id is in the policy
    /// deny list, otherwise `user_deny` when it is in the personal deny
    /// list (callers set `agent_auto_deny`, `no_tty`, … themselves).
    #[must_use]
    pub fn for_decision(
        merged: &crate::policy::MergedPolicy,
        user_deny: &[String],
        matched_ids: &[String],
        denied: bool,
        effective_challenge: Option<String>,
        escalation_reasons: Vec<String>,
    ) -> Self {
        let deny_reason = if !denied {
            None
        } else if matched_ids.iter().any(|id| merged.is_denied(id)) {
            Some(deny_reason::POLICY_DENY.to_string())
        } else if matched_ids.iter().any(|id| user_deny.contains(id)) {
            Some(deny_reason::USER_DENY.to_string())
        } else {
            Some("deny".to_string())
        };
        let policy_check_ids: Vec<String> = matched_ids
            .iter()
            .filter(|id| merged.is_enforced(id))
            .cloned()
            .collect();
        // The files that name the relevant ids: for a policy deny the
        // files that deny a matched id, otherwise those enforcing a match.
        let relevant: Vec<&String> = if deny_reason.as_deref() == Some(deny_reason::POLICY_DENY) {
            matched_ids
                .iter()
                .filter(|id| merged.is_denied(id))
                .collect()
        } else {
            policy_check_ids.iter().collect()
        };
        let mut policy_sources: Vec<String> = Vec::new();
        for id in relevant {
            for p in merged.sources_for(id) {
                let p = p.display().to_string();
                if !policy_sources.contains(&p) {
                    policy_sources.push(p);
                }
            }
        }
        Self {
            policy_sources,
            effective_challenge,
            deny_reason,
            policy_check_ids,
            escalation_reasons,
            tool_use_id: None,
        }
    }
}

/// Size information written when a command is longer than
/// [`MAX_STORED_COMMAND_BYTES`].
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[allow(clippy::struct_field_names)]
struct CommandDigest {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    command_bytes: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    command_sha256: Option<String>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    command_truncated: bool,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    command_redacted: bool,
}

#[derive(Serialize)]
struct AuditRecordOut<'a> {
    #[serde(flatten)]
    event: &'a AuditEvent,
    #[serde(flatten)]
    meta: AuditMeta,
    #[serde(flatten)]
    extra: &'a AuditExtra,
    #[serde(flatten)]
    digest: CommandDigest,
}

/// Read model for one audit record. Every field is optional so records
/// written by older versions (or by hand) still load.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct AuditEntry {
    pub event_id: String,
    pub timestamp: String,
    pub command: String,
    pub matched_ids: Vec<String>,
    pub challenge_type: String,
    pub outcome: Option<AuditOutcome>,
    pub context_labels: Vec<String>,
    pub severity: Option<Severity>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent_session_id: Option<String>,
    /// The agent's id for the tool call (Claude Code `tool_use_id`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool_use_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub blast_radius_scope: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub blast_radius_detail: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attempts: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub schema_version: Option<u32>,
    /// The shellfirm version that wrote the record (schema 4 and later).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uid: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub env_user: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hostname: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cwd: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub git_repo: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub git_branch: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub policy_sources: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub effective_challenge: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deny_reason: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub policy_check_ids: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub escalation_reasons: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub command_bytes: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub command_sha256: Option<String>,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub command_truncated: bool,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub command_redacted: bool,
}

// ---------------------------------------------------------------------------
// Metadata collection
// ---------------------------------------------------------------------------

fn env_user() -> Option<String> {
    ["USER", "LOGNAME", "USERNAME"]
        .iter()
        .find_map(|k| std::env::var(k).ok().filter(|v| !v.is_empty()))
}

/// Real uid of this process (Unix).
#[must_use]
pub fn current_uid() -> Option<u32> {
    #[cfg(unix)]
    {
        // SAFETY: getuid has no preconditions and cannot fail.
        Some(unsafe { libc::getuid() })
    }
    #[cfg(not(unix))]
    {
        None
    }
}

/// Account name for `uid` from the password database.
#[cfg(unix)]
fn passwd_name(uid: u32) -> Option<String> {
    let mut buf = vec![0 as libc::c_char; 4096];
    // SAFETY: an all-zero passwd struct is a valid out-parameter.
    let mut pwd: libc::passwd = unsafe { std::mem::zeroed() };
    let mut result: *mut libc::passwd = std::ptr::null_mut();
    // SAFETY: every pointer is valid for the duration of the call and the
    // buffer length matches the buffer.
    let rc = unsafe {
        libc::getpwuid_r(
            uid,
            &raw mut pwd,
            buf.as_mut_ptr(),
            buf.len(),
            &raw mut result,
        )
    };
    if rc != 0 || result.is_null() || pwd.pw_name.is_null() {
        return None;
    }
    // SAFETY: getpwuid_r succeeded, so pw_name points to a NUL-terminated
    // string inside `buf`.
    let name = unsafe { std::ffi::CStr::from_ptr(pwd.pw_name) };
    let name = name.to_string_lossy().to_string();
    (!name.is_empty()).then_some(name)
}

/// `(user, uid, env_user)`: the account of the real uid (falling back to
/// `$USER`), the uid, and `$USER` when it differs from the account name.
fn identity() -> (Option<String>, Option<u32>, Option<String>) {
    let uid = current_uid();
    #[cfg(unix)]
    let account = uid.and_then(passwd_name);
    #[cfg(not(unix))]
    let account: Option<String> = None;
    let env = env_user();
    match account {
        Some(name) => {
            let differs = env.filter(|e| *e != name);
            (Some(name), uid, differs)
        }
        None => (env, uid, None),
    }
}

fn current_hostname() -> Option<String> {
    #[cfg(unix)]
    {
        if let Ok(h) = nix::unistd::gethostname() {
            let h = h.to_string_lossy().to_string();
            if !h.is_empty() {
                return Some(h);
            }
        }
    }
    ["HOSTNAME", "COMPUTERNAME"]
        .iter()
        .find_map(|k| std::env::var(k).ok().filter(|v| !v.is_empty()))
}

/// Find the git repository root and current branch for `dir` by reading
/// `.git/HEAD` directly (no subprocess).
#[must_use]
pub fn git_info(dir: &Path) -> (Option<PathBuf>, Option<String>) {
    for d in dir.ancestors() {
        let dot_git = d.join(".git");
        let git_dir = if dot_git.is_dir() {
            Some(dot_git)
        } else if dot_git.is_file() {
            // worktree / submodule: "gitdir: <path>"
            fs::read_to_string(&dot_git).ok().and_then(|c| {
                c.lines().find_map(|l| l.strip_prefix("gitdir:")).map(|p| {
                    let p = PathBuf::from(p.trim());
                    if p.is_absolute() {
                        p
                    } else {
                        d.join(p)
                    }
                })
            })
        } else {
            None
        };
        if let Some(gd) = git_dir {
            let branch = fs::read_to_string(gd.join("HEAD")).ok().map(|head| {
                let head = head.trim();
                head.strip_prefix("ref: refs/heads/").map_or_else(
                    || format!("(detached {})", head.chars().take(12).collect::<String>()),
                    ToString::to_string,
                )
            });
            return (Some(d.to_path_buf()), branch);
        }
    }
    (None, None)
}

/// Collect the automatic metadata for a record.
#[must_use]
pub fn collect_meta() -> AuditMeta {
    collect_meta_for(None)
}

/// [`collect_meta`] for `command`.
///
/// When the command works in another
/// directory (`git -C ../infra …`, `cd ../infra && …`), `git_repo` /
/// `git_branch` are that directory's repository; otherwise the current
/// directory's. `cwd` is always the current directory.
#[must_use]
pub fn collect_meta_for(command: Option<&str>) -> AuditMeta {
    let cwd = std::env::current_dir().ok();
    let target = command.zip(cwd.as_deref()).and_then(|(c, cwd)| {
        let home = crate::env::Environment::home_dir(&crate::env::RealEnvironment);
        crate::context::command_work_dir(c, cwd, home.as_deref())
    });
    let (repo, branch) = target
        .as_deref()
        .or(cwd.as_deref())
        .map_or((None, None), git_info);
    let (user, uid, env_user) = identity();
    AuditMeta {
        schema_version: AUDIT_SCHEMA_VERSION,
        version: Some(env!("CARGO_PKG_VERSION").to_string()),
        user,
        uid,
        env_user,
        hostname: current_hostname(),
        cwd: cwd.map(|c| c.display().to_string()),
        git_repo: repo.map(|r| r.display().to_string()),
        git_branch: branch,
    }
}

// ---------------------------------------------------------------------------
// Writing
// ---------------------------------------------------------------------------

/// Append an audit event to the log file as a JSON line.
///
/// See [`log_event_with`].
///
/// # Errors
/// Returns an error if the file cannot be opened/created or JSON serialization fails.
pub fn log_event(audit_path: &Path, event: &AuditEvent) -> Result<()> {
    log_event_with(audit_path, event, &AuditExtra::default())
}

/// Append an audit event plus caller-provided details as one JSON line.
///
/// The record is written with a single `write()` on an `O_APPEND` file
/// descriptor (under an exclusive `flock` on Unix), so concurrent writers
/// never interleave. A new file is created with mode `0600`; an existing
/// file with wider permissions is tightened to `0600`. The log is rotated to
/// `<name>.1` once it exceeds [`DEFAULT_MAX_AUDIT_BYTES`].
///
/// # Errors
/// Returns an error if the file cannot be opened/created or JSON serialization fails.
pub fn log_event_with(audit_path: &Path, event: &AuditEvent, extra: &AuditExtra) -> Result<()> {
    log_event_with_limit(audit_path, event, extra, DEFAULT_MAX_AUDIT_BYTES)
}

fn open_append(path: &Path) -> std::io::Result<fs::File> {
    let mut opts = OpenOptions::new();
    opts.create(true).append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let file = opts.open(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(meta) = file.metadata() {
            if meta.permissions().mode() & 0o077 != 0 {
                let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o600));
            }
        }
    }
    Ok(file)
}

fn rotated_path_n(path: &Path, n: usize) -> PathBuf {
    let mut name = path.file_name().unwrap_or_default().to_os_string();
    name.push(format!(".{n}"));
    path.with_file_name(name)
}

#[cfg(test)]
fn rotated_path(path: &Path) -> PathBuf {
    rotated_path_n(path, 1)
}

/// Every existing log generation, oldest first (`audit.log.N` …
/// `audit.log.1`, then `audit.log`). Generations beyond the configured
/// limit that are still on disk are included too.
#[must_use]
pub fn log_files(audit_path: &Path) -> Vec<PathBuf> {
    let mut rotated: Vec<(usize, PathBuf)> = Vec::new();
    let prefix = format!(
        "{}.",
        audit_path.file_name().unwrap_or_default().to_string_lossy()
    );
    if let Some(dir) = audit_path.parent() {
        let dir = if dir.as_os_str().is_empty() {
            Path::new(".")
        } else {
            dir
        };
        for e in fs::read_dir(dir).into_iter().flatten().flatten() {
            let name = e.file_name().to_string_lossy().to_string();
            if let Some(n) = name
                .strip_prefix(&prefix)
                .and_then(|r| r.parse::<usize>().ok())
            {
                rotated.push((n, rotated_path_n(audit_path, n)));
            }
        }
    }
    rotated.sort_by_key(|r| std::cmp::Reverse(r.0));
    let mut out: Vec<PathBuf> = rotated.into_iter().map(|(_, p)| p).collect();
    if audit_path.exists() {
        out.push(audit_path.to_path_buf());
    }
    out
}

/// Shift `audit.log.k` → `audit.log.k+1` (dropping generations beyond
/// `keep`) and move `audit.log` to `audit.log.1`.
fn rotate_files(audit_path: &Path, keep: usize) -> std::io::Result<()> {
    // Never delete the generation being rotated (see `max_files_for`).
    let keep = keep.max(1);
    // Remove generations at or beyond the limit.
    for p in log_files(audit_path) {
        let n = p
            .file_name()
            .and_then(|f| f.to_str())
            .and_then(|f| f.rsplit('.').next())
            .and_then(|n| n.parse::<usize>().ok());
        if n.is_some_and(|n| n >= keep) && p != audit_path {
            let _ = fs::remove_file(&p);
        }
    }
    for n in (1..keep).rev() {
        let from = rotated_path_n(audit_path, n);
        if from.exists() {
            fs::rename(&from, rotated_path_n(audit_path, n + 1))?;
        }
    }
    fs::rename(audit_path, rotated_path_n(audit_path, 1))
}

/// Regexes for [`redact_secrets`]: `(regex, replacement)`.
fn redaction_rules() -> &'static [(regex::Regex, &'static str)] {
    static RULES: std::sync::OnceLock<Vec<(regex::Regex, &'static str)>> =
        std::sync::OnceLock::new();
    RULES.get_or_init(|| {
        let v = r#"(?:"[^"]*"|'[^']*'|[^\s'";&|)]+)"#;
        // A value that is not the next option (`mongosh -p --eval …` prompts).
        let v_arg = r#"(?:"[^"]*"|'[^']*'|[^\s'";&|)\-][^\s'";&|)]*)"#;
        let rules: Vec<(String, &'static str)> = vec![
            // NAME=value assignments whose name says "secret".
            (
                format!(
                    r"(?i)\b([A-Z0-9_]*(?:PASSWORD|PASSWD|_PWD|PASS|TOKEN|SECRET|API_?KEY|ACCESS_KEY|PRIVATE_KEY|CREDENTIALS?)[A-Z0-9_]*=){v}"
                ),
                "${1}***",
            ),
            // MYSQL_PWD=… (the name is exactly the suffix).
            (format!(r"\b(MYSQL_PWD=){v}"), "${1}***"),
            // REDISCLI_AUTH=… and other `*_AUTH` variables.
            (format!(r"(?i)\b([A-Z0-9_]*_AUTH=){v}"), "${1}***"),
            // redis-cli -a PASSWORD / --pass PASSWORD
            (
                format!(
                    r"(\b(?:redis-cli|valkey-cli|keydb-cli)\b[^;&|\n]*?\s(?:-a|--pass)\s+){v_arg}"
                ),
                "${1}***",
            ),
            // mongosh -p PASSWORD / --password PASSWORD (space-separated)
            (
                format!(
                    r"(\b(?:mongosh|mongo|mongodump|mongorestore|mongoexport|mongoimport|mongofiles|mongostat|mongotop)\b[^;&|\n]*?\s(?:-p|--password)\s+){v_arg}"
                ),
                "${1}***",
            ),
            // mongosh -pPASSWORD (attached value).
            (
                format!(
                    r"(\b(?:mongosh|mongo|mongodump|mongorestore|mongoexport|mongoimport|mongofiles|mongostat|mongotop)\b[^;&|\n]*?\s-p){v}"
                ),
                "${1}***",
            ),
            // clickhouse-client --password PASSWORD (space-separated; a
            // bare `--password` prompts).
            (
                format!(
                    r"(\b(?:clickhouse-client|clickhouse)\b[^;&|\n]*?\s--password\s+){v_arg}"
                ),
                "${1}***",
            ),
            // cqlsh -p PASSWORD / --password PASSWORD (Cassandra).
            (
                format!(r"(\bcqlsh\b[^;&|\n]*?\s(?:-p|--password)\s+){v_arg}"),
                "${1}***",
            ),
            // --password=… / --token=… / --secret=… / --api-key=…
            (
                format!(
                    r"(?i)(--(?:password|passwd|pass|token|secret|api-?key|access-token|auth-token|client-secret)=){v}"
                ),
                "${1}***",
            ),
            // --token VALUE / --api-key VALUE (space-separated values).
            (
                format!(
                    r"(?i)(--(?:token|secret|api-?key|access-token|auth-token|client-secret)\s+){v}"
                ),
                "${1}***",
            ),
            // sqlcmd / bcp -P PASSWORD and -PPASSWORD (SQL Server; only the
            // upper-case `-P`, lower-case `-p` prints statistics).
            (
                format!(r"(\b(?:sqlcmd|bcp)\b[^;&|\n]*?\s-P\s+){v_arg}"),
                "${1}***",
            ),
            (
                format!(r"(\b(?:sqlcmd|bcp)\b[^;&|\n]*?\s-P){v}"),
                "${1}***",
            ),
            // mysql/mariadb -pSECRET (attached value only; `-p` alone prompts).
            (
                format!(
                    r"(\b(?:mysql|mysqldump|mysqladmin|mysqlimport|mysqlcheck|mariadb|mariadb-dump)\b[^;&|\n]*?\s-p){v}"
                ),
                "${1}***",
            ),
            // user:password@ in URLs.
            (
                r#"(\b[A-Za-z][A-Za-z0-9+.\-]*://[^\s:/@'"]+:)[^\s@/'"]+@"#.to_string(),
                "${1}***@",
            ),
            // :password@ with an empty user (`redis://:pw@host`).
            (
                r#"(\b[A-Za-z][A-Za-z0-9+.\-]*://:)[^\s@/'"]+@"#.to_string(),
                "${1}***@",
            ),
            // Authorization / token headers.
            (
                r#"(?i)((?:authorization|proxy-authorization|x-api-key|x-auth-token|private-token)\s*:\s*(?:(?:bearer|basic|token|digest)\s+)?)[^\s'"]+"#
                    .to_string(),
                "${1}***",
            ),
            // curl -u user:password / --user user:password
            (
                r#"(\b(?:curl|wget)\b[^;&|\n]*?\s(?:-u\s*|--user[=\s]+|--http-password[=\s]+)['"]?[^\s:'"]*:)[^\s'"]+"#
                    .to_string(),
                "${1}***",
            ),
            // Well-known token formats.
            (r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b".to_string(), "***"),
            (r"\bgh[pousr]_[A-Za-z0-9]{20,}\b".to_string(), "***"),
            (r"\bgithub_pat_[A-Za-z0-9_]{20,}\b".to_string(), "***"),
            (r"\bxox[abprs]-[A-Za-z0-9-]{10,}".to_string(), "***"),
            (r"\bsk-[A-Za-z0-9_\-]{20,}".to_string(), "***"),
        ];
        rules
            .into_iter()
            .filter_map(|(re, rep)| regex::Regex::new(&re).ok().map(|r| (r, rep)))
            .collect()
    })
}

/// Undo [`crate::context::escape_invisible`].
///
/// Each `\u{XXXX}` that stands for an invisible or control character becomes
/// that character again. Other `\u{…}` text (a printable character, an invalid code point) is
/// kept as written.
#[must_use]
pub fn unescape_invisible(s: &str) -> String {
    if !s.contains("\\u{") {
        return s.to_string();
    }
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(i) = rest.find("\\u{") {
        out.push_str(&rest[..i]);
        let after = &rest[i + 3..];
        let decoded = after.find('}').and_then(|end| {
            let hex = &after[..end];
            let c = (!hex.is_empty() && hex.len() <= 6)
                .then(|| u32::from_str_radix(hex, 16).ok())
                .flatten()
                .and_then(char::from_u32)
                .filter(|c| {
                    crate::context::is_invisible(*c) || (c.is_control() && *c != '\t' && *c != '\n')
                })?;
            Some((c, end))
        });
        if let Some((c, end)) = decoded {
            out.push(c);
            rest = &after[end + 1..];
        } else {
            out.push_str("\\u{");
            rest = after;
        }
    }
    out.push_str(rest);
    out
}

/// Replace secrets in a command line with `***` before it is stored.
///
/// Covers `mysql -pSECRET`, `--password=…` (and `--token`, `--secret`,
/// `--api-key`), `NAME=value` assignments whose name contains `PASSWORD`,
/// `PASS`, `TOKEN`, `SECRET`, `KEY`, `CREDENTIAL` (`PGPASSWORD`,
/// `MYSQL_PWD`, `GITHUB_TOKEN`, `AWS_SECRET_ACCESS_KEY`, …), `user:pass@`
/// in URLs, `Authorization:`-style headers, `curl -u user:pass`, and AWS
/// (`AKIA…`), GitHub (`ghp_…`), Slack (`xoxb-…`) and `sk-…` keys.
///
/// Returns the redacted text and whether anything was replaced. This is a
/// best-effort safety net, not a guarantee: a secret passed positionally
/// (`tool login s3cr3t`) cannot be recognised.
#[must_use]
pub fn redact_secrets(command: &str) -> (String, bool) {
    let mut out = std::borrow::Cow::Borrowed(command);
    for (re, rep) in redaction_rules() {
        if re.is_match(&out) {
            out = std::borrow::Cow::Owned(re.replace_all(&out, *rep).into_owned());
        }
    }
    let changed = out != command;
    (out.into_owned(), changed)
}

/// Truncate `s` to at most `max` bytes at a character boundary.
fn truncate_at_char(s: &str, max: usize) -> &str {
    if s.len() <= max {
        return s;
    }
    let mut end = max;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

/// Lowercase hex SHA-256 of `data` (small self-contained implementation so
/// the audit log needs no extra dependency).
#[must_use]
#[allow(clippy::many_single_char_names, clippy::too_many_lines)]
pub fn sha256_hex(data: &[u8]) -> String {
    const K: [u32; 64] = [
        0x428a_2f98,
        0x7137_4491,
        0xb5c0_fbcf,
        0xe9b5_dba5,
        0x3956_c25b,
        0x59f1_11f1,
        0x923f_82a4,
        0xab1c_5ed5,
        0xd807_aa98,
        0x1283_5b01,
        0x2431_85be,
        0x550c_7dc3,
        0x72be_5d74,
        0x80de_b1fe,
        0x9bdc_06a7,
        0xc19b_f174,
        0xe49b_69c1,
        0xefbe_4786,
        0x0fc1_9dc6,
        0x240c_a1cc,
        0x2de9_2c6f,
        0x4a74_84aa,
        0x5cb0_a9dc,
        0x76f9_88da,
        0x983e_5152,
        0xa831_c66d,
        0xb003_27c8,
        0xbf59_7fc7,
        0xc6e0_0bf3,
        0xd5a7_9147,
        0x06ca_6351,
        0x1429_2967,
        0x27b7_0a85,
        0x2e1b_2138,
        0x4d2c_6dfc,
        0x5338_0d13,
        0x650a_7354,
        0x766a_0abb,
        0x81c2_c92e,
        0x9272_2c85,
        0xa2bf_e8a1,
        0xa81a_664b,
        0xc24b_8b70,
        0xc76c_51a3,
        0xd192_e819,
        0xd699_0624,
        0xf40e_3585,
        0x106a_a070,
        0x19a4_c116,
        0x1e37_6c08,
        0x2748_774c,
        0x34b0_bcb5,
        0x391c_0cb3,
        0x4ed8_aa4a,
        0x5b9c_ca4f,
        0x682e_6ff3,
        0x748f_82ee,
        0x78a5_636f,
        0x84c8_7814,
        0x8cc7_0208,
        0x90be_fffa,
        0xa450_6ceb,
        0xbef9_a3f7,
        0xc671_78f2,
    ];
    let mut h: [u32; 8] = [
        0x6a09_e667,
        0xbb67_ae85,
        0x3c6e_f372,
        0xa54f_f53a,
        0x510e_527f,
        0x9b05_688c,
        0x1f83_d9ab,
        0x5be0_cd19,
    ];
    let mut msg = data.to_vec();
    let bit_len = (data.len() as u64).wrapping_mul(8);
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bit_len.to_be_bytes());
    for chunk in msg.chunks_exact(64) {
        let mut w = [0u32; 64];
        for (i, word) in chunk.chunks_exact(4).enumerate() {
            w[i] = u32::from_be_bytes([word[0], word[1], word[2], word[3]]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }
        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh] = h;
        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ (!e & g);
            let t1 = hh
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let t2 = s0.wrapping_add(maj);
            hh = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }
        for (slot, v) in h.iter_mut().zip([a, b, c, d, e, f, g, hh]) {
            *slot = slot.wrapping_add(v);
        }
    }
    h.iter().fold(String::with_capacity(64), |mut acc, v| {
        use std::fmt::Write as _;
        let _ = write!(acc, "{v:08x}");
        acc
    })
}

fn log_event_with_limit(
    audit_path: &Path,
    event: &AuditEvent,
    extra: &AuditExtra,
    max_bytes: u64,
) -> Result<()> {
    if let Some(parent) = audit_path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)?;
        }
    }

    let meta = collect_meta_for(Some(&event.command));
    // Redact secrets, then cap the stored command so a few huge commands
    // cannot flush history. The digest is always of the original command.
    let (stored_event, digest);
    let (redacted, was_redacted) = redact_secrets(&event.command);
    let truncate = redacted.len() > MAX_STORED_COMMAND_BYTES;
    // The blast-radius description arrives escaped for display
    // (`src\u{202e}.txt`); the record keeps the real text, like `command`.
    let real_detail = event
        .blast_radius_detail
        .as_deref()
        .map(unescape_invisible)
        .filter(|d| Some(d.as_str()) != event.blast_radius_detail.as_deref());
    let event = if truncate || was_redacted || real_detail.is_some() {
        let mut e = event.clone();
        if let Some(d) = real_detail {
            e.blast_radius_detail = Some(d);
        }
        e.command = if truncate {
            format!(
                "{}…[truncated]",
                truncate_at_char(&redacted, MAX_STORED_COMMAND_BYTES)
            )
        } else {
            redacted
        };
        digest = CommandDigest {
            command_bytes: truncate.then_some(event.command.len()),
            command_sha256: Some(sha256_hex(event.command.as_bytes())),
            command_truncated: truncate,
            command_redacted: was_redacted,
        };
        stored_event = e;
        &stored_event
    } else {
        digest = CommandDigest::default();
        event
    };
    let record = AuditRecordOut {
        event,
        meta,
        extra,
        digest,
    };
    let mut line = serde_json::to_vec(&record)?;
    line.push(b'\n');

    let file = open_append(audit_path)?;

    #[cfg(unix)]
    let mut file = match nix::fcntl::Flock::lock(file, nix::fcntl::FlockArg::LockExclusive) {
        Ok(locked) => LockedOrPlain::Locked(locked),
        Err((plain, _)) => LockedOrPlain::Plain(plain),
    };
    #[cfg(not(unix))]
    let mut file = file;

    // Another writer may have rotated the file between our open() and the
    // lock: then our descriptor points at a rotated generation. Re-open the
    // current file instead (once is enough; rotation needs a full file).
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let same = match (file_ref(&file).metadata(), fs::metadata(audit_path)) {
            (Ok(a), Ok(b)) => a.ino() == b.ino() && a.dev() == b.dev(),
            _ => false,
        };
        if !same {
            drop(file);
            let fresh = open_append(audit_path)?;
            file = match nix::fcntl::Flock::lock(fresh, nix::fcntl::FlockArg::LockExclusive) {
                Ok(locked) => LockedOrPlain::Locked(locked),
                Err((plain, _)) => LockedOrPlain::Plain(plain),
            };
        }
    }

    // Rotation (under the lock): if the file is over the limit, shift the
    // generations and continue with a fresh file.
    let len = file_ref(&file).metadata().map_or(0, |m| m.len());
    if max_bytes > 0
        && len >= max_bytes
        && rotate_files(audit_path, max_files_for(audit_path)).is_ok()
    {
        {
            drop(file);
            let fresh = open_append(audit_path)?;
            #[cfg(unix)]
            {
                file = match nix::fcntl::Flock::lock(fresh, nix::fcntl::FlockArg::LockExclusive) {
                    Ok(locked) => LockedOrPlain::Locked(locked),
                    Err((plain, _)) => LockedOrPlain::Plain(plain),
                };
            }
            #[cfg(not(unix))]
            {
                file = fresh;
            }
        }
    }

    let f = file_mut(&mut file);
    let written = f.write(&line)?;
    if written < line.len() {
        // Extremely unlikely for a regular file; finish the record.
        f.write_all(&line[written..])?;
    }
    Ok(())
}

#[cfg(unix)]
enum LockedOrPlain {
    Locked(nix::fcntl::Flock<fs::File>),
    Plain(fs::File),
}

#[cfg(unix)]
fn file_ref(f: &LockedOrPlain) -> &fs::File {
    match f {
        LockedOrPlain::Locked(l) => l,
        LockedOrPlain::Plain(p) => p,
    }
}

#[cfg(unix)]
fn file_mut(f: &mut LockedOrPlain) -> &mut fs::File {
    match f {
        LockedOrPlain::Locked(l) => l,
        LockedOrPlain::Plain(p) => p,
    }
}

#[cfg(not(unix))]
const fn file_ref(f: &fs::File) -> &fs::File {
    f
}

#[cfg(not(unix))]
fn file_mut(f: &mut fs::File) -> &mut fs::File {
    f
}

// ---------------------------------------------------------------------------
// Reading
// ---------------------------------------------------------------------------

/// Read and return all audit log lines.
///
/// # Errors
/// Returns an error if the file cannot be read.
pub fn read_log(audit_path: &Path) -> Result<String> {
    if !audit_path.exists() {
        return Ok("No audit events recorded yet.".into());
    }
    Ok(fs::read_to_string(audit_path)?)
}

/// Parsed audit records plus the number of lines that could not be parsed.
#[derive(Debug, Default)]
pub struct AuditRead {
    pub entries: Vec<AuditEntry>,
    /// Lines skipped because they are not valid UTF-8, not JSON, or lack a
    /// `timestamp` / `outcome`.
    pub malformed: usize,
    /// The files that were read, oldest first.
    pub files: Vec<PathBuf>,
}

/// Read every log generation (see [`log_files`]), oldest first.
///
/// # Errors
/// Returns an error if an existing log file cannot be read (e.g. it is a
/// directory or unreadable).
pub fn read_entries(audit_path: &Path) -> Result<AuditRead> {
    let mut out = AuditRead::default();
    for p in log_files(audit_path) {
        let bytes = fs::read(&p)
            .map_err(|e| Error::Other(format!("could not read audit log {}: {e}", p.display())))?;
        out.files.push(p);
        for raw in bytes.split(|b| *b == b'\n') {
            // A line that is not valid UTF-8 (or not a record) is counted
            // and skipped; it never makes the whole read fail.
            let Ok(line) = std::str::from_utf8(raw) else {
                out.malformed += 1;
                continue;
            };
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            match serde_json::from_str::<AuditEntry>(line) {
                Ok(e) if !e.timestamp.is_empty() && e.outcome.is_some() => out.entries.push(e),
                _ => out.malformed += 1,
            }
        }
    }
    Ok(out)
}

/// Collapse records that share an `event_id` (the pre-challenge `Cancelled`
/// record followed by the final outcome), keeping the last one.
#[must_use]
pub fn collapse_events(entries: Vec<AuditEntry>) -> Vec<AuditEntry> {
    let mut last_index: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
    for (i, e) in entries.iter().enumerate() {
        if !e.event_id.is_empty() {
            last_index.insert(e.event_id.clone(), i);
        }
    }
    entries
        .into_iter()
        .enumerate()
        .filter(|(i, e)| e.event_id.is_empty() || last_index.get(&e.event_id) == Some(i))
        .map(|(_, e)| e)
        .collect()
}

/// Filters for `audit show`.
#[derive(Debug, Clone, Default)]
pub struct AuditFilter {
    /// Only records at or after this timestamp (`YYYY-MM-DDTHH:MM:SSZ`).
    pub since: Option<String>,
    pub outcome: Option<AuditOutcome>,
    /// Only records at or above this severity.
    pub min_severity: Option<Severity>,
    /// Keep only the last N records (after the other filters).
    pub limit: Option<usize>,
}

/// Apply a filter.
#[must_use]
pub fn filter_entries(entries: Vec<AuditEntry>, f: &AuditFilter) -> Vec<AuditEntry> {
    let mut v: Vec<AuditEntry> = entries
        .into_iter()
        .filter(|e| {
            f.since
                .as_ref()
                .is_none_or(|s| e.timestamp.as_str() >= s.as_str())
        })
        .filter(|e| {
            f.outcome
                .as_ref()
                .is_none_or(|o| e.outcome.as_ref() == Some(o))
        })
        .filter(|e| {
            f.min_severity
                .is_none_or(|min| e.severity.is_some_and(|s| s >= min))
        })
        .collect();
    if let Some(n) = f.limit {
        if v.len() > n {
            v.drain(..v.len() - n);
        }
    }
    v
}

/// Parse a `--since` value into a comparable UTC timestamp.
///
/// Accepts a relative duration (`30m`, `12h`, `7d`, `2w`), a date
/// (`2026-01-31`) or a full timestamp (`2026-01-31T10:00:00Z`).
///
/// # Errors
/// Returns an error describing the accepted formats.
pub fn parse_since(value: &str) -> Result<String> {
    let v = value.trim();
    let err = || {
        Error::Config(format!(
            "invalid --since value '{value}'. Use a duration like 30m, 12h, 7d, 2w, \
             a date like 2026-01-31, or a timestamp like 2026-01-31T10:00:00Z"
        ))
    };
    let is_duration =
        v.is_ascii() && v.len() >= 2 && v[..v.len() - 1].chars().all(|c| c.is_ascii_digit());
    if let Some(unit) = v
        .chars()
        .last()
        .filter(|c| is_duration && c.is_ascii_alphabetic())
    {
        let num: u64 = v[..v.len() - 1].parse().map_err(|_| err())?;
        let secs = match unit {
            's' => num,
            'm' => num * 60,
            'h' => num * 3600,
            'd' => num * 86_400,
            'w' => num * 7 * 86_400,
            _ => return Err(err()),
        };
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        return Ok(timestamp_from_epoch(now.saturating_sub(secs)));
    }
    let bytes = v.as_bytes();
    let is_date = v.len() == 10
        && bytes[4] == b'-'
        && bytes[7] == b'-'
        && v.chars()
            .enumerate()
            .all(|(i, c)| i == 4 || i == 7 || c.is_ascii_digit());
    if is_date {
        return if valid_date(&v[..10]) {
            Ok(format!("{v}T00:00:00Z"))
        } else {
            Err(err())
        };
    }
    let is_timestamp = v.len() == 20
        && v.is_ascii()
        && v.ends_with('Z')
        && bytes[10] == b'T'
        && bytes[13] == b':'
        && bytes[16] == b':'
        && valid_date(&v[..10])
        && [(11, 23), (14, 59), (17, 60)].iter().all(|&(i, max)| {
            v[i..i + 2]
                .parse::<u32>()
                .is_ok_and(|n| n <= max && v[i..i + 2].bytes().all(|b| b.is_ascii_digit()))
        });
    if is_timestamp {
        return Ok(v.to_string());
    }
    Err(err())
}

/// `YYYY-MM-DD` with a real month and day.
fn valid_date(d: &str) -> bool {
    let b = d.as_bytes();
    if d.len() != 10 || !d.is_ascii() || b[4] != b'-' || b[7] != b'-' {
        return false;
    }
    let (Ok(y), Ok(m), Ok(day)) = (
        d[..4].parse::<u32>(),
        d[5..7].parse::<u32>(),
        d[8..10].parse::<u32>(),
    ) else {
        return false;
    };
    let leap = (y % 4 == 0 && y % 100 != 0) || y % 400 == 0;
    let days = match m {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap => 29,
        2 => 28,
        _ => return false,
    };
    (1..=days).contains(&day)
}

/// Render records as a human-readable table.
#[must_use]
pub fn format_table(entries: &[AuditEntry]) -> String {
    use std::fmt::Write as _;
    let mut out = String::new();
    let _ = writeln!(
        out,
        "{:<20}  {:<9}  {:<8}  {:<28}  COMMAND",
        "TIME (UTC)", "OUTCOME", "SEVERITY", "CHECKS"
    );
    for e in entries {
        let outcome = e
            .outcome
            .as_ref()
            .map_or_else(|| "?".to_string(), ToString::to_string);
        let sev = e
            .severity
            .map_or_else(|| "?".to_string(), |s| s.to_string());
        let mut checks = e.matched_ids.join(",");
        if checks.chars().count() > 28 {
            checks = format!("{}…", checks.chars().take(27).collect::<String>());
        }
        // Invisible and bidi characters are shown escaped (`\u{202e}`): the
        // JSON formats keep the real text.
        let mut cmd = crate::context::escape_invisible(&e.command.replace('\n', " "));
        if cmd.chars().count() > 80 {
            cmd = format!("{}…", cmd.chars().take(79).collect::<String>());
        }
        let mut extras = Vec::new();
        if let Some(a) = &e.agent_name {
            extras.push(format!("agent={}", crate::context::escape_invisible(a)));
        }
        if let Some(t) = &e.tool_use_id {
            extras.push(format!(
                "tool_use_id={}",
                crate::context::escape_invisible(t)
            ));
        }
        if let Some(r) = &e.deny_reason {
            extras.push(format!("reason={r}"));
        }
        // A kubectl / helm row names the cluster context it ran against;
        // the git branch is only shown for the other rows (and git checks).
        let k8s: Vec<&String> = e
            .context_labels
            .iter()
            .filter(|l| l.starts_with("k8s="))
            .collect();
        for l in &k8s {
            extras.push(crate::context::escape_invisible(l));
        }
        if let Some(b) = e
            .git_branch
            .as_ref()
            .filter(|_| k8s.is_empty() || e.matched_ids.iter().any(|id| id.starts_with("git")))
        {
            extras.push(format!("branch={}", crate::context::escape_invisible(b)));
        }
        let extras = if extras.is_empty() {
            String::new()
        } else {
            format!("  [{}]", extras.join(" "))
        };
        let _ = writeln!(
            out,
            "{:<20}  {outcome:<9}  {sev:<8}  {checks:<28}  {cmd}{extras}",
            e.timestamp
        );
    }
    out
}

/// Clear the audit log (and every rotated generation).
///
/// # Errors
/// Returns an error if the file cannot be removed.
pub fn clear_log(audit_path: &Path) -> Result<()> {
    for p in log_files(audit_path) {
        if p.exists() {
            fs::remove_file(&p).map_err(|e| {
                Error::Other(format!("could not remove audit log {}: {e}", p.display()))
            })?;
        }
    }
    Ok(())
}

/// Get the current timestamp in ISO 8601 format.
#[must_use]
pub fn now_timestamp() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    timestamp_from_epoch(secs)
}

fn timestamp_from_epoch(secs: u64) -> String {
    let days = secs / 86400;
    let remaining = secs % 86400;
    let hours = remaining / 3600;
    let minutes = (remaining % 3600) / 60;
    let seconds = remaining % 60;
    let (year, month, day) = epoch_days_to_date(days);
    format!("{year:04}-{month:02}-{day:02}T{hours:02}:{minutes:02}:{seconds:02}Z")
}

/// Convert epoch days to (year, month, day). Simplified algorithm.
const fn epoch_days_to_date(days: u64) -> (u64, u64, u64) {
    // Algorithm based on Howard Hinnant's civil_from_days
    let z = days + 719_468;
    let era = z / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn event(id: &str, outcome: AuditOutcome, severity: Severity, ts: &str) -> AuditEvent {
        AuditEvent {
            event_id: id.into(),
            timestamp: ts.into(),
            command: "git push -f".into(),
            matched_ids: vec!["git:force_push".into()],
            challenge_type: "Math".into(),
            outcome,
            context_labels: vec!["branch=main".into()],
            severity,
            agent_name: None,
            agent_session_id: None,
            blast_radius_scope: None,
            blast_radius_detail: None,
            attempts: None,
        }
    }

    #[test]
    fn test_log_and_read() {
        let temp = tree_fs::TreeBuilder::default()
            .create()
            .expect("create tree");
        let path = temp.root.join("audit.log");

        let ev = event(
            "test-event-1",
            AuditOutcome::Allowed,
            Severity::High,
            "2026-02-15T10:00:00Z",
        );
        log_event(&path, &ev).unwrap();
        let content = read_log(&path).unwrap();
        // JSON lines format: each line is a valid JSON object, readable as
        // the original AuditEvent (backward compatible).
        let parsed: AuditEvent = serde_json::from_str(content.trim()).unwrap();
        assert_eq!(parsed.event_id, "test-event-1");
        assert_eq!(parsed.command, "git push -f");
        assert_eq!(parsed.outcome, AuditOutcome::Allowed);
        assert_eq!(parsed.matched_ids, vec!["git:force_push"]);
        assert_eq!(parsed.context_labels, vec!["branch=main"]);
        assert_eq!(parsed.severity, Severity::High);

        let entry: AuditEntry = serde_json::from_str(content.trim()).unwrap();
        assert_eq!(entry.schema_version, Some(AUDIT_SCHEMA_VERSION));
        assert!(entry.cwd.is_some());
    }

    #[test]
    fn extra_fields_are_written() {
        let temp = tree_fs::TreeBuilder::default().create().unwrap();
        let path = temp.root.join("audit.log");
        let extra = AuditExtra {
            policy_sources: vec!["/repo/.shellfirm.yaml".into()],
            effective_challenge: Some("Yes".into()),
            deny_reason: Some("policy_deny".into()),
            policy_check_ids: vec!["git:force_push".into()],
            escalation_reasons: vec!["protected branch `main`".into()],
            tool_use_id: Some("toolu_1".into()),
        };
        log_event_with(
            &path,
            &event(
                "x",
                AuditOutcome::Denied,
                Severity::High,
                "2026-02-15T10:00:00Z",
            ),
            &extra,
        )
        .unwrap();
        let read = read_entries(&path).unwrap();
        assert_eq!(read.entries.len(), 1);
        let e = &read.entries[0];
        assert_eq!(e.deny_reason.as_deref(), Some("policy_deny"));
        assert_eq!(e.effective_challenge.as_deref(), Some("Yes"));
        assert_eq!(e.policy_sources, vec!["/repo/.shellfirm.yaml".to_string()]);
        // `audit show --format json|jsonl` keeps the tool_use_id.
        assert_eq!(e.tool_use_id.as_deref(), Some("toolu_1"));
        let json = serde_json::to_value(e).unwrap();
        assert_eq!(json["tool_use_id"], "toolu_1");
        assert!(format_table(&read.entries).contains("tool_use_id=toolu_1"));
    }

    #[test]
    fn table_shows_the_k8s_context_for_kubectl_rows() {
        let kube = AuditEntry {
            command: "kubectl delete deploy api".into(),
            matched_ids: vec!["kubernetes-strict:delete_resource".into()],
            context_labels: vec!["k8s=prod-eu".into()],
            git_branch: Some("main".into()),
            ..AuditEntry::default()
        };
        let git = AuditEntry {
            command: "git push -f".into(),
            matched_ids: vec!["git:force_push".into()],
            git_branch: Some("main".into()),
            ..AuditEntry::default()
        };
        let table = format_table(&[kube, git]);
        let lines: Vec<&str> = table.lines().collect();
        assert!(lines[1].contains("[k8s=prod-eu]"), "{table}");
        assert!(!lines[1].contains("branch="), "{table}");
        assert!(lines[2].contains("[branch=main]"), "{table}");
    }

    #[test]
    fn sqlcmd_and_bcp_passwords_are_redacted() {
        for (cmd, want) in [
            (
                "sqlcmd -S db -U sa -P S3cret! -Q 'select 1'",
                "sqlcmd -S db -U sa -P *** -Q 'select 1'",
            ),
            (
                "sqlcmd -S db -U sa -PS3cret -i x.sql",
                "sqlcmd -S db -U sa -P*** -i x.sql",
            ),
            (
                "bcp dbo.t out t.dat -S db -U sa -P 'a b' -c",
                "bcp dbo.t out t.dat -S db -U sa -P *** -c",
            ),
            (
                "bcp dbo.t out t.dat -Uu -Ppw",
                "bcp dbo.t out t.dat -Uu -P***",
            ),
        ] {
            assert_eq!(redact_secrets(cmd).0, want, "{cmd}");
        }
        // `-p` (statistics) is not a password.
        assert!(!redact_secrets("sqlcmd -S db -p -Q 'select 1'").1);
    }

    #[test]
    fn table_escapes_invisible_characters_but_json_keeps_them() {
        let e = AuditEntry {
            timestamp: "2026-02-15T10:00:00Z".into(),
            command: "rm -rf src\u{202e}.txt # \u{200b}x".into(),
            git_branch: Some("main\u{200b}".into()),
            ..AuditEntry::default()
        };
        let table = format_table(std::slice::from_ref(&e));
        assert!(table.contains("src\\u{202e}.txt"), "{table}");
        assert!(table.contains("branch=main\\u{200b}"), "{table}");
        assert!(!table.contains('\u{202e}'));
        let json = serde_json::to_value(&e).unwrap();
        assert_eq!(json["command"], "rm -rf src\u{202e}.txt # \u{200b}x");
    }

    #[test]
    fn old_records_still_parse() {
        let temp = tree_fs::TreeBuilder::default().create().unwrap();
        let path = temp.root.join("audit.log");
        fs::write(
            &path,
            "{\"event_id\":\"a\",\"timestamp\":\"2026-01-01T00:00:00Z\",\"command\":\"rm -rf /\",\"matched_ids\":[\"fs:x\"],\"challenge_type\":\"Math\",\"outcome\":\"Allowed\",\"context_labels\":[],\"severity\":\"Critical\"}\nnot json\n",
        )
        .unwrap();
        let read = read_entries(&path).unwrap();
        assert_eq!(read.entries.len(), 1);
        assert_eq!(read.malformed, 1);
        assert_eq!(read.entries[0].schema_version, None);
    }

    #[cfg(unix)]
    #[test]
    fn audit_file_is_private() {
        use std::os::unix::fs::PermissionsExt;
        let temp = tree_fs::TreeBuilder::default().create().unwrap();
        let path = temp.root.join("audit.log");
        fs::write(&path, "").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        log_event(
            &path,
            &event(
                "p",
                AuditOutcome::Allowed,
                Severity::Low,
                "2026-01-01T00:00:00Z",
            ),
        )
        .unwrap();
        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }

    #[test]
    fn concurrent_writers_do_not_interleave() {
        let temp = tree_fs::TreeBuilder::default().create().unwrap();
        let path = temp.root.join("audit.log");
        let big = "x".repeat(8 * 1024);
        let handles: Vec<_> = (0..16)
            .map(|t| {
                let path = path.clone();
                let big = big.clone();
                std::thread::spawn(move || {
                    for i in 0..10 {
                        let mut ev = event(
                            &format!("{t}-{i}"),
                            AuditOutcome::Allowed,
                            Severity::Low,
                            "2026-01-01T00:00:00Z",
                        );
                        ev.command.clone_from(&big);
                        log_event(&path, &ev).unwrap();
                    }
                })
            })
            .collect();
        for h in handles {
            h.join().unwrap();
        }
        let read = read_entries(&path).unwrap();
        assert_eq!(read.malformed, 0);
        assert_eq!(read.entries.len(), 160);
    }

    #[test]
    fn rotation_moves_old_log_aside() {
        let temp = tree_fs::TreeBuilder::default().create().unwrap();
        let path = temp.root.join("audit.log");
        let ev = event(
            "r",
            AuditOutcome::Allowed,
            Severity::Low,
            "2026-01-01T00:00:00Z",
        );
        log_event_with_limit(&path, &ev, &AuditExtra::default(), 10).unwrap();
        log_event_with_limit(&path, &ev, &AuditExtra::default(), 10).unwrap();
        assert!(rotated_path(&path).exists());
        let read = read_entries(&path).unwrap();
        assert_eq!(read.entries.len(), 2);
        clear_log(&path).unwrap();
        assert!(!path.exists());
        assert!(!rotated_path(&path).exists());
    }

    #[test]
    fn collapse_and_filter() {
        let mk = |id: &str, o: AuditOutcome, s: Severity, ts: &str| -> AuditEntry {
            serde_json::from_str(&serde_json::to_string(&event(id, o, s, ts)).unwrap()).unwrap()
        };
        let entries = vec![
            mk(
                "a",
                AuditOutcome::Cancelled,
                Severity::High,
                "2026-01-01T00:00:00Z",
            ),
            mk(
                "a",
                AuditOutcome::Allowed,
                Severity::High,
                "2026-01-01T00:00:01Z",
            ),
            mk(
                "b",
                AuditOutcome::Denied,
                Severity::Critical,
                "2026-02-01T00:00:00Z",
            ),
            mk(
                "c",
                AuditOutcome::Skipped,
                Severity::Low,
                "2026-03-01T00:00:00Z",
            ),
        ];
        let collapsed = collapse_events(entries);
        assert_eq!(collapsed.len(), 3);
        assert_eq!(collapsed[0].outcome, Some(AuditOutcome::Allowed));

        let f = AuditFilter {
            outcome: Some(AuditOutcome::Denied),
            ..Default::default()
        };
        assert_eq!(filter_entries(collapsed.clone(), &f).len(), 1);
        let f = AuditFilter {
            min_severity: Some(Severity::High),
            ..Default::default()
        };
        assert_eq!(filter_entries(collapsed.clone(), &f).len(), 2);
        let f = AuditFilter {
            since: Some("2026-02-01T00:00:00Z".into()),
            ..Default::default()
        };
        assert_eq!(filter_entries(collapsed.clone(), &f).len(), 2);
        let f = AuditFilter {
            limit: Some(1),
            ..Default::default()
        };
        let last = filter_entries(collapsed, &f);
        assert_eq!(last.len(), 1);
        assert_eq!(last[0].event_id, "c");
        assert!(format_table(&last).contains("SKIPPED"));
    }

    #[test]
    fn parse_since_formats() {
        assert_eq!(parse_since("2026-01-31").unwrap(), "2026-01-31T00:00:00Z");
        assert_eq!(
            parse_since("2026-01-31T10:00:00Z").unwrap(),
            "2026-01-31T10:00:00Z"
        );
        assert_eq!(parse_since("7d").unwrap().len(), 20);
        assert!(parse_since("yesterday").is_err());
        assert!(parse_since("7y").is_err());
    }

    #[test]
    fn outcome_parse() {
        assert_eq!(AuditOutcome::parse("DENIED").unwrap(), AuditOutcome::Denied);
        assert!(AuditOutcome::parse("nope").is_err());
    }

    #[test]
    fn git_info_reads_head() {
        let temp = tree_fs::TreeBuilder::default()
            .add(".git/HEAD", "ref: refs/heads/feature/x\n")
            .add("sub/file", "")
            .create()
            .unwrap();
        let (repo, branch) = git_info(&temp.root.join("sub"));
        assert_eq!(repo.as_deref(), Some(temp.root.as_path()));
        assert_eq!(branch.as_deref(), Some("feature/x"));
    }

    #[test]
    fn test_read_nonexistent_log() {
        let path = PathBuf::from("/tmp/nonexistent-audit-test.log");
        let result = read_log(&path).unwrap();
        assert!(result.contains("No audit events"));
    }

    #[test]
    fn test_cancelled_outcome_serialization() {
        let temp = tree_fs::TreeBuilder::default()
            .create()
            .expect("create tree");
        let path = temp.root.join("audit.log");
        log_event(
            &path,
            &event(
                "cancel-test-1",
                AuditOutcome::Cancelled,
                Severity::Critical,
                "2026-02-15T10:00:00Z",
            ),
        )
        .unwrap();
        let content = read_log(&path).unwrap();
        let parsed: AuditEvent = serde_json::from_str(content.trim()).unwrap();
        assert_eq!(parsed.outcome, AuditOutcome::Cancelled);
        assert_eq!(format!("{}", parsed.outcome), "CANCELLED");
    }

    #[test]
    fn git_meta_follows_the_target_repository() {
        let temp = tree_fs::TreeBuilder::default()
            .add("infra/.git/HEAD", "ref: refs/heads/infra-main\n")
            .add("infra/x", "")
            .create()
            .unwrap();
        let infra = temp.root.join("infra");
        for command in [
            format!("git -C {} push -f", infra.display()),
            format!("cd {} && git reset --hard", infra.display()),
            format!("cd {} && rm -rf x", infra.display()),
        ] {
            let meta = collect_meta_for(Some(&command));
            assert_eq!(
                meta.git_repo.as_deref(),
                Some(infra.display().to_string().as_str())
            );
            assert_eq!(meta.git_branch.as_deref(), Some("infra-main"), "{command}");
            assert_eq!(
                meta.cwd,
                std::env::current_dir()
                    .ok()
                    .map(|c| c.display().to_string())
            );
        }
        // No other directory: the current one's repository.
        let here = collect_meta_for(Some("git push -f"));
        assert_eq!(here.git_repo, collect_meta().git_repo);
    }

    #[test]
    fn test_now_timestamp_format() {
        let ts = now_timestamp();
        assert!(ts.contains('T'));
        assert!(ts.ends_with('Z'));
        assert_eq!(ts.len(), 20);
    }

    #[test]
    fn sha256_matches_known_vectors() {
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            sha256_hex(&[b'a'; 1000]),
            "41edece42d63e8d9bf515a9ba6932e1c20cbc9f5a5d134645adb5db1b9737ea3"
        );
    }

    #[test]
    fn huge_commands_are_truncated_and_hashed() {
        let temp = tree_fs::TreeBuilder::default().create().unwrap();
        let path = temp.root.join("audit.log");
        let mut ev = event(
            "big",
            AuditOutcome::Asked,
            Severity::High,
            "2026-01-01T00:00:00Z",
        );
        ev.command = format!("echo {} && rm -rf ./src", "é".repeat(3 * 1024 * 1024));
        log_event(&path, &ev).unwrap();
        assert!(fs::metadata(&path).unwrap().len() < 16 * 1024);
        let e = &read_entries(&path).unwrap().entries[0];
        assert!(e.command_truncated);
        assert_eq!(e.command_bytes, Some(ev.command.len()));
        assert_eq!(
            e.command_sha256.as_deref(),
            Some(sha256_hex(ev.command.as_bytes()).as_str())
        );
    }

    #[test]
    fn rotation_keeps_n_generations_and_show_reads_them() {
        let temp = tree_fs::TreeBuilder::default().create().unwrap();
        let path = temp.root.join("audit.log");
        for i in 0..5 {
            fs::write(
                &path,
                format!(
                    "{}\n",
                    serde_json::to_string(&event(
                        &format!("e{i}"),
                        AuditOutcome::Allowed,
                        Severity::Low,
                        "2026-01-01T00:00:00Z"
                    ))
                    .unwrap()
                ),
            )
            .unwrap();
            rotate_files(&path, 3).unwrap();
        }
        let files = log_files(&path);
        assert_eq!(files.len(), 3, "{files:?}");
        assert!(!rotated_path_n(&path, 4).exists());
        let ids: Vec<String> = read_entries(&path)
            .unwrap()
            .entries
            .into_iter()
            .map(|e| e.event_id)
            .collect();
        assert_eq!(ids, vec!["e2", "e3", "e4"]);
        clear_log(&path).unwrap();
        assert!(log_files(&path).is_empty());
    }

    #[test]
    fn invalid_utf8_and_incomplete_lines_are_skipped() {
        let temp = tree_fs::TreeBuilder::default().create().unwrap();
        let path = temp.root.join("audit.log");
        let good = serde_json::to_string(&event(
            "g",
            AuditOutcome::Denied,
            Severity::High,
            "2026-01-01T00:00:00Z",
        ))
        .unwrap();
        let mut bytes = b"\xff\xfe\n{\"foo\":1}\n".to_vec();
        bytes.extend_from_slice(good.as_bytes());
        bytes.push(b'\n');
        fs::write(&path, bytes).unwrap();
        let r = read_entries(&path).unwrap();
        assert_eq!(r.entries.len(), 1);
        assert_eq!(r.malformed, 2);
    }

    #[test]
    fn parse_since_rejects_impossible_dates() {
        assert!(parse_since("2026-13-01").is_err());
        assert!(parse_since("2026-02-30").is_err());
        assert!(parse_since("2024-02-29").is_ok());
        assert!(parse_since("2026-01-31T25:00:00Z").is_err());
        assert!(parse_since("2026-01-31TAB:00:00Z").is_err());
    }

    #[test]
    fn no_terminal_outcome_round_trips() {
        assert_eq!(
            AuditOutcome::parse("no-terminal").unwrap(),
            AuditOutcome::NoTerminal
        );
        assert_eq!(
            serde_json::to_string(&AuditOutcome::NoTerminal).unwrap(),
            "\"NoTerminal\""
        );
    }

    #[test]
    fn identity_comes_from_the_uid() {
        let meta = collect_meta();
        #[cfg(unix)]
        assert_eq!(meta.uid, current_uid());
        assert_eq!(meta.schema_version, AUDIT_SCHEMA_VERSION);
    }

    #[test]
    fn extra_for_policy_deny() {
        let merged = crate::policy::MergedPolicy {
            extra_deny: vec!["git:force_push".into()],
            enforced_ids: ["git:force_push".to_string()].into_iter().collect(),
            sources: vec![PathBuf::from("/repo/.shellfirm.yaml")],
            ..Default::default()
        };
        let x = AuditExtra::for_decision(
            &merged,
            &[],
            &["git:force_push".into()],
            true,
            Some("Deny".into()),
            vec![],
        );
        assert_eq!(x.deny_reason.as_deref(), Some("policy_deny"));
        assert_eq!(x.policy_sources, vec!["/repo/.shellfirm.yaml".to_string()]);
        let y = AuditExtra::for_decision(
            &crate::policy::MergedPolicy::default(),
            &["git:reset".into()],
            &["git:reset".into()],
            true,
            None,
            vec![],
        );
        assert_eq!(y.deny_reason.as_deref(), Some("user_deny"));
        assert!(y.policy_sources.is_empty());
    }

    #[test]
    fn extra_policy_sources_are_the_files_that_name_the_id() {
        let mut id_sources = std::collections::BTreeMap::new();
        id_sources.insert(
            "kubernetes:delete_namespace".to_string(),
            vec![PathBuf::from("/etc/shellfirm/policy.yaml")],
        );
        id_sources.insert(
            "git:reset".to_string(),
            vec![PathBuf::from("/repo/.shellfirm.yaml")],
        );
        let merged = crate::policy::MergedPolicy {
            extra_deny: vec!["kubernetes:delete_namespace".into()],
            enforced_ids: [
                "kubernetes:delete_namespace".to_string(),
                "git:reset".to_string(),
            ]
            .into_iter()
            .collect(),
            sources: vec![
                PathBuf::from("/etc/shellfirm/policy.yaml"),
                PathBuf::from("/repo/.shellfirm.yaml"),
            ],
            org_sources: vec![PathBuf::from("/etc/shellfirm/policy.yaml")],
            id_sources,
            ..Default::default()
        };
        let x = AuditExtra::for_decision(
            &merged,
            &[],
            &["kubernetes:delete_namespace".into()],
            true,
            Some("Deny".into()),
            vec![],
        );
        assert_eq!(x.deny_reason.as_deref(), Some("policy_deny"));
        assert_eq!(
            x.policy_sources,
            vec!["/etc/shellfirm/policy.yaml".to_string()]
        );
        // A personal deny of an id the policy only escalates is a user deny,
        // but the policy enforcement is still attributed.
        let y = AuditExtra::for_decision(
            &merged,
            &["git:reset".into()],
            &["git:reset".into()],
            true,
            None,
            vec![],
        );
        assert_eq!(y.deny_reason.as_deref(), Some("user_deny"));
        assert_eq!(y.policy_check_ids, vec!["git:reset".to_string()]);
        assert_eq!(y.policy_sources, vec!["/repo/.shellfirm.yaml".to_string()]);
        // Not denied: no reason.
        let z = AuditExtra::for_decision(&merged, &[], &["git:reset".into()], false, None, vec![]);
        assert!(z.deny_reason.is_none());
    }

    #[test]
    fn max_files_is_never_zero() {
        assert_eq!(clamp_max_files(0), 1);
        assert_eq!(clamp_max_files(3), 3);
        assert_eq!(clamp_max_files(1000), MAX_AUDIT_FILES_LIMIT);
    }

    #[test]
    fn rotation_with_keep_zero_still_keeps_one_generation() {
        let temp = tree_fs::TreeBuilder::default().create().unwrap();
        let path = temp.root.join("audit.log");
        fs::write(&path, "old\n").unwrap();
        rotate_files(&path, 0).unwrap();
        assert_eq!(fs::read_to_string(rotated_path(&path)).unwrap(), "old\n");
    }

    /// Test inputs are assembled from pieces so this source file itself
    /// does not read like a risky command to shell hooks scanning it.
    fn j(parts: &[&str]) -> String {
        parts.concat()
    }

    #[test]
    fn unescape_invisible_restores_only_invisible_characters() {
        let shown = crate::context::escape_invisible("src\u{202e}.txt and b\u{200b}");
        assert_eq!(shown, "src\\u{202e}.txt and b\\u{200b}");
        assert_eq!(unescape_invisible(&shown), "src\u{202e}.txt and b\u{200b}");
        // Printable or invalid code points stay as written.
        assert_eq!(unescape_invisible("a\\u{41}b"), "a\\u{41}b");
        assert_eq!(unescape_invisible("a\\u{zz}\\u{"), "a\\u{zz}\\u{");
        assert_eq!(unescape_invisible("plain"), "plain");
    }

    #[test]
    fn deny_reason_for_outcome_tells_cancel_from_no_tty() {
        assert_eq!(
            deny_reason::for_outcome(&AuditOutcome::Cancelled),
            Some(deny_reason::CANCELLED)
        );
        assert_eq!(
            deny_reason::for_outcome(&AuditOutcome::NoTerminal),
            Some(deny_reason::NO_TTY)
        );
        assert_eq!(deny_reason::for_outcome(&AuditOutcome::Allowed), None);
        assert_ne!(deny_reason::CANCELLED, deny_reason::CHALLENGE_FAILED);
    }

    #[test]
    fn stored_blast_radius_detail_is_the_real_text() {
        let tmp = tree_fs::TreeBuilder::default().create().unwrap();
        let path = tmp.root.join("audit.log");
        let mut ev = event(
            "e1",
            AuditOutcome::Cancelled,
            Severity::High,
            "2026-02-15T10:00:00Z",
        );
        ev.blast_radius_detail = Some(crate::context::escape_invisible(
            "Deletes 2 paths (src\u{202e}.txt, b)",
        ));
        log_event(&path, &ev).unwrap();
        let line = std::fs::read_to_string(&path).unwrap();
        let v: serde_json::Value = serde_json::from_str(line.trim()).unwrap();
        assert_eq!(
            v["blast_radius_detail"].as_str(),
            Some("Deletes 2 paths (src\u{202e}.txt, b)")
        );
    }

    #[test]
    fn secrets_are_redacted() {
        let cases: Vec<(String, String)> = vec![
            (
                j(&["mysql -u root -pS3cret! db"]),
                j(&["mysql -u root -p*** db"]),
            ),
            (
                j(&["mysqldump --password=S3cret db"]),
                j(&["mysqldump --password=*** db"]),
            ),
            (
                j(&["PGPASSWORD=hunter2 psql -h db"]),
                j(&["PGPASSWORD=*** psql -h db"]),
            ),
            (j(&["MYSQL_PWD='a b' mysql"]), j(&["MYSQL_PWD=*** mysql"])),
            (
                j(&["export GITHUB_TOKEN=abc123; gh repo list"]),
                j(&["export GITHUB_TOKEN=***; gh repo list"]),
            ),
            (
                j(&["AWS_SECRET_ACCESS_KEY=xyz aws s3 ls"]),
                j(&["AWS_SECRET_ACCESS_KEY=*** aws s3 ls"]),
            ),
            (
                j(&["psql postgres://admin:pa55@db.prod:5432/app -c 'select 1'"]),
                j(&["psql postgres://admin:***@db.prod:5432/app -c 'select 1'"]),
            ),
            (
                j(&[r#"curl -H "Authorization: Bearer eyJhbGci.x.y" https://api/x"#]),
                j(&[r#"curl -H "Authorization: Bearer ***" https://api/x"#]),
            ),
            (
                j(&["curl -u admin:secret https://h/x"]),
                j(&["curl -u admin:*** https://h/x"]),
            ),
            (
                j(&["aws --profile x s3 ls # AKIA", "IOSFODNN7EXAMPLE"]),
                j(&["aws --profile x s3 ls # ***"]),
            ),
            (
                j(&["vault login --token s.abcdef"]),
                j(&["vault login --token ***"]),
            ),
            (
                j(&["redis-cli -a R3disPw PING"]),
                j(&["redis-cli -a *** PING"]),
            ),
            (
                j(&["redis-cli -h prod --pass RdPw33 PING"]),
                j(&["redis-cli -h prod --pass *** PING"]),
            ),
            (
                j(&["REDISCLI_AUTH=RcAuth5 redis-cli PING"]),
                j(&["REDISCLI_AUTH=*** redis-cli PING"]),
            ),
            (
                j(&["redis-cli -u redis://:UrlRedisPw@prod:6379 PING"]),
                j(&["redis-cli -u redis://:***@prod:6379 PING"]),
            ),
            (
                j(&["mongosh -u admin -p MgPw11 --eval 'db.x.find()'"]),
                j(&["mongosh -u admin -p *** --eval 'db.x.find()'"]),
            ),
            (
                j(&["mongosh --username admin --password MgPw22 --eval x"]),
                j(&["mongosh --username admin --password *** --eval x"]),
            ),
            (
                j(&[
                    "clickhouse-client --password ChPw10 -q 'DROP DATA",
                    "BASE prod'",
                ]),
                j(&[
                    "clickhouse-client --password *** -q 'DROP DATA",
                    "BASE prod'",
                ]),
            ),
            (
                j(&["clickhouse-client --password=ChPw11 -q x"]),
                j(&["clickhouse-client --password=*** -q x"]),
            ),
            (
                j(&["cqlsh -u cassandra -p CqPw12 -e 'DROP KEY", "SPACE prod'"]),
                j(&["cqlsh -u cassandra -p *** -e 'DROP KEY", "SPACE prod'"]),
            ),
            (
                j(&["cqlsh --password CqPw13 db1"]),
                j(&["cqlsh --password *** db1"]),
            ),
            (
                j(&["mongosh admin -u root -pMgPw15 --eval x"]),
                j(&["mongosh admin -u root -p*** --eval x"]),
            ),
            (j(&["mongo -pMgPw16 db"]), j(&["mongo -p*** db"])),
        ];
        for (input, want) in &cases {
            let (got, changed) = redact_secrets(input);
            assert!(changed, "{input}");
            assert_eq!(&got, want, "{input}");
        }
        for safe in [
            "git push -f origin main",
            "mkdir -p build && ls build",
            "ssh -p22 host",
            "docker run -p8080:80 img",
            "mysql -p db",
            "ls ./node_modules",
            "mongosh -u admin -p --eval x",
            "redis-cli -h prod PING",
            "clickhouse-client --password -q x",
            "cqlsh -p --help",
            "mongosh --port 27017 db",
            "mysql --password mydb",
        ] {
            let (got, changed) = redact_secrets(safe);
            assert!(!changed, "{safe} -> {got}");
            assert_eq!(got, safe);
        }
    }

    #[test]
    fn redacted_record_keeps_the_original_digest() {
        let temp = tree_fs::TreeBuilder::default().create().unwrap();
        let path = temp.root.join("audit.log");
        let mut ev = event(
            "r",
            AuditOutcome::Denied,
            Severity::High,
            "2026-02-15T10:00:00Z",
        );
        ev.command = j(&["mysql -uroot -phunter2 -e 'select 1'"]);
        log_event(&path, &ev).unwrap();
        let line = read_log(&path).unwrap();
        assert!(!line.contains("hunter2"), "{line}");
        let entry: AuditEntry = serde_json::from_str(line.trim()).unwrap();
        assert_eq!(entry.command, "mysql -uroot -p*** -e 'select 1'");
        assert!(entry.command_redacted);
        assert!(!entry.command_truncated);
        assert_eq!(
            entry.command_sha256.as_deref(),
            Some(sha256_hex(ev.command.as_bytes()).as_str())
        );
        // A command without secrets is stored verbatim, with no digest.
        let temp2 = tree_fs::TreeBuilder::default().create().unwrap();
        let path2 = temp2.root.join("audit.log");
        let ev2 = event(
            "s",
            AuditOutcome::Denied,
            Severity::High,
            "2026-02-15T10:00:00Z",
        );
        log_event(&path2, &ev2).unwrap();
        let entry2: AuditEntry = serde_json::from_str(read_log(&path2).unwrap().trim()).unwrap();
        assert!(!entry2.command_redacted);
        assert!(entry2.command_sha256.is_none());
    }
}
