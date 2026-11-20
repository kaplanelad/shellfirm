//! `shellfirm sandbox <agent>` — turn on an AI agent's own OS sandbox and
//! deny it the credential files shellfirm protects.
//!
//! shellfirm's hooks judge the text of a command; a script or child process
//! that opens `~/.ssh/id_rsa` at runtime never shows up in that text. The
//! agents' sandboxes (Seatbelt on macOS, bubblewrap on Linux) enforce file
//! access for every process a command starts, but by default they restrict
//! writes, not reads. This command writes the agent's native sandbox
//! settings so sandboxed commands cannot read credential files
//! ([`shellfirm::agent::CREDENTIAL_PATHS`]) or write startup, persistence
//! and settings files ([`shellfirm::agent::sandbox_write_protected_paths`]).
//!
//! The same file-safety rules as `shellfirm connect` apply (it reuses its
//! helpers): tolerant parsing, nothing written when a file cannot be parsed
//! or has an unexpected shape, a timestamped backup before every change,
//! atomic replacement. What shellfirm added to each file is recorded in
//! `sandbox.json` in shellfirm's configuration directory, so `--remove`
//! takes out exactly those entries (and puts back a `sandbox.enabled` /
//! `default_permissions` value it changed), never ones that were there
//! before.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::fs;
use std::io::Write as _;
use std::path::{Path, PathBuf};

use clap::{Arg, ArgAction, ArgMatches, Command};
use serde_json::{json, Map, Value};
use shellfirm::config::SandboxConfig;
use shellfirm::error::Result;

use super::connect_cmd::{self as connect, LoadedFile, OpResult, SaveMode};

/// File in shellfirm's configuration directory recording what was added.
const MANIFEST_FILE: &str = "sandbox.json";
const MANIFEST_VERSION: u32 = 1;

/// Name of the Codex permission profile shellfirm creates.
const CODEX_PROFILE: &str = "shellfirm";
/// `description` of that profile (also how `--remove` recognises it when
/// the record in `sandbox.json` is gone).
const CODEX_PROFILE_DESCRIPTION: &str =
    "Added by shellfirm sandbox: a built-in profile plus deny rules for credential files";

// ---------------------------------------------------------------------------
// Agents
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Agent {
    ClaudeCode,
    Codex,
}

impl Agent {
    fn from_name(name: &str) -> Option<Self> {
        match name {
            "claude-code" => Some(Self::ClaudeCode),
            "codex" => Some(Self::Codex),
            _ => None,
        }
    }

    const fn cli_name(self) -> &'static str {
        match self {
            Self::ClaudeCode => "claude-code",
            Self::Codex => "codex",
        }
    }

    const fn display_name(self) -> &'static str {
        match self {
            Self::ClaudeCode => "Claude Code",
            Self::Codex => "Codex CLI",
        }
    }
}

/// One row of `shellfirm sandbox --list`.
struct AgentInfo {
    name: &'static str,
    display: &'static str,
    supported: bool,
    detail: &'static str,
}

const AGENTS: &[AgentInfo] = &[
    AgentInfo {
        name: "claude-code",
        display: "Claude Code",
        supported: true,
        detail: "settings.json `sandbox`: enabled, filesystem.denyRead, filesystem.denyWrite \
                 (scopes: user ~/.claude/settings.json, project .claude/settings.json, \
                 local .claude/settings.local.json). The sandbox covers Bash commands and \
                 everything they start; macOS uses Seatbelt, Linux/WSL2 need bubblewrap and \
                 socat; native Windows has no sandbox.",
    },
    AgentInfo {
        name: "codex",
        display: "Codex CLI",
        supported: true,
        detail: "~/.codex/config.toml (or $CODEX_HOME): a permission profile \
                 ([permissions.<name>.filesystem], \"deny\" = no access, \"read\" = read-only) \
                 selected with default_permissions; user scope only. A `--sandbox` / \
                 `--dangerously-bypass-approvals-and-sandbox` flag on the codex command line \
                 replaces the profile for that run.",
    },
    AgentInfo {
        name: "gemini-cli",
        display: "Gemini CLI",
        supported: false,
        detail: "not supported: its sandbox is switched on per run (--sandbox, GEMINI_SANDBOX) \
                 and the macOS Seatbelt profile is chosen with the SEATBELT_PROFILE environment \
                 variable; there is no settings key for deny-read paths, so it would need a \
                 hand-written .sb profile.",
    },
    AgentInfo {
        name: "copilot-cli",
        display: "GitHub Copilot CLI",
        supported: false,
        detail: "not supported: it has tool permissions (--allow-tool / --deny-tool, trusted \
                 folders) but no OS sandbox with file deny rules that shellfirm could configure.",
    },
    AgentInfo {
        name: "qwen",
        display: "Qwen Code",
        supported: false,
        detail: "not supported: like Gemini CLI, its sandbox is switched on per run \
                 (--sandbox) and has no settings key for deny-read paths.",
    },
    AgentInfo {
        name: "cursor",
        display: "Cursor",
        supported: false,
        detail: NO_SANDBOX_WRITER,
    },
    AgentInfo {
        name: "windsurf",
        display: "Windsurf",
        supported: false,
        detail: NO_SANDBOX_WRITER,
    },
    AgentInfo {
        name: "cline",
        display: "Cline",
        supported: false,
        detail: NO_SANDBOX_WRITER,
    },
    AgentInfo {
        name: "opencode",
        display: "OpenCode",
        supported: false,
        detail: NO_SANDBOX_WRITER,
    },
    AgentInfo {
        name: "zed",
        display: "Zed",
        supported: false,
        detail: "not supported: shellfirm has no OS sandbox setting to write for it; \
                 `shellfirm connect zed` registers the MCP server.",
    },
];

/// [`AgentInfo::detail`] of a hook-only agent.
const NO_SANDBOX_WRITER: &str = "not supported: shellfirm has no OS sandbox setting with file \
     deny rules to write for it; `shellfirm connect` installs a hook that checks its commands \
     and file edits instead.";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Scope {
    User,
    Project,
    Local,
}

impl Scope {
    const fn name(self) -> &'static str {
        match self {
            Self::User => "user",
            Self::Project => "project",
            Self::Local => "local",
        }
    }
}

/// Paths the command is resolved against (injectable for tests).
#[derive(Debug, Clone)]
struct SandboxEnv {
    home: PathBuf,
    cwd: PathBuf,
    /// shellfirm's configuration directory (holds `sandbox.json`; its path
    /// is also denied for writes).
    config_dir: PathBuf,
    /// Codex's home (`$CODEX_HOME`, else `~/.codex`).
    codex_home: PathBuf,
    /// Claude Code's user directory (`$CLAUDE_CONFIG_DIR`, else `~/.claude`).
    claude_dir: PathBuf,
    /// Claude Code's managed settings file (read for settings that weaken
    /// the deny rules).
    claude_managed: Option<PathBuf>,
    /// Where backups of project files go (outside the repository).
    backup_dir: Option<PathBuf>,
}

#[derive(Debug, Clone, Copy)]
struct Options {
    dry_run: bool,
    remove: bool,
    scope: Scope,
}

fn settings_file(agent: Agent, scope: Scope, env: &SandboxEnv) -> PathBuf {
    match (agent, scope) {
        (Agent::ClaudeCode, Scope::User) => env.claude_dir.join("settings.json"),
        (Agent::ClaudeCode, Scope::Project) => env.cwd.join(".claude").join("settings.json"),
        (Agent::ClaudeCode, Scope::Local) => env.cwd.join(".claude").join("settings.local.json"),
        (Agent::Codex, _) => env.codex_home.join("config.toml"),
    }
}

// ---------------------------------------------------------------------------
// Paths
// ---------------------------------------------------------------------------

/// The paths written for one run.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct SandboxPaths {
    deny_read: Vec<String>,
    deny_write: Vec<String>,
    /// Problems with `sandbox.*` entries in settings.yaml (entry skipped).
    warnings: Vec<String>,
    /// Entries that cannot be written (`deny_read: ["/"]` would deny every
    /// read): the command refuses to run.
    errors: Vec<String>,
}

/// Platform-as-a-service CLI login files (long-lived account tokens).
/// Denied in the sandbox next to [`shellfirm::agent::CREDENTIAL_PATHS`].
const PAAS_CREDENTIAL_PATHS: &[&str] = &[
    "~/.railway/config.json",
    "~/.supabase/access-token",
    "~/.local/share/com.vercel.cli/auth.json",
    "~/Library/Application Support/com.vercel.cli/auth.json",
    "~/.config/netlify/config.json",
    "~/Library/Preferences/netlify/config.json",
    "~/.fly/config.yml",
];

/// `~/.ssh/` and `~/.ssh` are the same entry for every agent.
fn norm(p: &str) -> String {
    let t = p.trim();
    if t.len() > 1 {
        t.trim_end_matches('/').to_string()
    } else {
        t.to_string()
    }
}

/// `dir` as written into the agent's settings: `~/…` under the home
/// directory, else absolute (`None` for a shared project file, which must
/// not carry personal paths).
fn display_dir(dir: &Path, home: &Path, scope: Scope) -> Option<String> {
    if let Ok(rest) = dir.strip_prefix(home) {
        let rest = rest.display().to_string().replace('\\', "/");
        return Some(if rest.is_empty() {
            "~".into()
        } else {
            format!("~/{rest}")
        });
    }
    (scope != Scope::Project).then(|| dir.display().to_string())
}

/// One `sandbox.deny_read` / `deny_write` entry from settings.yaml.
enum Entry {
    /// Written as this (normalised) path.
    Use(String),
    /// Left out, with a warning (a relative path).
    Skip(String),
    /// The command refuses to run (it would deny everything, or it would be
    /// read as something it is not).
    Refuse(String),
}

fn user_entry(raw: &str, key: &str, home: &Path) -> Entry {
    let t = raw.trim();
    let fix = "remove it from settings.yaml (`shellfirm config edit`)";
    if t.is_empty() {
        return Entry::Refuse(format!("sandbox.{key}: an entry is empty; {fix}"));
    }
    if t.contains('$') {
        return Entry::Refuse(format!(
            "sandbox.{key}: `{t}`: environment variables are not expanded; write the path \
             with `~/` or in full, or {fix}"
        ));
    }
    if !(t == "~" || t.starts_with("~/") || t.starts_with('/')) {
        return Entry::Skip(format!(
            "sandbox.{key}: `{t}` is skipped (use a `~/` or absolute path)"
        ));
    }
    let p = lexical(t);
    let home = lexical(&home.display().to_string());
    if p == "/" || path_within(&home, &expand(&p, Path::new(&home))) {
        return Entry::Refuse(format!(
            "sandbox.{key}: `{t}` would cover every file the agent uses; {fix}"
        ));
    }
    Entry::Use(p)
}

/// `sandbox.deny_read` / `deny_write` entries in settings.yaml that
/// `shellfirm sandbox` refuses (it stops until they are fixed).
#[must_use]
pub fn settings_errors(home: &Path, cfg: &SandboxConfig) -> Vec<String> {
    [
        ("deny_read", &cfg.deny_read),
        ("deny_write", &cfg.deny_write),
    ]
    .into_iter()
    .flat_map(|(key, list)| list.iter().map(move |p| user_entry(p, key, home)))
    .filter_map(|e| match e {
        Entry::Refuse(e) => Some(e),
        _ => None,
    })
    .collect()
}

/// Built-in lists + `sandbox.deny_read` / `deny_write`, minus
/// `sandbox.exclude`.
fn sandbox_paths(cfg: &SandboxConfig, env: &SandboxEnv, scope: Scope) -> SandboxPaths {
    let mut out = SandboxPaths::default();
    let excluded: Vec<String> = cfg.exclude.iter().map(|p| norm(p)).collect();
    let home = env.home.as_path();
    let mut add = |list: &mut Vec<String>, p: &str, user: Option<&str>| {
        let p = match user.map(|key| user_entry(p, key, home)) {
            None => norm(p),
            Some(Entry::Use(p)) => p,
            Some(Entry::Skip(w)) => return out.warnings.push(w),
            Some(Entry::Refuse(e)) => return out.errors.push(e),
        };
        if !excluded.contains(&p) && !list.contains(&p) {
            list.push(p);
        }
    };
    // `$CLAUDE_CONFIG_DIR` holds what `~/.claude` would.
    let claude_dir = (env.claude_dir != env.home.join(".claude"))
        .then(|| display_dir(&env.claude_dir, &env.home, scope))
        .flatten();
    let mut read = Vec::new();
    for p in shellfirm::agent::CREDENTIAL_PATHS
        .iter()
        .chain(shellfirm::agent::SECRET_STORE_PATHS)
        .chain(PAAS_CREDENTIAL_PATHS)
    {
        add(&mut read, p, None);
    }
    if let Some(d) = &claude_dir {
        add(&mut read, &format!("{d}/.credentials.json"), None);
    }
    for p in &cfg.deny_read {
        add(&mut read, p, Some("deny_read"));
    }
    let mut write = Vec::new();
    for p in shellfirm::agent::sandbox_write_protected_paths() {
        add(&mut write, &p, None);
    }
    if let Some(d) = &claude_dir {
        add(&mut write, &format!("{d}/settings.json"), None);
        add(&mut write, &format!("{d}/.claude.json"), None);
    }
    if let Some(dir) = display_dir(&env.config_dir, &env.home, scope) {
        add(&mut write, &dir, None);
    }
    for p in &cfg.deny_write {
        add(&mut write, p, Some("deny_write"));
    }
    out.deny_read = read;
    out.deny_write = write;
    out
}

// ---------------------------------------------------------------------------
// Manifest (what shellfirm added to each file)
// ---------------------------------------------------------------------------

#[derive(
    Debug, Clone, Default, PartialEq, Eq, serde_derive::Serialize, serde_derive::Deserialize,
)]
struct Manifest {
    #[serde(default)]
    version: u32,
    /// Settings file (canonical path) → what shellfirm added to it.
    #[serde(default)]
    files: BTreeMap<String, Record>,
}

#[derive(
    Debug, Clone, Default, PartialEq, Eq, serde_derive::Serialize, serde_derive::Deserialize,
)]
#[allow(clippy::struct_excessive_bools)]
struct Record {
    agent: String,
    /// The file did not exist before shellfirm wrote it.
    #[serde(default)]
    created_file: bool,
    /// Deny-read entries shellfirm added (Codex: `"deny"`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    deny_read: Vec<String>,
    /// Deny-write entries shellfirm added (Codex: `"read"`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    deny_write: Vec<String>,
    /// Claude Code: shellfirm set `sandbox.enabled` to `true`.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    set_enabled: bool,
    /// Claude Code: `sandbox.enabled` before that (`None` = not set).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    enabled_before: Option<bool>,
    /// Codex: the permission profile holding the entries.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    profile: Option<String>,
    /// Codex: shellfirm created that profile.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    created_profile: bool,
    /// Codex: shellfirm set `default_permissions`.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    set_default: bool,
    /// Codex: `default_permissions` before that (`None` = not set).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    default_before: Option<String>,
}

fn manifest_path(config_dir: &Path) -> PathBuf {
    config_dir.join(MANIFEST_FILE)
}

fn load_manifest(config_dir: &Path) -> OpResult<Manifest> {
    let path = manifest_path(config_dir);
    match connect::read_regular_string(&path) {
        Ok(text) if text.trim().is_empty() => Ok(Manifest::default()),
        Ok(text) => serde_json::from_str(&text).map_err(|e| {
            format!(
                "could not parse {} ({e}); nothing was changed. Fix or delete it \
                 (it records what `shellfirm sandbox` added, for --remove).",
                path.display()
            )
        }),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Manifest::default()),
        Err(e) => Err(format!("could not read {}: {e}", path.display())),
    }
}

fn save_manifest(config_dir: &Path, manifest: &Manifest) -> OpResult<()> {
    let path = manifest_path(config_dir);
    if manifest.files.is_empty() {
        return match fs::remove_file(&path) {
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => {
                Err(format!("could not remove {}: {e}", path.display()))
            }
            _ => Ok(()),
        };
    }
    fs::create_dir_all(config_dir)
        .map_err(|e| format!("could not create {}: {e}", config_dir.display()))?;
    let mut m = manifest.clone();
    m.version = MANIFEST_VERSION;
    let text = serde_json::to_string_pretty(&m).map_err(|e| e.to_string())? + "\n";
    let tmp = config_dir.join(format!(".{MANIFEST_FILE}.tmp-{}", std::process::id()));
    let res = fs::write(&tmp, text).and_then(|()| fs::rename(&tmp, &path));
    if let Err(e) = res {
        let _ = fs::remove_file(&tmp);
        return Err(format!("could not write {}: {e}", path.display()));
    }
    Ok(())
}

/// Stable key for a settings file, before and after it exists: the
/// deepest existing ancestor is canonicalised (`/var` → `/private/var`).
fn manifest_key(path: &Path) -> String {
    for anc in path.ancestors() {
        if let Ok(canon) = fs::canonicalize(anc) {
            let rest = path.strip_prefix(anc).unwrap_or_else(|_| Path::new(""));
            let full = if rest.as_os_str().is_empty() {
                canon
            } else {
                canon.join(rest)
            };
            return full.display().to_string();
        }
    }
    path.display().to_string()
}

fn push_unique(list: &mut Vec<String>, items: &[String]) {
    for i in items {
        if !list.contains(i) {
            list.push(i.clone());
        }
    }
}

// ---------------------------------------------------------------------------
// Claude Code (settings.json `sandbox`)
// ---------------------------------------------------------------------------

/// A change to one file, computed in memory.
#[derive(Debug, Default)]
struct Change {
    actions: Vec<String>,
    warnings: Vec<String>,
}

fn string_items(arr: &[Value]) -> Vec<String> {
    arr.iter()
        .filter_map(Value::as_str)
        .map(norm)
        .collect::<Vec<_>>()
}

fn list_action(verb: &str, key: &str, items: &[String]) -> String {
    let mut s = format!("{verb} {key} ({}):", items.len());
    for i in items {
        let _ = write!(s, "\n        {i}");
    }
    s
}

/// `a` is `b` or inside it (both normalised, `~` kept as is).
fn path_within(a: &str, b: &str) -> bool {
    a == b || a.strip_prefix(b).is_some_and(|r| r.starts_with('/'))
}

/// `p` with `.` and `..` components and repeated `/` resolved lexically
/// (`~/.ssh/../.aws` is `~/.aws`).
fn lexical(p: &str) -> String {
    let (lead, rest) = if let Some(r) = p.strip_prefix('~') {
        ("~", r)
    } else if let Some(r) = p.strip_prefix('/') {
        ("", r)
    } else {
        return p.to_string();
    };
    let mut parts: Vec<&str> = Vec::new();
    for c in rest.split('/') {
        match c {
            "" | "." => {}
            ".." => {
                parts.pop();
            }
            c => parts.push(c),
        }
    }
    match (lead, parts.is_empty()) {
        ("~", true) => "~".into(),
        (_, true) => "/".into(),
        _ => format!("{lead}/{}", parts.join("/")),
    }
}

/// `p` as an absolute path for comparisons: `~` is `home`.
fn expand(p: &str, home: &Path) -> String {
    let p = lexical(&norm(p));
    let home = home.display().to_string();
    if p == "~" {
        home
    } else if let Some(r) = p.strip_prefix("~/") {
        format!("{}/{r}", home.trim_end_matches('/'))
    } else {
        p
    }
}

/// Settings in one Claude Code settings file that let sandboxed commands
/// past shellfirm's deny rules. Claude Code merges the sandbox lists of
/// every scope, and a narrower allow entry wins over a wider deny, so an
/// `allowRead` / `allowWrite` entry equal to or inside a denied path
/// re-opens it (a wider one, such as `/`, does not).
fn claude_weakening(value: &Value, file: &Path, paths: &SandboxPaths, home: &Path) -> Vec<String> {
    let mut out = Vec::new();
    let sandbox = &value["sandbox"];
    let fs_obj = &sandbox["filesystem"];
    let f = file.display();
    if fs_obj["disabled"].as_bool() == Some(true) {
        out.push(format!(
            "sandbox.filesystem.disabled is true in {f}: filesystem isolation is off, so the \
             deny rules have no effect"
        ));
    }
    for (key, denied) in [
        ("allowRead", &paths.deny_read),
        ("allowWrite", &paths.deny_write),
    ] {
        for a in fs_obj[key]
            .as_array()
            .map(|a| string_items(a))
            .unwrap_or_default()
        {
            let ea = expand(&a, home);
            if let Some(d) = denied.iter().find(|d| path_within(&ea, &expand(d, home))) {
                out.push(format!(
                    "sandbox.filesystem.{key} `{a}` in {f} re-opens `{d}` (a narrower allow \
                     wins over shellfirm's deny)"
                ));
            }
        }
    }
    let excluded = sandbox["excludedCommands"]
        .as_array()
        .map(|a| string_items(a))
        .unwrap_or_default();
    if !excluded.is_empty() {
        out.push(format!(
            "sandbox.excludedCommands in {f} run outside the sandbox, without these deny rules: {}",
            excluded.join(", ")
        ));
    }
    out
}

/// Every Claude Code settings file that applies here, highest precedence
/// first: managed, local, project (when `cwd` is not `home`), user.
fn claude_files(env: &SandboxEnv) -> Vec<PathBuf> {
    let mut files: Vec<PathBuf> = env.claude_managed.iter().cloned().collect();
    if env.cwd != env.home {
        files.push(settings_file(Agent::ClaudeCode, Scope::Local, env));
        files.push(settings_file(Agent::ClaudeCode, Scope::Project, env));
    }
    files.push(settings_file(Agent::ClaudeCode, Scope::User, env));
    files
}

/// [`claude_weakening`] over every scope; `current` is the file being
/// changed, with its new content.
fn claude_weakening_all(
    env: &SandboxEnv,
    paths: &SandboxPaths,
    current: Option<(&Path, &Value)>,
) -> Vec<String> {
    let mut out = Vec::new();
    for f in claude_files(env) {
        let v = match current {
            Some((p, v)) if p == f => Some(v.clone()),
            _ => connect::read_value(&f).ok().flatten(),
        };
        if let Some(v) = v {
            out.extend(claude_weakening(&v, &f, paths, &env.home));
        }
    }
    out
}

/// Claude Code's effective `sandbox.enabled` is the value in the
/// highest-precedence file that sets it: `Some` with that file when it is
/// `false` (and the file is not `own`, whose state is reported anyway).
fn claude_sandbox_off(
    env: &SandboxEnv,
    current: Option<(&Path, &Value)>,
    own: &Path,
) -> Option<String> {
    for f in claude_files(env) {
        let v = match current {
            Some((p, v)) if p == f => Some(v.clone()),
            _ => connect::read_value(&f).ok().flatten(),
        };
        let Some(on) = v.and_then(|v| v["sandbox"]["enabled"].as_bool()) else {
            continue;
        };
        return (!on && f != own).then(|| {
            format!(
                "sandbox.enabled is false in {}, which Claude Code applies over this file: \
                 commands run without the sandbox (remove it or set it to true)",
                f.display()
            )
        });
    }
    None
}

fn claude_install(
    value: &mut Value,
    path: &Path,
    paths: &SandboxPaths,
    record: &mut Record,
) -> OpResult<Change> {
    let mut ch = Change::default();
    let root = connect::root_object(value, path)?;
    let sandbox = connect::child_object(root, "sandbox", path, true)?
        .ok_or_else(|| "internal: sandbox".to_string())?;
    match sandbox.get("enabled") {
        Some(Value::Bool(true)) => {}
        Some(Value::Bool(false)) | None => {
            let before = sandbox.get("enabled").and_then(Value::as_bool);
            if !record.set_enabled {
                record.set_enabled = true;
                record.enabled_before = before;
            }
            sandbox.insert("enabled".into(), Value::Bool(true));
            ch.actions.push(format!(
                "set sandbox.enabled: true{}",
                if before == Some(false) {
                    " (was false)"
                } else {
                    ""
                }
            ));
        }
        Some(_) => {
            return Err(format!(
                "`sandbox.enabled` in {} is not true/false; refusing to modify it",
                path.display()
            ))
        }
    }
    let needs_fs = !paths.deny_read.is_empty() || !paths.deny_write.is_empty();
    let fs_obj = connect::child_object(sandbox, "filesystem", path, needs_fs)?;
    if let Some(fs_obj) = fs_obj {
        for (key, wanted, rec) in [
            ("denyRead", &paths.deny_read, &mut record.deny_read),
            ("denyWrite", &paths.deny_write, &mut record.deny_write),
        ] {
            // Entries shellfirm added earlier that its list no longer has
            // (`sandbox.exclude` changed): take them out.
            let dropped: Vec<String> = rec
                .iter()
                .filter(|p| !wanted.contains(p))
                .cloned()
                .collect();
            if !dropped.is_empty() {
                rec.retain(|p| wanted.contains(p));
                if let Some(Value::Array(arr)) = fs_obj.get_mut(key) {
                    let n = arr.len();
                    arr.retain(|v| v.as_str().map(norm).is_none_or(|s| !dropped.contains(&s)));
                    if arr.len() < n {
                        ch.actions.push(list_action(
                            "remove from",
                            &format!("sandbox.filesystem.{key} (no longer in shellfirm's list)"),
                            &dropped,
                        ));
                    }
                }
            }
            let existing = match fs_obj.get(key) {
                Some(Value::Array(a)) => string_items(a),
                _ => Vec::new(),
            };
            let added: Vec<String> = wanted
                .iter()
                .filter(|p| !existing.contains(p))
                .cloned()
                .collect();
            if added.is_empty() {
                continue;
            }
            let what = format!("sandbox.filesystem.{key}");
            let arr = connect::child_array(fs_obj, key, &what, path, true)?
                .ok_or_else(|| "internal: array".to_string())?;
            arr.extend(added.iter().cloned().map(Value::String));
            push_unique(rec, &added);
            ch.actions.push(list_action("add to", &what, &added));
        }
    }
    Ok(ch)
}

/// Remove shellfirm's entries. Without a record (the manifest was lost),
/// entries equal to today's lists are removed and `sandbox.enabled` is
/// left alone.
fn claude_remove(
    value: &mut Value,
    path: &Path,
    record: Option<&Record>,
    paths: &SandboxPaths,
) -> OpResult<Change> {
    let mut ch = Change::default();
    let Some(root) = value.as_object_mut() else {
        return Err(format!(
            "{} does not contain a JSON object at the top level; refusing to modify it",
            path.display()
        ));
    };
    let Some(sandbox) = connect::child_object(root, "sandbox", path, false)? else {
        return Ok(ch);
    };
    let (read, write) = record.map_or_else(
        || (paths.deny_read.clone(), paths.deny_write.clone()),
        |r| (r.deny_read.clone(), r.deny_write.clone()),
    );
    let mut touched = false;
    if let Some(fs_obj) = connect::child_object(sandbox, "filesystem", path, false)? {
        for (key, ours) in [("denyRead", &read), ("denyWrite", &write)] {
            let what = format!("sandbox.filesystem.{key}");
            let Some(arr) = connect::child_array(fs_obj, key, &what, path, false)? else {
                continue;
            };
            let mut removed = Vec::new();
            arr.retain(|v| {
                let hit = v.as_str().map(norm).filter(|s| ours.contains(s));
                let keep = hit.is_none();
                removed.extend(hit);
                keep
            });
            if removed.is_empty() {
                continue;
            }
            touched = true;
            if arr.is_empty() {
                fs_obj.remove(key);
            }
            ch.actions.push(list_action("remove from", &what, &removed));
        }
        if touched && fs_obj.is_empty() {
            sandbox.remove("filesystem");
        }
    }
    if let Some(r) = record.filter(|r| r.set_enabled) {
        if sandbox.get("enabled") == Some(&Value::Bool(true)) {
            touched = true;
            match r.enabled_before {
                None => {
                    sandbox.remove("enabled");
                    ch.actions
                        .push("remove sandbox.enabled (shellfirm set it)".into());
                }
                Some(b) => {
                    sandbox.insert("enabled".into(), Value::Bool(b));
                    ch.actions.push(format!("set sandbox.enabled back to {b}"));
                }
            }
        }
    }
    if touched && sandbox.is_empty() {
        root.remove("sandbox");
    }
    Ok(ch)
}

/// shellfirm's entries in a Claude Code settings file.
fn claude_state(value: &Value, paths: &SandboxPaths) -> (bool, Vec<String>, Vec<String>) {
    let sandbox = &value["sandbox"];
    let enabled = sandbox["enabled"].as_bool() == Some(true);
    let present = |key: &str, wanted: &[String]| -> Vec<String> {
        let have = sandbox["filesystem"][key]
            .as_array()
            .map(|a| string_items(a))
            .unwrap_or_default();
        wanted
            .iter()
            .filter(|p| have.contains(p))
            .cloned()
            .collect()
    };
    (
        enabled,
        present("denyRead", &paths.deny_read),
        present("denyWrite", &paths.deny_write),
    )
}

// ---------------------------------------------------------------------------
// Codex (config.toml permission profile)
// ---------------------------------------------------------------------------

const CODEX_DENY: &str = "deny";
const CODEX_READ_ONLY: &str = "read";

/// `(path, mode)` pairs for Codex: no access for credential paths,
/// read-only for the write-protected ones.
fn codex_entries(read: &[String], write: &[String]) -> Vec<(String, &'static str)> {
    let mut out: Vec<(String, &'static str)> =
        read.iter().map(|p| (p.clone(), CODEX_DENY)).collect();
    for p in write {
        if !read.contains(p) {
            out.push((p.clone(), CODEX_READ_ONLY));
        }
    }
    out
}

fn parse_toml(content: &str, path: &Path) -> OpResult<toml_edit::DocumentMut> {
    content.parse::<toml_edit::DocumentMut>().map_err(|e| {
        format!(
            "could not parse {} as TOML ({}); nothing was changed. Fix the file or edit it by hand.",
            path.display(),
            e.to_string().trim()
        )
    })
}

fn toml_str<'a>(
    doc: &'a toml_edit::DocumentMut,
    key: &str,
    path: &Path,
) -> OpResult<Option<&'a str>> {
    doc.get(key).map_or(Ok(None), |item| {
        item.as_str().map(Some).ok_or_else(|| {
            format!(
                "`{key}` in {} is not a string; refusing to modify it",
                path.display()
            )
        })
    })
}

fn permissions_table<'a>(
    doc: &'a mut toml_edit::DocumentMut,
    path: &Path,
    create: bool,
) -> OpResult<Option<&'a mut toml_edit::Table>> {
    if doc.get("permissions").is_none() {
        if !create {
            return Ok(None);
        }
        let mut t = toml_edit::Table::new();
        t.set_implicit(true);
        doc.insert("permissions", toml_edit::Item::Table(t));
    }
    doc.get_mut("permissions")
        .and_then(toml_edit::Item::as_table_mut)
        .map(Some)
        .ok_or_else(|| {
            format!(
                "`permissions` in {} is not a table; refusing to modify it",
                path.display()
            )
        })
}

fn sub_table<'a>(
    parent: &'a mut toml_edit::Table,
    key: &str,
    what: &str,
    path: &Path,
    create: bool,
) -> OpResult<Option<&'a mut toml_edit::Table>> {
    if parent.get(key).is_none() {
        if !create {
            return Ok(None);
        }
        parent.insert(key, toml_edit::Item::Table(toml_edit::Table::new()));
    }
    let item = parent
        .get_mut(key)
        .ok_or_else(|| "internal: table".to_string())?;
    // `[permissions] dev = { filesystem = { … } }` is an inline table.
    if let Some(t) = item.as_inline_table_mut() {
        let t = std::mem::take(t);
        *item = toml_edit::Item::Table(t.into_table());
    }
    item.as_table_mut().map(Some).ok_or_else(|| {
        format!(
            "`{what}` in {} is not a table; refusing to modify it",
            path.display()
        )
    })
}

/// Codex runs without a sandbox although no top-level setting says so:
/// the active `profile` sets `sandbox_mode` / `default_permissions` to full
/// access, or the selected permission profile extends
/// `:danger-full-access`. Returns what does it.
fn codex_full_access(doc: &toml_edit::DocumentMut) -> Option<String> {
    let full =
        |v: Option<&toml_edit::Item>, want: &str| v.and_then(toml_edit::Item::as_str) == Some(want);
    let mut selected = doc
        .get("default_permissions")
        .and_then(toml_edit::Item::as_str)
        .map(str::to_string);
    if let Some(name) = doc.get("profile").and_then(toml_edit::Item::as_str) {
        let prof = doc.get("profiles").and_then(|p| p.get(name));
        if full(
            prof.and_then(|p| p.get("sandbox_mode")),
            "danger-full-access",
        ) {
            return Some(format!(
                "the active profile [profiles.{name}] sets sandbox_mode = \"danger-full-access\""
            ));
        }
        if let Some(d) = prof
            .and_then(|p| p.get("default_permissions"))
            .and_then(toml_edit::Item::as_str)
        {
            selected = Some(d.to_string());
        }
    }
    // Follow `extends` through custom profiles (a loop ends the walk).
    let mut name = selected?;
    for _ in 0..16 {
        if name == ":danger-full-access" {
            return Some(
                "the selected permission profile is (or extends) \
                         \":danger-full-access\""
                    .into(),
            );
        }
        if name.starts_with(':') {
            return None;
        }
        name = doc
            .get("permissions")
            .and_then(|p| p.get(&name))
            .and_then(|t| t.get("extends"))
            .and_then(toml_edit::Item::as_str)?
            .to_string();
    }
    None
}

/// Entries in the selected Codex profile that re-open a path shellfirm
/// denies: Codex applies the most specific entry, so a weaker mode on a
/// denied path or inside it wins (a wider entry such as `"/" = "write"`
/// does not). `equal`: also report entries on the same path.
fn codex_weakening(
    doc: &toml_edit::DocumentMut,
    paths: &SandboxPaths,
    home: &Path,
    equal: bool,
) -> Vec<String> {
    doc.get("default_permissions")
        .and_then(toml_edit::Item::as_str)
        .filter(|n| !n.starts_with(':'))
        .map_or_else(Vec::new, |profile| {
            codex_profile_weakening(doc, profile, paths, home, equal, None)
        })
}

/// [`codex_weakening`] for the entries of `profile` in `doc`; `file`: the
/// file to name in the message (a project file, not the user's).
fn codex_profile_weakening(
    doc: &toml_edit::DocumentMut,
    profile: &str,
    paths: &SandboxPaths,
    home: &Path,
    equal: bool,
    file: Option<&Path>,
) -> Vec<String> {
    let mut out = Vec::new();
    let Some(fs_t) = doc
        .get("permissions")
        .and_then(|p| p.get(profile))
        .and_then(|t| t.get("filesystem"))
        .and_then(toml_edit::Item::as_table_like)
    else {
        return out;
    };
    for (k, item) in fs_t.iter() {
        let Some(mode) = item.as_str() else {
            continue;
        };
        let ek = expand(k, home);
        let hit = |list: &[String], weak: bool| {
            list.iter()
                .find(|d| weak && path_within(&ek, &expand(d, home)) && (equal || norm(k) != **d))
                .cloned()
        };
        let reopened = hit(&paths.deny_read, !matches!(mode, CODEX_DENY | "none"))
            .or_else(|| hit(&paths.deny_write, mode == "write"));
        if let Some(d) = reopened {
            out.push(file.map_or_else(
                || {
                    format!(
                        "your entry `\"{k}\" = \"{mode}\"` in [permissions.{profile}.filesystem] \
                         re-opens `{d}` (shellfirm keeps your entries; change it by hand)"
                    )
                },
                |f| {
                    format!(
                        "the entry `\"{k}\" = \"{mode}\"` in [permissions.{profile}.filesystem] \
                         of {} re-opens `{d}` (Codex merges it over the user file when you \
                         trust this project)",
                        f.display()
                    )
                },
            ));
        }
    }
    out
}

/// Entries a project `.codex/config.toml` adds to `profile` (the one
/// holding shellfirm's entries) that re-open a denied path: Codex merges the
/// project file's tables over the user file's.
fn codex_project_weakening(env: &SandboxEnv, profile: &str, paths: &SandboxPaths) -> Vec<String> {
    if env.cwd == env.home {
        return Vec::new();
    }
    let path = env.cwd.join(".codex").join("config.toml");
    connect::read_regular_string(&path)
        .ok()
        .and_then(|t| t.parse::<toml_edit::DocumentMut>().ok())
        .map_or_else(Vec::new, |doc| {
            codex_profile_weakening(&doc, profile, paths, &env.home, true, Some(&path))
        })
}

/// A project `.codex/config.toml` (Codex applies it over the user file for
/// a trusted project) that runs without a sandbox or selects a permission
/// profile other than `profile`, the one holding shellfirm's entries.
fn codex_project_off(env: &SandboxEnv, profile: Option<&str>) -> Option<String> {
    if env.cwd == env.home {
        return None;
    }
    let path = env.cwd.join(".codex").join("config.toml");
    let doc = connect::read_regular_string(&path)
        .ok()?
        .parse::<toml_edit::DocumentMut>()
        .ok()?;
    let why = codex_full_access(&doc)
        .or_else(|| {
            (doc.get("sandbox_mode").and_then(toml_edit::Item::as_str)
                == Some("danger-full-access"))
            .then(|| "sandbox_mode = \"danger-full-access\"".to_string())
        })
        .or_else(|| {
            doc.get("default_permissions")
                .and_then(toml_edit::Item::as_str)
                .filter(|d| Some(*d) != profile)
                .map(|d| format!("default_permissions = \"{d}\" replaces shellfirm's profile"))
        })?;
    Some(format!(
        "{why} in {} (Codex applies it over the user file when you trust this project)",
        path.display()
    ))
}

/// Which profile gets the entries, and whether shellfirm has to create it
/// (with the built-in profile it extends).
fn codex_target(
    doc: &toml_edit::DocumentMut,
    path: &Path,
) -> OpResult<(String, Option<&'static str>)> {
    if let Some(why) = codex_full_access(doc) {
        return Err(format!(
            "Codex is set to run without a sandbox ({why} in {}); shellfirm does not change \
             that. Choose a sandboxed mode or profile first, then re-run.",
            path.display()
        ));
    }
    let builtin = |name: &str| -> OpResult<&'static str> {
        match name {
            ":workspace" => Ok(":workspace"),
            ":read-only" => Ok(":read-only"),
            ":danger-full-access" => Err(format!(
                "Codex is set to run without a sandbox (default_permissions = \
                 \":danger-full-access\" in {}); shellfirm does not change that. Choose \
                 :workspace or :read-only first, then re-run.",
                path.display()
            )),
            other => Err(format!(
                "default_permissions = \"{other}\" in {} is not a built-in Codex profile \
                 shellfirm knows; refusing to modify it",
                path.display()
            )),
        }
    };
    if let Some(name) = toml_str(doc, "default_permissions", path)? {
        if name.starts_with(':') {
            return Ok((CODEX_PROFILE.into(), Some(builtin(name)?)));
        }
        let exists = doc
            .get("permissions")
            .and_then(|p| p.get(name))
            .is_some_and(toml_edit::Item::is_table_like);
        if !exists {
            return Err(format!(
                "default_permissions = \"{name}\" in {} names no [permissions.{name}] profile; \
                 fix the file first",
                path.display()
            ));
        }
        return Ok((name.to_string(), None));
    }
    let base = match toml_str(doc, "sandbox_mode", path)? {
        Some("read-only") => ":read-only",
        Some("workspace-write") | None => {
            let custom = doc
                .get("sandbox_workspace_write")
                .and_then(toml_edit::Item::as_table_like)
                .is_some_and(|t| !t.is_empty());
            if custom {
                return Err(format!(
                    "{} has [sandbox_workspace_write] settings, which Codex ignores once a \
                     permission profile is selected. Move them into a [permissions.<name>] \
                     profile (workspace_roots, network) with default_permissions = \"<name>\", \
                     then re-run: shellfirm adds its entries to that profile.",
                    path.display()
                ));
            }
            ":workspace"
        }
        Some("danger-full-access") => {
            return Err(format!(
                "Codex is set to run without a sandbox (sandbox_mode = \"danger-full-access\" \
                 in {}); shellfirm does not change that. Choose workspace-write or read-only \
                 first, then re-run.",
                path.display()
            ))
        }
        Some(other) => {
            return Err(format!(
                "sandbox_mode = \"{other}\" in {} is not a Codex sandbox mode shellfirm knows; \
                 refusing to modify it",
                path.display()
            ))
        }
    };
    if doc
        .get("permissions")
        .and_then(|p| p.get(CODEX_PROFILE))
        .is_some()
    {
        return Err(format!(
            "{} already has a [permissions.{CODEX_PROFILE}] profile that is not selected; \
             set default_permissions = \"{CODEX_PROFILE}\" to use it, or rename it",
            path.display()
        ));
    }
    Ok((CODEX_PROFILE.into(), Some(base)))
}

#[allow(clippy::too_many_lines)]
fn codex_install(
    doc: &mut toml_edit::DocumentMut,
    path: &Path,
    paths: &SandboxPaths,
    record: &mut Record,
) -> OpResult<Change> {
    let mut ch = Change::default();
    let (profile, create) = codex_target(doc, path)?;
    if let Some(base) = create {
        let before = toml_str(doc, "default_permissions", path)?.map(str::to_string);
        let perms = permissions_table(doc, path, true)?
            .ok_or_else(|| "internal: permissions".to_string())?;
        let mut t = toml_edit::Table::new();
        t.insert("description", toml_edit::value(CODEX_PROFILE_DESCRIPTION));
        t.insert("extends", toml_edit::value(base));
        perms.insert(&profile, toml_edit::Item::Table(t));
        record.created_profile = true;
        ch.actions.push(format!(
            "add permission profile [permissions.{profile}] (extends = \"{base}\")"
        ));
        doc.insert("default_permissions", toml_edit::value(profile.as_str()));
        if !record.set_default {
            record.set_default = true;
            record.default_before.clone_from(&before);
        }
        ch.actions.push(format!(
            "set default_permissions = \"{profile}\"{}",
            before.map_or_else(String::new, |b| format!(" (was \"{b}\")"))
        ));
        if base == ":workspace" && toml_str(doc, "sandbox_mode", path)?.is_none() {
            ch.warnings.push(
                "Codex picks :read-only for a project you have not marked trusted or \
                 untrusted; with this profile such projects use :workspace (write access to \
                 the project) like trusted ones. Set extends = \":read-only\" in the profile \
                 to keep them read-only everywhere."
                    .into(),
            );
        }
    }
    record.profile = Some(profile.clone());
    let perms =
        permissions_table(doc, path, true)?.ok_or_else(|| "internal: permissions".to_string())?;
    let prof = sub_table(
        perms,
        &profile,
        &format!("permissions.{profile}"),
        path,
        false,
    )?
    .ok_or_else(|| format!("[permissions.{profile}] is missing in {}", path.display()))?;
    let what = format!("permissions.{profile}.filesystem");
    let fs_t = sub_table(prof, "filesystem", &what, path, true)?
        .ok_or_else(|| "internal: filesystem".to_string())?;
    // Entries shellfirm added earlier that its lists no longer have
    // (`sandbox.exclude` changed): take them out.
    let mut dropped = Vec::new();
    for (p, mode) in codex_entries(&record.deny_read, &record.deny_write) {
        let still = if mode == CODEX_DENY {
            paths.deny_read.contains(&p)
        } else {
            paths.deny_write.contains(&p)
        };
        if !still && fs_t.get(&p).and_then(toml_edit::Item::as_str) == Some(mode) {
            fs_t.remove(&p);
            dropped.push(p);
        }
    }
    record.deny_read.retain(|p| paths.deny_read.contains(p));
    record.deny_write.retain(|p| paths.deny_write.contains(p));
    if !dropped.is_empty() {
        ch.actions.push(list_action(
            "remove from",
            &format!("[{what}] (no longer in shellfirm's list)"),
            &dropped,
        ));
    }
    let mut added_read = Vec::new();
    let mut added_write = Vec::new();
    for (p, mode) in codex_entries(&paths.deny_read, &paths.deny_write) {
        match fs_t.get(&p) {
            None => {
                fs_t.insert(&p, toml_edit::value(mode));
                if mode == CODEX_DENY {
                    added_read.push(p);
                } else {
                    added_write.push(p);
                }
            }
            Some(item) => {
                let have = item.as_str();
                // "none" is Codex's older spelling of "deny".
                let strong_enough = have == Some(mode)
                    || matches!(have, Some(CODEX_DENY | "none"))
                    || (mode == CODEX_READ_ONLY && have == Some(CODEX_READ_ONLY));
                if !strong_enough {
                    ch.warnings.push(format!(
                        "kept your entry `\"{p}\" = {}` in [{what}] (shellfirm would write \"{mode}\")",
                        item.to_string().trim()
                    ));
                }
            }
        }
    }
    if fs_t.is_empty() {
        prof.remove("filesystem");
    }
    if !added_read.is_empty() {
        ch.actions.push(list_action(
            "add to",
            &format!("[{what}] as \"deny\""),
            &added_read,
        ));
    }
    if !added_write.is_empty() {
        ch.actions.push(list_action(
            "add to",
            &format!("[{what}] as \"read\""),
            &added_write,
        ));
    }
    push_unique(&mut record.deny_read, &added_read);
    push_unique(&mut record.deny_write, &added_write);
    Ok(ch)
}

#[allow(clippy::too_many_lines)]
fn codex_remove(
    doc: &mut toml_edit::DocumentMut,
    path: &Path,
    record: Option<&Record>,
    paths: &SandboxPaths,
) -> OpResult<Change> {
    let mut ch = Change::default();
    // Without a record: shellfirm's own profile is recognised by its
    // description; entries elsewhere are removed when they equal today's.
    let fallback;
    let record = if let Some(r) = record {
        r
    } else {
        let ours = doc
            .get("permissions")
            .and_then(|p| p.get(CODEX_PROFILE))
            .and_then(|t| t.get("description"))
            .and_then(toml_edit::Item::as_str)
            == Some(CODEX_PROFILE_DESCRIPTION);
        let profile = if ours {
            Some(CODEX_PROFILE.to_string())
        } else {
            toml_str(doc, "default_permissions", path)?
                .filter(|n| !n.starts_with(':'))
                .map(str::to_string)
        };
        fallback = Record {
            agent: Agent::Codex.cli_name().into(),
            deny_read: paths.deny_read.clone(),
            deny_write: paths.deny_write.clone(),
            profile,
            created_profile: ours,
            set_default: ours,
            ..Record::default()
        };
        &fallback
    };
    let Some(profile) = record.profile.clone() else {
        return Ok(ch);
    };
    let what = format!("permissions.{profile}.filesystem");
    let mut profile_gone = false;
    if let Some(perms) = permissions_table(doc, path, false)? {
        if let Some(prof) = sub_table(
            perms,
            &profile,
            &format!("permissions.{profile}"),
            path,
            false,
        )? {
            if let Some(fs_t) = sub_table(prof, "filesystem", &what, path, false)? {
                let mut removed_read = Vec::new();
                let mut removed_write = Vec::new();
                for (p, mode) in codex_entries(&record.deny_read, &record.deny_write) {
                    if fs_t.get(&p).and_then(toml_edit::Item::as_str) == Some(mode) {
                        fs_t.remove(&p);
                        if mode == CODEX_DENY {
                            removed_read.push(p);
                        } else {
                            removed_write.push(p);
                        }
                    }
                }
                let removed_any = !removed_read.is_empty() || !removed_write.is_empty();
                if !removed_read.is_empty() {
                    ch.actions.push(list_action(
                        "remove from",
                        &format!("[{what}]"),
                        &removed_read,
                    ));
                }
                if !removed_write.is_empty() {
                    ch.actions.push(list_action(
                        "remove from",
                        &format!("[{what}]"),
                        &removed_write,
                    ));
                }
                if removed_any && fs_t.is_empty() {
                    prof.remove("filesystem");
                }
            }
            if record.created_profile {
                let only_ours = prof.iter().all(|(k, v)| match k {
                    "description" => v.as_str() == Some(CODEX_PROFILE_DESCRIPTION),
                    "extends" => true,
                    _ => false,
                });
                if only_ours {
                    perms.remove(&profile);
                    profile_gone = true;
                    ch.actions
                        .push(format!("remove permission profile [permissions.{profile}]"));
                } else {
                    ch.warnings.push(format!(
                        "kept [permissions.{profile}]: it has settings shellfirm did not add"
                    ));
                }
            }
        }
        if perms.is_empty() {
            doc.remove("permissions");
        }
    }
    if record.set_default
        && toml_str(doc, "default_permissions", path)? == Some(profile.as_str())
        && (profile_gone || record.default_before.is_some())
    {
        match &record.default_before {
            None => {
                doc.remove("default_permissions");
                ch.actions
                    .push("remove default_permissions (shellfirm set it)".into());
            }
            Some(b) => {
                doc.insert("default_permissions", toml_edit::value(b.as_str()));
                ch.actions
                    .push(format!("set default_permissions back to \"{b}\""));
            }
        }
    }
    Ok(ch)
}

/// `(selected, read entries present, write entries present)` for Codex.
fn codex_state(
    doc: &toml_edit::DocumentMut,
    paths: &SandboxPaths,
) -> (Option<String>, Vec<String>, Vec<String>) {
    let Some(profile) = doc
        .get("default_permissions")
        .and_then(toml_edit::Item::as_str)
        .filter(|n| !n.starts_with(':'))
    else {
        return (None, Vec::new(), Vec::new());
    };
    let fs_t = doc
        .get("permissions")
        .and_then(|p| p.get(profile))
        .and_then(|t| t.get("filesystem"));
    let mode_of = |p: &str| {
        fs_t.and_then(|t| t.get(p))
            .and_then(toml_edit::Item::as_str)
    };
    let read = paths
        .deny_read
        .iter()
        .filter(|p| matches!(mode_of(p), Some(CODEX_DENY | "none")))
        .cloned()
        .collect();
    let write = paths
        .deny_write
        .iter()
        .filter(|p| matches!(mode_of(p), Some(CODEX_DENY | "none" | CODEX_READ_ONLY)))
        .cloned()
        .collect();
    (Some(profile.to_string()), read, write)
}

// ---------------------------------------------------------------------------
// Run
// ---------------------------------------------------------------------------

/// A file as loaded for the run, in its own format.
enum Doc {
    Json(Value),
    Toml(toml_edit::DocumentMut),
}

impl Doc {
    fn render(&self) -> OpResult<String> {
        match self {
            Self::Json(v) => Ok(serde_json::to_string_pretty(v).map_err(|e| e.to_string())? + "\n"),
            Self::Toml(d) => Ok(d.to_string()),
        }
    }

    fn is_empty(&self) -> bool {
        match self {
            Self::Json(v) => v.as_object().is_some_and(Map::is_empty),
            Self::Toml(d) => d.as_table().is_empty() && d.to_string().trim().is_empty(),
        }
    }
}

fn load(agent: Agent, path: &Path) -> OpResult<(LoadedFile, Doc)> {
    match agent {
        Agent::ClaudeCode => {
            let f = connect::load_file(path)?;
            let v = f.value.clone();
            Ok((f, Doc::Json(v)))
        }
        Agent::Codex => {
            let (file, doc) = match connect::read_text(path)? {
                None => (
                    LoadedFile {
                        path: path.to_path_buf(),
                        write_path: path.to_path_buf(),
                        exists: false,
                        value: json!({}),
                        lossy_format: false,
                    },
                    toml_edit::DocumentMut::new(),
                ),
                Some((write_path, text)) => (
                    LoadedFile {
                        path: path.to_path_buf(),
                        write_path,
                        exists: true,
                        value: json!({}),
                        lossy_format: false,
                    },
                    parse_toml(text.strip_prefix('\u{feff}').unwrap_or(&text), path)?,
                ),
            };
            Ok((file, Doc::Toml(doc)))
        }
    }
}

#[allow(clippy::too_many_lines)]
fn execute(
    agent: Agent,
    opts: Options,
    env: &SandboxEnv,
    cfg: &SandboxConfig,
    out: &mut String,
) -> OpResult<()> {
    let _ = writeln!(
        out,
        "\nshellfirm {} {} {} sandbox{}{}\n",
        shellfirm::config::glyph("—", "-"),
        if opts.remove {
            "removing from"
        } else {
            "configuring"
        },
        agent.display_name(),
        if agent == Agent::ClaudeCode {
            format!(" ({} scope)", opts.scope.name())
        } else {
            String::new()
        },
        if opts.dry_run { " (dry run)" } else { "" }
    );
    if agent == Agent::Codex && opts.scope != Scope::User {
        return Err("Codex CLI: only --scope user is supported (~/.codex/config.toml)".into());
    }
    let paths = sandbox_paths(cfg, env, opts.scope);
    for w in &paths.warnings {
        let _ = writeln!(out, "  ! {w}");
    }
    if !paths.errors.is_empty() {
        return Err(paths.errors.join("\n"));
    }

    let path = settings_file(agent, opts.scope, env);
    if opts.scope != Scope::User {
        if let Some((link, target)) = connect::symlink_out_of(&path, &env.cwd) {
            return Err(connect::symlink_refusal(
                &path,
                &link,
                &target,
                opts.scope.name(),
            ));
        }
    }
    let mut manifest = load_manifest(&env.config_dir)?;
    let (file, doc) = load(agent, &path)?;
    let key = manifest_key(&file.write_path);
    let existing = manifest.files.get(&key).cloned();

    let mut doc = doc;
    let mut record = existing.clone().unwrap_or_else(|| Record {
        agent: agent.cli_name().into(),
        created_file: !file.exists,
        ..Record::default()
    });
    let change = match (&mut doc, opts.remove) {
        (Doc::Json(v), false) => claude_install(v, &path, &paths, &mut record)?,
        (Doc::Json(v), true) => claude_remove(v, &path, existing.as_ref(), &paths)?,
        (Doc::Toml(d), false) => codex_install(d, &path, &paths, &mut record)?,
        (Doc::Toml(d), true) => codex_remove(d, &path, existing.as_ref(), &paths)?,
    };
    let mut warnings = change.warnings;
    if !opts.remove {
        // Settings (in this file or another scope) that undo the denies.
        match &doc {
            Doc::Json(v) => {
                warnings.extend(claude_sandbox_off(env, Some((&path, v)), &path));
                warnings.extend(claude_weakening_all(env, &paths, Some((&path, v))));
            }
            Doc::Toml(d) => {
                warnings.extend(codex_project_off(env, record.profile.as_deref()));
                warnings.extend(codex_weakening(d, &paths, &env.home, false));
                if let Some(p) = record.profile.as_deref() {
                    warnings.extend(codex_project_weakening(env, p, &paths));
                }
            }
        }
    }
    for w in &warnings {
        let _ = writeln!(out, "  ! {w}");
    }
    if opts.remove && existing.is_none() && !change.actions.is_empty() {
        let _ = writeln!(
            out,
            "  ! no record of what shellfirm added to {} ({} is missing it): removing the \
             entries that match shellfirm's current lists",
            path.display(),
            manifest_path(&env.config_dir).display()
        );
    }

    if change.actions.is_empty() {
        let _ = writeln!(
            out,
            "\nNothing to change: {}",
            if opts.remove {
                format!("no shellfirm sandbox entries in {}.", path.display())
            } else {
                format!(
                    "{} already has shellfirm's sandbox settings in {}.",
                    agent.display_name(),
                    path.display()
                )
            }
        );
        if opts.remove && existing.is_some() && !opts.dry_run {
            manifest.files.remove(&key);
            save_manifest(&env.config_dir, &manifest)?;
        }
        return Ok(());
    }

    let delete = opts.remove
        && doc.is_empty()
        && existing.as_ref().is_none_or(|r| r.created_file)
        && !fs::symlink_metadata(&path).is_ok_and(|m| m.file_type().is_symlink());
    let mut actions = change.actions;
    if delete {
        actions.push("delete the file (only shellfirm's entries were in it)".into());
    }
    // The change list is shown once the file is written (or for a dry
    // run): a failed write shows only the error.
    let mut block = String::new();
    if opts.dry_run {
        let _ = writeln!(
            block,
            "  Would {} {}:",
            if file.exists { "update" } else { "create" },
            path.display()
        );
    } else {
        let _ = writeln!(block, "  {}:", path.display());
    }
    if file.lossy_format {
        let _ = writeln!(
            block,
            "    ! this file contains comments or trailing commas, which will not be kept (a backup is made first)"
        );
    }
    for a in &actions {
        let _ = writeln!(block, "    - {a}");
    }
    let backup_dir = env.backup_dir.as_deref();
    if opts.dry_run {
        if file.exists {
            let _ = writeln!(
                block,
                "    (a timestamped backup would be written first{})",
                backup_dir.map_or_else(String::new, |d| format!(" to {}", d.display()))
            );
        }
        out.push_str(&block);
        out.push_str("\nDry run: no changes were made. Run without --dry-run to apply.\n");
        return Ok(());
    }

    let text = doc.render()?;
    let mode = if delete {
        SaveMode::Remove
    } else {
        SaveMode::Write
    };
    // The record is saved first: when it cannot be written, the file is
    // left as it was (`--remove` must find what shellfirm added), and a
    // failed file write puts the old record back.
    let before = manifest.clone();
    if opts.remove {
        manifest.files.remove(&key);
    } else {
        manifest.files.insert(key, record);
    }
    save_manifest(&env.config_dir, &manifest)
        .map_err(|e| format!("{e}; {} was not changed", path.display()))?;
    let backup = match connect::save_text(&file, &text, backup_dir, mode) {
        Ok(b) => b,
        Err(e) => {
            let _ = save_manifest(&env.config_dir, &before);
            return Err(e);
        }
    };
    out.push_str(&block);
    if delete && opts.scope != Scope::User {
        // `.claude` that shellfirm emptied.
        connect::remove_empty_parents(&path, &env.cwd);
    }
    let _ = writeln!(
        out,
        "    ✓ {}{}",
        if delete { "removed" } else { "written" },
        backup.map_or_else(String::new, |b| format!(" (backup: {})", b.display()))
    );

    out.push('\n');
    if opts.remove {
        let _ = writeln!(
            out,
            "shellfirm's sandbox entries removed from {}.",
            agent.display_name()
        );
        return Ok(());
    }
    let n_read = paths.deny_read.len();
    let n_write = paths.deny_write.len();
    if opts.scope == Scope::Local && !file.exists {
        let _ = writeln!(
            out,
            "{} is yours only: keep it out of git (add `.claude/settings.local.json` to \
             .gitignore). Claude Code ignores it for you only when Claude Code creates it.\n",
            path.display()
        );
    }
    match agent {
        Agent::ClaudeCode => {
            let _ = writeln!(
                out,
                "Claude Code now runs Bash commands in its sandbox: they (and every process \
                 they start) cannot read the {n_read} credential paths or write the {n_write} \
                 startup/settings paths above. Restart running Claude Code sessions.\n\
                 - macOS uses Seatbelt (built in); Linux and WSL2 need bubblewrap and socat \
                 installed. Where the sandbox cannot start, Claude Code runs commands without \
                 it unless sandbox.failIfUnavailable is true.\n\
                 - A command that fails in the sandbox may be retried outside it; that retry \
                 goes through your permission prompt and shellfirm's hook. \
                 sandbox.allowUnsandboxedCommands: false forbids it.\n\
                 - The sandbox does not cover Claude Code's Read tool: the Read hook from \
                 `shellfirm connect claude-code` asks before it opens a credential file.\n\
                 - Change the lists with sandbox.deny_read / deny_write / exclude in \
                 shellfirm's settings.yaml, then re-run this command."
            );
        }
        Agent::Codex => {
            let _ = writeln!(
                out,
                "Codex commands now run with a permission profile that denies the {n_read} \
                 credential paths and makes the {n_write} startup/settings paths read-only. \
                 Restart running Codex sessions. A `--sandbox` or \
                 `--dangerously-bypass-approvals-and-sandbox` flag replaces the profile for \
                 that run.\n\
                 - Change the lists with sandbox.deny_read / deny_write / exclude in \
                 shellfirm's settings.yaml, then re-run this command."
            );
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Status (`shellfirm status`, `shellfirm doctor`)
// ---------------------------------------------------------------------------

/// shellfirm's sandbox entries in one agent settings file.
#[derive(Debug, Clone, PartialEq, Eq, serde_derive::Serialize)]
pub struct SandboxStatus {
    /// `claude-code` or `codex`.
    pub tool: &'static str,
    /// `user`, `project` or `local`.
    pub scope: &'static str,
    pub file: String,
    /// The sandbox is on (Claude Code `sandbox.enabled`; Codex: a custom
    /// permission profile is selected).
    pub enabled: bool,
    /// Codex: the selected permission profile.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub profile: Option<String>,
    pub deny_read: usize,
    pub deny_read_expected: usize,
    pub deny_write: usize,
    pub deny_write_expected: usize,
    /// `sandbox.json` records shellfirm's changes to this file.
    pub recorded: bool,
    /// Expected entries that are not in the file at all (re-running
    /// `shellfirm sandbox` adds them).
    pub missing: usize,
    /// Settings that undo the deny rules (this file or another scope);
    /// shellfirm keeps them, so re-running does not change them.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub weakened: Vec<String>,
    /// The sandbox is off although this file turns it on: another file
    /// the agent applies over it says so.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub off: Option<String>,
    /// `sandbox.deny_read` / `deny_write` entries in settings.yaml that
    /// `shellfirm sandbox` refuses (fix them before re-running).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub settings_errors: Vec<String>,
    /// The file could not be read or parsed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl SandboxStatus {
    /// On, with every expected entry present.
    #[must_use]
    pub const fn complete(&self) -> bool {
        self.enabled
            && self.error.is_none()
            && self.weakened.is_empty()
            && self.settings_errors.is_empty()
            && self.deny_read == self.deny_read_expected
            && self.deny_write == self.deny_write_expected
    }

    /// One line for `status` / `doctor`.
    #[must_use]
    pub fn line(&self) -> String {
        let mut s = format!(
            "{} ({}): sandbox {}, read denies {}/{}, write denies {}/{}",
            self.tool,
            self.scope,
            if self.enabled { "on" } else { "off" },
            self.deny_read,
            self.deny_read_expected,
            self.deny_write,
            self.deny_write_expected
        );
        if let Some(e) = &self.error {
            let _ = write!(s, " (error: {e})");
            return s;
        }
        if let Some(o) = &self.off {
            let _ = write!(s, " ({o})");
        }
        for w in &self.weakened {
            let _ = write!(s, " (weakened: {w})");
        }
        if !self.settings_errors.is_empty() {
            let _ = write!(
                s,
                " (refused in settings.yaml: {}; then re-run `shellfirm sandbox {}`)",
                self.settings_errors.join("; "),
                self.tool
            );
        } else if (!self.enabled && self.off.is_none()) || self.missing > 0 {
            let scope = if self.tool == "codex" {
                String::new()
            } else {
                format!(" --scope {}", self.scope)
            };
            let _ = write!(s, " (re-run `shellfirm sandbox {}{scope}`)", self.tool);
        }
        s
    }
}

/// shellfirm's sandbox entries in every agent settings file it knows
/// (project and local scope too when `cwd` is not `home`). Files without
/// any of them are left out.
#[must_use]
pub fn sandbox_status(
    home: &Path,
    cwd: &Path,
    config_dir: &Path,
    cfg: &SandboxConfig,
) -> Vec<SandboxStatus> {
    let env = SandboxEnv {
        home: home.to_path_buf(),
        cwd: cwd.to_path_buf(),
        config_dir: config_dir.to_path_buf(),
        codex_home: codex_home(home),
        claude_dir: connect::claude_user_dir(home),
        claude_managed: Some(connect::claude_managed_settings()),
        backup_dir: None,
    };
    sandbox_status_in(&env, cfg)
}

fn sandbox_status_in(env: &SandboxEnv, cfg: &SandboxConfig) -> Vec<SandboxStatus> {
    let (home, cwd, config_dir) = (&env.home, &env.cwd, &env.config_dir);
    let manifest = load_manifest(config_dir).unwrap_or_default();
    let mut rows = Vec::new();
    let mut targets = vec![(Agent::ClaudeCode, Scope::User)];
    if cwd != home {
        targets.push((Agent::ClaudeCode, Scope::Project));
        targets.push((Agent::ClaudeCode, Scope::Local));
    }
    targets.push((Agent::Codex, Scope::User));
    for (agent, scope) in targets {
        let path = settings_file(agent, scope, env);
        let outside = (scope != Scope::User)
            .then(|| connect::symlink_out_of(&path, cwd))
            .flatten();
        // An unreadable folder on the path is reported, not skipped.
        if matches!(path.try_exists(), Ok(false)) && outside.is_none() {
            continue;
        }
        let paths = sandbox_paths(cfg, env, scope);
        let recorded = manifest.files.contains_key(&manifest_key(&path));
        let mut row = SandboxStatus {
            tool: agent.cli_name(),
            scope: scope.name(),
            file: path.display().to_string(),
            enabled: false,
            profile: None,
            deny_read: 0,
            deny_read_expected: paths.deny_read.len(),
            deny_write: 0,
            deny_write_expected: paths.deny_write.len(),
            recorded,
            missing: 0,
            weakened: Vec::new(),
            off: None,
            settings_errors: paths.errors.clone(),
            error: None,
        };
        if let Some((link, target)) = outside {
            row.error = Some(connect::symlink_refusal(
                &path,
                &link,
                &target,
                scope.name(),
            ));
            rows.push(row);
            continue;
        }
        match agent {
            Agent::ClaudeCode => match connect::read_value(&path) {
                Ok(v) => {
                    let (enabled, r, w) = claude_state(&v.unwrap_or_else(|| json!({})), &paths);
                    row.enabled = enabled;
                    row.deny_read = r.len();
                    row.deny_write = w.len();
                    row.missing =
                        paths.deny_read.len() + paths.deny_write.len() - r.len() - w.len();
                    row.weakened = claude_weakening_all(env, &paths, None);
                    row.off = claude_sandbox_off(env, None, &path);
                }
                Err(e) => row.error = Some(e),
            },
            Agent::Codex => match connect::read_regular_string(&path)
                .map_err(|e| format!("can't read {}: {e}", path.display()))
                .and_then(|t| parse_toml(&t, &path))
            {
                Ok(d) => {
                    let (profile, r, w) = codex_state(&d, &paths);
                    row.off = codex_project_off(env, profile.as_deref());
                    row.enabled = profile.is_some();
                    row.profile = profile;
                    row.deny_read = r.len();
                    row.deny_write = w.len();
                    row.missing = codex_entries(&paths.deny_read, &paths.deny_write)
                        .iter()
                        .filter(|(p, _)| !codex_has_key(&d, p))
                        .count();
                    row.weakened = codex_weakening(&d, &paths, home, true);
                    if let Some(p) = row.profile.as_deref() {
                        row.weakened.extend(codex_project_weakening(env, p, &paths));
                    }
                    if let Some(why) = codex_full_access(&d) {
                        row.weakened
                            .push(format!("Codex runs without a sandbox: {why}"));
                    }
                }
                Err(e) => row.error = Some(e),
            },
        }
        if row.off.is_some() {
            row.enabled = false;
        }
        if row.recorded || row.deny_read > 0 || row.deny_write > 0 || row.error.is_some() {
            rows.push(row);
        }
    }
    rows
}

/// The selected Codex profile has an entry for `p` (any mode).
fn codex_has_key(doc: &toml_edit::DocumentMut, p: &str) -> bool {
    doc.get("default_permissions")
        .and_then(toml_edit::Item::as_str)
        .and_then(|n| doc.get("permissions")?.get(n)?.get("filesystem")?.get(p))
        .is_some()
}

fn codex_home(home: &Path) -> PathBuf {
    std::env::var_os("CODEX_HOME")
        .filter(|v| !v.is_empty())
        .map_or_else(|| home.join(".codex"), PathBuf::from)
}

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

const SUPPORTED: &str = "claude-code, codex";

pub fn command() -> Command {
    Command::new("sandbox")
        .about("Turn on an AI agent's OS sandbox and deny it your credential files")
        .long_about(
            "Turn on an AI agent's own OS sandbox and deny it the credential files shellfirm \
             protects.\n\n\
             shellfirm's hooks judge the text of a command; a script or child process that \
             opens ~/.ssh/id_rsa at runtime never shows up in that text. The agent's sandbox \
             enforces file access for every process a command starts, so shellfirm writes \
             deny rules into it as a backstop: no reads of SSH/GPG keys, cloud and registry \
             credentials, token files and keychains; no writes to shell startup files, SSH \
             and git config, autostart entries, AI-agent settings and shellfirm's own \
             configuration.\n\n\
             claude-code  settings.json `sandbox`: enabled, filesystem.denyRead, \
             filesystem.denyWrite\n\
             \x20            --scope user (~/.claude/settings.json, default), project \
             (.claude/settings.json, shared), local (.claude/settings.local.json)\n\
             codex        ~/.codex/config.toml: a `shellfirm` permission profile extending \
             the built-in one (or your own selected profile gets the entries), \"deny\" for \
             credential paths and \"read\" for protected ones\n\n\
             Existing settings are kept and merged; nothing is weakened. What shellfirm adds \
             is recorded in sandbox.json in its configuration directory, so --remove takes \
             out exactly that. See the paths with --list; change them with sandbox.deny_read, \
             sandbox.deny_write and sandbox.exclude in settings.yaml.",
        )
        .arg(super::config_dir_arg())
        .arg(
            Arg::new("agent")
                .help("AI agent: claude-code, codex (see --list)")
                .value_parser([
                    "claude-code",
                    "codex",
                    "gemini-cli",
                    "gemini",
                    "copilot-cli",
                    "copilot",
                    "qwen",
                    "cursor",
                    "windsurf",
                    "cline",
                    "opencode",
                    "zed",
                ])
                .required_unless_present("list"),
        )
        .arg(
            Arg::new("list")
                .long("list")
                .help("Show which agents are supported and the paths that would be denied")
                .action(ArgAction::SetTrue)
                .conflicts_with_all(["remove", "dry-run", "scope"]),
        )
        .arg(
            Arg::new("scope")
                .long("scope")
                .help("Claude Code: user (default), project (shared .claude/settings.json) or local (.claude/settings.local.json)")
                .value_parser(["user", "project", "local"]),
        )
        .arg(
            Arg::new("dry-run")
                .long("dry-run")
                .help("Show what would change without writing anything")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("remove")
                .long("remove")
                .visible_alias("uninstall")
                .help("Remove the entries shellfirm added (only those; other settings are kept)")
                .action(ArgAction::SetTrue),
        )
}

fn list_text(paths: &SandboxPaths) -> String {
    let mut out = String::from("AI agents `shellfirm sandbox` can configure:\n\n");
    for a in AGENTS {
        let _ = writeln!(
            out,
            "  {:<12} {}{}\n      {}\n",
            a.name,
            a.display,
            if a.supported { " (supported)" } else { "" },
            a.detail
        );
    }
    let _ = writeln!(
        out,
        "Paths sandboxed commands may not read ({}):",
        paths.deny_read.len()
    );
    for p in &paths.deny_read {
        let _ = writeln!(out, "  {p}");
    }
    let _ = writeln!(
        out,
        "\nPaths sandboxed commands may not write ({}):",
        paths.deny_write.len()
    );
    for p in &paths.deny_write {
        let _ = writeln!(out, "  {p}");
    }
    for w in &paths.warnings {
        let _ = writeln!(out, "\n! {w}");
    }
    out.push_str(
        "\nChange the lists in settings.yaml: sandbox.deny_read and sandbox.deny_write add \
         paths, sandbox.exclude leaves built-in entries out. Project .env files are not \
         listed (their reads are not flagged); add them with sandbox.deny_read if you want.",
    );
    out
}

pub fn run(matches: &ArgMatches, config: &shellfirm::Config) -> Result<shellfirm::CmdExit> {
    let exit = |code: i32, message: String| {
        Ok(shellfirm::CmdExit {
            code,
            message: Some(message),
        })
    };
    let Some(home) = dirs::home_dir() else {
        return exit(1, "Could not determine your home directory".into());
    };
    let (settings, settings_error) = config.load_settings_lenient();
    if let Some(e) = settings_error {
        return exit(
            1,
            format!(
                "Error: {e}\nFix it with `shellfirm config edit` first: the sandbox lists \
                 come from it."
            ),
        );
    }
    let scope = match matches.get_one::<String>("scope").map(String::as_str) {
        Some("project") => Scope::Project,
        Some("local") => Scope::Local,
        _ => Scope::User,
    };
    let env = SandboxEnv {
        codex_home: codex_home(&home),
        claude_dir: connect::claude_user_dir(&home),
        claude_managed: Some(connect::claude_managed_settings()),
        home,
        cwd: std::env::current_dir().unwrap_or_default(),
        config_dir: config.root_folder.clone(),
        backup_dir: (scope != Scope::User)
            .then(|| dirs::cache_dir().map(|d| d.join("shellfirm").join("backups")))
            .flatten(),
    };
    if matches.get_flag("list") {
        return Ok(crate::print_stdout(&list_text(&sandbox_paths(
            &settings.sandbox,
            &env,
            Scope::User,
        ))));
    }
    // `gemini` / `copilot`: the names `shellfirm connect` uses.
    let name = match matches
        .get_one::<String>("agent")
        .map_or("", String::as_str)
    {
        "gemini" => "gemini-cli",
        "copilot" => "copilot-cli",
        n => n,
    };
    let Some(agent) = Agent::from_name(name) else {
        let why = AGENTS
            .iter()
            .find(|a| a.name == name)
            .map_or("unknown agent", |a| a.detail);
        return exit(
            2,
            format!("{name}: {why}\nSupported: {SUPPORTED} (see `shellfirm sandbox --list`)"),
        );
    };
    if agent == Agent::Codex && scope != Scope::User {
        return exit(
            2,
            "codex: only --scope user is supported (~/.codex/config.toml)".into(),
        );
    }
    let opts = Options {
        dry_run: matches.get_flag("dry-run"),
        remove: matches.get_flag("remove"),
        scope,
    };
    let mut out = String::new();
    // Typos in settings.yaml (`sandbox.deny_reads`) change the lists.
    for w in config.settings_warnings() {
        let _ = writeln!(out, "\n  ! settings.yaml: {w}");
    }
    let res = execute(agent, opts, &env, &settings.sandbox, &mut out);
    {
        let mut stdout = std::io::stdout().lock();
        if let Err(e) = stdout
            .write_all(out.as_bytes())
            .and_then(|()| stdout.flush())
        {
            return exit(74, format!("shellfirm: error: writing output: {e}"));
        }
    }
    match res {
        Ok(()) => Ok(shellfirm::CmdExit {
            code: 0,
            message: None,
        }),
        Err(e) => exit(1, format!("Error: {e}")),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    struct Tmp {
        _tree: tree_fs::Tree,
        env: SandboxEnv,
    }

    fn tmp() -> Tmp {
        let tree = tree_fs::TreeBuilder::default().create().unwrap();
        let home = tree.root.join("home");
        let cwd = tree.root.join("project");
        fs::create_dir_all(&home).unwrap();
        fs::create_dir_all(&cwd).unwrap();
        let env = SandboxEnv {
            config_dir: home.join(".config").join("shellfirm"),
            codex_home: home.join(".codex"),
            claude_dir: home.join(".claude"),
            claude_managed: None,
            backup_dir: Some(tree.root.join("backups")),
            home,
            cwd,
        };
        Tmp { _tree: tree, env }
    }

    fn opts(remove: bool, scope: Scope) -> Options {
        Options {
            dry_run: false,
            remove,
            scope,
        }
    }

    fn run_with(
        agent: Agent,
        o: &Options,
        env: &SandboxEnv,
        cfg: &SandboxConfig,
    ) -> (OpResult<()>, String) {
        let mut out = String::new();
        let r = execute(agent, *o, env, cfg, &mut out);
        (r, out)
    }

    fn run(agent: Agent, o: &Options, env: &SandboxEnv) -> (OpResult<()>, String) {
        run_with(agent, o, env, &SandboxConfig::default())
    }

    fn write(path: &Path, content: &str) {
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, content).unwrap();
    }

    fn read_json(path: &Path) -> Value {
        serde_json::from_str(&fs::read_to_string(path).unwrap()).unwrap()
    }

    fn strings(v: &Value) -> Vec<String> {
        v.as_array()
            .unwrap()
            .iter()
            .map(|s| s.as_str().unwrap().to_string())
            .collect()
    }

    fn claude_user(env: &SandboxEnv) -> PathBuf {
        settings_file(Agent::ClaudeCode, Scope::User, env)
    }

    // -- paths --

    #[test]
    fn paths_come_from_the_shared_lists_and_settings() {
        let t = tmp();
        let p = sandbox_paths(&SandboxConfig::default(), &t.env, Scope::User);
        for c in shellfirm::agent::CREDENTIAL_PATHS {
            assert!(p.deny_read.contains(&(*c).to_string()), "{c}");
        }
        assert!(p.deny_read.contains(&"~/Library/Keychains".to_string()));
        assert!(!p.deny_read.iter().any(|x| x.contains(".env")));
        assert!(p.deny_write.contains(&"~/.zshrc".to_string()));
        assert!(p.deny_write.contains(&"~/.config/shellfirm".to_string()));

        let cfg = SandboxConfig {
            deny_read: vec!["~/work/secrets/".into(), "relative/x".into()],
            deny_write: vec!["/etc/hosts".into()],
            exclude: vec!["~/.npmrc".into(), "~/.zshrc".into()],
        };
        let p = sandbox_paths(&cfg, &t.env, Scope::User);
        assert!(p.deny_read.contains(&"~/work/secrets".to_string()));
        assert!(!p.deny_read.contains(&"~/.npmrc".to_string()));
        assert!(!p.deny_write.contains(&"~/.zshrc".to_string()));
        assert!(p.deny_write.contains(&"/etc/hosts".to_string()));
        assert_eq!(p.warnings.len(), 1, "{:?}", p.warnings);
        assert!(p.warnings[0].contains("relative/x"));
    }

    #[test]
    fn shared_project_file_gets_no_personal_config_dir() {
        let mut t = tmp();
        t.env.config_dir = PathBuf::from("/opt/team/shellfirm");
        let project = sandbox_paths(&SandboxConfig::default(), &t.env, Scope::Project);
        assert!(!project.deny_write.iter().any(|p| p.contains("/opt/team")));
        let local = sandbox_paths(&SandboxConfig::default(), &t.env, Scope::Local);
        assert!(local
            .deny_write
            .contains(&"/opt/team/shellfirm".to_string()));
    }

    // -- Claude Code --

    #[test]
    fn claude_fresh_install_and_remove() {
        let t = tmp();
        let (r, out) = run(Agent::ClaudeCode, &opts(false, Scope::User), &t.env);
        r.unwrap();
        assert!(out.contains("set sandbox.enabled: true"), "{out}");
        let path = claude_user(&t.env);
        let v = read_json(&path);
        assert_eq!(v["sandbox"]["enabled"], true);
        let read = strings(&v["sandbox"]["filesystem"]["denyRead"]);
        assert!(read.contains(&"~/.ssh".to_string()));
        assert!(read.contains(&"~/.aws".to_string()));
        let write = strings(&v["sandbox"]["filesystem"]["denyWrite"]);
        assert!(write.contains(&"~/.bashrc".to_string()));
        // Nothing that would weaken prompts or the sandbox.
        let keys: Vec<&String> = v["sandbox"].as_object().unwrap().keys().collect();
        assert_eq!(keys, ["enabled", "filesystem"]);
        let m = load_manifest(&t.env.config_dir).unwrap();
        let rec = &m.files[&manifest_key(&path)];
        assert!(rec.created_file && rec.set_enabled && rec.enabled_before.is_none());

        let rows = sandbox_status_in(&t.env, &SandboxConfig::default());
        assert_eq!(rows.len(), 1);
        assert!(rows[0].complete(), "{rows:?}");

        let (r, out) = run(Agent::ClaudeCode, &opts(true, Scope::User), &t.env);
        r.unwrap();
        assert!(out.contains("delete the file"), "{out}");
        assert!(!path.exists());
        assert!(!manifest_path(&t.env.config_dir).exists());
    }

    #[test]
    fn claude_merges_and_remove_restores_the_file() {
        let t = tmp();
        let path = claude_user(&t.env);
        let original = json!({
            "model": "opus",
            "permissions": {"deny": ["Read(./.env)"]},
            "sandbox": {
                "enabled": false,
                "autoAllowBashIfSandboxed": false,
                "excludedCommands": ["docker"],
                "filesystem": {
                    "denyRead": ["~/.ssh/", "~/private"],
                    "allowWrite": ["~/.kube"]
                },
                "network": {"allowedDomains": ["github.com"]}
            }
        });
        let text = serde_json::to_string_pretty(&original).unwrap() + "\n";
        write(&path, &text);

        let (r, out) = run(Agent::ClaudeCode, &opts(false, Scope::User), &t.env);
        r.unwrap();
        assert!(out.contains("(was false)"), "{out}");
        assert!(out.contains("excludedCommands"), "{out}");
        assert!(out.contains("backup:"), "{out}");
        let v = read_json(&path);
        assert_eq!(v["model"], "opus");
        assert_eq!(v["permissions"], original["permissions"]);
        assert_eq!(v["sandbox"]["enabled"], true);
        assert_eq!(v["sandbox"]["autoAllowBashIfSandboxed"], false);
        assert_eq!(v["sandbox"]["network"], original["sandbox"]["network"]);
        assert_eq!(v["sandbox"]["filesystem"]["allowWrite"], json!(["~/.kube"]));
        let read = strings(&v["sandbox"]["filesystem"]["denyRead"]);
        assert_eq!(&read[..2], ["~/.ssh/", "~/private"]);
        // `~/.ssh/` is already there: not added twice, and not recorded.
        assert_eq!(read.iter().filter(|p| norm(p) == "~/.ssh").count(), 1);
        let m = load_manifest(&t.env.config_dir).unwrap();
        let rec = &m.files[&manifest_key(&path)];
        assert!(!rec.deny_read.contains(&"~/.ssh".to_string()));
        assert_eq!(rec.enabled_before, Some(false));

        // Idempotent.
        let (r, out) = run(Agent::ClaudeCode, &opts(false, Scope::User), &t.env);
        r.unwrap();
        assert!(out.contains("Nothing to change"), "{out}");

        let (r, _) = run(Agent::ClaudeCode, &opts(true, Scope::User), &t.env);
        r.unwrap();
        assert_eq!(fs::read_to_string(&path).unwrap(), text);
    }

    #[test]
    fn claude_jsonc_is_read_and_lossy_rewrite_is_announced() {
        let t = tmp();
        let path = claude_user(&t.env);
        write(&path, "{\n  // my settings\n  \"model\": \"opus\",\n}\n");
        let (r, out) = run(Agent::ClaudeCode, &opts(false, Scope::User), &t.env);
        r.unwrap();
        assert!(out.contains("comments or trailing commas"), "{out}");
        assert_eq!(read_json(&path)["model"], "opus");
        assert!(fs::read_dir(t.env.backup_dir.as_ref().unwrap())
            .unwrap()
            .any(|e| e
                .unwrap()
                .file_name()
                .to_string_lossy()
                .contains(".shellfirm-bak-")));
    }

    #[test]
    fn claude_dry_run_writes_nothing() {
        let t = tmp();
        let o = Options {
            dry_run: true,
            ..opts(false, Scope::Project)
        };
        let (r, out) = run(Agent::ClaudeCode, &o, &t.env);
        r.unwrap();
        assert!(out.contains("Would create"), "{out}");
        assert!(out.contains("~/.ssh"), "{out}");
        assert!(!t.env.cwd.join(".claude").exists());
        assert!(!manifest_path(&t.env.config_dir).exists());
    }

    #[test]
    fn claude_bad_shapes_are_refused() {
        let t = tmp();
        let path = claude_user(&t.env);
        for bad in [
            r#"{"sandbox": true}"#,
            r#"{"sandbox": {"enabled": "yes"}}"#,
            r#"{"sandbox": {"filesystem": {"denyRead": "~/.ssh"}}}"#,
            "{not json",
        ] {
            write(&path, bad);
            let (r, _) = run(Agent::ClaudeCode, &opts(false, Scope::User), &t.env);
            assert!(r.is_err(), "{bad}");
            assert_eq!(fs::read_to_string(&path).unwrap(), bad);
        }
        assert!(!manifest_path(&t.env.config_dir).exists());
    }

    #[test]
    fn claude_remove_without_record_keeps_enabled() {
        let t = tmp();
        let path = claude_user(&t.env);
        run(Agent::ClaudeCode, &opts(false, Scope::User), &t.env)
            .0
            .unwrap();
        fs::remove_file(manifest_path(&t.env.config_dir)).unwrap();
        let (r, out) = run(Agent::ClaudeCode, &opts(true, Scope::User), &t.env);
        r.unwrap();
        assert!(out.contains("no record"), "{out}");
        let v = read_json(&path);
        assert_eq!(v, json!({"sandbox": {"enabled": true}}));
    }

    #[test]
    fn claude_project_and_local_scopes() {
        let t = tmp();
        run(Agent::ClaudeCode, &opts(false, Scope::Project), &t.env)
            .0
            .unwrap();
        run(Agent::ClaudeCode, &opts(false, Scope::Local), &t.env)
            .0
            .unwrap();
        assert!(t.env.cwd.join(".claude/settings.json").exists());
        assert!(t.env.cwd.join(".claude/settings.local.json").exists());
        assert!(!claude_user(&t.env).exists());
        let rows = sandbox_status_in(&t.env, &SandboxConfig::default());
        let scopes: Vec<&str> = rows.iter().map(|r| r.scope).collect();
        assert_eq!(scopes, ["project", "local"]);
        run(Agent::ClaudeCode, &opts(true, Scope::Project), &t.env)
            .0
            .unwrap();
        run(Agent::ClaudeCode, &opts(true, Scope::Local), &t.env)
            .0
            .unwrap();
        assert!(!t.env.cwd.join(".claude").exists());
    }

    #[test]
    fn status_reports_drift() {
        let t = tmp();
        let path = claude_user(&t.env);
        run(Agent::ClaudeCode, &opts(false, Scope::User), &t.env)
            .0
            .unwrap();
        let mut v = read_json(&path);
        v["sandbox"]["filesystem"]["denyRead"]
            .as_array_mut()
            .unwrap()
            .retain(|p| p != "~/.ssh");
        write(&path, &serde_json::to_string(&v).unwrap());
        let rows = sandbox_status_in(&t.env, &SandboxConfig::default());
        assert!(!rows[0].complete());
        assert!(rows[0]
            .line()
            .contains("re-run `shellfirm sandbox claude-code --scope user`"));
        // Re-running puts it back.
        let (r, out) = run(Agent::ClaudeCode, &opts(false, Scope::User), &t.env);
        r.unwrap();
        assert!(out.contains("~/.ssh"), "{out}");
        let rows = sandbox_status_in(&t.env, &SandboxConfig::default());
        assert!(rows[0].complete());
    }

    #[test]
    fn settings_extras_are_written_and_removed() {
        let t = tmp();
        let cfg = SandboxConfig {
            deny_read: vec!["~/work/secrets".into()],
            exclude: vec!["~/.npmrc".into()],
            ..SandboxConfig::default()
        };
        let path = claude_user(&t.env);
        run_with(Agent::ClaudeCode, &opts(false, Scope::User), &t.env, &cfg)
            .0
            .unwrap();
        let read = strings(&read_json(&path)["sandbox"]["filesystem"]["denyRead"]);
        assert!(read.contains(&"~/work/secrets".to_string()));
        assert!(!read.contains(&"~/.npmrc".to_string()));
        // Removing after the list changed still takes out what was added.
        run(Agent::ClaudeCode, &opts(true, Scope::User), &t.env)
            .0
            .unwrap();
        assert!(!path.exists());
    }

    // -- Codex --

    fn codex_file(env: &SandboxEnv) -> PathBuf {
        settings_file(Agent::Codex, Scope::User, env)
    }

    #[test]
    fn codex_fresh_install_and_remove() {
        let t = tmp();
        let (r, out) = run(Agent::Codex, &opts(false, Scope::User), &t.env);
        r.unwrap();
        assert!(out.contains("[permissions.shellfirm]"), "{out}");
        let path = codex_file(&t.env);
        let doc = parse_toml(&fs::read_to_string(&path).unwrap(), &path).unwrap();
        assert_eq!(doc["default_permissions"].as_str(), Some("shellfirm"));
        assert_eq!(
            doc["permissions"]["shellfirm"]["extends"].as_str(),
            Some(":workspace")
        );
        let fs_t = &doc["permissions"]["shellfirm"]["filesystem"];
        assert_eq!(fs_t["~/.ssh"].as_str(), Some("deny"));
        assert_eq!(fs_t["~/.aws"].as_str(), Some("deny"));
        assert_eq!(fs_t["~/.zshrc"].as_str(), Some("read"));
        let rows = sandbox_status(
            &t.env.home,
            &t.env.home,
            &t.env.config_dir,
            &SandboxConfig::default(),
        );
        assert_eq!(rows.len(), 1);
        assert!(rows[0].complete(), "{rows:?}");
        let (r, out) = run(Agent::Codex, &opts(false, Scope::User), &t.env);
        r.unwrap();
        assert!(out.contains("Nothing to change"), "{out}");
        run(Agent::Codex, &opts(true, Scope::User), &t.env)
            .0
            .unwrap();
        assert!(!path.exists());
    }

    #[test]
    fn codex_keeps_comments_and_remove_restores_the_text() {
        let t = tmp();
        let path = codex_file(&t.env);
        let text = "# my config\nmodel = \"gpt-5\" # pinned\nsandbox_mode = \"read-only\"\n\n[mcp_servers.docs]\ncommand = \"docs-mcp\"\n";
        write(&path, text);
        run(Agent::Codex, &opts(false, Scope::User), &t.env)
            .0
            .unwrap();
        let now = fs::read_to_string(&path).unwrap();
        assert!(
            now.starts_with("# my config\nmodel = \"gpt-5\" # pinned\n"),
            "{now}"
        );
        assert!(now.contains("extends = \":read-only\""), "{now}");
        run(Agent::Codex, &opts(true, Scope::User), &t.env)
            .0
            .unwrap();
        assert_eq!(fs::read_to_string(&path).unwrap(), text);
    }

    #[test]
    fn codex_builtin_default_is_restored() {
        let t = tmp();
        let path = codex_file(&t.env);
        let text = "default_permissions = \":read-only\"\n";
        write(&path, text);
        let (r, out) = run(Agent::Codex, &opts(false, Scope::User), &t.env);
        r.unwrap();
        assert!(out.contains("(was \":read-only\")"), "{out}");
        run(Agent::Codex, &opts(true, Scope::User), &t.env)
            .0
            .unwrap();
        assert_eq!(fs::read_to_string(&path).unwrap(), text);
    }

    #[test]
    fn codex_user_profile_gets_the_entries() {
        let t = tmp();
        let path = codex_file(&t.env);
        let text = "default_permissions = \"dev\"\n\n[permissions.dev]\nextends = \":workspace\"\n\n[permissions.dev.filesystem]\n\"~/.ssh\" = \"read\"\n\"/srv/data\" = \"write\"\n";
        write(&path, text);
        let (r, out) = run(Agent::Codex, &opts(false, Scope::User), &t.env);
        r.unwrap();
        assert!(
            out.contains("kept your entry `\"~/.ssh\" = \"read\"`"),
            "{out}"
        );
        assert!(!out.contains("add permission profile"), "{out}");
        let doc = parse_toml(&fs::read_to_string(&path).unwrap(), &path).unwrap();
        let fs_t = &doc["permissions"]["dev"]["filesystem"];
        assert_eq!(fs_t["~/.ssh"].as_str(), Some("read"));
        assert_eq!(fs_t["~/.aws"].as_str(), Some("deny"));
        assert!(doc["permissions"].get("shellfirm").is_none());
        run(Agent::Codex, &opts(true, Scope::User), &t.env)
            .0
            .unwrap();
        assert_eq!(fs::read_to_string(&path).unwrap(), text);
    }

    #[test]
    fn codex_refuses_configs_it_would_weaken_or_misread() {
        let t = tmp();
        let path = codex_file(&t.env);
        for bad in [
            "sandbox_mode = \"danger-full-access\"\n",
            "default_permissions = \":danger-full-access\"\n",
            "[sandbox_workspace_write]\nnetwork_access = true\n",
            "default_permissions = \"missing\"\n",
            "[permissions.shellfirm]\nextends = \":workspace\"\n",
            "default_permissions = 3\n",
            "model = [\n",
        ] {
            write(&path, bad);
            let (r, _) = run(Agent::Codex, &opts(false, Scope::User), &t.env);
            assert!(r.is_err(), "{bad}");
            assert_eq!(fs::read_to_string(&path).unwrap(), bad);
        }
    }

    #[test]
    fn codex_remove_without_record_recognises_its_profile() {
        let t = tmp();
        let path = codex_file(&t.env);
        write(&path, "model = \"gpt-5\"\n");
        run(Agent::Codex, &opts(false, Scope::User), &t.env)
            .0
            .unwrap();
        fs::remove_file(manifest_path(&t.env.config_dir)).unwrap();
        run(Agent::Codex, &opts(true, Scope::User), &t.env)
            .0
            .unwrap();
        assert_eq!(fs::read_to_string(&path).unwrap(), "model = \"gpt-5\"\n");
    }

    #[test]
    fn codex_scope_other_than_user_is_refused() {
        let t = tmp();
        let (r, _) = run(Agent::Codex, &opts(false, Scope::Project), &t.env);
        assert!(r.is_err());
    }

    #[test]
    fn list_names_every_agent_and_path() {
        let t = tmp();
        let text = list_text(&sandbox_paths(
            &SandboxConfig::default(),
            &t.env,
            Scope::User,
        ));
        for a in AGENTS {
            assert!(text.contains(a.name));
        }
        assert!(text.contains("~/.ssh"));
        assert!(text.contains("sandbox.exclude"));
    }

    fn status(env: &SandboxEnv) -> Vec<SandboxStatus> {
        sandbox_status_in(env, &SandboxConfig::default())
    }

    #[cfg(unix)]
    #[test]
    fn project_and_local_scope_never_write_through_a_symlink_out_of_the_project() {
        let t = tmp();
        let victim = t.env.home.join(".codex/hooks.json");
        write(&victim, r#"{"hooks":{}}"#);
        let claude = t.env.cwd.join(".claude");
        fs::create_dir_all(&claude).unwrap();
        std::os::unix::fs::symlink("../../home/.codex/hooks.json", claude.join("settings.json"))
            .unwrap();
        let (r, _) = run(Agent::ClaudeCode, &opts(false, Scope::Project), &t.env);
        assert!(r.unwrap_err().contains("outside this project"));
        assert_eq!(fs::read_to_string(&victim).unwrap(), r#"{"hooks":{}}"#);
        let rows = status(&t.env);
        let row = rows.iter().find(|r| r.scope == "project").unwrap();
        assert!(row
            .error
            .as_deref()
            .unwrap()
            .contains("outside this project"));
        assert!(!row.complete());

        // `.claude` itself linked to the user's directory.
        fs::remove_file(claude.join("settings.json")).unwrap();
        fs::remove_dir(&claude).unwrap();
        fs::create_dir_all(t.env.home.join(".claude")).unwrap();
        std::os::unix::fs::symlink(t.env.home.join(".claude"), &claude).unwrap();
        let (r, _) = run(Agent::ClaudeCode, &opts(false, Scope::Local), &t.env);
        let e = r.unwrap_err();
        assert!(e.contains("outside this project"), "{e}");
        assert!(
            e.contains("at local scope") && !e.contains("project scope"),
            "{e}"
        );
        assert!(!t.env.home.join(".claude/settings.local.json").exists());
    }

    #[test]
    fn codex_without_a_sandbox_through_a_profile_is_refused() {
        let t = tmp();
        let path = codex_file(&t.env);
        for bad in [
            "default_permissions = \"dev\"\n[permissions.dev]\nextends = \":danger-full-access\"\n",
            "default_permissions = \"a\"\n[permissions.a]\nextends = \"b\"\n[permissions.b]\nextends = \":danger-full-access\"\n",
            "profile = \"yolo\"\n[profiles.yolo]\nsandbox_mode = \"danger-full-access\"\napproval_policy = \"never\"\n",
            "profile = \"yolo\"\n[profiles.yolo]\ndefault_permissions = \":danger-full-access\"\n",
        ] {
            write(&path, bad);
            let (r, _) = run(Agent::Codex, &opts(false, Scope::User), &t.env);
            assert!(r.unwrap_err().contains("without a sandbox"), "{bad}");
            assert_eq!(fs::read_to_string(&path).unwrap(), bad);
        }
        // A profile that is sandboxed is fine (and a loop ends).
        write(
            &path,
            "profile = \"p\"\n[profiles.p]\nsandbox_mode = \"workspace-write\"\n",
        );
        run(Agent::Codex, &opts(false, Scope::User), &t.env)
            .0
            .unwrap();
        let mut d = parse_toml(
            "default_permissions = \"a\"\n[permissions.a]\nextends = \"a\"\n",
            &path,
        )
        .unwrap();
        assert!(codex_full_access(&d).is_none());
        d.remove("default_permissions");
        assert!(codex_full_access(&d).is_none());
    }

    #[test]
    fn claude_settings_that_reopen_a_denied_path_are_reported() {
        let t = tmp();
        let home = t.env.home.display().to_string();
        let local = settings_file(Agent::ClaudeCode, Scope::Local, &t.env);
        for (allow, hit) in [
            ("~/.ssh", true),
            ("~/.ssh/id_rsa", true),
            ("~/.ssh/", true),
            (&*format!("{home}/.aws"), true),
            ("~/.aws/../.ssh/id_rsa", true),
            ("/", false),
            ("~", false),
            ("~/projects", false),
        ] {
            write(
                &local,
                &json!({"sandbox":{"filesystem":{"allowRead":[allow]}}}).to_string(),
            );
            let (r, out) = run(
                Agent::ClaudeCode,
                &Options {
                    dry_run: true,
                    ..opts(false, Scope::Local)
                },
                &t.env,
            );
            r.unwrap();
            assert_eq!(out.contains("re-opens"), hit, "{allow}: {out}");
        }
        // Another scope's file counts too (Claude Code merges the lists),
        // and so does allowWrite.
        fs::remove_file(&local).unwrap();
        write(
            &claude_user(&t.env),
            r#"{"sandbox":{"filesystem":{"allowWrite":["~/.zshrc"]}}}"#,
        );
        let (r, out) = run(Agent::ClaudeCode, &opts(false, Scope::Project), &t.env);
        r.unwrap();
        assert!(out.contains("allowWrite `~/.zshrc`"), "{out}");
        // Status: on with every entry, but not "complete", and no re-run
        // suggestion (re-running keeps the user's entry).
        let rows = status(&t.env);
        let row = rows.iter().find(|r| r.scope == "project").unwrap();
        assert!(row.enabled && row.missing == 0, "{row:?}");
        assert!(!row.complete());
        let line = row.line();
        assert!(
            line.contains("weakened: sandbox.filesystem.allowWrite"),
            "{line}"
        );
        assert!(!line.contains("re-run"), "{line}");
    }

    #[test]
    fn codex_entries_that_reopen_a_denied_path_are_reported() {
        let t = tmp();
        let path = codex_file(&t.env);
        write(
            &path,
            "default_permissions = \"dev\"\n[permissions.dev]\nextends = \":workspace\"\n[permissions.dev.filesystem]\n\"/\" = \"write\"\n\"~/.ssh/id_rsa\" = \"read\"\n",
        );
        let (r, out) = run(Agent::Codex, &opts(false, Scope::User), &t.env);
        r.unwrap();
        assert!(out.contains("`\"~/.ssh/id_rsa\" = \"read\"`"), "{out}");
        // A wider entry does not win over shellfirm's narrower ones.
        assert!(!out.contains("`\"/\" = \"write\"`"), "{out}");
        let rows = status(&t.env);
        assert!(!rows[0].complete());
        assert_eq!(rows[0].missing, 0);
        assert!(!rows[0].line().contains("re-run"), "{}", rows[0].line());
        // Kept equal entry: reported, and re-running cannot fix it.
        write(
            &path,
            "default_permissions = \"dev\"\n[permissions.dev]\nextends = \":workspace\"\n[permissions.dev.filesystem]\n\"~/.ssh\" = \"read\"\n",
        );
        run(Agent::Codex, &opts(false, Scope::User), &t.env)
            .0
            .unwrap();
        let rows = status(&t.env);
        let line = rows[0].line();
        assert!(
            line.contains("weakened: your entry `\"~/.ssh\" = \"read\"`"),
            "{line}"
        );
        assert!(!line.contains("re-run"), "{line}");
    }

    #[test]
    fn an_exclude_added_later_takes_the_entry_out() {
        let t = tmp();
        let path = claude_user(&t.env);
        run(Agent::ClaudeCode, &opts(false, Scope::User), &t.env)
            .0
            .unwrap();
        assert!(
            strings(&read_json(&path)["sandbox"]["filesystem"]["denyRead"])
                .contains(&"~/.npmrc".to_string())
        );
        let cfg = SandboxConfig {
            exclude: vec!["~/.npmrc".into(), "~/.zshrc".into()],
            ..SandboxConfig::default()
        };
        let (r, out) = run_with(Agent::ClaudeCode, &opts(false, Scope::User), &t.env, &cfg);
        r.unwrap();
        assert!(out.contains("no longer in shellfirm's list"), "{out}");
        let fs_v = &read_json(&path)["sandbox"]["filesystem"];
        assert!(!strings(&fs_v["denyRead"]).contains(&"~/.npmrc".to_string()));
        assert!(!strings(&fs_v["denyWrite"]).contains(&"~/.zshrc".to_string()));
        let rows = sandbox_status_in(&t.env, &cfg);
        assert!(rows[0].complete(), "{}", rows[0].line());

        // Codex too.
        run(Agent::Codex, &opts(false, Scope::User), &t.env)
            .0
            .unwrap();
        run_with(Agent::Codex, &opts(false, Scope::User), &t.env, &cfg)
            .0
            .unwrap();
        let text = fs::read_to_string(codex_file(&t.env)).unwrap();
        assert!(
            !text.contains("~/.npmrc") && !text.contains("~/.zshrc"),
            "{text}"
        );
        assert!(text.contains("~/.ssh"));
    }

    #[test]
    fn paas_logins_are_denied_and_whole_disk_entries_refused() {
        let t = tmp();
        let p = sandbox_paths(&SandboxConfig::default(), &t.env, Scope::User);
        for c in [
            "~/.railway/config.json",
            "~/.supabase/access-token",
            "~/.local/share/com.vercel.cli/auth.json",
            "~/.config/netlify/config.json",
            "~/.fly/config.yml",
        ] {
            assert!(p.deny_read.contains(&c.to_string()), "{c}");
        }
        for bad in ["/", "~", "~/", "/tmp/.."] {
            let cfg = SandboxConfig {
                deny_read: vec![bad.into()],
                ..SandboxConfig::default()
            };
            let (r, _) = run_with(Agent::ClaudeCode, &opts(false, Scope::User), &t.env, &cfg);
            assert!(r.unwrap_err().contains("would cover every file"), "{bad}");
            assert!(!claude_user(&t.env).exists());
        }
        let cfg = SandboxConfig {
            deny_read: vec!["~/.ssh/../work/keys/".into()],
            ..SandboxConfig::default()
        };
        let p = sandbox_paths(&cfg, &t.env, Scope::User);
        assert!(
            p.deny_read.contains(&"~/work/keys".to_string()),
            "{:?}",
            p.deny_read
        );
    }

    #[test]
    fn cli_accepts_the_connect_agent_names() {
        for name in [
            "gemini",
            "copilot",
            "gemini-cli",
            "copilot-cli",
            "qwen",
            "cursor",
            "windsurf",
            "cline",
            "opencode",
            "zed",
        ] {
            assert!(
                command().try_get_matches_from(["sandbox", name]).is_ok(),
                "{name}"
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn a_failed_write_shows_only_the_error() {
        use std::os::unix::fs::PermissionsExt;
        let t = tmp();
        let path = claude_user(&t.env);
        write(&path, "{}");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o444)).unwrap();
        let (r, out) = run(Agent::ClaudeCode, &opts(false, Scope::User), &t.env);
        assert!(r.unwrap_err().contains("read-only"));
        assert!(!out.contains("set sandbox.enabled"), "{out}");
    }

    #[test]
    fn local_scope_says_to_keep_the_file_out_of_git_and_claude_dir_is_used() {
        let mut t = tmp();
        let (r, out) = run(Agent::ClaudeCode, &opts(false, Scope::Local), &t.env);
        r.unwrap();
        assert!(out.contains("keep it out of git"), "{out}");
        let (_, out) = run(Agent::ClaudeCode, &opts(false, Scope::Local), &t.env);
        assert!(!out.contains("keep it out of git"), "{out}");
        // Removing it removes the `.claude` directory it created.
        run(Agent::ClaudeCode, &opts(true, Scope::Local), &t.env)
            .0
            .unwrap();
        assert!(!t.env.cwd.join(".claude").exists());

        t.env.claude_dir = t.env.home.join("ccd");
        run(Agent::ClaudeCode, &opts(false, Scope::User), &t.env)
            .0
            .unwrap();
        assert!(t.env.home.join("ccd/settings.json").exists());
        assert!(!t.env.home.join(".claude").exists());
    }

    #[test]
    fn every_connect_agent_without_a_sandbox_writer_is_explained() {
        for name in ["qwen", "cursor", "windsurf", "cline", "opencode", "zed"] {
            let a = AGENTS.iter().find(|a| a.name == name).unwrap();
            assert!(
                !a.supported && a.detail.starts_with("not supported: "),
                "{name}"
            );
            assert!(Agent::from_name(name).is_none(), "{name}");
        }
        let list = list_text(&sandbox_paths(
            &SandboxConfig::default(),
            &tmp().env,
            Scope::User,
        ));
        assert!(list.contains("cursor       Cursor"), "{list}");
    }

    #[test]
    fn a_moved_claude_config_dir_is_denied_like_dot_claude() {
        let mut t = tmp();
        let default = sandbox_paths(&SandboxConfig::default(), &t.env, Scope::User);
        assert!(!default.deny_read.iter().any(|p| p.contains("ccd")));
        t.env.claude_dir = t.env.home.join("ccd");
        let p = sandbox_paths(&SandboxConfig::default(), &t.env, Scope::User);
        assert!(p.deny_read.contains(&"~/ccd/.credentials.json".to_string()));
        assert!(p.deny_write.contains(&"~/ccd/settings.json".to_string()));
        assert!(p.deny_write.contains(&"~/ccd/.claude.json".to_string()));
        assert_eq!(p.deny_read.len(), default.deny_read.len() + 1);
        t.env.claude_dir = PathBuf::from("/opt/cc");
        let p = sandbox_paths(&SandboxConfig::default(), &t.env, Scope::User);
        assert!(p
            .deny_read
            .contains(&"/opt/cc/.credentials.json".to_string()));
        // A shared project file gets no personal path.
        let p = sandbox_paths(&SandboxConfig::default(), &t.env, Scope::Project);
        assert!(!p.deny_write.iter().any(|x| x.starts_with("/opt/cc")));
    }

    #[test]
    fn home_its_parents_and_unexpanded_or_empty_entries_are_refused() {
        let t = tmp();
        let home = t.env.home.display().to_string();
        let parent = t.env.home.parent().unwrap().display().to_string();
        for bad in [
            home.clone(),
            format!("{home}/"),
            format!("{home}/./"),
            format!("{home}/.ssh/../.."),
            parent,
            "//".into(),
            "$HOME".into(),
            "$HOME/.ssh".into(),
            String::new(),
            "  ".into(),
        ] {
            for key in ["read", "write"] {
                let cfg = if key == "read" {
                    SandboxConfig {
                        deny_read: vec![bad.clone()],
                        ..SandboxConfig::default()
                    }
                } else {
                    SandboxConfig {
                        deny_write: vec![bad.clone()],
                        ..SandboxConfig::default()
                    }
                };
                let (r, _) = run_with(Agent::ClaudeCode, &opts(false, Scope::User), &t.env, &cfg);
                let e = r.unwrap_err();
                assert!(e.contains(&format!("sandbox.deny_{key}")), "{bad:?}: {e}");
                assert!(!claude_user(&t.env).exists(), "{bad:?}");
                assert_eq!(settings_errors(&t.env.home, &cfg), vec![e], "{bad:?}");
            }
        }
        // A sibling of home, and a path inside it, are fine.
        let cfg = SandboxConfig {
            deny_read: vec![format!("{home}x/keys"), format!("{home}/work/keys")],
            ..SandboxConfig::default()
        };
        assert!(settings_errors(&t.env.home, &cfg).is_empty());
        let p = sandbox_paths(&cfg, &t.env, Scope::User);
        assert!(p.errors.is_empty(), "{:?}", p.errors);
        assert!(p.deny_read.contains(&format!("{home}/work/keys")));
    }

    #[test]
    fn status_names_a_refused_settings_entry_instead_of_a_rerun() {
        let t = tmp();
        run(Agent::ClaudeCode, &opts(false, Scope::User), &t.env)
            .0
            .unwrap();
        let cfg = SandboxConfig {
            deny_read: vec!["/".into()],
            ..SandboxConfig::default()
        };
        let rows = sandbox_status_in(&t.env, &cfg);
        assert!(!rows[0].complete());
        assert_eq!(rows[0].deny_read, rows[0].deny_read_expected);
        let line = rows[0].line();
        assert!(
            line.contains("refused in settings.yaml: sandbox.deny_read: `/`"),
            "{line}"
        );
        assert!(line.contains("shellfirm config edit"), "{line}");
        assert!(!line.contains("--scope user"), "{line}");
    }

    #[test]
    fn a_project_or_local_file_that_turns_the_sandbox_off_is_reported() {
        let t = tmp();
        run(Agent::ClaudeCode, &opts(false, Scope::User), &t.env)
            .0
            .unwrap();
        assert!(status(&t.env)[0].complete());
        let project = t.env.cwd.join(".claude/settings.json");
        let local = t.env.cwd.join(".claude/settings.local.json");
        for file in [&project, &local] {
            write(file, r#"{"sandbox":{"enabled":false}}"#);
            let rows = status(&t.env);
            let row = rows.iter().find(|r| r.scope == "user").unwrap();
            assert!(!row.enabled && !row.complete());
            let line = row.line();
            assert!(line.contains("sandbox off"), "{line}");
            assert!(
                line.contains(&format!("sandbox.enabled is false in {}", file.display())),
                "{line}"
            );
            assert!(!line.contains("re-run"), "{line}");
            // Re-running says so too.
            let (r, out) = run(Agent::ClaudeCode, &opts(false, Scope::User), &t.env);
            r.unwrap();
            assert!(out.contains("sandbox.enabled is false in"), "{out}");
            fs::remove_file(file).unwrap();
        }
        // Local `true` wins over project `false`.
        write(&project, r#"{"sandbox":{"enabled":false}}"#);
        write(&local, r#"{"sandbox":{"enabled":true}}"#);
        let rows = status(&t.env);
        assert!(rows.iter().find(|r| r.scope == "user").unwrap().enabled);
    }

    #[test]
    fn a_project_codex_config_without_the_profile_is_reported() {
        let t = tmp();
        run(Agent::Codex, &opts(false, Scope::User), &t.env)
            .0
            .unwrap();
        let codex =
            |rows: Vec<SandboxStatus>| rows.into_iter().find(|r| r.tool == "codex").unwrap();
        assert!(codex(status(&t.env)).complete());
        let project = t.env.cwd.join(".codex/config.toml");
        for (text, why) in [
            (
                "sandbox_mode = \"danger-full-access\"\n",
                "danger-full-access",
            ),
            (
                "default_permissions = \"open\"\n[permissions.open]\nextends = \":workspace\"\n",
                "default_permissions = \"open\" replaces shellfirm's profile",
            ),
            (
                "default_permissions = \":danger-full-access\"\n",
                ":danger-full-access",
            ),
        ] {
            write(&project, text);
            let row = codex(status(&t.env));
            assert!(!row.enabled && !row.complete(), "{text}");
            let line = row.line();
            assert!(line.contains(why) && line.contains("sandbox off"), "{line}");
        }
        write(
            &project,
            "default_permissions = \"shellfirm\"\nmodel = \"o3\"\n",
        );
        assert!(codex(status(&t.env)).complete());
    }

    #[test]
    fn removing_a_user_file_shellfirm_created_keeps_its_backup() {
        let mut t = tmp();
        // User-scope backups go next to the file, as in a real run.
        t.env.backup_dir = None;
        let path = claude_user(&t.env);
        run(Agent::ClaudeCode, &opts(false, Scope::User), &t.env)
            .0
            .unwrap();
        run(Agent::ClaudeCode, &opts(true, Scope::User), &t.env)
            .0
            .unwrap();
        // As docs/sandbox.md says: the file is gone, its backup and the
        // user folder stay.
        assert!(!path.exists());
        let left: Vec<_> = fs::read_dir(path.parent().unwrap())
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(left.len(), 1, "{left:?}");
        assert!(
            left[0].starts_with("settings.json.shellfirm-bak-"),
            "{left:?}"
        );
    }

    #[test]
    fn a_project_codex_entry_that_reopens_a_denied_path_is_weakening() {
        let t = tmp();
        run(Agent::Codex, &opts(false, Scope::User), &t.env)
            .0
            .unwrap();
        let project = t.env.cwd.join(".codex/config.toml");
        // Codex deep-merges the project tables over the user file's.
        write(
            &project,
            "[permissions.shellfirm.filesystem]\n\"~/.ssh\" = \"write\"\n",
        );
        let row = status(&t.env)
            .into_iter()
            .find(|r| r.tool == "codex")
            .unwrap();
        assert!(!row.complete(), "{row:?}");
        assert!(
            row.weakened
                .iter()
                .any(|w| w.contains("re-opens `~/.ssh`") && w.contains(project.to_str().unwrap())),
            "{row:?}"
        );
        // Re-running `sandbox` warns about it too.
        let (r, out) = run(Agent::Codex, &opts(false, Scope::User), &t.env);
        r.unwrap();
        assert!(out.contains("re-opens `~/.ssh`"), "{out}");
        // Another profile, or a stricter entry, is no weakening.
        write(
            &project,
            "[permissions.other.filesystem]\n\"~/.ssh\" = \"write\"\n\
             [permissions.shellfirm.filesystem]\n\"~/.ssh\" = \"none\"\n",
        );
        assert!(status(&t.env)
            .into_iter()
            .find(|r| r.tool == "codex")
            .unwrap()
            .complete());
    }

    #[cfg(unix)]
    #[test]
    fn a_record_that_cannot_be_written_leaves_the_settings_file_alone() {
        use std::os::unix::fs::PermissionsExt;
        let t = tmp();
        fs::create_dir_all(&t.env.config_dir).unwrap();
        fs::set_permissions(&t.env.config_dir, fs::Permissions::from_mode(0o555)).unwrap();
        let (r, _) = run(Agent::ClaudeCode, &opts(false, Scope::User), &t.env);
        fs::set_permissions(&t.env.config_dir, fs::Permissions::from_mode(0o755)).unwrap();
        assert!(r.unwrap_err().contains("was not changed"));
        assert!(!claude_user(&t.env).exists());
        // A failed settings write puts the old record back.
        let path = claude_user(&t.env);
        write(&path, "{}");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o444)).unwrap();
        assert!(run(Agent::ClaudeCode, &opts(false, Scope::User), &t.env)
            .0
            .is_err());
        assert!(load_manifest(&t.env.config_dir).unwrap().files.is_empty());
        fs::remove_file(&path).unwrap();
        // Install then remove leaves nothing of shellfirm's.
        run(Agent::ClaudeCode, &opts(false, Scope::User), &t.env)
            .0
            .unwrap();
        run(Agent::ClaudeCode, &opts(true, Scope::User), &t.env)
            .0
            .unwrap();
        assert!(!path.exists());
    }

    #[cfg(unix)]
    #[test]
    fn an_unreadable_agent_folder_is_reported_not_skipped() {
        use std::os::unix::fs::PermissionsExt;
        let t = tmp();
        for agent in [Agent::ClaudeCode, Agent::Codex] {
            run(agent, &opts(false, Scope::User), &t.env).0.unwrap();
        }
        let dirs = [t.env.claude_dir.clone(), t.env.codex_home.clone()];
        for d in &dirs {
            fs::set_permissions(d, fs::Permissions::from_mode(0o000)).unwrap();
        }
        let rows = status(&t.env);
        for d in &dirs {
            fs::set_permissions(d, fs::Permissions::from_mode(0o755)).unwrap();
        }
        assert_eq!(rows.len(), 2, "{rows:?}");
        assert!(
            rows.iter()
                .all(|r| r.error.as_deref().unwrap().contains("can't read")),
            "{rows:?}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_fifo_at_a_settings_path_is_an_error_not_a_hang() {
        let t = tmp();
        let claude = claude_user(&t.env);
        let codex = codex_file(&t.env);
        for p in [&claude, &codex] {
            fs::create_dir_all(p.parent().unwrap()).unwrap();
            assert!(std::process::Command::new("mkfifo")
                .arg(p)
                .status()
                .unwrap()
                .success());
        }
        for agent in [Agent::ClaudeCode, Agent::Codex] {
            let (r, _) = run(agent, &opts(false, Scope::User), &t.env);
            assert!(r.unwrap_err().contains("not a regular file"), "{agent:?}");
        }
        let rows = status(&t.env);
        assert_eq!(rows.len(), 2);
        assert!(rows
            .iter()
            .all(|r| r.error.as_deref().unwrap().contains("not a regular file")));
    }
}
