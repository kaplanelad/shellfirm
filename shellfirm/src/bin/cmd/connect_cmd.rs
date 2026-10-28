//! `shellfirm connect <tool>` — install/remove AI-agent integrations.
//!
//! Safety rules for touching other tools' config files:
//! - Files are parsed tolerantly (JSONC: comments, trailing commas, BOM). If a
//!   file can't be parsed, nothing is written and the command fails.
//! - Unexpected shapes (root not an object, `hooks` not an object, ...) are
//!   reported as errors, never "fixed" by overwriting.
//! - Every modified existing file gets a timestamped backup first, and is
//!   replaced atomically (temp file + rename, original permissions kept,
//!   symlinks followed).
//! - Key order is preserved; uninstall removes only shellfirm's own entries.

use std::fmt::Write as _;
use std::fs;
use std::io::Write as _;
use std::path::{Path, PathBuf};

use clap::{Arg, ArgAction, ArgMatches, Command};
use serde_json::{json, Map, Value};
use shellfirm::error::Result;

/// Hook arguments written by this version.
const CLAUDE_HOOK_ARGS: &str = "check --hook claude-code";
const CURSOR_HOOK_ARGS: &str = "check --hook cursor";
const BINARY: &str = "shellfirm";
const MCP_ARGS: &[&str] = &["mcp"];
/// `timeout` (seconds) written on hook entries. shellfirm answers in well
/// under a second; the optional LLM review is capped at 10 s.
const HOOK_TIMEOUT_SECS: u64 = 30;

type OpResult<T> = std::result::Result<T, String>;

// ---------------------------------------------------------------------------
// Providers and plan
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Component {
    Hooks,
    Mcp,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Scope {
    User,
    Project,
}

/// What to do inside one config file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OpKind {
    /// `hooks.PreToolUse[]` in Claude Code settings.json.
    ClaudeHooks,
    /// `mcpServers.shellfirm` with `"type": "stdio"` (Claude Code `~/.claude.json` / `.mcp.json`).
    ClaudeMcp,
    /// Remove the `mcpServers.shellfirm` entry older versions wrote into
    /// `~/.claude/settings.json` (Claude Code never read it there).
    LegacyClaudeSettingsMcp,
    /// Cursor `hooks.json` `hooks.beforeShellExecution[]`.
    CursorHooks,
    /// Plain `mcpServers.shellfirm` (Cursor, Windsurf, Cline).
    StandardMcp,
    /// Zed `context_servers.shellfirm`.
    ZedMcp,
}

impl OpKind {
    const fn component(self) -> Component {
        match self {
            Self::ClaudeHooks | Self::CursorHooks => Component::Hooks,
            _ => Component::Mcp,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Provider {
    ClaudeCode,
    Cursor,
    Windsurf,
    Zed,
    Cline,
}

const SUPPORTED_PROVIDERS: &str = "claude-code, cursor, windsurf, zed, cline";

impl Provider {
    fn from_name(name: &str) -> Option<Self> {
        match name {
            "claude-code" => Some(Self::ClaudeCode),
            "cursor" => Some(Self::Cursor),
            "windsurf" => Some(Self::Windsurf),
            "zed" => Some(Self::Zed),
            "cline" => Some(Self::Cline),
            _ => None,
        }
    }

    #[allow(dead_code)]
    const fn cli_name(self) -> &'static str {
        match self {
            Self::ClaudeCode => "claude-code",
            Self::Cursor => "cursor",
            Self::Windsurf => "windsurf",
            Self::Zed => "zed",
            Self::Cline => "cline",
        }
    }

    const fn display_name(self) -> &'static str {
        match self {
            Self::ClaudeCode => "Claude Code",
            Self::Cursor => "Cursor",
            Self::Windsurf => "Windsurf",
            Self::Zed => "Zed",
            Self::Cline => "Cline",
        }
    }

    const fn supports_hooks(self) -> bool {
        matches!(self, Self::ClaudeCode | Self::Cursor)
    }

    const fn supports_scope(self) -> bool {
        matches!(self, Self::ClaudeCode | Self::Cursor)
    }
}

/// Paths the plan is resolved against (injectable for tests).
#[derive(Debug, Clone)]
struct ConnectEnv {
    home: PathBuf,
    cwd: PathBuf,
    /// Where backups of project-scope files go (outside the repository).
    backup_dir: Option<PathBuf>,
    /// shellfirm's configuration directory, recorded in user-scope hooks.
    config_dir: Option<PathBuf>,
}

#[derive(Debug, Clone, Copy)]
#[allow(clippy::struct_excessive_bools)]
struct Options {
    dry_run: bool,
    uninstall: bool,
    hooks: bool,
    mcp: bool,
    scope: Scope,
    /// Claude Code: write `"onFailure": "block"` (needs Claude Code >= 2.1.295).
    fail_closed: bool,
}

fn cline_settings_path(home: &Path) -> Option<PathBuf> {
    let rel = "Code/User/globalStorage/saoudrizwan.claude-dev/settings/cline_mcp_settings.json";
    if cfg!(target_os = "macos") {
        Some(home.join("Library/Application Support").join(rel))
    } else if cfg!(target_os = "linux") {
        Some(home.join(".config").join(rel))
    } else {
        None
    }
}

/// Ordered list of `(file, operations)` for a provider.
#[allow(clippy::trivially_copy_pass_by_ref)]
fn plan(
    provider: Provider,
    opts: &Options,
    env: &ConnectEnv,
) -> OpResult<Vec<(PathBuf, Vec<OpKind>)>> {
    let mut steps: Vec<(PathBuf, OpKind)> = Vec::new();
    let base = match opts.scope {
        Scope::User => env.home.clone(),
        Scope::Project => env.cwd.clone(),
    };
    match provider {
        Provider::ClaudeCode => {
            let settings = base.join(".claude").join("settings.json");
            if opts.hooks {
                steps.push((settings.clone(), OpKind::ClaudeHooks));
            }
            if opts.mcp {
                match opts.scope {
                    Scope::User => {
                        steps.push((env.home.join(".claude.json"), OpKind::ClaudeMcp));
                        steps.push((settings, OpKind::LegacyClaudeSettingsMcp));
                    }
                    Scope::Project => steps.push((base.join(".mcp.json"), OpKind::ClaudeMcp)),
                }
            }
        }
        Provider::Cursor => {
            let dir = base.join(".cursor");
            if opts.hooks {
                steps.push((dir.join("hooks.json"), OpKind::CursorHooks));
            }
            if opts.mcp {
                steps.push((dir.join("mcp.json"), OpKind::StandardMcp));
            }
        }
        Provider::Windsurf => steps.push((
            env.home
                .join(".codeium")
                .join("windsurf")
                .join("mcp_config.json"),
            OpKind::StandardMcp,
        )),
        Provider::Zed => steps.push((
            env.home.join(".config").join("zed").join("settings.json"),
            OpKind::ZedMcp,
        )),
        Provider::Cline => {
            let path = cline_settings_path(&env.home).ok_or_else(|| {
                "Cline's settings location is unknown on this platform".to_string()
            })?;
            steps.push((path, OpKind::StandardMcp));
        }
    }

    let mut grouped: Vec<(PathBuf, Vec<OpKind>)> = Vec::new();
    for (path, op) in steps {
        if let Some((_, ops)) = grouped.iter_mut().find(|(p, _)| *p == path) {
            ops.push(op);
        } else {
            grouped.push((path, vec![op]));
        }
    }
    Ok(grouped)
}

// ---------------------------------------------------------------------------
// Hook command recognition
// ---------------------------------------------------------------------------

/// What the hook entries written by this run look like.
#[derive(Debug, Clone, Default)]
struct InstallSpec {
    /// Configuration directory recorded in the hook command (user scope).
    config_dir: Option<String>,
    /// Write `"onFailure": "block"` on Claude Code hooks.
    fail_closed: bool,
}

impl InstallSpec {
    fn hook_command(&self, args: &str) -> String {
        let mut cmd = format!("{BINARY} {args}");
        if let Some(dir) = &self.config_dir {
            let _ = write!(cmd, " --config-dir {}", shell_quote(dir));
        }
        cmd
    }

    fn mcp_args(&self) -> Vec<String> {
        let mut args: Vec<String> = MCP_ARGS.iter().map(ToString::to_string).collect();
        if let Some(dir) = &self.config_dir {
            args.push("--config-dir".into());
            args.push(dir.clone());
        }
        args
    }
}

/// Quote `s` for a POSIX shell when needed.
fn shell_quote(s: &str) -> String {
    let plain = !s.is_empty()
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || "_./:@%+=,-".contains(c));
    if plain {
        s.to_string()
    } else {
        format!("'{}'", s.replace('\'', r"'\''"))
    }
}

/// Split a hook command line like a POSIX shell would (quotes and
/// backslashes only). `None` for unbalanced quotes.
fn shell_split(cmd: &str) -> Option<Vec<String>> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut in_word = false;
    let mut chars = cmd.chars();
    while let Some(c) = chars.next() {
        match c {
            '\'' => {
                in_word = true;
                loop {
                    match chars.next()? {
                        '\'' => break,
                        ch => cur.push(ch),
                    }
                }
            }
            '"' => {
                in_word = true;
                loop {
                    match chars.next()? {
                        '"' => break,
                        '\\' => cur.push(chars.next()?),
                        ch => cur.push(ch),
                    }
                }
            }
            '\\' => {
                in_word = true;
                cur.push(chars.next()?);
            }
            c if c.is_whitespace() => {
                if in_word {
                    out.push(std::mem::take(&mut cur));
                    in_word = false;
                }
            }
            c => {
                in_word = true;
                cur.push(c);
            }
        }
    }
    if in_word {
        out.push(cur);
    }
    Some(out)
}

/// A recognised shellfirm hook command.
#[derive(Debug, Clone, PartialEq, Eq)]
struct HookCmd {
    /// `check --stdin --format json --exit-code` (installed by <= 0.3.10).
    legacy: bool,
    /// `--config-dir` value, if any.
    config_dir: Option<String>,
}

/// Recognise a hook command written by any shellfirm version (or edited by
/// the user with extra shellfirm flags such as `--log debug`) for `target`
/// (`claude-code` or `cursor`). Anything else (another program, shell
/// operators, unknown flags) is not ours.
fn parse_shellfirm_hook(cmd: &str, target: &str) -> Option<HookCmd> {
    let tokens = shell_split(cmd)?;
    let (bin, rest) = tokens.split_first()?;
    let name = Path::new(bin).file_name().and_then(|n| n.to_str())?;
    if name != BINARY && name != "shellfirm.exe" {
        return None;
    }
    let mut it = rest.iter().map(String::as_str);
    let mut seen_check = false;
    let (mut hook, mut config_dir, mut format) = (None, None, None);
    let (mut stdin, mut exit_code) = (false, false);
    let value = |flag: &str, tok: &str, it: &mut dyn Iterator<Item = &str>| -> Option<String> {
        tok.strip_prefix(flag)
            .and_then(|r| r.strip_prefix('='))
            .map(ToString::to_string)
            .or_else(|| {
                (tok == flag)
                    .then(|| it.next().map(ToString::to_string))
                    .flatten()
            })
    };
    while let Some(tok) = it.next() {
        if tok == "check" && !seen_check {
            seen_check = true;
        } else if tok == "--log" || tok.starts_with("--log=") {
            value("--log", tok, &mut it)?;
        } else if !seen_check {
            return None;
        } else if tok == "--hook" || tok.starts_with("--hook=") {
            hook = Some(value("--hook", tok, &mut it)?);
        } else if tok == "--config-dir" || tok.starts_with("--config-dir=") {
            config_dir = Some(value("--config-dir", tok, &mut it)?);
        } else if tok == "--format" || tok.starts_with("--format=") {
            format = Some(value("--format", tok, &mut it)?);
        } else if tok == "--stdin" {
            stdin = true;
        } else if tok == "--exit-code" {
            exit_code = true;
        } else if tok == "--no-context" {
        } else {
            return None;
        }
    }
    if !seen_check {
        return None;
    }
    if hook.as_deref() == Some(target) && format.is_none() && !exit_code {
        return Some(HookCmd {
            legacy: false,
            config_dir,
        });
    }
    // `--format claude-hook|cursor-hook` (optionally with `--stdin` /
    // `--exit-code`, which current versions reject) and `--hook X
    // --exit-code` are shellfirm hooks that must be rewritten.
    let format_target = match format.as_deref() {
        Some("claude-hook") => Some("claude-code"),
        Some("cursor-hook") => Some("cursor"),
        _ => None,
    };
    let hook_format_form = hook.as_deref().map_or_else(
        || format_target == Some(target),
        |h| h == target && (format.is_none() || format_target == Some(target)),
    );
    let legacy = hook_format_form
        || (target == "claude-code"
            && hook.is_none()
            && stdin
            && exit_code
            && format.as_deref() == Some("json"));
    legacy.then_some(HookCmd {
        legacy: true,
        config_dir,
    })
}

fn is_claude_hook(cmd: &str) -> bool {
    parse_shellfirm_hook(cmd, "claude-code").is_some()
}

fn is_cursor_hook(cmd: &str) -> bool {
    parse_shellfirm_hook(cmd, "cursor").is_some()
}

/// Does a Claude Code hook `matcher` select `tool`? Rules from the Claude
/// Code hooks docs: `*`, `""` or omitted match everything; a value made only
/// of letters, digits, `_`, `-`, spaces, `,` and `|` is a list of exact tool
/// names; anything else is an (unanchored) regular expression.
fn matcher_covers(matcher: Option<&str>, tool: &str) -> bool {
    let Some(m) = matcher.map(str::trim) else {
        return true;
    };
    if m.is_empty() || m == "*" {
        return true;
    }
    let exact_list = m
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | ' ' | ',' | '|'));
    if exact_list {
        return m.split(['|', ',']).map(str::trim).any(|t| t == tool);
    }
    regex::Regex::new(m).is_ok_and(|re| re.is_match(tool))
}

// ---------------------------------------------------------------------------
// JSON shape helpers
// ---------------------------------------------------------------------------

fn root_object<'a>(value: &'a mut Value, path: &Path) -> OpResult<&'a mut Map<String, Value>> {
    value.as_object_mut().ok_or_else(|| {
        format!(
            "{} does not contain a JSON object at the top level; refusing to modify it",
            path.display()
        )
    })
}

fn child_object<'a>(
    parent: &'a mut Map<String, Value>,
    key: &str,
    path: &Path,
    create: bool,
) -> OpResult<Option<&'a mut Map<String, Value>>> {
    if !parent.contains_key(key) {
        if !create {
            return Ok(None);
        }
        parent.insert(key.to_string(), json!({}));
    }
    match parent.get_mut(key) {
        Some(Value::Object(m)) => Ok(Some(m)),
        _ => Err(format!(
            "`{key}` in {} is not a JSON object; refusing to modify it",
            path.display()
        )),
    }
}

fn child_array<'a>(
    parent: &'a mut Map<String, Value>,
    key: &str,
    what: &str,
    path: &Path,
    create: bool,
) -> OpResult<Option<&'a mut Vec<Value>>> {
    if !parent.contains_key(key) {
        if !create {
            return Ok(None);
        }
        parent.insert(key.to_string(), json!([]));
    }
    match parent.get_mut(key) {
        Some(Value::Array(a)) => Ok(Some(a)),
        _ => Err(format!(
            "`{what}` in {} is not a JSON array; refusing to modify it",
            path.display()
        )),
    }
}

fn hook_command_of(v: &Value) -> Option<&str> {
    v.get("command").and_then(Value::as_str)
}

/// What is installed in a Claude Code settings file (read-only, tolerant).
#[derive(Debug, Default, Clone, PartialEq, Eq)]
struct ClaudeHookState {
    /// Tools (`Bash` + file-writing tools) covered by a shellfirm hook.
    covered: Vec<&'static str>,
    /// Number of shellfirm hook entries (any matcher).
    entries: usize,
    /// Entries using the legacy `--stdin --format json --exit-code` line.
    legacy: usize,
    /// Entries with `"onFailure": "block"`.
    fail_closed: usize,
    /// `--config-dir` values recorded in the entries.
    config_dirs: Vec<String>,
}

const CLAUDE_TOOLS: &[&str] = &[
    "Bash",
    "PowerShell",
    "Monitor",
    "Write",
    "Edit",
    "MultiEdit",
    "NotebookEdit",
];

fn claude_hook_state(value: &Value) -> ClaudeHookState {
    let mut st = ClaudeHookState::default();
    let Some(groups) = value
        .get("hooks")
        .and_then(|h| h.get("PreToolUse"))
        .and_then(Value::as_array)
    else {
        return st;
    };
    for g in groups {
        let matcher = g.get("matcher").and_then(Value::as_str);
        let Some(hs) = g.get("hooks").and_then(Value::as_array) else {
            continue;
        };
        let mut ours = false;
        for h in hs {
            let Some(hc) = hook_command_of(h).and_then(|c| parse_shellfirm_hook(c, "claude-code"))
            else {
                continue;
            };
            ours = true;
            st.entries += 1;
            st.legacy += usize::from(hc.legacy);
            if h.get("onFailure").and_then(Value::as_str) == Some("block") {
                st.fail_closed += 1;
            }
            if let Some(d) = hc.config_dir {
                if !st.config_dirs.contains(&d) {
                    st.config_dirs.push(d);
                }
            }
        }
        if ours {
            for t in CLAUDE_TOOLS {
                if matcher_covers(matcher, t) && !st.covered.contains(t) {
                    st.covered.push(t);
                }
            }
        }
    }
    st
}

/// Hook settings the user chose themselves on shellfirm's Claude Code hooks
/// (a `timeout` other than [`HOOK_TIMEOUT_SECS`], an `onFailure` other than
/// `block`). `connect` keeps them; the result describes them, e.g.
/// `["timeout 120s", "onFailure: allow"]`.
fn kept_hook_settings(value: &Value) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let Some(groups) = value
        .get("hooks")
        .and_then(|h| h.get("PreToolUse"))
        .and_then(Value::as_array)
    else {
        return out;
    };
    for h in groups
        .iter()
        .filter_map(|g| g.get("hooks").and_then(Value::as_array))
        .flatten()
    {
        if hook_command_of(h).is_none_or(|c| parse_shellfirm_hook(c, "claude-code").is_none()) {
            continue;
        }
        let mut push = |s: String| {
            if !out.contains(&s) {
                out.push(s);
            }
        };
        match h.get("timeout") {
            Some(t) if t.as_u64() != Some(HOOK_TIMEOUT_SECS) => push(format!("timeout {t}s")),
            _ => {}
        }
        match h.get("onFailure") {
            Some(Value::String(v)) if v != "block" => push(format!("onFailure: {v}")),
            Some(v) if !v.is_string() => push(format!("onFailure: {v}")),
            _ => {}
        }
    }
    out
}

/// Read-only: is shellfirm's hook protecting the Bash tool?
#[cfg(test)]
fn claude_hooks_installed(value: &Value) -> bool {
    claude_hook_state(value).covered.contains(&"Bash")
}

/// Cursor hook event holding the shell-command hook.
const CURSOR_SHELL_EVENT: &str = "beforeShellExecution";
/// Cursor hook event holding the file-edit hook.
const CURSOR_TOOL_EVENT: &str = "preToolUse";
/// Matcher of the Cursor file-edit hook (Cursor matchers are regexes; tool
/// names from Cursor's hooks docs).
const CURSOR_FILE_MATCHER: &str = "Write|Delete";

fn cursor_event_entries<'a>(value: &'a Value, event: &str) -> Vec<(HookCmd, &'a Value)> {
    value
        .get("hooks")
        .and_then(|h| h.get(event))
        .and_then(Value::as_array)
        .map(|hs| {
            hs.iter()
                .filter_map(|h| {
                    hook_command_of(h)
                        .and_then(|c| parse_shellfirm_hook(c, "cursor"))
                        .map(|hc| (hc, h))
                })
                .collect()
        })
        .unwrap_or_default()
}

fn cursor_hook_entries(value: &Value) -> Vec<(HookCmd, &Value)> {
    cursor_event_entries(value, CURSOR_SHELL_EVENT)
}

/// shellfirm `preToolUse` entries whose matcher covers Cursor's `Write`.
fn cursor_file_hook_entries(value: &Value) -> Vec<(HookCmd, &Value)> {
    cursor_event_entries(value, CURSOR_TOOL_EVENT)
        .into_iter()
        .filter(|(_, h)| {
            let m = h.get("matcher").and_then(Value::as_str);
            m.is_none_or(|m| {
                m.trim().is_empty()
                    || m == "*"
                    || regex::Regex::new(m).is_ok_and(|re| re.is_match("Write"))
            })
        })
        .collect()
}

#[cfg(test)]
fn cursor_hooks_installed(value: &Value) -> bool {
    !cursor_hook_entries(value).is_empty()
}

fn server_installed(value: &Value, container: &str) -> bool {
    value
        .get(container)
        .and_then(Value::as_object)
        .is_some_and(|m| m.contains_key(BINARY))
}

fn legacy_settings_mcp_present(value: &Value) -> bool {
    value
        .get("mcpServers")
        .and_then(|m| m.get(BINARY))
        .and_then(|s| s.get("command"))
        .and_then(Value::as_str)
        .is_some_and(|c| Path::new(c).file_name().and_then(|n| n.to_str()) == Some(BINARY))
}

/// Bring existing shellfirm hook entries up to date in place: legacy command
/// lines are replaced, a missing `--config-dir` / `timeout` / `onFailure` is
/// added. Returns the number of entries changed.
fn upgrade_hook_entry(
    h: &mut Value,
    hc: &HookCmd,
    args: &str,
    spec: &InstallSpec,
    on_failure: Option<bool>,
) -> bool {
    // A legacy line is rewritten, keeping a custom `--config-dir`.
    let desired = InstallSpec {
        config_dir: hc.config_dir.clone().or_else(|| spec.config_dir.clone()),
        ..spec.clone()
    }
    .hook_command(args);
    let Some(obj) = h.as_object_mut() else {
        return false;
    };
    let mut changed = false;
    let old = obj
        .get("command")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    if hc.legacy {
        obj.insert("command".into(), json!(desired));
        changed = true;
    } else if hc.config_dir.is_none() {
        if let Some(dir) = &spec.config_dir {
            obj.insert(
                "command".into(),
                json!(format!("{old} --config-dir {}", shell_quote(dir))),
            );
            changed = true;
        }
    }
    if !obj.contains_key("timeout") {
        obj.insert("timeout".into(), json!(HOOK_TIMEOUT_SECS));
        changed = true;
    }
    match on_failure {
        Some(true) if !obj.contains_key("onFailure") => {
            obj.insert("onFailure".into(), json!("block"));
            changed = true;
        }
        // `--no-fail-closed`: downgrade an existing fail-closed entry.
        Some(false) if obj.get("onFailure").and_then(Value::as_str) == Some("block") => {
            obj.shift_remove("onFailure");
            changed = true;
        }
        _ => {}
    }
    changed
}

fn claude_hook_entry(spec: &InstallSpec) -> Value {
    let mut entry = json!({
        "type": "command",
        "command": spec.hook_command(CLAUDE_HOOK_ARGS),
        "timeout": HOOK_TIMEOUT_SECS,
    });
    if spec.fail_closed {
        entry["onFailure"] = json!("block");
    }
    entry
}

/// Remove duplicate shellfirm hooks: within a group only the first one is
/// kept, and a group whose matcher adds no tool beyond the earlier
/// shellfirm groups loses its shellfirm hook (the group itself is dropped
/// when nothing else is left in it). Returns the number removed.
fn dedupe_claude_hooks(groups: &mut Vec<Value>) -> usize {
    let mut covered: Vec<&'static str> = Vec::new();
    let mut removed = 0usize;
    groups.retain_mut(|g| {
        let matcher = g
            .get("matcher")
            .and_then(Value::as_str)
            .map(ToString::to_string);
        let Some(hs) = g.get_mut("hooks").and_then(Value::as_array_mut) else {
            return true;
        };
        let ours = |h: &Value| hook_command_of(h).is_some_and(is_claude_hook);
        if !hs.iter().any(ours) {
            return true;
        }
        let adds: Vec<&'static str> = CLAUDE_TOOLS
            .iter()
            .copied()
            .filter(|t| matcher_covers(matcher.as_deref(), t) && !covered.contains(t))
            .collect();
        let keep_one = !adds.is_empty();
        let n = hs.len();
        let mut kept = false;
        hs.retain(|h| {
            if !ours(h) {
                return true;
            }
            if keep_one && !kept {
                kept = true;
                return true;
            }
            false
        });
        removed += n - hs.len();
        covered.extend(adds);
        !hs.is_empty()
    });
    removed
}

#[allow(clippy::too_many_lines)]
fn install_claude_hooks(
    value: &mut Value,
    path: &Path,
    spec: &InstallSpec,
) -> OpResult<Vec<String>> {
    let mut actions = Vec::new();
    let root = root_object(value, path)?;
    let before = claude_hook_state(&Value::Object(root.clone()));
    // New entries use the configuration directory the existing hooks
    // already record (e.g. a team directory), so all hooks read the same
    // settings.
    let spec = &InstallSpec {
        config_dir: before
            .config_dirs
            .first()
            .cloned()
            .or_else(|| spec.config_dir.clone()),
        ..spec.clone()
    };
    let desired = spec.hook_command(CLAUDE_HOOK_ARGS);
    if before.entries > 0 {
        let hooks = child_object(root, "hooks", path, false)?.expect("present");
        let groups =
            child_array(hooks, "PreToolUse", "hooks.PreToolUse", path, false)?.expect("present");
        let duplicates = dedupe_claude_hooks(groups);
        if duplicates > 0 {
            actions.push(format!(
                "remove {duplicates} duplicate shellfirm hook(s) (shellfirm would run twice per tool call)"
            ));
        }
        let mut upgraded = 0usize;
        let mut legacy = 0usize;
        let mut downgraded = 0usize;
        for g in groups.iter_mut() {
            let Some(hs) = g.get_mut("hooks").and_then(Value::as_array_mut) else {
                continue;
            };
            for h in hs.iter_mut() {
                let Some(hc) =
                    hook_command_of(h).and_then(|c| parse_shellfirm_hook(c, "claude-code"))
                else {
                    continue;
                };
                legacy += usize::from(hc.legacy);
                let had_block = h.get("onFailure").and_then(Value::as_str) == Some("block");
                if upgrade_hook_entry(h, &hc, CLAUDE_HOOK_ARGS, spec, Some(spec.fail_closed)) {
                    upgraded += 1;
                    downgraded += usize::from(had_block && h.get("onFailure").is_none());
                }
            }
        }
        if upgraded > 0 {
            // Values the user set themselves are kept (see
            // `kept_hook_settings`): only claim what was actually written.
            let kept = kept_hook_settings(&Value::Object(root.clone()));
            let where_unset = if kept.is_empty() {
                ""
            } else {
                " where not set"
            };
            actions.push(format!(
                "upgrade {upgraded} existing shellfirm hook(s) in place{} (timeout {HOOK_TIMEOUT_SECS}s{}{}{})",
                if legacy > 0 {
                    format!(", replacing {legacy} legacy command line(s) with `{desired}`")
                } else {
                    String::new()
                },
                where_unset,
                if spec.fail_closed {
                    format!(", onFailure: block{where_unset}")
                } else if downgraded > 0 {
                    format!(", onFailure removed from {downgraded} (--no-fail-closed)")
                } else {
                    String::new()
                },
                if spec.config_dir.is_some() { ", pinned --config-dir" } else { "" },
            ));
        }
    }

    let state = claude_hook_state(&Value::Object(root.clone()));
    let hooks = child_object(root, "hooks", path, true)?.expect("created");
    let groups =
        child_array(hooks, "PreToolUse", "hooks.PreToolUse", path, true)?.expect("created");
    let missing_shell: Vec<&str> = shellfirm::agent::SHELL_TOOLS
        .iter()
        .copied()
        .filter(|t| !state.covered.contains(t))
        .collect();
    if !missing_shell.is_empty() {
        let matcher = missing_shell.join("|");
        groups.push(json!({ "matcher": matcher, "hooks": [claude_hook_entry(spec)] }));
        actions.push(format!(
            "add hooks.PreToolUse entry (matcher \"{matcher}\") running `{desired}`"
        ));
    }
    let missing: Vec<&str> = shellfirm::agent::FILE_WRITE_TOOLS
        .iter()
        .copied()
        .filter(|t| !state.covered.contains(t))
        .collect();
    if !missing.is_empty() {
        let matcher = missing.join("|");
        groups.push(json!({ "matcher": matcher, "hooks": [claude_hook_entry(spec)] }));
        actions.push(format!(
            "add hooks.PreToolUse entry (matcher \"{matcher}\") so edits to shellfirm, policy, \
             agent-settings and shell startup files need approval"
        ));
    }
    if before.config_dirs.len() > 1 && (!missing.is_empty() || !missing_shell.is_empty()) {
        actions.push(format!(
            "note: the existing shellfirm hooks use different --config-dir values ({}); the new \
             entries use {}, so different tools may read different settings",
            before.config_dirs.join(", "),
            before.config_dirs[0]
        ));
    }
    Ok(actions)
}

/// Upgrade (and dedupe) the shellfirm entries of one Cursor hook event.
/// Returns `(entries kept, upgraded, failClosed removed, duplicates removed)`.
fn upgrade_cursor_event(list: &mut Vec<Value>, spec: &InstallSpec) -> (usize, usize, usize, usize) {
    let (mut kept, mut upgraded, mut unfailed) = (0usize, 0usize, 0usize);
    let n = list.len();
    let mut seen = false;
    list.retain(|h| {
        if !hook_command_of(h).is_some_and(is_cursor_hook) {
            return true;
        }
        let keep = !seen;
        seen = true;
        keep
    });
    let duplicates = n - list.len();
    for h in list.iter_mut() {
        let Some(hc) = hook_command_of(h).and_then(|c| parse_shellfirm_hook(c, "cursor")) else {
            continue;
        };
        kept += 1;
        let mut changed = upgrade_hook_entry(h, &hc, CURSOR_HOOK_ARGS, spec, None);
        // shellfirm prints nothing for safe commands; with `failClosed`
        // Cursor treats "no output" as a failure and would block them all.
        if let Some(obj) = h.as_object_mut() {
            if obj.get("failClosed").and_then(Value::as_bool) == Some(true) {
                obj.shift_remove("failClosed");
                unfailed += 1;
                changed = true;
            }
        }
        upgraded += usize::from(changed);
    }
    (kept, upgraded, unfailed, duplicates)
}

fn install_cursor_hooks(
    value: &mut Value,
    path: &Path,
    spec: &InstallSpec,
) -> OpResult<Vec<String>> {
    let mut actions = Vec::new();
    let existing_dir = cursor_hook_entries(value)
        .into_iter()
        .chain(cursor_event_entries(value, CURSOR_TOOL_EVENT))
        .find_map(|(hc, _)| hc.config_dir);
    let spec = &InstallSpec {
        config_dir: existing_dir.or_else(|| spec.config_dir.clone()),
        ..spec.clone()
    };
    let desired = spec.hook_command(CURSOR_HOOK_ARGS);
    let has_file_hook = !cursor_file_hook_entries(value).is_empty();
    let root = root_object(value, path)?;
    let had_hooks_key = root.contains_key("hooks");
    let hooks = child_object(root, "hooks", path, true)?.expect("created");
    let mut kept_shell = 0usize;
    for event in [CURSOR_SHELL_EVENT, CURSOR_TOOL_EVENT] {
        let Some(list) = child_array(hooks, event, &format!("hooks.{event}"), path, false)? else {
            continue;
        };
        let (kept, upgraded, unfailed, duplicates) = upgrade_cursor_event(list, spec);
        if event == CURSOR_SHELL_EVENT {
            kept_shell = kept;
        }
        if duplicates > 0 {
            actions.push(format!(
                "remove {duplicates} duplicate shellfirm hook(s) from hooks.{event}"
            ));
        }
        if unfailed > 0 {
            actions.push(format!(
                "remove \"failClosed\": true from {unfailed} shellfirm hook(s) in hooks.{event} \
                 (shellfirm prints nothing for safe commands, which Cursor would treat as a \
                 failure and block)"
            ));
        }
        if upgraded > unfailed {
            actions.push(format!(
                "upgrade {} existing shellfirm hook(s) in hooks.{event} in place (timeout {HOOK_TIMEOUT_SECS}s{})",
                upgraded - unfailed,
                if spec.config_dir.is_some() { ", pinned --config-dir" } else { "" }
            ));
        }
    }
    if kept_shell == 0 {
        let list = child_array(
            hooks,
            CURSOR_SHELL_EVENT,
            "hooks.beforeShellExecution",
            path,
            true,
        )?
        .expect("created");
        list.push(json!({ "command": desired, "timeout": HOOK_TIMEOUT_SECS }));
        actions.push(format!(
            "add hooks.beforeShellExecution entry running `{desired}`"
        ));
    }
    if !has_file_hook {
        let list = child_array(hooks, CURSOR_TOOL_EVENT, "hooks.preToolUse", path, true)?
            .expect("created");
        list.push(json!({
            "command": desired,
            "matcher": CURSOR_FILE_MATCHER,
            "timeout": HOOK_TIMEOUT_SECS,
        }));
        actions.push(format!(
            "add hooks.preToolUse entry (matcher \"{CURSOR_FILE_MATCHER}\") so agent edits to \
             shellfirm, policy, agent-settings and shell startup files are blocked"
        ));
    }
    if hooks.is_empty() && !had_hooks_key {
        root.shift_remove("hooks");
    }
    if !actions.is_empty() && !root.contains_key("version") {
        root.insert("version".into(), json!(1));
    }
    Ok(actions)
}

/// Apply an install operation. Returns human-readable action descriptions
/// (empty = nothing to do).
fn install(
    op: OpKind,
    value: &mut Value,
    path: &Path,
    spec: &InstallSpec,
) -> OpResult<Vec<String>> {
    match op {
        OpKind::ClaudeHooks => return install_claude_hooks(value, path, spec),
        OpKind::CursorHooks => return install_cursor_hooks(value, path, spec),
        OpKind::LegacyClaudeSettingsMcp => return uninstall(op, value, path),
        OpKind::ClaudeMcp | OpKind::StandardMcp | OpKind::ZedMcp => {}
    }
    let container = if op == OpKind::ZedMcp {
        "context_servers"
    } else {
        "mcpServers"
    };
    if server_installed(value, container) {
        return Ok(Vec::new());
    }
    let root = root_object(value, path)?;
    let args = spec.mcp_args();
    let entry = match op {
        OpKind::ClaudeMcp => {
            json!({ "type": "stdio", "command": BINARY, "args": args, "env": {} })
        }
        OpKind::ZedMcp => json!({ "command": BINARY, "args": args, "env": {} }),
        _ => json!({ "command": BINARY, "args": args }),
    };
    let servers = child_object(root, container, path, true)?.expect("created");
    servers.insert(BINARY.into(), entry.clone());
    Ok(vec![format!("add {container}.{BINARY} = {entry}")])
}

/// Apply an uninstall operation, removing only shellfirm's own entries.
fn uninstall(op: OpKind, value: &mut Value, path: &Path) -> OpResult<Vec<String>> {
    let Some(root) = value.as_object_mut() else {
        // Nothing of ours can be in a non-object file.
        return Ok(Vec::new());
    };
    let mut actions = Vec::new();
    match op {
        OpKind::ClaudeHooks => {
            let Some(hooks) = child_object(root, "hooks", path, false)? else {
                return Ok(actions);
            };
            let Some(groups) = child_array(hooks, "PreToolUse", "hooks.PreToolUse", path, false)?
            else {
                return Ok(actions);
            };
            let before = groups.len();
            let mut removed = 0usize;
            groups.retain_mut(|group| {
                let Some(inner) = group.get_mut("hooks").and_then(Value::as_array_mut) else {
                    return true;
                };
                let n = inner.len();
                inner.retain(|h| !hook_command_of(h).is_some_and(is_claude_hook));
                removed += n - inner.len();
                // Drop the group only when it became empty because of us.
                !(n > 0 && inner.is_empty())
            });
            if removed > 0 {
                actions.push(format!(
                    "remove {removed} shellfirm hook(s) from hooks.PreToolUse"
                ));
                if groups.is_empty() && before > 0 {
                    hooks.shift_remove("PreToolUse");
                    if hooks.is_empty() {
                        root.shift_remove("hooks");
                    }
                }
            }
        }
        OpKind::CursorHooks => {
            let Some(hooks) = child_object(root, "hooks", path, false)? else {
                return Ok(actions);
            };
            for event in [CURSOR_SHELL_EVENT, CURSOR_TOOL_EVENT] {
                let Some(list) = child_array(hooks, event, &format!("hooks.{event}"), path, false)?
                else {
                    continue;
                };
                let n = list.len();
                list.retain(|h| !hook_command_of(h).is_some_and(is_cursor_hook));
                if list.len() < n {
                    actions.push(format!("remove shellfirm hook from hooks.{event}"));
                    if list.is_empty() {
                        hooks.shift_remove(event);
                    }
                }
            }
            if hooks.is_empty() && !actions.is_empty() {
                root.shift_remove("hooks");
            }
        }
        OpKind::ClaudeMcp
        | OpKind::StandardMcp
        | OpKind::ZedMcp
        | OpKind::LegacyClaudeSettingsMcp => {
            if op == OpKind::LegacyClaudeSettingsMcp
                && !legacy_settings_mcp_present(&Value::Object(root.clone()))
            {
                return Ok(actions);
            }
            let container = if op == OpKind::ZedMcp {
                "context_servers"
            } else {
                "mcpServers"
            };
            let Some(servers) = child_object(root, container, path, false)? else {
                return Ok(actions);
            };
            if servers.shift_remove(BINARY).is_some() {
                actions.push(if op == OpKind::LegacyClaudeSettingsMcp {
                    format!(
                        "remove stale {container}.{BINARY} (Claude Code does not load MCP servers from this file)"
                    )
                } else {
                    format!("remove {container}.{BINARY}")
                });
                if servers.is_empty() {
                    root.shift_remove(container);
                }
            }
        }
    }
    Ok(actions)
}

/// `true` when a file holds nothing but (at most) a Cursor `version` key, so
/// it can be deleted instead of being left behind as a `{}` stub.
fn is_empty_stub(value: &Value, ops: &[OpKind]) -> bool {
    value.as_object().is_some_and(|m| {
        m.is_empty()
            || (ops.contains(&OpKind::CursorHooks) && m.len() == 1 && m.contains_key("version"))
    })
}

// ---------------------------------------------------------------------------
// Status (used by `shellfirm status`)
// ---------------------------------------------------------------------------

/// The state of one AI-agent integration, for `shellfirm status`.
// Consumed by `status` (wired up by the status/config workstream).
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone, PartialEq, Eq, serde_derive::Serialize)]
pub struct IntegrationStatus {
    /// `claude-code`, `cursor`, `windsurf`, `zed` or `cline`.
    pub tool: &'static str,
    /// `user` or `project`.
    pub scope: &'static str,
    /// File holding the command hook (tools with hooks only).
    pub hook_file: Option<String>,
    /// A shellfirm hook intercepts the agent's shell commands (Claude Code:
    /// its matcher covers `Bash`).
    pub hook_installed: bool,
    /// At least one shellfirm hook entry exists, whatever its matcher. With
    /// `hook_installed == false` this means "hook present but Bash not
    /// covered" (e.g. an `Edit|Write`-only entry).
    pub hook_present: bool,
    /// Claude Code shell tools (`Bash`, `PowerShell`, `Monitor`) that no
    /// shellfirm hook covers while a hook is present (re-run `connect`).
    pub shell_tools_missing: Vec<&'static str>,
    /// Claude Code: Write/Edit/MultiEdit/NotebookEdit are covered too.
    /// Cursor: a `preToolUse` hook covers `Write`.
    pub file_tools_covered: bool,
    /// At least one hook uses the legacy (<= 0.3.10) command line.
    pub legacy_hook: bool,
    /// Every shellfirm hook blocks the tool call when shellfirm cannot run
    /// (Claude Code `onFailure: block`; Cursor hooks are never fail-closed).
    pub fail_closed: bool,
    /// Configuration directory recorded in the hook command.
    pub config_dir: Option<String>,
    /// File holding the MCP server registration.
    pub mcp_file: Option<String>,
    /// shellfirm is registered as an MCP server.
    pub mcp_registered: bool,
    /// A file could not be read or parsed.
    pub error: Option<String>,
}

#[allow(dead_code)]
fn read_value(path: &Path) -> std::result::Result<Option<Value>, String> {
    if !path.exists() {
        return Ok(None);
    }
    let content = fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
    parse_jsonc(&content)
        .map(|(v, _)| Some(v))
        .map_err(|e| format!("{}: {e}", path.display()))
}

/// Report every AI-agent integration shellfirm knows about, for the user
/// (`home`) and, when it differs, the project (`cwd`) scope.
///
/// Call it from `shellfirm status` as
/// `connect_cmd::integration_status(&home, &cwd)` (both from `dirs::home_dir()`
/// / `std::env::current_dir()`); rows with neither a hook (`hook_present`)
/// nor an MCP registration can be hidden. A row with `hook_present` but not
/// `hook_installed` should be shown as "hook present but Bash not covered",
/// and a non-empty `shell_tools_missing` as "PowerShell/Monitor not covered".
#[must_use]
#[allow(clippy::too_many_lines)]
pub fn integration_status(home: &Path, cwd: &Path) -> Vec<IntegrationStatus> {
    let env = ConnectEnv {
        home: home.to_path_buf(),
        cwd: cwd.to_path_buf(),
        backup_dir: None,
        config_dir: None,
    };
    let mut out = Vec::new();
    let mut scopes = vec![Scope::User];
    if cwd != home {
        scopes.push(Scope::Project);
    }
    for provider in [
        Provider::ClaudeCode,
        Provider::Cursor,
        Provider::Windsurf,
        Provider::Zed,
        Provider::Cline,
    ] {
        for &scope in &scopes {
            if scope == Scope::Project && !provider.supports_scope() {
                continue;
            }
            let opts = Options {
                dry_run: true,
                uninstall: false,
                hooks: provider.supports_hooks(),
                mcp: true,
                scope,
                fail_closed: true,
            };
            let Ok(files) = plan(provider, &opts, &env) else {
                continue;
            };
            let mut st = IntegrationStatus {
                tool: provider.cli_name(),
                scope: if scope == Scope::User {
                    "user"
                } else {
                    "project"
                },
                hook_file: None,
                hook_installed: false,
                hook_present: false,
                shell_tools_missing: Vec::new(),
                file_tools_covered: false,
                legacy_hook: false,
                fail_closed: false,
                config_dir: None,
                mcp_file: None,
                mcp_registered: false,
                error: None,
            };
            for (path, ops) in files {
                let value = match read_value(&path) {
                    Ok(v) => v.unwrap_or_else(|| json!({})),
                    Err(e) => {
                        st.error = Some(e);
                        continue;
                    }
                };
                for op in ops {
                    match op {
                        OpKind::ClaudeHooks => {
                            let s = claude_hook_state(&value);
                            st.hook_file = Some(path.display().to_string());
                            st.hook_installed = s.covered.contains(&"Bash");
                            st.hook_present = s.entries > 0;
                            if s.entries > 0 {
                                st.shell_tools_missing = shellfirm::agent::SHELL_TOOLS
                                    .iter()
                                    .copied()
                                    .filter(|t| !s.covered.contains(t))
                                    .collect();
                            }
                            st.file_tools_covered = shellfirm::agent::FILE_WRITE_TOOLS
                                .iter()
                                .all(|t| s.covered.contains(t));
                            st.legacy_hook = s.legacy > 0;
                            st.fail_closed = s.entries > 0 && s.fail_closed == s.entries;
                            st.config_dir = s.config_dirs.first().cloned();
                        }
                        OpKind::CursorHooks => {
                            let entries = cursor_hook_entries(&value);
                            st.hook_file = Some(path.display().to_string());
                            let files = cursor_file_hook_entries(&value);
                            st.hook_installed = !entries.is_empty();
                            st.hook_present = !entries.is_empty()
                                || !cursor_event_entries(&value, CURSOR_TOOL_EVENT).is_empty();
                            st.file_tools_covered = !files.is_empty();
                            st.legacy_hook =
                                entries.iter().chain(files.iter()).any(|(hc, _)| hc.legacy);
                            st.config_dir =
                                entries.iter().find_map(|(hc, _)| hc.config_dir.clone());
                        }
                        OpKind::ClaudeMcp | OpKind::StandardMcp | OpKind::ZedMcp => {
                            let container = if op == OpKind::ZedMcp {
                                "context_servers"
                            } else {
                                "mcpServers"
                            };
                            st.mcp_file = Some(path.display().to_string());
                            st.mcp_registered = server_installed(&value, container);
                        }
                        OpKind::LegacyClaudeSettingsMcp => {}
                    }
                }
            }
            out.push(st);
        }
    }
    out
}

// ---------------------------------------------------------------------------
// JSONC parsing and safe file IO
// ---------------------------------------------------------------------------

/// Strip `//` and `/* */` comments and trailing commas (outside strings).
/// Returns the cleaned text and whether anything was removed.
fn strip_jsonc(input: &str) -> (String, bool) {
    let input = input.strip_prefix('\u{feff}').unwrap_or(input);
    let chars: Vec<char> = input.chars().collect();
    let mut out = String::with_capacity(input.len());
    let mut changed = false;
    let mut i = 0;
    let mut in_str = false;
    while i < chars.len() {
        let c = chars[i];
        if in_str {
            out.push(c);
            if c == '\\' && i + 1 < chars.len() {
                out.push(chars[i + 1]);
                i += 2;
                continue;
            }
            if c == '"' {
                in_str = false;
            }
            i += 1;
            continue;
        }
        match c {
            '"' => {
                in_str = true;
                out.push(c);
                i += 1;
            }
            '/' if chars.get(i + 1) == Some(&'/') => {
                changed = true;
                while i < chars.len() && chars[i] != '\n' {
                    i += 1;
                }
            }
            '/' if chars.get(i + 1) == Some(&'*') => {
                changed = true;
                i += 2;
                while i < chars.len() && !(chars[i] == '*' && chars.get(i + 1) == Some(&'/')) {
                    if chars[i] == '\n' {
                        out.push('\n');
                    }
                    i += 1;
                }
                i += 2;
                out.push(' ');
            }
            _ => {
                out.push(c);
                i += 1;
            }
        }
    }

    // Second pass: trailing commas.
    let chars: Vec<char> = out.chars().collect();
    let mut result = String::with_capacity(out.len());
    let mut in_str = false;
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        if in_str {
            result.push(c);
            if c == '\\' && i + 1 < chars.len() {
                result.push(chars[i + 1]);
                i += 2;
                continue;
            }
            if c == '"' {
                in_str = false;
            }
        } else if c == '"' {
            in_str = true;
            result.push(c);
        } else if c == ',' {
            let next = chars[i + 1..].iter().find(|ch| !ch.is_whitespace());
            if matches!(next, Some('}' | ']')) {
                changed = true;
            } else {
                result.push(c);
            }
        } else {
            result.push(c);
        }
        i += 1;
    }
    (result, changed)
}

/// Parse JSON or JSONC. Returns the value and whether comments/trailing
/// commas were present (they cannot be preserved on rewrite).
fn parse_jsonc(content: &str) -> std::result::Result<(Value, bool), String> {
    if content.trim().is_empty() {
        return Ok((json!({}), false));
    }
    match serde_json::from_str(content.strip_prefix('\u{feff}').unwrap_or(content)) {
        Ok(v) => Ok((v, false)),
        Err(strict_err) => {
            let (clean, changed) = strip_jsonc(content);
            if !changed {
                return Err(strict_err.to_string());
            }
            serde_json::from_str(&clean)
                .map(|v| (v, true))
                .map_err(|e| e.to_string())
        }
    }
}

struct LoadedFile {
    /// Path as shown to the user.
    path: PathBuf,
    /// Where to write (symlink target if `path` is a symlink).
    write_path: PathBuf,
    exists: bool,
    value: Value,
    lossy_format: bool,
}

fn load_file(path: &Path) -> OpResult<LoadedFile> {
    if !path.exists() {
        if fs::symlink_metadata(path).is_ok() {
            return Err(format!(
                "{} is a dangling symlink; refusing to modify it",
                path.display()
            ));
        }
        return Ok(LoadedFile {
            path: path.to_path_buf(),
            write_path: path.to_path_buf(),
            exists: false,
            value: json!({}),
            lossy_format: false,
        });
    }
    let write_path = fs::canonicalize(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let bytes = fs::read(path).map_err(|e| format!("could not read {}: {e}", path.display()))?;
    let content = String::from_utf8(bytes).map_err(|_| {
        format!(
            "{} is not valid UTF-8; refusing to modify it",
            path.display()
        )
    })?;
    let (value, lossy_format) = parse_jsonc(&content).map_err(|e| {
        format!(
            "could not parse {} as JSON/JSONC ({e}); nothing was changed. Fix the file or edit it by hand.",
            path.display()
        )
    })?;
    Ok(LoadedFile {
        path: path.to_path_buf(),
        write_path,
        exists: true,
        value,
        lossy_format,
    })
}

/// Where to back up `path`. With `backup_dir` (project scope) the backup
/// goes there, named after the full path, so nothing lands in the repository.
fn backup_path_for(path: &Path, backup_dir: Option<&Path>) -> PathBuf {
    let stamp: String = shellfirm::audit::now_timestamp()
        .chars()
        .filter(char::is_ascii_alphanumeric)
        .collect();
    let (dir, name) = backup_dir.map_or_else(
        || {
            (
                path.parent().map(Path::to_path_buf).unwrap_or_default(),
                path.file_name()
                    .map_or_else(|| "config".into(), |n| n.to_string_lossy().into_owned()),
            )
        },
        |d| {
            let flat: String = path
                .display()
                .to_string()
                .trim_start_matches(['/', '\\'])
                .chars()
                .map(|c| {
                    if matches!(c, '/' | '\\' | ':') {
                        '%'
                    } else {
                        c
                    }
                })
                .collect();
            (d.to_path_buf(), flat)
        },
    );
    let mut candidate = dir.join(format!("{name}.shellfirm-bak-{stamp}"));
    let mut n = 1;
    while candidate.exists() {
        candidate = dir.join(format!("{name}.shellfirm-bak-{stamp}-{n}"));
        n += 1;
    }
    candidate
}

fn create_private_dir(dir: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dir)
    }
    #[cfg(not(unix))]
    {
        fs::create_dir_all(dir)
    }
}

/// What to do with a file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SaveMode {
    Write,
    /// The file would only be an empty stub after uninstall: delete it.
    Remove,
}

/// Write `value` to `file` atomically (or remove the file), after backing up
/// the existing file. Returns the backup path (if a backup was made).
fn save_file(
    file: &LoadedFile,
    value: &Value,
    backup_dir: Option<&Path>,
    mode: SaveMode,
) -> OpResult<Option<PathBuf>> {
    let target = &file.write_path;
    let mut backup = None;
    let mut permissions = None;
    if file.exists {
        let meta = fs::metadata(target).map_err(|e| format!("{}: {e}", file.path.display()))?;
        if meta.permissions().readonly() {
            return Err(format!(
                "{} is read-only; make it writable or edit it by hand",
                file.path.display()
            ));
        }
        permissions = Some(meta.permissions());
        if let Some(d) = backup_dir {
            create_private_dir(d)
                .map_err(|e| format!("could not create backup directory {}: {e}", d.display()))?;
        }
        let bak = backup_path_for(target, backup_dir);
        fs::copy(target, &bak)
            .map_err(|e| format!("could not back up {}: {e}", file.path.display()))?;
        backup = Some(bak);
    }

    if mode == SaveMode::Remove {
        if file.exists {
            fs::remove_file(target)
                .map_err(|e| format!("could not remove {}: {e}", file.path.display()))?;
        }
        return Ok(backup);
    }

    let parent = target
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .map_or_else(|| PathBuf::from("."), Path::to_path_buf);
    fs::create_dir_all(&parent)
        .map_err(|e| format!("could not create {}: {e}", parent.display()))?;

    let text = serde_json::to_string_pretty(value).map_err(|e| e.to_string())? + "\n";
    let name = target
        .file_name()
        .map_or_else(|| "config".into(), |n| n.to_string_lossy().into_owned());
    let tmp = parent.join(format!(".{name}.shellfirm-tmp-{}", std::process::id()));
    let write = || -> std::io::Result<()> {
        let mut f = fs::File::create(&tmp)?;
        f.write_all(text.as_bytes())?;
        f.sync_all()?;
        if let Some(ref p) = permissions {
            fs::set_permissions(&tmp, p.clone())?;
        }
        fs::rename(&tmp, target)
    };
    if let Err(e) = write() {
        let _ = fs::remove_file(&tmp);
        return Err(format!("could not write {}: {e}", file.path.display()));
    }
    Ok(backup)
}

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

fn dry_run_arg() -> Arg {
    Arg::new("dry-run")
        .long("dry-run")
        .help("Show what would change without writing anything")
        .action(ArgAction::SetTrue)
}

fn uninstall_arg() -> Arg {
    Arg::new("uninstall")
        .long("uninstall")
        .help("Remove shellfirm's entries (only those; other config is kept)")
        .action(ArgAction::SetTrue)
}

fn hooks_tool_subcommand(name: &'static str, about: &'static str, long: &'static str) -> Command {
    let cmd = Command::new(name);
    let cmd = if name == "claude-code" {
        cmd.arg(
            Arg::new("no-fail-closed")
                .long("no-fail-closed")
                .help("Don't add \"onFailure\": \"block\" to the hook (for Claude Code older than 2.1.295)")
                .action(ArgAction::SetTrue),
        )
    } else {
        cmd
    };
    cmd
        .about(about)
        .long_about(long)
        .arg(
            Arg::new("hooks-only")
                .long("hooks-only")
                .help("Only the command-interception hook (no MCP)")
                .action(ArgAction::SetTrue)
                .conflicts_with("mcp-only"),
        )
        .arg(
            Arg::new("mcp-only")
                .long("mcp-only")
                .help("Only the MCP server registration (no hook)")
                .action(ArgAction::SetTrue)
                .conflicts_with("hooks-only"),
        )
        .arg(
            Arg::new("scope")
                .long("scope")
                .help("user: your home directory (default); project: the current directory (for team rollout)")
                .value_parser(["user", "project"])
                .default_value("user"),
        )
        .arg(dry_run_arg())
        .arg(uninstall_arg())
}

fn mcp_only_subcommand(name: &'static str, about: &'static str) -> Command {
    Command::new(name)
        .about(about)
        .arg(dry_run_arg())
        .arg(uninstall_arg())
}

pub fn command() -> Command {
    Command::new("connect")
        .about("Connect AI tool integrations (hooks + MCP)")
        .arg_required_else_help(true)
        .subcommand(hooks_tool_subcommand(
            "claude-code",
            "Connect Claude Code (PreToolUse hook + MCP server)",
            "Connect Claude Code.\n\n\
            user scope:    hook in ~/.claude/settings.json, MCP server in ~/.claude.json\n\
            project scope: hook in ./.claude/settings.json, MCP server in ./.mcp.json\n\n\
            The hook runs `shellfirm check --hook claude-code` before every tool call that runs \
            a shell command (matcher Bash|PowerShell|Monitor): risky commands get an `ask` \
            prompt, dangerous ones are denied, everything else is left to Claude Code's normal \
            permission rules. A second PreToolUse entry (matcher \
            Write|Edit|MultiEdit|NotebookEdit) asks before the agent edits shellfirm, \
            project-policy, agent-settings, hook or shell startup files.\n\n\
            Hooks are written with \"timeout\": 30 and \"onFailure\": \"block\" (Claude Code \
            >= 2.1.295 then blocks the tool call when shellfirm is missing, crashes or times \
            out; use --no-fail-closed for older versions, which also removes \
            \"onFailure\" from existing shellfirm hooks). User-scope hooks record the \
            configuration directory (--config-dir) so a redirected HOME/XDG_CONFIG_HOME cannot \
            swap in other settings. Existing shellfirm hooks (also legacy ones and ones with \
            extra flags such as --log debug) are upgraded in place, duplicate shellfirm hooks are \
            removed, and new entries reuse the --config-dir already recorded. Project-scope backups are \
            written to ~/.cache/shellfirm/backups, not into the repository.",
        ))
        .subcommand(hooks_tool_subcommand(
            "cursor",
            "Connect Cursor (beforeShellExecution hook + MCP server)",
            "Connect Cursor.\n\n\
            user scope:    ~/.cursor/hooks.json and ~/.cursor/mcp.json\n\
            project scope: ./.cursor/hooks.json and ./.cursor/mcp.json\n\n\
            The beforeShellExecution hook answers deny/ask for risky commands and prints \
            nothing for safe ones (Cursor documents no neutral answer, and an explicit allow \
            could skip Cursor's own approval). A preToolUse hook (matcher Write|Delete) denies \
            agent edits of shellfirm, policy, agent-settings, hook and shell startup files \
            (Cursor does not enforce `ask` for preToolUse, so the user makes such changes by \
            hand). The hooks are not marked failClosed (Cursor counts \"no output\" as a \
            failure and would then block every safe command; an existing failClosed on a \
            shellfirm hook is removed): if shellfirm is missing or times out, Cursor lets the \
            action through. shellfirm itself never exits without a decision for risky input \
            (crashes become deny).",
        ))
        .subcommand(mcp_only_subcommand(
            "windsurf",
            "Register shellfirm's MCP tools with Windsurf (advisory; no interception)",
        ))
        .subcommand(mcp_only_subcommand(
            "zed",
            "Register shellfirm's MCP tools with Zed (advisory; no interception)",
        ))
        .subcommand(mcp_only_subcommand(
            "cline",
            "Register shellfirm's MCP tools with Cline (advisory; no interception)",
        ))
}

fn flag(m: &ArgMatches, name: &str) -> bool {
    m.try_get_one::<bool>(name)
        .ok()
        .flatten()
        .copied()
        .unwrap_or(false)
}

#[allow(clippy::unnecessary_wraps)]
pub fn run(matches: &ArgMatches) -> Result<shellfirm::CmdExit> {
    let Some((name, sub)) = matches.subcommand() else {
        return Ok(shellfirm::CmdExit {
            code: 2,
            message: Some(format!("Specify an AI tool: {SUPPORTED_PROVIDERS}")),
        });
    };
    let Some(provider) = Provider::from_name(name) else {
        return Ok(shellfirm::CmdExit {
            code: 2,
            message: Some(format!(
                "Unknown AI tool: {name}. Supported: {SUPPORTED_PROVIDERS}"
            )),
        });
    };
    let Some(home) = dirs::home_dir() else {
        return Ok(shellfirm::CmdExit {
            code: 1,
            message: Some("Could not determine your home directory".into()),
        });
    };
    let hooks_only = flag(sub, "hooks-only");
    let mcp_only = flag(sub, "mcp-only");
    let scope = match sub
        .try_get_one::<String>("scope")
        .ok()
        .flatten()
        .map(String::as_str)
    {
        Some("project") => Scope::Project,
        _ => Scope::User,
    };
    let opts = Options {
        dry_run: flag(sub, "dry-run"),
        uninstall: flag(sub, "uninstall"),
        hooks: !mcp_only && provider.supports_hooks(),
        mcp: !hooks_only,
        scope,
        fail_closed: !flag(sub, "no-fail-closed"),
    };
    let env = ConnectEnv {
        home,
        cwd: std::env::current_dir().unwrap_or_default(),
        backup_dir: (scope == Scope::Project)
            .then(|| dirs::cache_dir().map(|d| d.join("shellfirm").join("backups")))
            .flatten(),
        config_dir: shellfirm::Config::new(None).ok().map(|c| c.root_folder),
    };

    let mut out = String::new();
    let res = execute(provider, &opts, &env, &mut out);
    {
        let mut stdout = std::io::stdout().lock();
        if let Err(e) = stdout
            .write_all(out.as_bytes())
            .and_then(|()| stdout.flush())
        {
            return Ok(shellfirm::CmdExit {
                code: 74,
                message: Some(format!("shellfirm: error: writing output: {e}")),
            });
        }
    }
    Ok(match res {
        Ok(()) => shellfirm::CmdExit {
            code: 0,
            message: None,
        },
        Err(e) => shellfirm::CmdExit {
            code: 1,
            message: Some(format!("Error: {e}")),
        },
    })
}

/// Run the whole connect/uninstall flow, writing user-facing output to `out`.
#[allow(clippy::too_many_lines, clippy::trivially_copy_pass_by_ref)]
fn execute(provider: Provider, opts: &Options, env: &ConnectEnv, out: &mut String) -> OpResult<()> {
    let verb = if opts.uninstall {
        "removing"
    } else {
        "connecting"
    };
    let _ = writeln!(
        out,
        "\nshellfirm {} {verb} {} integration{}\n",
        shellfirm::config::glyph("—", "-"),
        provider.display_name(),
        if opts.dry_run { " (dry run)" } else { "" }
    );

    if !opts.hooks && !opts.mcp {
        return Err(format!(
            "{} has no command hook; run `shellfirm connect {}` without --hooks-only",
            provider.display_name(),
            match provider {
                Provider::Windsurf => "windsurf",
                Provider::Zed => "zed",
                Provider::Cline => "cline",
                _ => "<tool>",
            }
        ));
    }
    if opts.scope == Scope::Project && !provider.supports_scope() {
        return Err(format!(
            "{} does not support --scope project",
            provider.display_name()
        ));
    }

    // 1. Load and parse every file first; abort before writing anything.
    let files = plan(provider, opts, env)?;
    let mut loaded = Vec::new();
    for (path, ops) in files {
        loaded.push((load_file(&path)?, ops));
    }

    // 2. Compute changes in memory.
    let spec = InstallSpec {
        // A project-scope file is shared with the team: no personal paths.
        config_dir: if opts.scope == Scope::User {
            env.config_dir.as_ref().map(|d| d.display().to_string())
        } else {
            None
        },
        fail_closed: opts.fail_closed,
    };
    let mut changes: Vec<(&LoadedFile, Value, Vec<String>, SaveMode)> = Vec::new();
    let mut already: Vec<Component> = Vec::new();
    for (file, ops) in &loaded {
        let mut value = file.value.clone();
        let mut actions = Vec::new();
        for op in ops {
            let acts = if opts.uninstall {
                uninstall(*op, &mut value, &file.path)?
            } else {
                install(*op, &mut value, &file.path, &spec)?
            };
            if acts.is_empty() && !opts.uninstall && *op != OpKind::LegacyClaudeSettingsMcp {
                already.push(op.component());
            }
            actions.extend(acts);
        }
        if !actions.is_empty() {
            // Don't leave `{}` stubs behind (a symlinked file is kept).
            let mode =
                if opts.uninstall && is_empty_stub(&value, ops) && file.path == file.write_path {
                    actions.push("delete the file (only shellfirm's entries were in it)".into());
                    SaveMode::Remove
                } else {
                    SaveMode::Write
                };
            changes.push((file, value, actions, mode));
        }
    }

    for c in &already {
        let _ = writeln!(
            out,
            "  = {} already installed",
            if *c == Component::Hooks {
                "Hook"
            } else {
                "MCP server"
            }
        );
    }
    // Settings the user chose on existing hooks are kept: say so, with the
    // values shellfirm would have written.
    if !opts.uninstall {
        for (file, _) in &loaded {
            let value = changes
                .iter()
                .find(|c| std::ptr::eq(c.0, file))
                .map_or(&file.value, |c| &c.1);
            let kept = kept_hook_settings(value);
            if !kept.is_empty() {
                let _ = writeln!(
                    out,
                    "  ! kept your own hook settings in {} ({}); shellfirm writes timeout {HOOK_TIMEOUT_SECS}s{} \
                     on new hooks. Edit the file to change them.",
                    file.path.display(),
                    kept.join(", "),
                    if opts.fail_closed {
                        " and onFailure: block (fail closed)"
                    } else {
                        ""
                    }
                );
            }
        }
    }

    if changes.is_empty() {
        let _ = writeln!(
            out,
            "\nNothing to change: {}",
            if opts.uninstall {
                format!(
                    "no shellfirm configuration found for {}.",
                    provider.display_name()
                )
            } else {
                format!(
                    "shellfirm is already connected to {}.",
                    provider.display_name()
                )
            }
        );
        return Ok(());
    }

    // 3. Show the plan / write.
    let mut written: Vec<String> = Vec::new();
    let backup_dir = env.backup_dir.as_deref();
    for (file, value, actions, mode) in &changes {
        if opts.dry_run {
            let _ = writeln!(
                out,
                "  Would {} {}:",
                if file.exists { "update" } else { "create" },
                file.path.display()
            );
        } else {
            let _ = writeln!(out, "  {}:", file.path.display());
        }
        for a in actions {
            let _ = writeln!(out, "    - {a}");
        }
        if file.lossy_format {
            let _ = writeln!(
                out,
                "    ! this file contains comments or trailing commas, which will not be kept (a backup is made first)"
            );
        }
        if opts.dry_run {
            if file.exists {
                let _ = writeln!(
                    out,
                    "    (a timestamped backup would be written first{})",
                    backup_dir.map_or_else(String::new, |d| format!(" to {}", d.display()))
                );
            }
            continue;
        }
        match save_file(file, value, backup_dir, *mode) {
            Ok(backup) => {
                written.push(file.path.display().to_string());
                if *mode == SaveMode::Remove && opts.scope == Scope::Project {
                    // `.claude` / `.cursor` that shellfirm emptied (fails if not empty).
                    if let Some(parent) = file.path.parent().filter(|p| *p != env.cwd) {
                        let _ = fs::remove_dir(parent);
                    }
                }
                let _ = writeln!(
                    out,
                    "    ✓ {}{}",
                    if *mode == SaveMode::Remove {
                        "removed"
                    } else {
                        "written"
                    },
                    backup.map_or_else(String::new, |b| format!(" (backup: {})", b.display()))
                );
            }
            Err(e) => {
                if written.is_empty() {
                    return Err(e);
                }
                return Err(format!(
                    "{e}. Already updated before the failure: {}",
                    written.join(", ")
                ));
            }
        }
    }

    out.push('\n');
    if opts.dry_run {
        out.push_str("Dry run: no changes were made. Run without --dry-run to apply.\n");
        return Ok(());
    }
    if opts.uninstall {
        let _ = writeln!(out, "shellfirm removed from {}.", provider.display_name());
        return Ok(());
    }
    let note = match provider {
        Provider::ClaudeCode if opts.hooks => {
            "Claude Code Bash/PowerShell/Monitor commands are now checked by shellfirm before they run \
             (risky -> ask, dangerous -> deny; everything else follows your normal \
             Claude Code permissions). Restart running Claude Code sessions."
        }
        Provider::Cursor if opts.hooks => {
            "Cursor shell commands are now checked by shellfirm (beforeShellExecution hook), \
             and agent edits of protected files are blocked (preToolUse hook). \
             Restart Cursor to pick up the change."
        }
        _ => {
            "MCP tools registered. Note: commands are NOT automatically intercepted — the \
             agent has to choose to call shellfirm's tools."
        }
    };
    let _ = writeln!(out, "{note}");
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::super::check_cmd::LEGACY_CLAUDE_HOOK_ARGS;
    use super::*;

    fn opts(uninstall: bool, hooks: bool, mcp: bool) -> Options {
        Options {
            dry_run: false,
            uninstall,
            hooks,
            mcp,
            scope: Scope::User,
            fail_closed: true,
        }
    }

    struct Sandbox {
        tree: tree_fs::Tree,
        env: ConnectEnv,
    }

    fn sandbox() -> Sandbox {
        let tree = tree_fs::TreeBuilder::default().create().unwrap();
        let home = tree.root.join("home");
        let cwd = tree.root.join("project");
        fs::create_dir_all(&home).unwrap();
        fs::create_dir_all(&cwd).unwrap();
        Sandbox {
            env: ConnectEnv {
                home,
                cwd,
                backup_dir: None,
                config_dir: None,
            },
            tree,
        }
    }

    fn write(path: &Path, content: &str) {
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, content).unwrap();
    }

    fn read_json(path: &Path) -> Value {
        serde_json::from_str(&fs::read_to_string(path).unwrap()).unwrap()
    }

    fn backups(dir: &Path) -> Vec<PathBuf> {
        fs::read_dir(dir)
            .unwrap()
            .filter_map(|e| e.ok().map(|e| e.path()))
            .filter(|p| p.to_string_lossy().contains(".shellfirm-bak-"))
            .collect()
    }

    fn exec(p: Provider, o: &Options, env: &ConnectEnv) -> (OpResult<()>, String) {
        let mut out = String::new();
        let r = execute(p, o, env, &mut out);
        (r, out)
    }

    // -- JSONC --

    #[test]
    fn jsonc_comments_and_trailing_commas_parse() {
        let src = "\u{feff}{\n // c\n \"model\":\"opus\", /* x */\n \"url\": \"http://a//b\",\n \"permissions\":{\"allow\":[\"Bash(ls)\",],},\n}";
        let (v, lossy) = parse_jsonc(src).unwrap();
        assert!(lossy);
        assert_eq!(v["model"], "opus");
        assert_eq!(v["url"], "http://a//b");
        assert_eq!(v["permissions"]["allow"][0], "Bash(ls)");
    }

    #[test]
    fn strict_json_is_not_lossy() {
        let (v, lossy) = parse_jsonc(r#"{"a": "// not a comment, ]"}"#).unwrap();
        assert!(!lossy);
        assert_eq!(v["a"], "// not a comment, ]");
        assert!(parse_jsonc("").unwrap().0.is_object());
    }

    #[test]
    fn garbage_does_not_parse() {
        assert!(parse_jsonc("{not json").is_err());
        assert!(parse_jsonc("{\"a\": // c\n").is_err());
    }

    // -- Claude Code end-to-end on temp dirs --

    #[test]
    fn claude_fresh_install_writes_hook_and_mcp_to_correct_files() {
        let sb = sandbox();
        let (r, out) = exec(Provider::ClaudeCode, &opts(false, true, true), &sb.env);
        r.unwrap();
        let settings = read_json(&sb.env.home.join(".claude/settings.json"));
        let cmd = &settings["hooks"]["PreToolUse"][0]["hooks"][0]["command"];
        assert_eq!(cmd, "shellfirm check --hook claude-code");
        assert_eq!(
            settings["hooks"]["PreToolUse"][0]["matcher"],
            "Bash|PowerShell|Monitor"
        );
        let entry = &settings["hooks"]["PreToolUse"][0]["hooks"][0];
        assert_eq!(entry["onFailure"], "block");
        assert_eq!(entry["timeout"], HOOK_TIMEOUT_SECS);
        assert_eq!(
            settings["hooks"]["PreToolUse"][1]["matcher"],
            "Write|Edit|MultiEdit|NotebookEdit"
        );
        assert_eq!(
            claude_hook_state(&settings).covered,
            [
                "Bash",
                "PowerShell",
                "Monitor",
                "Write",
                "Edit",
                "MultiEdit",
                "NotebookEdit"
            ]
        );
        assert!(settings.get("mcpServers").is_none());
        let claude_json = read_json(&sb.env.home.join(".claude.json"));
        assert_eq!(claude_json["mcpServers"]["shellfirm"]["type"], "stdio");
        assert_eq!(claude_json["mcpServers"]["shellfirm"]["args"][0], "mcp");
        assert!(out.contains("✓ written"));

        // idempotent
        let before = fs::read(sb.env.home.join(".claude/settings.json")).unwrap();
        let (r, out) = exec(Provider::ClaudeCode, &opts(false, true, true), &sb.env);
        r.unwrap();
        assert!(out.contains("already connected"), "{out}");
        assert_eq!(
            before,
            fs::read(sb.env.home.join(".claude/settings.json")).unwrap()
        );
    }

    #[test]
    fn claude_install_preserves_jsonc_content_and_key_order_and_backs_up() {
        let sb = sandbox();
        let path = sb.env.home.join(".claude/settings.json");
        let original = "{\n // c\n \"model\":\"opus\",\n \"permissions\":{\"deny\":[\"Bash(rm:*)\"],},\n \"env\": {\"Z\": \"1\", \"A\": \"2\"}\n}";
        write(&path, original);
        let (r, out) = exec(Provider::ClaudeCode, &opts(false, true, false), &sb.env);
        r.unwrap();
        assert!(out.contains("comments or trailing commas"));
        let v = read_json(&path);
        assert_eq!(v["model"], "opus");
        assert_eq!(v["permissions"]["deny"][0], "Bash(rm:*)");
        let keys: Vec<&String> = v.as_object().unwrap().keys().collect();
        assert_eq!(keys, ["model", "permissions", "env", "hooks"]);
        let env_keys: Vec<&String> = v["env"].as_object().unwrap().keys().collect();
        assert_eq!(env_keys, ["Z", "A"]);
        let baks = backups(path.parent().unwrap());
        assert_eq!(baks.len(), 1);
        assert_eq!(fs::read_to_string(&baks[0]).unwrap(), original);
    }

    #[test]
    fn unparseable_file_aborts_without_writing() {
        let sb = sandbox();
        let path = sb.env.home.join(".claude/settings.json");
        write(&path, "{ \"model\": \"opus\", oops");
        let (r, _) = exec(Provider::ClaudeCode, &opts(false, true, true), &sb.env);
        let err = r.unwrap_err();
        assert!(err.contains("could not parse"), "{err}");
        assert_eq!(
            fs::read_to_string(&path).unwrap(),
            "{ \"model\": \"opus\", oops"
        );
        assert!(
            !sb.env.home.join(".claude.json").exists(),
            "nothing else written"
        );
        assert!(backups(path.parent().unwrap()).is_empty());
    }

    #[test]
    fn unexpected_shapes_are_errors_not_panics() {
        for content in [
            "[1,2,3]",
            r#"{"hooks":"oops"}"#,
            r#"{"hooks":{"PreToolUse":{"matcher":"Bash"}}}"#,
            "\"str\"",
        ] {
            let sb = sandbox();
            let path = sb.env.home.join(".claude/settings.json");
            write(&path, content);
            let (r, _) = exec(Provider::ClaudeCode, &opts(false, true, false), &sb.env);
            assert!(r.is_err(), "expected error for {content}");
            assert_eq!(fs::read_to_string(&path).unwrap(), content);
        }
        let sb = sandbox();
        write(&sb.env.home.join(".claude.json"), r#"{"mcpServers": []}"#);
        let (r, _) = exec(Provider::ClaudeCode, &opts(false, false, true), &sb.env);
        assert!(r.unwrap_err().contains("mcpServers"));
    }

    #[cfg(unix)]
    #[test]
    fn read_only_file_is_a_clear_error() {
        use std::os::unix::fs::PermissionsExt;
        let sb = sandbox();
        let path = sb.env.home.join(".claude/settings.json");
        write(&path, "{}");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o444)).unwrap();
        let (r, out) = exec(Provider::ClaudeCode, &opts(false, true, false), &sb.env);
        assert!(r.unwrap_err().contains("read-only"));
        assert!(!out.contains('✓'));
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn symlink_target_is_written_and_mode_kept() {
        use std::os::unix::fs::PermissionsExt;
        let sb = sandbox();
        let real = sb.env.home.join("dotfiles/settings.json");
        write(&real, "{\"model\":\"x\"}");
        fs::set_permissions(&real, fs::Permissions::from_mode(0o600)).unwrap();
        fs::create_dir_all(sb.env.home.join(".claude")).unwrap();
        let link = sb.env.home.join(".claude/settings.json");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        exec(Provider::ClaudeCode, &opts(false, true, false), &sb.env)
            .0
            .unwrap();
        assert!(fs::symlink_metadata(&link)
            .unwrap()
            .file_type()
            .is_symlink());
        assert_eq!(read_json(&real)["model"], "x");
        assert!(claude_hooks_installed(&read_json(&real)));
        let mode = fs::metadata(&real).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }

    #[test]
    fn uninstall_removes_only_exact_shellfirm_hooks() {
        let sb = sandbox();
        let path = sb.env.home.join(".claude/settings.json");
        write(
            &path,
            r#"{"hooks":{"PreToolUse":[
                {"matcher":"Bash","hooks":[{"type":"command","command":"/opt/myaudit.sh"},
                                           {"type":"command","command":"shellfirm check --stdin --format json --exit-code"}]},
                {"matcher":"Edit","hooks":[{"type":"command","command":"~/tools/shellfirm-lint-notes.sh"}]},
                {"matcher":"Bash","hooks":[{"type":"command","command":"/usr/local/bin/shellfirm check --hook claude-code"}]}
            ]},"mcpServers":{"shellfirm":{"command":"shellfirm","args":["mcp"]},"other":{"command":"o"}}}"#,
        );
        let (r, out) = exec(Provider::ClaudeCode, &opts(true, true, true), &sb.env);
        r.unwrap();
        assert!(out.contains("remove 2 shellfirm hook(s)"), "{out}");
        let v = read_json(&path);
        let groups = v["hooks"]["PreToolUse"].as_array().unwrap();
        assert_eq!(groups.len(), 2);
        assert_eq!(groups[0]["hooks"][0]["command"], "/opt/myaudit.sh");
        assert_eq!(groups[0]["hooks"].as_array().unwrap().len(), 1);
        assert_eq!(
            groups[1]["hooks"][0]["command"],
            "~/tools/shellfirm-lint-notes.sh"
        );
        // stale legacy MCP entry removed, other server kept
        assert!(v["mcpServers"].get("shellfirm").is_none());
        assert_eq!(v["mcpServers"]["other"]["command"], "o");
    }

    #[test]
    fn uninstall_cleans_up_containers_it_emptied() {
        let sb = sandbox();
        exec(Provider::ClaudeCode, &opts(false, true, true), &sb.env)
            .0
            .unwrap();
        exec(Provider::ClaudeCode, &opts(true, true, true), &sb.env)
            .0
            .unwrap();
        // files that only held shellfirm's entries are removed, not left as `{}`
        assert!(!sb.env.home.join(".claude/settings.json").exists());
        assert!(!sb.env.home.join(".claude.json").exists());
        let (r, out) = exec(Provider::ClaudeCode, &opts(true, true, true), &sb.env);
        r.unwrap();
        assert!(out.contains("no shellfirm configuration found"));
    }

    #[test]
    fn uninstall_hooks_only_keeps_mcp() {
        let sb = sandbox();
        exec(Provider::ClaudeCode, &opts(false, true, true), &sb.env)
            .0
            .unwrap();
        exec(Provider::ClaudeCode, &opts(true, true, false), &sb.env)
            .0
            .unwrap();
        assert!(!sb.env.home.join(".claude/settings.json").exists());
        assert!(server_installed(
            &read_json(&sb.env.home.join(".claude.json")),
            "mcpServers"
        ));
    }

    #[test]
    fn existing_custom_mcp_entry_is_kept() {
        let sb = sandbox();
        let path = sb.env.home.join(".claude.json");
        write(
            &path,
            r#"{"numStartups": 3, "mcpServers": {"shellfirm": {"command": "/opt/sf", "args": ["mcp", "--x"]}}}"#,
        );
        let (r, out) = exec(Provider::ClaudeCode, &opts(false, false, true), &sb.env);
        r.unwrap();
        assert!(out.contains("already"));
        assert_eq!(
            read_json(&path)["mcpServers"]["shellfirm"]["command"],
            "/opt/sf"
        );
    }

    #[test]
    fn legacy_settings_mcp_entry_is_migrated() {
        let sb = sandbox();
        let settings = sb.env.home.join(".claude/settings.json");
        write(
            &settings,
            r#"{"hooks":{"PreToolUse":[{"matcher":"Bash","hooks":[{"type":"command","command":"shellfirm check --stdin --format json --exit-code"}]}]},"mcpServers":{"shellfirm":{"command":"shellfirm","args":["mcp"]}}}"#,
        );
        let (r, out) = exec(Provider::ClaudeCode, &opts(false, true, true), &sb.env);
        r.unwrap();
        assert!(out.contains("replacing 1 legacy command line"), "{out}");
        let v = read_json(&settings);
        assert!(v.get("mcpServers").is_none());
        assert!(claude_hooks_installed(&v), "legacy hook upgraded in place");
        let groups = v["hooks"]["PreToolUse"].as_array().unwrap();
        assert_eq!(
            groups[0]["hooks"].as_array().unwrap().len(),
            1,
            "no duplicate"
        );
        assert_eq!(
            groups[0]["hooks"][0]["command"],
            "shellfirm check --hook claude-code"
        );
        assert_eq!(claude_hook_state(&v).legacy, 0);
        assert!(server_installed(
            &read_json(&sb.env.home.join(".claude.json")),
            "mcpServers"
        ));
    }

    #[test]
    fn project_scope_uses_project_files() {
        let sb = sandbox();
        let o = Options {
            scope: Scope::Project,
            ..opts(false, true, true)
        };
        exec(Provider::ClaudeCode, &o, &sb.env).0.unwrap();
        assert!(claude_hooks_installed(&read_json(
            &sb.env.cwd.join(".claude/settings.json")
        )));
        assert!(server_installed(
            &read_json(&sb.env.cwd.join(".mcp.json")),
            "mcpServers"
        ));
        assert!(!sb.env.home.join(".claude.json").exists());
    }

    #[test]
    fn dry_run_writes_nothing_and_has_no_checkmarks() {
        let sb = sandbox();
        let path = sb.env.home.join(".claude/settings.json");
        write(&path, r#"{"model":"opus"}"#);
        let o = Options {
            dry_run: true,
            ..opts(false, true, true)
        };
        let (r, out) = exec(Provider::ClaudeCode, &o, &sb.env);
        r.unwrap();
        assert!(!out.contains('✓'), "{out}");
        assert!(out.contains("Would update"));
        assert!(out.contains("Would create"));
        assert!(out.trim_end().ends_with("Run without --dry-run to apply."));
        assert_eq!(fs::read_to_string(&path).unwrap(), r#"{"model":"opus"}"#);
        assert!(!sb.env.home.join(".claude.json").exists());
        assert!(backups(path.parent().unwrap()).is_empty());

        let o = Options {
            dry_run: true,
            ..opts(true, true, true)
        };
        exec(Provider::ClaudeCode, &opts(false, true, true), &sb.env)
            .0
            .unwrap();
        let before = fs::read(&path).unwrap();
        exec(Provider::ClaudeCode, &o, &sb.env).0.unwrap();
        assert_eq!(before, fs::read(&path).unwrap());
    }

    // -- Cursor --

    #[test]
    fn cursor_user_scope_hooks_and_mcp() {
        let sb = sandbox();
        let (r, out) = exec(Provider::Cursor, &opts(false, true, true), &sb.env);
        r.unwrap();
        let hooks = read_json(&sb.env.home.join(".cursor/hooks.json"));
        assert_eq!(hooks["version"], 1);
        assert_eq!(
            hooks["hooks"]["beforeShellExecution"][0]["command"],
            "shellfirm check --hook cursor"
        );
        assert!(server_installed(
            &read_json(&sb.env.home.join(".cursor/mcp.json")),
            "mcpServers"
        ));
        assert!(!sb.env.cwd.join(".cursor").exists(), "project untouched");
        assert!(out.contains("beforeShellExecution"));

        exec(Provider::Cursor, &opts(true, true, true), &sb.env)
            .0
            .unwrap();
        assert!(!sb.env.home.join(".cursor/hooks.json").exists());
        assert!(!sb.env.home.join(".cursor/mcp.json").exists());
    }

    // -- MCP-only tools --

    #[test]
    fn zed_jsonc_settings_are_kept_and_message_is_honest() {
        let sb = sandbox();
        let path = sb.env.home.join(".config/zed/settings.json");
        write(
            &path,
            "// Zed settings\n{\n  \"theme\": \"One Dark\",\n  \"vim_mode\": true,\n  \"context_servers\": {\"github\": {\"command\": \"gh-mcp\"}},\n}\n",
        );
        let (r, out) = exec(Provider::Zed, &opts(false, false, true), &sb.env);
        r.unwrap();
        let v = read_json(&path);
        assert_eq!(v["theme"], "One Dark");
        assert_eq!(v["vim_mode"], true);
        assert_eq!(v["context_servers"]["github"]["command"], "gh-mcp");
        assert_eq!(v["context_servers"]["shellfirm"]["command"], "shellfirm");
        assert!(out.contains("NOT automatically intercepted"), "{out}");
        assert!(!out.contains("protected"));
    }

    #[test]
    fn mcp_only_providers_install_and_uninstall() {
        for p in [Provider::Windsurf, Provider::Cline, Provider::Zed] {
            let sb = sandbox();
            if p == Provider::Cline && cline_settings_path(&sb.env.home).is_none() {
                continue;
            }
            exec(p, &opts(false, false, true), &sb.env).0.unwrap();
            let file = plan(p, &opts(false, false, true), &sb.env).unwrap()[0]
                .0
                .clone();
            let container = if p == Provider::Zed {
                "context_servers"
            } else {
                "mcpServers"
            };
            assert!(server_installed(&read_json(&file), container), "{p:?}");
            exec(p, &opts(true, false, true), &sb.env).0.unwrap();
            assert!(!file.exists(), "{p:?}");
        }
    }

    #[test]
    fn hooks_only_on_mcp_only_tool_is_error() {
        let sb = sandbox();
        let (r, _) = exec(Provider::Zed, &opts(false, false, false), &sb.env);
        assert!(r.unwrap_err().contains("no command hook"));
    }

    #[test]
    fn hook_command_recognition_accepts_shellfirm_flags_only() {
        assert!(is_claude_hook(
            "shellfirm check --hook claude-code --log debug"
        ));
        assert!(is_claude_hook(
            "shellfirm --log=debug check --hook=claude-code"
        ));
        assert!(is_claude_hook(
            "shellfirm check --hook claude-code --config-dir '/Users/me/Library/Application Support/shellfirm'"
        ));
        assert_eq!(
            parse_shellfirm_hook(
                "shellfirm check --hook claude-code --config-dir '/a b/c'",
                "claude-code"
            ),
            Some(HookCmd {
                legacy: false,
                config_dir: Some("/a b/c".into())
            })
        );
        assert!(!is_claude_hook("shellfirm check --hook cursor"));
        assert!(!is_claude_hook(
            "shellfirm check --hook claude-code; rm -rf ~"
        ));
        // rejected by current versions (usage error): recognised so it is rewritten
        assert!(
            parse_shellfirm_hook(
                "shellfirm check --hook claude-code --exit-code",
                "claude-code"
            )
            .unwrap()
            .legacy
        );
        assert!(!is_claude_hook("shellfirm check --hook 'claude-code"));
        assert!(!is_claude_hook("shellfirm config ignore x"));
        assert!(!is_cursor_hook(
            "shellfirm check --stdin --format json --exit-code"
        ));
        let mut legacy = String::from("shellfirm ");
        legacy.push_str(LEGACY_CLAUDE_HOOK_ARGS);
        assert!(parse_shellfirm_hook(&legacy, "claude-code").unwrap().legacy);
    }

    #[test]
    fn matcher_semantics_follow_claude_code_docs() {
        assert!(matcher_covers(None, "Bash"));
        assert!(matcher_covers(Some("*"), "Bash"));
        assert!(matcher_covers(Some(""), "Write"));
        assert!(matcher_covers(Some("Bash"), "Bash"));
        assert!(!matcher_covers(Some("Bash"), "Write"));
        assert!(matcher_covers(Some("Edit|Write"), "Write"));
        assert!(!matcher_covers(Some("Edit|Write"), "Bash"));
        assert!(
            !matcher_covers(Some("Edit"), "NotebookEdit"),
            "exact, not regex"
        );
        assert!(
            matcher_covers(Some("Edit.*"), "NotebookEdit"),
            "regex, unanchored"
        );
        assert!(matcher_covers(Some("^Ba"), "Bash"));
    }

    #[test]
    fn only_bash_covering_hooks_count_as_installed() {
        let sb = sandbox();
        let path = sb.env.home.join(".claude/settings.json");
        write(
            &path,
            r#"{"hooks":{"PreToolUse":[{"matcher":"Edit|Write","hooks":[{"type":"command","command":"shellfirm check --hook claude-code --log debug"}]}]}}"#,
        );
        let v = read_json(&path);
        assert!(!claude_hooks_installed(&v));
        let (r, out) = exec(Provider::ClaudeCode, &opts(false, true, false), &sb.env);
        r.unwrap();
        assert!(!out.contains("already installed"), "{out}");
        let v = read_json(&path);
        let groups = v["hooks"]["PreToolUse"].as_array().unwrap();
        assert_eq!(groups.len(), 3, "{v}");
        assert_eq!(groups[1]["matcher"], "Bash|PowerShell|Monitor");
        assert_eq!(groups[2]["matcher"], "MultiEdit|NotebookEdit");
        // user flags are kept, fail-closed options added
        assert_eq!(
            groups[0]["hooks"][0]["command"],
            "shellfirm check --hook claude-code --log debug"
        );
        assert_eq!(groups[0]["hooks"][0]["onFailure"], "block");
        // idempotent
        let (r, out) = exec(Provider::ClaudeCode, &opts(false, true, false), &sb.env);
        r.unwrap();
        assert!(out.contains("Hook already installed"), "{out}");
        // uninstall removes the `--log debug` hook too
        exec(Provider::ClaudeCode, &opts(true, true, false), &sb.env)
            .0
            .unwrap();
        assert!(!path.exists());
    }

    #[test]
    fn user_scope_pins_config_dir_and_upgrades_existing_hooks() {
        let mut sb = sandbox();
        sb.env.config_dir = Some(PathBuf::from(
            "/Users/me/Library/Application Support/shellfirm",
        ));
        let path = sb.env.home.join(".claude/settings.json");
        write(
            &path,
            r#"{"hooks":{"PreToolUse":[{"matcher":"Bash","hooks":[{"type":"command","command":"shellfirm check --hook claude-code"}]}]}}"#,
        );
        let (r, out) = exec(Provider::ClaudeCode, &opts(false, true, true), &sb.env);
        r.unwrap();
        assert!(out.contains("pinned --config-dir"), "{out}");
        let v = read_json(&path);
        let expected = "shellfirm check --hook claude-code --config-dir '/Users/me/Library/Application Support/shellfirm'";
        assert_eq!(v["hooks"]["PreToolUse"][0]["hooks"][0]["command"], expected);
        assert_eq!(v["hooks"]["PreToolUse"][1]["hooks"][0]["command"], expected);
        let mcp = read_json(&sb.env.home.join(".claude.json"));
        assert_eq!(mcp["mcpServers"]["shellfirm"]["args"][1], "--config-dir");
        // the recorded dir parses back
        assert_eq!(
            claude_hook_state(&v).config_dirs,
            ["/Users/me/Library/Application Support/shellfirm"]
        );
    }

    #[test]
    fn no_fail_closed_omits_on_failure() {
        let sb = sandbox();
        let o = Options {
            fail_closed: false,
            ..opts(false, true, false)
        };
        exec(Provider::ClaudeCode, &o, &sb.env).0.unwrap();
        let v = read_json(&sb.env.home.join(".claude/settings.json"));
        assert!(v["hooks"]["PreToolUse"][0]["hooks"][0]
            .get("onFailure")
            .is_none());
        assert_eq!(
            v["hooks"]["PreToolUse"][0]["hooks"][0]["timeout"],
            HOOK_TIMEOUT_SECS
        );
    }

    #[test]
    fn project_scope_backups_go_outside_the_repo_and_no_stubs_remain() {
        let mut sb = sandbox();
        sb.env.backup_dir = Some(sb.tree.root.join("cache/backups"));
        let o = Options {
            scope: Scope::Project,
            ..opts(false, true, true)
        };
        let settings = sb.env.cwd.join(".claude/settings.json");
        write(&settings, r#"{"permissions":{"allow":["Bash(ls)"]}}"#);
        exec(Provider::ClaudeCode, &o, &sb.env).0.unwrap();
        let hook = &read_json(&settings)["hooks"]["PreToolUse"][0]["hooks"][0]["command"];
        assert_eq!(
            hook, "shellfirm check --hook claude-code",
            "no personal path"
        );
        let un = Options {
            uninstall: true,
            ..o
        };
        exec(Provider::ClaudeCode, &un, &sb.env).0.unwrap();
        assert_eq!(
            read_json(&settings),
            json!({"permissions":{"allow":["Bash(ls)"]}})
        );
        assert!(!sb.env.cwd.join(".mcp.json").exists(), "no {{}} stub");
        let in_repo: Vec<PathBuf> = backups(&sb.env.cwd)
            .into_iter()
            .chain(backups(&sb.env.cwd.join(".claude")))
            .collect();
        assert!(in_repo.is_empty(), "{in_repo:?}");
        let bdir = sb.env.backup_dir.clone().unwrap();
        assert!(backups(&bdir).len() >= 2, "{:?}", backups(&bdir));

        // created-from-scratch files and dirs disappear entirely
        let mut sb = sandbox();
        sb.env.backup_dir = Some(sb.tree.root.join("cache/backups"));
        exec(Provider::Cursor, &o, &sb.env).0.unwrap();
        assert!(sb.env.cwd.join(".cursor/hooks.json").exists());
        exec(
            Provider::Cursor,
            &Options {
                uninstall: true,
                ..o
            },
            &sb.env,
        )
        .0
        .unwrap();
        assert!(!sb.env.cwd.join(".cursor").exists());
    }

    #[test]
    fn integration_status_reports_hooks_and_mcp() {
        let sb = sandbox();
        exec(Provider::ClaudeCode, &opts(false, true, true), &sb.env)
            .0
            .unwrap();
        let st = integration_status(&sb.env.home, &sb.env.cwd);
        let cc = st
            .iter()
            .find(|s| s.tool == "claude-code" && s.scope == "user")
            .unwrap();
        assert!(cc.hook_installed && cc.file_tools_covered && cc.fail_closed);
        assert!(cc.mcp_registered && !cc.legacy_hook);
        let cur = st
            .iter()
            .find(|s| s.tool == "cursor" && s.scope == "user")
            .unwrap();
        assert!(!cur.hook_installed && !cur.mcp_registered);
        assert!(st
            .iter()
            .any(|s| s.tool == "claude-code" && s.scope == "project"));
        let json = serde_json::to_value(cc).unwrap();
        assert_eq!(json["tool"], "claude-code");
    }

    #[test]
    fn hook_command_recognition_is_exact() {
        assert!(is_claude_hook("shellfirm check --hook claude-code"));
        assert!(is_claude_hook(
            "/opt/homebrew/bin/shellfirm  check --stdin --format json --exit-code"
        ));
        assert!(!is_claude_hook("~/tools/shellfirm-lint-notes.sh"));
        assert!(!is_claude_hook(
            "shellfirm check --hook claude-code && evil"
        ));
        assert!(!is_claude_hook("myshellfirm check --hook claude-code"));
        assert!(is_cursor_hook("shellfirm check --hook cursor"));
    }

    #[test]
    fn upgrade_adds_powershell_and_monitor_and_dedupes() {
        let sb = sandbox();
        let path = sb.env.home.join(".claude/settings.json");
        write(
            &path,
            r#"{"hooks":{"PreToolUse":[
                {"matcher":"Bash","hooks":[{"type":"command","command":"shellfirm check --hook claude-code"}]},
                {"matcher":"Bash","hooks":[{"type":"command","command":"shellfirm check --hook claude-code --log debug"}]},
                {"matcher":"Write|Edit|MultiEdit|NotebookEdit","hooks":[
                    {"type":"command","command":"shellfirm check --hook claude-code"},
                    {"type":"command","command":"shellfirm check --hook claude-code"}]}
            ]}}"#,
        );
        let (r, out) = exec(Provider::ClaudeCode, &opts(false, true, false), &sb.env);
        r.unwrap();
        assert!(
            out.contains("remove 2 duplicate shellfirm hook(s)"),
            "{out}"
        );
        let v = read_json(&path);
        let groups = v["hooks"]["PreToolUse"].as_array().unwrap();
        let matchers: Vec<&str> = groups
            .iter()
            .map(|g| g["matcher"].as_str().unwrap())
            .collect();
        assert_eq!(
            matchers,
            [
                "Bash",
                "Write|Edit|MultiEdit|NotebookEdit",
                "PowerShell|Monitor"
            ],
            "{v}"
        );
        assert_eq!(claude_hook_state(&v).entries, 3);
        let st = integration_status(&sb.env.home, &sb.env.cwd);
        let cc = st
            .iter()
            .find(|s| s.tool == "claude-code" && s.scope == "user")
            .unwrap();
        assert!(cc.shell_tools_missing.is_empty() && cc.hook_present);
    }

    #[test]
    fn user_hook_settings_are_kept_and_reported() {
        let sb = sandbox();
        let path = sb.env.home.join(".claude/settings.json");
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(
            &path,
            r#"{"hooks":{"PreToolUse":[{"matcher":"Bash","hooks":[{"type":"command","command":"shellfirm check --hook claude-code","timeout":120,"onFailure":"allow"}]}]}}"#,
        )
        .unwrap();
        let (r, out) = exec(Provider::ClaudeCode, &opts(false, true, false), &sb.env);
        r.unwrap();
        assert!(
            out.contains("kept your own hook settings") && out.contains("onFailure: allow"),
            "{out}"
        );
        assert!(out.contains("timeout 120s"), "{out}");
        assert!(!out.contains("(timeout 30s, onFailure: block"), "{out}");
        let v = read_json(&path);
        assert_eq!(
            v["hooks"]["PreToolUse"][0]["hooks"][0]["onFailure"],
            "allow"
        );
        assert_eq!(v["hooks"]["PreToolUse"][0]["hooks"][0]["timeout"], 120);
        // The rerun still says so.
        let (r, out) = exec(Provider::ClaudeCode, &opts(false, true, false), &sb.env);
        r.unwrap();
        assert!(out.contains("kept your own hook settings"), "{out}");
    }

    #[test]
    fn no_fail_closed_downgrades_existing_hooks() {
        let sb = sandbox();
        exec(Provider::ClaudeCode, &opts(false, true, false), &sb.env)
            .0
            .unwrap();
        let o = Options {
            fail_closed: false,
            ..opts(false, true, false)
        };
        let (r, out) = exec(Provider::ClaudeCode, &o, &sb.env);
        r.unwrap();
        assert!(out.contains("onFailure removed"), "{out}");
        let v = read_json(&sb.env.home.join(".claude/settings.json"));
        assert!(v["hooks"]["PreToolUse"]
            .as_array()
            .unwrap()
            .iter()
            .all(|g| g["hooks"][0].get("onFailure").is_none()));
        // and back
        exec(Provider::ClaudeCode, &opts(false, true, false), &sb.env)
            .0
            .unwrap();
        let v = read_json(&sb.env.home.join(".claude/settings.json"));
        assert_eq!(
            v["hooks"]["PreToolUse"][0]["hooks"][0]["onFailure"],
            "block"
        );
    }

    #[test]
    fn new_entries_reuse_recorded_custom_config_dir() {
        let mut sb = sandbox();
        sb.env.config_dir = Some(PathBuf::from("/home/me/.config/shellfirm"));
        let path = sb.env.home.join(".claude/settings.json");
        write(
            &path,
            r#"{"hooks":{"PreToolUse":[{"matcher":"Bash","hooks":[{"type":"command","command":"shellfirm check --stdin --format json --exit-code --config-dir /etc/team-shellfirm"}]}]}}"#,
        );
        exec(Provider::ClaudeCode, &opts(false, true, false), &sb.env)
            .0
            .unwrap();
        let v = read_json(&path);
        for g in v["hooks"]["PreToolUse"].as_array().unwrap() {
            assert_eq!(
                g["hooks"][0]["command"],
                "shellfirm check --hook claude-code --config-dir /etc/team-shellfirm",
                "{v}"
            );
        }
    }

    #[test]
    fn hook_format_spellings_are_recognised_as_legacy() {
        let h = parse_shellfirm_hook(
            "shellfirm check --stdin --format cursor-hook --exit-code",
            "cursor",
        )
        .unwrap();
        assert!(h.legacy);
        assert!(
            parse_shellfirm_hook("shellfirm check --format claude-hook", "claude-code")
                .unwrap()
                .legacy
        );
        assert!(
            parse_shellfirm_hook("shellfirm check --hook cursor --exit-code", "cursor")
                .unwrap()
                .legacy
        );
        assert!(
            parse_shellfirm_hook("shellfirm check --format cursor-hook", "claude-code").is_none()
        );
        assert!(
            !parse_shellfirm_hook("shellfirm check --hook cursor", "cursor")
                .unwrap()
                .legacy
        );
    }

    #[test]
    fn cursor_upgrade_removes_fail_closed_and_adds_file_hook() {
        let sb = sandbox();
        let path = sb.env.home.join(".cursor/hooks.json");
        write(
            &path,
            r#"{"version":1,"hooks":{"beforeShellExecution":[
                {"command":"shellfirm check --stdin --format cursor-hook --exit-code","failClosed":true},
                {"command":"shellfirm check --hook cursor"},
                {"command":"./mine.sh","failClosed":true}]}}"#,
        );
        let (r, out) = exec(Provider::Cursor, &opts(false, true, false), &sb.env);
        r.unwrap();
        assert!(out.contains("failClosed"), "{out}");
        let v = read_json(&path);
        let shell = v["hooks"]["beforeShellExecution"].as_array().unwrap();
        assert_eq!(shell.len(), 2, "{v}");
        assert_eq!(shell[0]["command"], "shellfirm check --hook cursor");
        assert!(shell[0].get("failClosed").is_none());
        assert_eq!(shell[1]["failClosed"], true, "foreign hook untouched");
        assert_eq!(v["hooks"]["preToolUse"][0]["matcher"], CURSOR_FILE_MATCHER);
        let st = integration_status(&sb.env.home, &sb.env.cwd);
        let cur = st
            .iter()
            .find(|s| s.tool == "cursor" && s.scope == "user")
            .unwrap();
        assert!(cur.hook_installed && cur.file_tools_covered && !cur.legacy_hook);
        // idempotent, then uninstall removes both events
        let (_, out) = exec(Provider::Cursor, &opts(false, true, false), &sb.env);
        assert!(out.contains("Hook already installed"), "{out}");
        exec(Provider::Cursor, &opts(true, true, false), &sb.env)
            .0
            .unwrap();
        let v = read_json(&path);
        assert!(v["hooks"].get("preToolUse").is_none(), "{v}");
        assert_eq!(
            v["hooks"]["beforeShellExecution"][0]["command"],
            "./mine.sh"
        );
    }

    #[test]
    fn status_flags_hook_without_bash() {
        let sb = sandbox();
        write(
            &sb.env.home.join(".claude/settings.json"),
            r#"{"hooks":{"PreToolUse":[{"matcher":"Edit|Write","hooks":[{"type":"command","command":"shellfirm check --hook claude-code"}]}]}}"#,
        );
        let st = integration_status(&sb.env.home, &sb.env.cwd);
        let cc = st
            .iter()
            .find(|s| s.tool == "claude-code" && s.scope == "user")
            .unwrap();
        assert!(cc.hook_present && !cc.hook_installed);
        assert_eq!(cc.shell_tools_missing, ["Bash", "PowerShell", "Monitor"]);
    }

    #[test]
    fn cli_definition_is_valid() {
        command().debug_assert();
    }
}
