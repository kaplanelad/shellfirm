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

mod agents;

/// Hook arguments written by this version.
const CLAUDE_HOOK_ARGS: &str = "check --hook claude-code";
const CURSOR_HOOK_ARGS: &str = "check --hook cursor";
const BINARY: &str = "shellfirm";
const MCP_ARGS: &[&str] = &["mcp"];
/// `timeout` (seconds) written on hook entries. shellfirm answers in well
/// under a second; the optional LLM review is capped at 10 s.
const HOOK_TIMEOUT_SECS: u64 = 30;

pub(super) type OpResult<T> = std::result::Result<T, String>;

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
    /// Codex CLI `hooks.json` `hooks.PreToolUse[]`.
    CodexHooks,
    /// Gemini CLI `settings.json` `hooks.BeforeTool[]`.
    GeminiHooks,
    /// Qwen Code `settings.json` `hooks.PreToolUse[]`.
    QwenHooks,
    /// GitHub Copilot CLI hook file `hooks.preToolUse[]`.
    CopilotHooks,
    /// Windsurf `hooks.json` `hooks.pre_run_command[]` (and file hooks).
    WindsurfHooks,
    /// Cline `PreToolUse` hook script (a file shellfirm owns).
    ClineScript,
    /// `OpenCode` plugin (a file shellfirm owns).
    OpenCodePlugin,
}

impl OpKind {
    const fn component(self) -> Component {
        match self {
            Self::ClaudeMcp | Self::LegacyClaudeSettingsMcp | Self::StandardMcp | Self::ZedMcp => {
                Component::Mcp
            }
            _ => Component::Hooks,
        }
    }

    /// A file shellfirm owns entirely (not a JSON file it edits).
    const fn is_owned_file(self) -> bool {
        matches!(self, Self::ClineScript | Self::OpenCodePlugin)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Provider {
    ClaudeCode,
    Cursor,
    Codex,
    Gemini,
    Qwen,
    Copilot,
    Windsurf,
    Cline,
    OpenCode,
    Zed,
}

const SUPPORTED_PROVIDERS: &str =
    "claude-code, cursor, codex, gemini, qwen, copilot, windsurf, cline, opencode, zed";

/// Every provider, in `status` order.
const ALL_PROVIDERS: [Provider; 10] = [
    Provider::ClaudeCode,
    Provider::Cursor,
    Provider::Codex,
    Provider::Gemini,
    Provider::Qwen,
    Provider::Copilot,
    Provider::Windsurf,
    Provider::Cline,
    Provider::OpenCode,
    Provider::Zed,
];

impl Provider {
    fn from_name(name: &str) -> Option<Self> {
        ALL_PROVIDERS.into_iter().find(|p| p.cli_name() == name)
    }

    const fn cli_name(self) -> &'static str {
        match self {
            Self::ClaudeCode => "claude-code",
            Self::Cursor => "cursor",
            Self::Codex => "codex",
            Self::Gemini => "gemini",
            Self::Qwen => "qwen",
            Self::Copilot => "copilot",
            Self::Windsurf => "windsurf",
            Self::Cline => "cline",
            Self::OpenCode => "opencode",
            Self::Zed => "zed",
        }
    }

    const fn display_name(self) -> &'static str {
        match self {
            Self::ClaudeCode => "Claude Code",
            Self::Cursor => "Cursor",
            Self::Codex => "Codex CLI",
            Self::Gemini => "Gemini CLI",
            Self::Qwen => "Qwen Code",
            Self::Copilot => "GitHub Copilot CLI",
            Self::Windsurf => "Windsurf",
            Self::Cline => "Cline",
            Self::OpenCode => "OpenCode",
            Self::Zed => "Zed",
        }
    }

    const fn supports_hooks(self) -> bool {
        !matches!(self, Self::Zed)
    }

    /// shellfirm registers its MCP server with this tool.
    const fn supports_mcp(self) -> bool {
        matches!(
            self,
            Self::ClaudeCode | Self::Cursor | Self::Windsurf | Self::Cline | Self::Zed
        )
    }

    /// `--scope project` is available (for the hook; the MCP registration of
    /// Windsurf and Cline is user-level only).
    const fn supports_scope(self) -> bool {
        self.supports_hooks()
    }

    /// The MCP registration follows `--scope` (otherwise it is user-level).
    const fn mcp_follows_scope(self) -> bool {
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
    /// Agent home directories moved by environment variables.
    dirs: AgentDirs,
}

/// Where agents keep their user-level configuration when an environment
/// variable moves it (`None`: the default under `home`).
#[derive(Debug, Clone, Default)]
struct AgentDirs {
    /// `CODEX_HOME` (default `~/.codex`).
    codex_home: Option<PathBuf>,
    /// `COPILOT_HOME` (default `~/.copilot`).
    copilot_home: Option<PathBuf>,
    /// `XDG_CONFIG_HOME` (default `~/.config`), for `OpenCode`.
    xdg_config_home: Option<PathBuf>,
    /// `CLAUDE_CONFIG_DIR` (default `~/.claude`; `.claude.json` moves into
    /// it too).
    claude_config_dir: Option<PathBuf>,
    /// Claude Code's managed settings file (read for `disableAllHooks`).
    claude_managed: Option<PathBuf>,
    /// The running shellfirm binary: the Cline script and the `OpenCode`
    /// plugin fall back to it when `shellfirm` is not on the agent's PATH.
    current_exe: Option<PathBuf>,
}

impl AgentDirs {
    fn from_env() -> Self {
        let var = |k: &str| {
            std::env::var_os(k)
                .filter(|v| !v.is_empty())
                .map(PathBuf::from)
                .filter(|p| p.is_absolute())
        };
        Self {
            codex_home: var("CODEX_HOME"),
            copilot_home: var("COPILOT_HOME"),
            xdg_config_home: var("XDG_CONFIG_HOME"),
            claude_config_dir: claude_config_dir_from(
                std::env::var_os("CLAUDE_CONFIG_DIR"),
                std::env::current_dir().ok().as_deref(),
            ),
            claude_managed: Some(claude_managed_settings()),
            current_exe: std::env::current_exe().ok(),
        }
    }

    /// Claude Code's user directory: `$CLAUDE_CONFIG_DIR`, else `~/.claude`.
    fn claude_dir(&self, home: &Path) -> PathBuf {
        self.claude_config_dir
            .clone()
            .unwrap_or_else(|| home.join(".claude"))
    }

    /// Claude Code's `.claude.json` (user MCP servers): inside
    /// `$CLAUDE_CONFIG_DIR` when it is set, else `~/.claude.json`.
    fn claude_json(&self, home: &Path) -> PathBuf {
        self.claude_config_dir
            .as_ref()
            .map_or_else(|| home.join(".claude.json"), |d| d.join(".claude.json"))
    }
}

/// `$CLAUDE_CONFIG_DIR` as Claude Code uses it: a relative value (`rel`,
/// a literal `~/cc`) is relative to the current directory. Empty: unset.
fn claude_config_dir_from(
    value: Option<std::ffi::OsString>,
    cwd: Option<&Path>,
) -> Option<PathBuf> {
    let p = PathBuf::from(value.filter(|v| !v.is_empty())?);
    if p.is_absolute() {
        Some(p)
    } else {
        cwd.map(|c| c.join(p))
    }
}

/// Claude Code's user directory for `home`: `$CLAUDE_CONFIG_DIR` (a
/// relative one resolved against the current directory) or `~/.claude`.
#[must_use]
pub(super) fn claude_user_dir(home: &Path) -> PathBuf {
    AgentDirs::from_env().claude_dir(home)
}

/// Where Claude Code reads managed (organisation) settings on this platform.
#[must_use]
pub(super) fn claude_managed_settings() -> PathBuf {
    if cfg!(target_os = "macos") {
        PathBuf::from("/Library/Application Support/ClaudeCode/managed-settings.json")
    } else if cfg!(windows) {
        PathBuf::from(r"C:\Program Files\ClaudeCode\managed-settings.json")
    } else {
        PathBuf::from("/etc/claude-code/managed-settings.json")
    }
}

/// `path` (under `root`) reaches outside `root` through a symlink: the
/// file itself or a directory between `root` and it is a link that points
/// out of `root`, or a dangling link. Returns the offending link and where
/// it leads. A project-scope file is shared with the repository; a link
/// planted in it must not make shellfirm write another file (an agent's
/// user settings, say).
#[must_use]
pub(super) fn symlink_out_of(path: &Path, root: &Path) -> Option<(PathBuf, String)> {
    let rel = path.strip_prefix(root).ok()?;
    let root_canon = fs::canonicalize(root).unwrap_or_else(|_| root.to_path_buf());
    let mut cur = root.to_path_buf();
    for comp in rel.components() {
        cur.push(comp);
        if !fs::symlink_metadata(&cur).is_ok_and(|m| m.file_type().is_symlink()) {
            continue;
        }
        match fs::canonicalize(&cur) {
            Ok(target) if target.starts_with(&root_canon) => {}
            Ok(target) => return Some((cur, target.display().to_string())),
            Err(_) => return Some((cur, "a missing target".into())),
        }
    }
    None
}

/// The error for [`symlink_out_of`]; `scope` is `project` or `local`.
pub(super) fn symlink_refusal(path: &Path, link: &Path, target: &str, scope: &str) -> String {
    format!(
        "{} is a symlink to {target}, outside this project; shellfirm does not write through \
         it at {scope} scope (it would change {}). Remove the link, or edit the file by hand.",
        link.display(),
        if link == path {
            "that file".to_string()
        } else {
            format!("a file other than {}", path.display())
        }
    )
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
#[allow(clippy::trivially_copy_pass_by_ref, clippy::too_many_lines)]
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
            let settings = match opts.scope {
                Scope::User => env.dirs.claude_dir(&env.home).join("settings.json"),
                Scope::Project => base.join(".claude").join("settings.json"),
            };
            if opts.hooks {
                steps.push((settings.clone(), OpKind::ClaudeHooks));
            }
            if opts.mcp {
                match opts.scope {
                    Scope::User => {
                        steps.push((env.dirs.claude_json(&env.home), OpKind::ClaudeMcp));
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
        Provider::Codex if opts.hooks => {
            let dir = match opts.scope {
                Scope::User => env
                    .dirs
                    .codex_home
                    .clone()
                    .unwrap_or_else(|| env.home.join(".codex")),
                Scope::Project => base.join(".codex"),
            };
            steps.push((dir.join("hooks.json"), OpKind::CodexHooks));
        }
        Provider::Gemini if opts.hooks => {
            steps.push((
                base.join(".gemini").join("settings.json"),
                OpKind::GeminiHooks,
            ));
        }
        Provider::Qwen if opts.hooks => {
            steps.push((base.join(".qwen").join("settings.json"), OpKind::QwenHooks));
        }
        Provider::Copilot if opts.hooks => {
            let dir = match opts.scope {
                Scope::User => env
                    .dirs
                    .copilot_home
                    .clone()
                    .unwrap_or_else(|| env.home.join(".copilot"))
                    .join("hooks"),
                Scope::Project => base.join(".github").join("hooks"),
            };
            steps.push((dir.join("shellfirm.json"), OpKind::CopilotHooks));
        }
        Provider::OpenCode if opts.hooks => {
            let dir = match opts.scope {
                Scope::User => env
                    .dirs
                    .xdg_config_home
                    .clone()
                    .unwrap_or_else(|| env.home.join(".config"))
                    .join("opencode"),
                Scope::Project => base.join(".opencode"),
            };
            steps.push((
                dir.join("plugins").join("shellfirm.js"),
                OpKind::OpenCodePlugin,
            ));
        }
        Provider::Codex
        | Provider::Gemini
        | Provider::Qwen
        | Provider::Copilot
        | Provider::OpenCode => {}
        Provider::Windsurf => {
            if opts.hooks {
                let path = match opts.scope {
                    Scope::User => env
                        .home
                        .join(".codeium")
                        .join("windsurf")
                        .join("hooks.json"),
                    Scope::Project => base.join(".windsurf").join("hooks.json"),
                };
                steps.push((path, OpKind::WindsurfHooks));
            }
            if opts.mcp && opts.scope == Scope::User {
                steps.push((
                    env.home
                        .join(".codeium")
                        .join("windsurf")
                        .join("mcp_config.json"),
                    OpKind::StandardMcp,
                ));
            }
        }
        Provider::Zed => steps.push((
            env.home.join(".config").join("zed").join("settings.json"),
            OpKind::ZedMcp,
        )),
        Provider::Cline => {
            if opts.hooks {
                if cfg!(windows) {
                    return Err("shellfirm's Cline hook is a POSIX shell script; it is not \
                                available on Windows (use --mcp-only)"
                        .into());
                }
                let dir = match opts.scope {
                    Scope::User => env.home.join("Documents").join("Cline").join("Hooks"),
                    Scope::Project => base.join(".clinerules").join("hooks"),
                };
                steps.push((dir.join("PreToolUse"), OpKind::ClineScript));
            }
            if opts.mcp && opts.scope == Scope::User {
                let path = cline_settings_path(&env.home).ok_or_else(|| {
                    "Cline's settings location is unknown on this platform".to_string()
                })?;
                steps.push((path, OpKind::StandardMcp));
            }
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

pub(super) fn root_object<'a>(
    value: &'a mut Value,
    path: &Path,
) -> OpResult<&'a mut Map<String, Value>> {
    value.as_object_mut().ok_or_else(|| {
        format!(
            "{} does not contain a JSON object at the top level; refusing to modify it",
            path.display()
        )
    })
}

pub(super) fn child_object<'a>(
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

pub(super) fn child_array<'a>(
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
    "Read",
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
/// Cursor hook event that runs before the agent reads a file (its payload
/// carries `file_path`); a read of a credential file is blocked.
const CURSOR_READ_EVENT: &str = "beforeReadFile";
/// Every Cursor event shellfirm writes an entry in.
const CURSOR_EVENTS: [&str; 3] = [CURSOR_SHELL_EVENT, CURSOR_TOOL_EVENT, CURSOR_READ_EVENT];

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
    let missing_read: Vec<&str> = shellfirm::agent::FILE_READ_TOOLS
        .iter()
        .copied()
        .filter(|t| !state.covered.contains(t))
        .collect();
    if !missing_read.is_empty() {
        let matcher = missing_read.join("|");
        groups.push(json!({ "matcher": matcher, "hooks": [claude_hook_entry(spec)] }));
        actions.push(format!(
            "add hooks.PreToolUse entry (matcher \"{matcher}\") so reading a private key or a \
             credentials file needs approval"
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
    let existing_dir = CURSOR_EVENTS
        .iter()
        .flat_map(|e| cursor_event_entries(value, e))
        .find_map(|(hc, _)| hc.config_dir);
    let spec = &InstallSpec {
        config_dir: existing_dir.or_else(|| spec.config_dir.clone()),
        ..spec.clone()
    };
    let desired = spec.hook_command(CURSOR_HOOK_ARGS);
    let has_file_hook = !cursor_file_hook_entries(value).is_empty();
    let has_read_hook = !cursor_event_entries(value, CURSOR_READ_EVENT).is_empty();
    let root = root_object(value, path)?;
    let had_hooks_key = root.contains_key("hooks");
    let hooks = child_object(root, "hooks", path, true)?.expect("created");
    let mut kept_shell = 0usize;
    for event in CURSOR_EVENTS {
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
    if !has_read_hook {
        let list = child_array(hooks, CURSOR_READ_EVENT, "hooks.beforeReadFile", path, true)?
            .expect("created");
        list.push(json!({ "command": desired, "timeout": HOOK_TIMEOUT_SECS }));
        actions.push(
            "add hooks.beforeReadFile entry so agent reads of private keys and credential \
             files are blocked"
                .into(),
        );
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
    if let Some(r) = agents::install(op, value, path, spec) {
        return r;
    }
    match op {
        OpKind::ClaudeHooks => return install_claude_hooks(value, path, spec),
        OpKind::CursorHooks => return install_cursor_hooks(value, path, spec),
        OpKind::LegacyClaudeSettingsMcp => return uninstall(op, value, path),
        OpKind::ClaudeMcp | OpKind::StandardMcp | OpKind::ZedMcp => {}
        _ => return Err(format!("internal error: {op:?} is not a JSON operation")),
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
    if let Some(r) = agents::uninstall(op, value, path) {
        return r;
    }
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
            for event in CURSOR_EVENTS {
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
        OpKind::CodexHooks
        | OpKind::GeminiHooks
        | OpKind::QwenHooks
        | OpKind::CopilotHooks
        | OpKind::WindsurfHooks
        | OpKind::ClineScript
        | OpKind::OpenCodePlugin => {}
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

/// A planned change to a file shellfirm owns (Cline script, `OpenCode` plugin).
struct OwnedChange {
    path: PathBuf,
    exists: bool,
    /// New content; `None` removes the file.
    content: Option<String>,
    executable: bool,
    actions: Vec<String>,
}

/// What to do with a file shellfirm owns. `None`: nothing to change. A file
/// at `path` that shellfirm did not write is never replaced or removed.
#[allow(clippy::trivially_copy_pass_by_ref)]
fn plan_owned(
    op: OpKind,
    path: &Path,
    opts: &Options,
    spec: &InstallSpec,
    fallback: Option<&str>,
) -> OpResult<Option<OwnedChange>> {
    let current = match read_regular(path) {
        Ok(b) => Some(String::from_utf8_lossy(&b).into_owned()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            if fs::symlink_metadata(path).is_ok() {
                return Err(format!(
                    "{} is a dangling symlink; refusing to modify it",
                    path.display()
                ));
            }
            None
        }
        Err(e) => return Err(format!("could not read {}: {e}", path.display())),
    };
    let ours = current.as_deref().is_some_and(|c| agents::is_ours(op, c));
    let what = if op == OpKind::ClineScript {
        "Cline PreToolUse hook script"
    } else {
        "OpenCode plugin"
    };
    if opts.uninstall {
        return Ok(ours.then(|| OwnedChange {
            path: path.to_path_buf(),
            exists: true,
            content: None,
            executable: false,
            actions: vec![format!("remove the shellfirm {what}")],
        }));
    }
    if current.is_some() && !ours {
        return Err(format!(
            "{} exists and was not written by shellfirm; nothing was changed. Move it away (or \
             call `shellfirm check --hook {}` from it) and run this again.",
            path.display(),
            if op == OpKind::ClineScript {
                "cline"
            } else {
                "opencode"
            }
        ));
    }
    // An existing shellfirm file keeps the configuration directory it records.
    let spec = InstallSpec {
        config_dir: current
            .as_deref()
            .and_then(|c| agents::recorded_config_dir(op, c))
            .or_else(|| spec.config_dir.clone()),
        ..spec.clone()
    };
    let desired = agents::owned_content(op, &spec, fallback);
    if current.as_deref() == Some(desired.as_str()) {
        return Ok(None);
    }
    Ok(Some(OwnedChange {
        path: path.to_path_buf(),
        exists: current.is_some(),
        executable: op == OpKind::ClineScript,
        actions: vec![if current.is_some() {
            format!("rewrite the shellfirm {what} (it is out of date)")
        } else {
            format!(
                "add the {what} running `{}`",
                spec.hook_command(&format!(
                    "check --hook {}",
                    if op == OpKind::ClineScript {
                        "cline"
                    } else {
                        "opencode"
                    }
                ))
            )
        }],
        content: Some(desired),
    }))
}

/// Write (or remove) a file shellfirm owns, backing up the old one first.
fn save_owned(c: &OwnedChange, backup_dir: Option<&Path>) -> OpResult<Option<PathBuf>> {
    let target = if c.exists {
        fs::canonicalize(&c.path).map_err(|e| format!("{}: {e}", c.path.display()))?
    } else {
        c.path.clone()
    };
    let backup = if c.exists {
        if let Some(d) = backup_dir {
            create_private_dir(d)
                .map_err(|e| format!("could not create backup directory {}: {e}", d.display()))?;
        }
        let bak = backup_path_for(&target, backup_dir);
        fs::copy(&target, &bak)
            .map_err(|e| format!("could not back up {}: {e}", c.path.display()))?;
        prune_backups(&bak);
        Some(bak)
    } else {
        None
    };
    let Some(content) = &c.content else {
        fs::remove_file(&target)
            .map_err(|e| format!("could not remove {}: {e}", c.path.display()))?;
        return Ok(backup);
    };
    let parent = target
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .map_or_else(|| PathBuf::from("."), Path::to_path_buf);
    fs::create_dir_all(&parent)
        .map_err(|e| format!("could not create {}: {e}", parent.display()))?;
    let name = target
        .file_name()
        .map_or_else(|| "hook".into(), |n| n.to_string_lossy().into_owned());
    let tmp = parent.join(format!(".{name}.shellfirm-tmp-{}", std::process::id()));
    let write = || -> std::io::Result<()> {
        let mut f = fs::File::create(&tmp)?;
        f.write_all(content.as_bytes())?;
        f.sync_all()?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = if c.executable { 0o755 } else { 0o644 };
            fs::set_permissions(&tmp, fs::Permissions::from_mode(mode))?;
        }
        fs::rename(&tmp, &target)
    };
    if let Err(e) = write() {
        let _ = fs::remove_file(&tmp);
        return Err(format!("could not write {}: {e}", c.path.display()));
    }
    Ok(backup)
}

/// `true` when a file holds nothing but (at most) a Cursor `version` key, so
/// it can be deleted instead of being left behind as a `{}` stub.
fn is_empty_stub(value: &Value, ops: &[OpKind]) -> bool {
    value.as_object().is_some_and(|m| {
        m.is_empty()
            || ((ops.contains(&OpKind::CursorHooks) || ops.contains(&OpKind::CopilotHooks))
                && m.len() == 1
                && m.contains_key("version"))
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
    /// `claude-code`, `cursor`, `codex`, `gemini`, `qwen`, `copilot`,
    /// `windsurf`, `cline`, `opencode` or `zed`.
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
    /// Claude Code: Write/Edit/MultiEdit/NotebookEdit and Read are covered too.
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
    /// Things to know about an installed hook (the agent must trust it
    /// first, a file at its path that shellfirm did not write, ...).
    pub notes: Vec<String>,
    /// Why the hook does not run although it is installed (turned off in
    /// the agent's settings), each with how to turn it back on.
    pub hook_off: Vec<String>,
    /// A file could not be read or parsed.
    pub error: Option<String>,
}

/// Read `path` only when it is a regular file (see
/// [`shellfirm::config::read_regular_file`]).
pub(super) fn read_regular(path: &Path) -> std::io::Result<Vec<u8>> {
    shellfirm::config::read_regular_file(path)
}

/// [`read_regular`] as UTF-8 text.
pub(super) fn read_regular_string(path: &Path) -> std::io::Result<String> {
    shellfirm::config::read_regular_string(path)
}

pub(super) fn read_value(path: &Path) -> std::result::Result<Option<Value>, String> {
    // A folder on the path that cannot be read is an error, not "missing".
    match path.try_exists() {
        Ok(false) => return Ok(None),
        Err(e) => return Err(format!("can't read {}: {e}", path.display())),
        Ok(true) => {}
    }
    let content = read_regular_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
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
    integration_status_in(&ConnectEnv {
        home: home.to_path_buf(),
        cwd: cwd.to_path_buf(),
        backup_dir: None,
        config_dir: None,
        dirs: AgentDirs::from_env(),
    })
}

#[allow(clippy::too_many_lines)]
fn integration_status_in(env: &ConnectEnv) -> Vec<IntegrationStatus> {
    let (home, cwd) = (env.home.as_path(), env.cwd.as_path());
    let mut out = Vec::new();
    let mut scopes = vec![Scope::User];
    if cwd != home {
        scopes.push(Scope::Project);
    }
    for provider in ALL_PROVIDERS {
        for &scope in &scopes {
            if scope == Scope::Project && !provider.supports_scope() {
                continue;
            }
            let opts = Options {
                dry_run: true,
                uninstall: false,
                // shellfirm's Cline hook is a POSIX shell script.
                hooks: provider.supports_hooks() && !(cfg!(windows) && provider == Provider::Cline),
                mcp: provider.supports_mcp(),
                scope,
                fail_closed: true,
            };
            let Ok(files) = plan(provider, &opts, env) else {
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
                notes: Vec::new(),
                hook_off: Vec::new(),
                error: None,
            };
            for (path, ops) in files {
                if scope == Scope::Project {
                    if let Some((link, target)) = symlink_out_of(&path, cwd) {
                        st.hook_file = Some(path.display().to_string());
                        st.error = Some(symlink_refusal(&path, &link, &target, "project"));
                        continue;
                    }
                }
                if let Some(&op) = ops.iter().find(|o| o.is_owned_file()) {
                    st.hook_file = Some(path.display().to_string());
                    match read_regular_string(&path) {
                        Ok(content) if agents::is_ours(op, &content) => {
                            st.hook_present = true;
                            st.hook_installed = true;
                            st.file_tools_covered = true;
                            // Both answer "block" themselves when shellfirm
                            // cannot run.
                            st.fail_closed = true;
                            st.config_dir = agents::recorded_config_dir(op, &content);
                            if op == OpKind::ClineScript {
                                st.notes.push(
                                    "in the VS Code extension, turn on \"Enable Hooks\" in \
                                     Cline's settings"
                                        .into(),
                                );
                            }
                        }
                        Ok(_) => st.notes.push(format!(
                            "{} exists but was not written by shellfirm",
                            path.display()
                        )),
                        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                        Err(e) => st.error = Some(format!("{}: {e}", path.display())),
                    }
                    continue;
                }
                let value = match read_value(&path) {
                    Ok(v) => v.unwrap_or_else(|| json!({})),
                    Err(e) => {
                        st.error = Some(e);
                        continue;
                    }
                };
                for op in ops {
                    if agents::status(op, &value, &mut st) {
                        st.hook_file = Some(path.display().to_string());
                        continue;
                    }
                    match op {
                        OpKind::ClaudeHooks => {
                            st.hook_file = Some(path.display().to_string());
                            fill_claude_hook_state(&mut st, &value);
                        }
                        OpKind::CursorHooks => {
                            let entries = cursor_hook_entries(&value);
                            st.hook_file = Some(path.display().to_string());
                            let files = cursor_file_hook_entries(&value);
                            st.hook_installed = !entries.is_empty();
                            st.hook_present = !entries.is_empty()
                                || !cursor_event_entries(&value, CURSOR_TOOL_EVENT).is_empty()
                                || !cursor_event_entries(&value, CURSOR_READ_EVENT).is_empty();
                            let reads = cursor_event_entries(&value, CURSOR_READ_EVENT);
                            st.file_tools_covered = !files.is_empty() && !reads.is_empty();
                            st.legacy_hook = entries
                                .iter()
                                .chain(files.iter())
                                .chain(reads.iter())
                                .any(|(hc, _)| hc.legacy);
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
                        _ => {}
                    }
                }
            }
            if st.hook_present {
                match provider {
                    Provider::ClaudeCode => st.hook_off.extend(
                        claude_hooks_off(env)
                            .into_iter()
                            .chain(claude_managed_only(env)),
                    ),
                    Provider::Codex => st.hook_off.extend(codex_hooks_off(env)),
                    _ => {}
                }
            }
            out.push(st);
        }
        if provider == Provider::ClaudeCode {
            out.extend(claude_managed_row(env));
        }
    }
    out
}

/// What the shellfirm entries in Claude Code `hooks` cover.
fn fill_claude_hook_state(st: &mut IntegrationStatus, value: &Value) {
    let s = claude_hook_state(value);
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
        .chain(shellfirm::agent::FILE_READ_TOOLS)
        .all(|t| s.covered.contains(t));
    st.legacy_hook = s.legacy > 0;
    st.fail_closed = s.entries > 0 && s.fail_closed == s.entries;
    st.config_dir = s.config_dirs.first().cloned();
}

/// A shellfirm hook in Claude Code's managed settings (put there by an
/// administrator; `connect` never writes that file). `None` when the file
/// is missing or holds no shellfirm hook.
fn claude_managed_row(env: &ConnectEnv) -> Option<IntegrationStatus> {
    let path = env.dirs.claude_managed.as_ref()?;
    let mut st = IntegrationStatus {
        tool: Provider::ClaudeCode.cli_name(),
        scope: "managed",
        hook_file: Some(path.display().to_string()),
        hook_installed: false,
        hook_present: false,
        shell_tools_missing: Vec::new(),
        file_tools_covered: false,
        legacy_hook: false,
        fail_closed: false,
        config_dir: None,
        mcp_file: None,
        mcp_registered: false,
        notes: Vec::new(),
        hook_off: Vec::new(),
        error: None,
    };
    match read_value(path) {
        Ok(None) => return None,
        Ok(Some(value)) => {
            fill_claude_hook_state(&mut st, &value);
            if !st.hook_present {
                return None;
            }
            // Only managed settings can turn managed hooks off.
            if value.get("disableAllHooks").and_then(Value::as_bool) == Some(true) {
                st.hook_off.push(format!(
                    "disableAllHooks is true in {}: Claude Code runs no hook (remove it or set \
                     it to false)",
                    path.display()
                ));
            }
        }
        Err(e) => st.error = Some(e),
    }
    Some(st)
}

/// The managed settings file holds a shellfirm hook that covers `Bash`.
fn claude_managed_hook(env: &ConnectEnv) -> bool {
    claude_managed_row(env).is_some_and(|r| r.hook_installed && r.hook_off.is_empty())
}

/// Claude Code's `disableAllHooks`: the value from the highest-precedence
/// settings file that sets it (managed, local, project, user). `Some` with
/// the file when it turns every hook off.
fn claude_hooks_off(env: &ConnectEnv) -> Option<String> {
    let dir = env.cwd.join(".claude");
    let project = (env.cwd != env.home)
        .then(|| [dir.join("settings.local.json"), dir.join("settings.json")])
        .into_iter()
        .flatten();
    let files = env
        .dirs
        .claude_managed
        .iter()
        .cloned()
        .chain(project)
        .chain([env.dirs.claude_dir(&env.home).join("settings.json")]);
    files.into_iter().find_map(|f| {
        let v = read_value(&f).ok().flatten()?;
        let off = v.get("disableAllHooks")?.as_bool()?;
        Some(off.then(|| {
            format!(
                "disableAllHooks is true in {}: Claude Code runs no hook (remove it or set it \
                 to false)",
                f.display()
            )
        }))
    })?
}

/// Claude Code's managed setting that loads only managed hooks.
pub(super) const MANAGED_HOOKS_ONLY: &str = "allowManagedHooksOnly";

/// Claude Code's managed `allowManagedHooksOnly`: user, project and plugin
/// hooks (where `shellfirm connect` puts its hook) are not loaded.
fn claude_managed_only(env: &ConnectEnv) -> Option<String> {
    let f = env.dirs.claude_managed.as_ref()?;
    let on = read_value(f).ok()??.get(MANAGED_HOOKS_ONLY)?.as_bool()?;
    on.then(|| {
        let advice = if claude_managed_hook(env) {
            "the shellfirm hook in that file runs instead"
        } else {
            "put the shellfirm hook in that file, or remove the setting"
        };
        format!(
            "{MANAGED_HOOKS_ONLY} is true in {}: Claude Code runs only hooks from managed \
             settings ({advice})",
            f.display()
        )
    })
}

/// Codex's hooks feature flag (`[features] hooks`, formerly `codex_hooks`,
/// on by default): the project `.codex/config.toml` overrides the user one.
fn codex_hooks_off(env: &ConnectEnv) -> Option<String> {
    let user = env
        .dirs
        .codex_home
        .clone()
        .unwrap_or_else(|| env.home.join(".codex"))
        .join("config.toml");
    let mut files = Vec::new();
    if env.cwd != env.home {
        files.push(env.cwd.join(".codex").join("config.toml"));
    }
    files.push(user);
    files.into_iter().find_map(|f| {
        let doc = read_regular_string(&f)
            .ok()?
            .parse::<toml_edit::DocumentMut>()
            .ok()?;
        let features = doc.get("features")?;
        let (key, on) = ["hooks", "codex_hooks"]
            .into_iter()
            .find_map(|k| features.get(k)?.as_bool().map(|b| (k, b)))?;
        Some((!on).then(|| {
            format!(
                "hooks are turned off in {} ([features] {key} = false): Codex runs no hook \
                 (set it to true)",
                f.display()
            )
        }))
    })?
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

pub(super) struct LoadedFile {
    /// Path as shown to the user.
    pub(super) path: PathBuf,
    /// Where to write (symlink target if `path` is a symlink).
    pub(super) write_path: PathBuf,
    pub(super) exists: bool,
    pub(super) value: Value,
    pub(super) lossy_format: bool,
}

/// Read a config file that is about to be modified: `None` when it does not
/// exist, else the path to write to (symlink target) and its text.
pub(super) fn read_text(path: &Path) -> OpResult<Option<(PathBuf, String)>> {
    if !path.exists() {
        if fs::symlink_metadata(path).is_ok() {
            return Err(format!(
                "{} is a dangling symlink; refusing to modify it",
                path.display()
            ));
        }
        return Ok(None);
    }
    let write_path = fs::canonicalize(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let bytes =
        read_regular(path).map_err(|e| format!("could not read {}: {e}", path.display()))?;
    let content = String::from_utf8(bytes).map_err(|_| {
        format!(
            "{} is not valid UTF-8; refusing to modify it",
            path.display()
        )
    })?;
    Ok(Some((write_path, content)))
}

pub(super) fn load_file(path: &Path) -> OpResult<LoadedFile> {
    let Some((write_path, content)) = read_text(path)? else {
        return Ok(LoadedFile {
            path: path.to_path_buf(),
            write_path: path.to_path_buf(),
            exists: false,
            value: json!({}),
            lossy_format: false,
        });
    };
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
            let shown = path.display().to_string();
            // Windows: the canonical path is `\\?\C:\…` (`\\?\UNC\…` on a
            // share); that prefix is not part of the name, and `?`, `*`,
            // `<`, `>`, `"`, `|` cannot appear in a file name there.
            #[cfg(windows)]
            let shown = shown
                .strip_prefix(r"\\?\UNC\")
                .map(str::to_string)
                .or_else(|| shown.strip_prefix(r"\\?\").map(str::to_string))
                .unwrap_or(shown);
            let flat: String = shown
                .trim_start_matches(['/', '\\'])
                .chars()
                .map(|c| {
                    if matches!(c, '/' | '\\' | ':')
                        || (cfg!(windows) && matches!(c, '?' | '*' | '<' | '>' | '"' | '|'))
                    {
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

/// Remove the directories between `file` and `root` that are left empty
/// (`.github/hooks` and `.github` after a project-scope uninstall). A
/// directory that still holds anything stays.
pub(super) fn remove_empty_parents(file: &Path, root: &Path) {
    for dir in file.ancestors().skip(1) {
        if dir == root || !dir.starts_with(root) || fs::remove_dir(dir).is_err() {
            break;
        }
    }
}

/// shellfirm keeps this many backups of each file; older ones are deleted.
pub(super) const BACKUPS_KEPT: usize = 3;

/// `rest` is what [`backup_path_for`] puts after `.shellfirm-bak-`: a
/// `YYYYMMDDTHHMMSSZ` stamp, then an optional `-<n>`.
fn is_backup_suffix(rest: &str) -> bool {
    let (stamp, n) = rest.split_once('-').unwrap_or((rest, "1"));
    let b = stamp.as_bytes();
    b.len() == 16
        && b[8] == b'T'
        && b[15] == b'Z'
        && b[..8].iter().chain(&b[9..15]).all(u8::is_ascii_digit)
        && !n.is_empty()
        && n.bytes().all(|c| c.is_ascii_digit())
}

/// Delete all but the newest [`BACKUPS_KEPT`] shellfirm backups of the
/// file `bak` (just written) is a backup of.
fn prune_backups(bak: &Path) {
    let (Some(dir), Some(name)) = (bak.parent(), bak.file_name().and_then(|n| n.to_str())) else {
        return;
    };
    let Some(idx) = name.find(".shellfirm-bak-") else {
        return;
    };
    let prefix = &name[..idx + ".shellfirm-bak-".len()];
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    // Named `<prefix><UTC timestamp>[-<n>]`: the name sorts by age.
    let mut found: Vec<(String, PathBuf)> = entries
        .filter_map(std::result::Result::ok)
        .filter_map(|e| {
            let n = e.file_name().to_str()?.to_string();
            // Only names shellfirm writes: not a user's own
            // `settings.json.shellfirm-bak-mine`.
            is_backup_suffix(n.strip_prefix(prefix)?).then(|| (n.clone(), e.path()))
        })
        .collect();
    found.sort();
    let excess = found.len().saturating_sub(BACKUPS_KEPT);
    for (_, p) in found.into_iter().take(excess) {
        let _ = fs::remove_file(p);
    }
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
pub(super) enum SaveMode {
    Write,
    /// The file would only be an empty stub after uninstall: delete it.
    Remove,
}

/// Write `value` to `file` atomically (or remove the file), after backing up
/// the existing file. Returns the backup path (if a backup was made).
pub(super) fn save_file(
    file: &LoadedFile,
    value: &Value,
    backup_dir: Option<&Path>,
    mode: SaveMode,
) -> OpResult<Option<PathBuf>> {
    let text = serde_json::to_string_pretty(value).map_err(|e| e.to_string())? + "\n";
    save_text(file, &text, backup_dir, mode)
}

/// [`save_file`] for content that is already serialized (any format).
pub(super) fn save_text(
    file: &LoadedFile,
    text: &str,
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
        prune_backups(&bak);
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

/// A tool with a hook and no MCP registration.
fn hooks_only_subcommand(name: &'static str, about: &'static str, long: &'static str) -> Command {
    Command::new(name)
        .about(about)
        .long_about(long)
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

#[allow(clippy::too_many_lines)]
pub fn command() -> Command {
    Command::new("connect")
        .about("Connect AI agents (blocking hooks, MCP server)")
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
            project-policy, agent-settings, hook or shell startup files, and a third (matcher \
            Read) asks before it reads a private key or a credentials file.\n\n\
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
        .subcommand(hooks_only_subcommand(
            "codex",
            "Connect OpenAI Codex CLI (PreToolUse hook)",
            "Connect OpenAI Codex CLI (0.124.0 or later).\n\n\
            user scope:    ~/.codex/hooks.json ($CODEX_HOME/hooks.json when set)\n\
            project scope: ./.codex/hooks.json (Codex loads it in trusted projects)\n\n\
            A PreToolUse hook (matcher Bash|apply_patch) runs `shellfirm check --hook codex` \
            before every shell command and apply_patch edit. Codex hooks cannot ask, so \
            risky commands are denied with the reason and a safer alternative, like dangerous \
            ones; safe commands get no answer (Codex's own approvals apply). Codex runs a new \
            or changed hook only after you trust it: the TUI lists it when it starts (or use \
            /hooks), and `codex exec` skips it until then. If shellfirm is missing or times \
            out, Codex runs the command.",
        ))
        .subcommand(hooks_only_subcommand(
            "gemini",
            "Connect Google Gemini CLI (BeforeTool hook)",
            "Connect Google Gemini CLI.\n\n\
            user scope:    ~/.gemini/settings.json\n\
            project scope: ./.gemini/settings.json (Gemini asks you to trust project hooks)\n\n\
            A BeforeTool hook named \"shellfirm\" (matcher \
            ^(run_shell_command|write_file|replace|read_file|read_many_files)$, timeout 30000 ms) runs \
            `shellfirm check --hook gemini`: risky commands and edits ask (Gemini CLI 0.36.0 \
            or later; older versions ignore the ask), dangerous ones are denied. Turn it off \
            with /hooks disable shellfirm.",
        ))
        .subcommand(hooks_only_subcommand(
            "qwen",
            "Connect Qwen Code (PreToolUse hook)",
            "Connect Qwen Code.\n\n\
            user scope:    ~/.qwen/settings.json\n\
            project scope: ./.qwen/settings.json (Qwen Code asks you to approve project hooks)\n\n\
            A PreToolUse hook (matcher \
            run_shell_command|write_file|edit|read_file|read_many_files) runs \
            `shellfirm check --hook qwen`: risky commands and edits ask, dangerous ones are \
            denied (headless runs deny what would be asked).",
        ))
        .subcommand(hooks_only_subcommand(
            "copilot",
            "Connect GitHub Copilot CLI (preToolUse hook)",
            "Connect GitHub Copilot CLI (1.0.4 or later).\n\n\
            user scope:    ~/.copilot/hooks/shellfirm.json ($COPILOT_HOME/hooks when set)\n\
            project scope: ./.github/hooks/shellfirm.json (also used by Copilot cloud agent)\n\n\
            A preToolUse hook runs `shellfirm check --hook copilot` before every tool call: \
            risky shell commands and edits ask (autopilot and the cloud agent deny them), \
            dangerous ones are denied. Copilot denies the tool call when the hook fails \
            (shellfirm missing or crashing), except on a timeout.",
        ))
        .subcommand(hooks_tool_subcommand(
            "windsurf",
            "Connect Windsurf (Cascade hooks + MCP server)",
            "Connect Windsurf.\n\n\
            user scope:    hooks in ~/.codeium/windsurf/hooks.json, MCP server in \
            ~/.codeium/windsurf/mcp_config.json\n\
            project scope: hooks in ./.windsurf/hooks.json (the MCP registration is \
            user-level only)\n\n\
            pre_run_command, pre_write_code and pre_read_code hooks run `shellfirm check \
            --hook windsurf`, which blocks with exit code 2 and the reason on stderr. Cascade \
            hooks cannot ask, so risky commands are blocked like dangerous ones. If shellfirm \
            is missing, Cascade runs the action.",
        ))
        .subcommand(hooks_tool_subcommand(
            "cline",
            "Connect Cline (PreToolUse hook script + MCP server)",
            "Connect Cline (3.36 or later; macOS and Linux).\n\n\
            user scope:    hook script ~/Documents/Cline/Hooks/PreToolUse, MCP server in \
            Cline's cline_mcp_settings.json\n\
            project scope: hook script ./.clinerules/hooks/PreToolUse (the MCP registration is \
            user-level only)\n\n\
            The script runs `shellfirm check --hook cline` before every tool call and \
            answers {\"cancel\": true} (which stops the task) for dangerous and risky \
            commands and edits: Cline hooks cannot ask. It also cancels when shellfirm cannot \
            run. In the VS Code extension, turn on \"Enable Hooks\" in Cline's settings. An \
            existing PreToolUse script that shellfirm did not write is never replaced.",
        ))
        .subcommand(hooks_only_subcommand(
            "opencode",
            "Connect OpenCode (tool.execute.before plugin)",
            "Connect OpenCode.\n\n\
            user scope:    ~/.config/opencode/plugins/shellfirm.js ($XDG_CONFIG_HOME when set)\n\
            project scope: ./.opencode/plugins/shellfirm.js\n\n\
            The plugin sends bash, write, edit, read and apply_patch calls to `shellfirm check \
            --hook opencode` and throws (which blocks the call) unless shellfirm allows it: \
            dangerous and risky ones are blocked, because the plugin cannot ask. It also \
            blocks when shellfirm cannot run.",
        ))
        .subcommand(mcp_only_subcommand(
            "zed",
            "Register shellfirm's MCP tools with Zed (advisory; no interception)",
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
        mcp: !hooks_only && provider.supports_mcp(),
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
        dirs: AgentDirs::from_env(),
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

/// An installed hook that the agent's settings turn off (this file or
/// another scope): say so, with how to turn it on.
fn hook_off_warnings(provider: Provider, scope: Scope, env: &ConnectEnv, out: &mut String) {
    let scope = if scope == Scope::User {
        "user"
    } else {
        "project"
    };
    for row in integration_status_in(env)
        .iter()
        .filter(|r| r.tool == provider.cli_name() && r.scope == scope)
    {
        for off in &row.hook_off {
            let _ = writeln!(out, "! The hook does not run yet: {off}.");
        }
    }
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
        return Err(if provider.supports_hooks() {
            format!(
                "shellfirm does not register an MCP server with {}; run `shellfirm connect {}` \
                 without --mcp-only",
                provider.display_name(),
                provider.cli_name()
            )
        } else {
            format!(
                "{} has no command hook; run `shellfirm connect {}` without --hooks-only",
                provider.display_name(),
                provider.cli_name()
            )
        });
    }
    if opts.scope == Scope::Project && !provider.supports_scope() {
        return Err(format!(
            "{} does not support --scope project",
            provider.display_name()
        ));
    }

    // 1. Load and parse every file first; abort before writing anything.
    let files = plan(provider, opts, env)?;
    if opts.scope == Scope::Project {
        for (path, _) in &files {
            if let Some((link, target)) = symlink_out_of(path, &env.cwd) {
                return Err(symlink_refusal(path, &link, &target, "project"));
            }
        }
    }
    let mut loaded = Vec::new();
    let mut owned_files = Vec::new();
    for (path, ops) in files {
        if let Some(&op) = ops.iter().find(|o| o.is_owned_file()) {
            owned_files.push((path, op));
        } else {
            loaded.push((load_file(&path)?, ops));
        }
    }
    if opts.scope == Scope::Project && opts.mcp && !provider.mcp_follows_scope() {
        let _ = writeln!(
            out,
            "  ! the {} MCP registration is user-level only; run `shellfirm connect {}` \
             (user scope) for it",
            provider.display_name(),
            provider.cli_name()
        );
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
    let fallback = (opts.scope == Scope::User)
        .then_some(env.dirs.current_exe.as_ref())
        .flatten()
        .map(|p| p.display().to_string());
    let mut owned: Vec<OwnedChange> = Vec::new();
    for (path, op) in &owned_files {
        match plan_owned(*op, path, opts, &spec, fallback.as_deref())? {
            Some(c) => owned.push(c),
            None if !opts.uninstall => already.push(Component::Hooks),
            None => {}
        }
    }
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
            // Asked of the file itself: its canonical path also differs
            // when a parent directory is a link (macOS `/var` →
            // `/private/var`) and always on Windows (`\\?\` prefix).
            let is_symlink =
                fs::symlink_metadata(&file.path).is_ok_and(|m| m.file_type().is_symlink());
            let mode = if opts.uninstall && is_empty_stub(&value, ops) && !is_symlink {
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

    if changes.is_empty() && owned.is_empty() {
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
        if !opts.uninstall && opts.hooks {
            hook_off_warnings(provider, opts.scope, env, out);
        }
        return Ok(());
    }

    // 3. Show the plan / write.
    let mut written: Vec<String> = Vec::new();
    let backup_dir = env.backup_dir.as_deref();
    for (file, value, actions, mode) in &changes {
        // The change list is shown once the file is written (or for a dry
        // run): a failed write shows only the error.
        let mut block = String::new();
        if opts.dry_run {
            let _ = writeln!(
                block,
                "  Would {} {}:",
                if file.exists { "update" } else { "create" },
                file.path.display()
            );
        } else {
            let _ = writeln!(block, "  {}:", file.path.display());
        }
        if file.lossy_format {
            let _ = writeln!(
                block,
                "    ! this file contains comments or trailing commas, which will not be kept (a backup is made first)"
            );
        }
        for a in actions {
            let _ = writeln!(block, "    - {a}");
        }
        if opts.dry_run {
            if file.exists {
                let _ = writeln!(
                    block,
                    "    (a timestamped backup would be written first{})",
                    backup_dir.map_or_else(String::new, |d| format!(" to {}", d.display()))
                );
            }
            out.push_str(&block);
            continue;
        }
        match save_file(file, value, backup_dir, *mode) {
            Ok(backup) => {
                out.push_str(&block);
                written.push(file.path.display().to_string());
                if *mode == SaveMode::Remove && opts.scope == Scope::Project {
                    // `.claude` / `.cursor` that shellfirm emptied.
                    remove_empty_parents(&file.path, &env.cwd);
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

    for c in &owned {
        let verb = match (&c.content, c.exists) {
            (None, _) => "remove",
            (Some(_), true) => "update",
            (Some(_), false) => "create",
        };
        let mut block = String::new();
        if opts.dry_run {
            let _ = writeln!(block, "  Would {verb} {}:", c.path.display());
        } else {
            let _ = writeln!(block, "  {}:", c.path.display());
        }
        for a in &c.actions {
            let _ = writeln!(block, "    - {a}");
        }
        if opts.dry_run {
            if c.exists {
                let _ = writeln!(
                    block,
                    "    (a timestamped backup would be written first{})",
                    backup_dir.map_or_else(String::new, |d| format!(" to {}", d.display()))
                );
            }
            out.push_str(&block);
            continue;
        }
        match save_owned(c, backup_dir) {
            Ok(backup) => {
                out.push_str(&block);
                written.push(c.path.display().to_string());
                if c.content.is_none() && opts.scope == Scope::Project {
                    // The `hooks` / `plugins` directories shellfirm emptied.
                    remove_empty_parents(&c.path, &env.cwd);
                }
                let _ = writeln!(
                    out,
                    "    ✓ {}{}",
                    if c.content.is_none() {
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
    if opts.hooks {
        hook_off_warnings(provider, opts.scope, env, out);
    }
    let note = match provider {
        Provider::ClaudeCode if opts.hooks => {
            "Claude Code Bash/PowerShell/Monitor commands are now checked by shellfirm before they run \
             (risky -> ask, dangerous -> deny; everything else follows your normal \
             Claude Code permissions). Restart running Claude Code sessions."
        }
        Provider::Cursor if opts.hooks => {
            "Cursor shell commands are now checked by shellfirm (beforeShellExecution hook), \
             agent edits of protected files are blocked (preToolUse hook), and so are reads \
             of credential files (beforeReadFile hook). \
             Restart Cursor to pick up the change."
        }
        Provider::Codex if opts.hooks => {
            "Codex shell commands and apply_patch edits are now checked by shellfirm \
             (PreToolUse hook; dangerous and risky ones are denied, because Codex hooks cannot \
             ask). Codex runs a new or changed hook only after you trust it: start `codex` \
             once and trust it (or open /hooks); `codex exec` skips an untrusted hook. Needs \
             Codex CLI 0.124.0 or later."
        }
        Provider::Gemini if opts.hooks => {
            "Gemini CLI shell commands, file writes and reads are now checked by shellfirm \
             (BeforeTool hook: risky -> ask, dangerous -> deny). Asking needs Gemini CLI \
             0.36.0 or later. Restart running Gemini CLI sessions."
        }
        Provider::Qwen if opts.hooks => {
            "Qwen Code shell commands, file writes and reads are now checked by shellfirm \
             (PreToolUse hook: risky -> ask, dangerous -> deny; headless runs deny what would \
             be asked). Restart running Qwen Code sessions."
        }
        Provider::Copilot if opts.hooks => {
            "GitHub Copilot CLI tool calls are now checked by shellfirm (preToolUse hook: \
             risky -> ask, dangerous -> deny; autopilot denies what would be asked). Needs \
             Copilot CLI 1.0.4 or later. Restart running Copilot sessions."
        }
        Provider::Windsurf if opts.hooks => {
            "Windsurf (Cascade) commands, file writes and reads are now checked by shellfirm \
             (pre_run_command / pre_write_code / pre_read_code hooks; dangerous and risky ones \
             are blocked, because Cascade hooks cannot ask). Restart Windsurf."
        }
        Provider::Cline if opts.hooks => {
            "Cline tool calls are now checked by shellfirm (PreToolUse hook; dangerous and \
             risky ones cancel the task, because Cline hooks cannot ask). In the VS Code \
             extension, turn on \"Enable Hooks\" in Cline's settings (Cline 3.36 or later)."
        }
        Provider::OpenCode if opts.hooks => {
            "OpenCode shell commands, file edits and reads are now checked by shellfirm \
             (plugin; dangerous and risky ones are blocked, because the plugin cannot ask). \
             Restart OpenCode."
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
                dirs: AgentDirs::default(),
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
                "NotebookEdit",
                "Read"
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
    fn an_unreadable_agent_folder_is_an_error_not_missing() {
        use std::os::unix::fs::PermissionsExt;
        let mut sb = sandbox();
        sb.env.dirs.claude_config_dir = Some(sb.tree.root.join("ccd"));
        for p in [Provider::ClaudeCode, Provider::Codex] {
            exec(p, &hooks_only(false), &sb.env).0.unwrap();
        }
        let dirs = [sb.tree.root.join("ccd"), sb.env.home.join(".codex")];
        for d in &dirs {
            fs::set_permissions(d, fs::Permissions::from_mode(0o000)).unwrap();
        }
        let rows = integration_status_in(&sb.env);
        for d in &dirs {
            fs::set_permissions(d, fs::Permissions::from_mode(0o755)).unwrap();
        }
        for tool in ["claude-code", "codex"] {
            let row = rows
                .iter()
                .find(|s| s.tool == tool && s.scope == "user")
                .unwrap();
            assert!(
                row.error
                    .as_deref()
                    .is_some_and(|e| e.contains("can't read")),
                "{row:?}"
            );
        }
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
        assert_eq!(groups.len(), 4, "{v}");
        assert_eq!(groups[1]["matcher"], "Bash|PowerShell|Monitor");
        assert_eq!(groups[2]["matcher"], "MultiEdit|NotebookEdit");
        assert_eq!(groups[3]["matcher"], "Read");
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
                "PowerShell|Monitor",
                "Read"
            ],
            "{v}"
        );
        assert_eq!(claude_hook_state(&v).entries, 4);
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

    // -- Codex, Gemini, Qwen, Copilot, Windsurf, Cline, OpenCode --

    fn hooks_only(uninstall: bool) -> Options {
        opts(uninstall, true, false)
    }

    #[test]
    fn codex_install_merges_with_user_hooks_and_uninstall_keeps_them() {
        let sb = sandbox();
        let path = sb.env.home.join(".codex/hooks.json");
        // A user hook of their own, on the same event.
        write(
            &path,
            r#"{"description":"mine","hooks":{"PreToolUse":[{"matcher":"Bash","hooks":[{"type":"command","command":"python3 ~/.codex/hooks/log.py"}]}],"Stop":[{"hooks":[{"type":"command","command":"notify"}]}]}}"#,
        );
        let (r, out) = exec(Provider::Codex, &hooks_only(false), &sb.env);
        r.unwrap();
        assert!(out.contains("trust"), "{out}");
        let v = read_json(&path);
        let groups = v["hooks"]["PreToolUse"].as_array().unwrap();
        assert_eq!(groups.len(), 2);
        assert_eq!(
            groups[0]["hooks"][0]["command"],
            "python3 ~/.codex/hooks/log.py"
        );
        assert_eq!(groups[1]["matcher"], "Bash|apply_patch");
        assert_eq!(groups[1]["hooks"][0]["type"], "command");
        assert_eq!(
            groups[1]["hooks"][0]["command"],
            "shellfirm check --hook codex"
        );
        assert_eq!(groups[1]["hooks"][0]["timeout"], HOOK_TIMEOUT_SECS);
        // Codex rejects unknown top-level keys in hooks.json: only `hooks`
        // and the user's `description` are there.
        let keys: Vec<&String> = v.as_object().unwrap().keys().collect();
        assert_eq!(keys, ["description", "hooks"]);
        assert_eq!(backups(path.parent().unwrap()).len(), 1);

        let (r, out) = exec(Provider::Codex, &hooks_only(false), &sb.env);
        r.unwrap();
        assert!(out.contains("already connected"), "{out}");

        let (r, _) = exec(Provider::Codex, &hooks_only(true), &sb.env);
        r.unwrap();
        let v = read_json(&path);
        assert_eq!(v["hooks"]["PreToolUse"].as_array().unwrap().len(), 1);
        assert_eq!(v["hooks"]["Stop"][0]["hooks"][0]["command"], "notify");
    }

    #[test]
    fn codex_home_and_project_scope() {
        let sb = sandbox();
        let custom = sb.tree.root.join("codex-home");
        let env = ConnectEnv {
            dirs: AgentDirs {
                codex_home: Some(custom.clone()),
                ..AgentDirs::default()
            },
            ..sb.env.clone()
        };
        exec(Provider::Codex, &hooks_only(false), &env).0.unwrap();
        assert!(custom.join("hooks.json").exists());
        assert!(!sb.env.home.join(".codex/hooks.json").exists());
        let project = Options {
            scope: Scope::Project,
            ..hooks_only(false)
        };
        exec(Provider::Codex, &project, &env).0.unwrap();
        let v = read_json(&sb.env.cwd.join(".codex/hooks.json"));
        // A team file records no personal --config-dir.
        assert_eq!(
            v["hooks"]["PreToolUse"][0]["hooks"][0]["command"],
            "shellfirm check --hook codex"
        );
    }

    #[test]
    fn gemini_jsonc_settings_keep_other_keys_and_get_a_named_hook() {
        let sb = sandbox();
        let path = sb.env.home.join(".gemini/settings.json");
        write(
            &path,
            "{\n  // my theme\n  \"ui\": {\"theme\": \"GitHub\"},\n  \"hooks\": {\"AfterTool\": [{\"matcher\": \"write_file\", \"hooks\": [{\"type\": \"command\", \"command\": \"prettier\"}]}],},\n}\n",
        );
        let (r, out) = exec(Provider::Gemini, &hooks_only(false), &sb.env);
        r.unwrap();
        assert!(out.contains("comments or trailing commas"), "{out}");
        let v = read_json(&path);
        assert_eq!(v["ui"]["theme"], "GitHub");
        assert_eq!(
            v["hooks"]["AfterTool"][0]["hooks"][0]["command"],
            "prettier"
        );
        let g = &v["hooks"]["BeforeTool"][0];
        assert_eq!(
            g["matcher"],
            "^(run_shell_command|write_file|replace|read_file|read_many_files)$"
        );
        assert_eq!(g["hooks"][0]["name"], "shellfirm");
        // Gemini timeouts are milliseconds.
        assert_eq!(g["hooks"][0]["timeout"], HOOK_TIMEOUT_SECS * 1000);

        let mut env = sb.env.clone();
        env.config_dir = Some(sb.tree.root.join("cfg"));
        let (r, out) = exec(Provider::Gemini, &hooks_only(false), &env);
        r.unwrap();
        assert!(out.contains("pinned --config-dir"), "{out}");
        let v = read_json(&path);
        let cmd = v["hooks"]["BeforeTool"][0]["hooks"][0]["command"]
            .as_str()
            .unwrap();
        assert!(
            cmd.starts_with("shellfirm check --hook gemini --config-dir "),
            "{cmd}"
        );
        assert_eq!(v["hooks"]["BeforeTool"].as_array().unwrap().len(), 1);

        // Turned off in Gemini's own settings: status says so.
        let mut v = read_json(&path);
        v["hooksConfig"] = json!({"disabled": ["shellfirm"]});
        write(&path, &v.to_string());
        let st = integration_status_in(&sb.env);
        let row = st
            .iter()
            .find(|s| s.tool == "gemini" && s.scope == "user")
            .unwrap();
        assert!(row.hook_installed && row.file_tools_covered && !row.fail_closed);
        assert!(
            row.hook_off
                .iter()
                .any(|n| n.contains("hooksConfig.disabled")),
            "{row:?}"
        );
        assert!(row.mcp_file.is_none());

        // `connect` takes shellfirm out of hooksConfig.disabled.
        let (r, out) = exec(Provider::Gemini, &hooks_only(false), &sb.env);
        r.unwrap();
        assert!(
            out.contains("take shellfirm out of hooksConfig.disabled"),
            "{out}"
        );
        assert_eq!(read_json(&path)["hooksConfig"]["disabled"], json!([]));
        let st = integration_status_in(&sb.env);
        assert!(st.iter().all(|s| s.hook_off.is_empty()), "{st:?}");

        // Hooks turned off altogether: connect says so (it leaves the
        // switch to the user).
        let mut v = read_json(&path);
        v["hooksConfig"] = json!({"enabled": false});
        write(&path, &v.to_string());
        let (r, out) = exec(Provider::Gemini, &hooks_only(false), &sb.env);
        r.unwrap();
        assert!(
            out.contains("The hook does not run yet: hooks are turned off"),
            "{out}"
        );
        v["hooksConfig"] = json!({});
        write(&path, &v.to_string());

        exec(Provider::Gemini, &hooks_only(true), &sb.env)
            .0
            .unwrap();
        let v = read_json(&path);
        assert!(v["hooks"].get("BeforeTool").is_none(), "{v}");
        assert_eq!(
            v["hooks"]["AfterTool"][0]["hooks"][0]["command"],
            "prettier"
        );
    }

    #[test]
    fn group_hooks_are_deduped_and_a_partial_matcher_is_completed() {
        let sb = sandbox();
        let path = sb.env.home.join(".qwen/settings.json");
        write(
            &path,
            r#"{"hooks":{"PreToolUse":[
                {"matcher":"run_shell_command","hooks":[{"type":"command","command":"shellfirm check --hook qwen","timeout":5}]},
                {"matcher":"run_shell_command","hooks":[{"type":"command","command":"shellfirm check --hook qwen"},{"type":"command","command":"audit.sh"}]}
            ]}}"#,
        );
        let (r, out) = exec(Provider::Qwen, &hooks_only(false), &sb.env);
        r.unwrap();
        assert!(out.contains("duplicate"), "{out}");
        let v = read_json(&path);
        let groups = v["hooks"]["PreToolUse"].as_array().unwrap();
        // The user's own timeout is kept; the second group keeps only audit.sh;
        // a group for the file tools is added.
        assert_eq!(groups[0]["hooks"][0]["timeout"], 5);
        assert_eq!(groups[1]["hooks"].as_array().unwrap().len(), 1);
        assert_eq!(groups[1]["hooks"][0]["command"], "audit.sh");
        assert_eq!(
            groups[2]["matcher"],
            "write_file|edit|read_file|read_many_files"
        );
        let st = integration_status_in(&sb.env);
        let row = st
            .iter()
            .find(|s| s.tool == "qwen" && s.scope == "user")
            .unwrap();
        assert!(row.hook_installed && row.file_tools_covered);
    }

    #[test]
    fn copilot_owns_its_hook_file() {
        let sb = sandbox();
        let path = sb.env.home.join(".copilot/hooks/shellfirm.json");
        let (r, _) = exec(Provider::Copilot, &hooks_only(false), &sb.env);
        r.unwrap();
        let v = read_json(&path);
        assert_eq!(v["version"], 1);
        let e = &v["hooks"]["preToolUse"][0];
        assert_eq!(e["type"], "command");
        assert_eq!(e["bash"], "shellfirm check --hook copilot");
        assert_eq!(e["powershell"], "shellfirm check --hook copilot");
        assert_eq!(e["timeoutSec"], HOOK_TIMEOUT_SECS);
        assert!(
            e.get("matcher").is_none(),
            "every tool goes through the hook"
        );
        let st = integration_status_in(&sb.env);
        let row = st
            .iter()
            .find(|s| s.tool == "copilot" && s.scope == "user")
            .unwrap();
        assert!(row.hook_installed && row.fail_closed);

        // A dry run of the uninstall changes nothing; the uninstall removes
        // the file (nothing else was in it).
        let dry = Options {
            dry_run: true,
            ..hooks_only(true)
        };
        let (r, out) = exec(Provider::Copilot, &dry, &sb.env);
        r.unwrap();
        assert!(out.contains("Would update"), "{out}");
        assert!(path.exists());
        exec(Provider::Copilot, &hooks_only(true), &sb.env)
            .0
            .unwrap();
        assert!(!path.exists());

        // COPILOT_HOME moves the user directory; project scope writes
        // .github/hooks.
        let env = ConnectEnv {
            dirs: AgentDirs {
                copilot_home: Some(sb.tree.root.join("cp")),
                ..AgentDirs::default()
            },
            // Project-scope backups go outside the repository.
            backup_dir: Some(sb.tree.root.join("backups")),
            ..sb.env.clone()
        };
        exec(Provider::Copilot, &hooks_only(false), &env).0.unwrap();
        assert!(sb.tree.root.join("cp/hooks/shellfirm.json").exists());
        let project = Options {
            scope: Scope::Project,
            ..hooks_only(false)
        };
        exec(Provider::Copilot, &project, &env).0.unwrap();
        assert!(sb.env.cwd.join(".github/hooks/shellfirm.json").exists());
        let project_off = Options {
            scope: Scope::Project,
            ..hooks_only(true)
        };
        exec(Provider::Copilot, &project_off, &env).0.unwrap();
        // The `.github` directories shellfirm emptied are gone too.
        assert!(!sb.env.cwd.join(".github").exists());
    }

    #[test]
    fn windsurf_hooks_and_mcp() {
        let sb = sandbox();
        let hooks = sb.env.home.join(".codeium/windsurf/hooks.json");
        write(
            &hooks,
            r#"{"hooks":{"post_write_code":[{"command":"npx prettier --write","show_output":true}],"pre_run_command":[{"command":"python3 log.py"}]}}"#,
        );
        exec(Provider::Windsurf, &opts(false, true, true), &sb.env)
            .0
            .unwrap();
        let v = read_json(&hooks);
        assert_eq!(
            v["hooks"]["pre_run_command"][0]["command"],
            "python3 log.py"
        );
        assert_eq!(
            v["hooks"]["pre_run_command"][1]["command"],
            "shellfirm check --hook windsurf"
        );
        assert_eq!(v["hooks"]["pre_run_command"][1]["show_output"], false);
        for event in ["pre_write_code", "pre_read_code"] {
            assert_eq!(
                v["hooks"][event][0]["command"], "shellfirm check --hook windsurf",
                "{event}"
            );
        }
        let mcp = read_json(&sb.env.home.join(".codeium/windsurf/mcp_config.json"));
        assert_eq!(mcp["mcpServers"]["shellfirm"]["command"], "shellfirm");
        let st = integration_status_in(&sb.env);
        let row = st
            .iter()
            .find(|s| s.tool == "windsurf" && s.scope == "user")
            .unwrap();
        assert!(row.hook_installed && row.file_tools_covered && row.mcp_registered);
        assert!(!row.fail_closed);

        // --hooks-only uninstall keeps the MCP server and the user's hooks.
        exec(Provider::Windsurf, &opts(true, true, false), &sb.env)
            .0
            .unwrap();
        let v = read_json(&hooks);
        assert_eq!(v["hooks"]["pre_run_command"].as_array().unwrap().len(), 1);
        assert!(v["hooks"].get("pre_read_code").is_none());
        assert!(sb
            .env
            .home
            .join(".codeium/windsurf/mcp_config.json")
            .exists());
    }

    #[cfg(unix)]
    #[test]
    fn cline_script_is_owned_and_a_foreign_one_is_never_replaced() {
        let sb = sandbox();
        let env = ConnectEnv {
            dirs: AgentDirs {
                current_exe: Some(PathBuf::from("/opt/shellfirm/bin/shellfirm")),
                ..AgentDirs::default()
            },
            ..sb.env.clone()
        };
        let script = sb.env.home.join("Documents/Cline/Hooks/PreToolUse");
        exec(Provider::Cline, &hooks_only(false), &env).0.unwrap();
        let content = fs::read_to_string(&script).unwrap();
        assert!(
            content.starts_with("#!/bin/sh\n# shellfirm-hook: cline\n"),
            "{content}"
        );
        assert!(
            content.contains("SHELLFIRM=/opt/shellfirm/bin/shellfirm"),
            "{content}"
        );
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&script).unwrap().permissions().mode() & 0o777,
                0o755
            );
        }
        let (r, out) = exec(Provider::Cline, &hooks_only(false), &env);
        r.unwrap();
        assert!(out.contains("already connected"), "{out}");

        // An out-of-date shellfirm script is rewritten (with a backup).
        fs::write(
            &script,
            content.replace("check --hook cline", "check --hook cline --log debug"),
        )
        .unwrap();
        let (r, out) = exec(Provider::Cline, &hooks_only(false), &env);
        r.unwrap();
        assert!(out.contains("out of date"), "{out}");
        assert_eq!(fs::read_to_string(&script).unwrap(), content);
        assert_eq!(backups(script.parent().unwrap()).len(), 1);

        // Someone else's PreToolUse script: refused on install, kept on
        // uninstall.
        fs::write(&script, "#!/bin/sh\necho '{\"cancel\": false}'\n").unwrap();
        let (r, _) = exec(Provider::Cline, &hooks_only(false), &env);
        let err = r.unwrap_err();
        assert!(err.contains("not written by shellfirm"), "{err}");
        exec(Provider::Cline, &hooks_only(true), &env).0.unwrap();
        assert!(script.exists());
        let st = integration_status_in(&env);
        let row = st
            .iter()
            .find(|s| s.tool == "cline" && s.scope == "user")
            .unwrap();
        assert!(!row.hook_present);
        assert!(row
            .notes
            .iter()
            .any(|n| n.contains("not written by shellfirm")));
    }

    #[test]
    fn opencode_plugin_install_project_scope_and_uninstall() {
        let sb = sandbox();
        let env = ConnectEnv {
            dirs: AgentDirs {
                xdg_config_home: Some(sb.tree.root.join("xdg")),
                current_exe: Some(PathBuf::from("/usr/local/bin/shellfirm")),
                ..AgentDirs::default()
            },
            backup_dir: Some(sb.tree.root.join("backups")),
            ..sb.env.clone()
        };
        exec(Provider::OpenCode, &hooks_only(false), &env)
            .0
            .unwrap();
        let user = sb.tree.root.join("xdg/opencode/plugins/shellfirm.js");
        let content = fs::read_to_string(&user).unwrap();
        assert!(content.contains("\"tool.execute.before\""));
        assert!(content.contains("const FALLBACK = \"/usr/local/bin/shellfirm\""));
        let project = Options {
            scope: Scope::Project,
            ..hooks_only(false)
        };
        exec(Provider::OpenCode, &project, &env).0.unwrap();
        let shared = sb.env.cwd.join(".opencode/plugins/shellfirm.js");
        // A team file names no personal binary path.
        assert!(fs::read_to_string(&shared)
            .unwrap()
            .contains("const FALLBACK = null"));
        let st = integration_status_in(&env);
        for scope in ["user", "project"] {
            let row = st
                .iter()
                .find(|s| s.tool == "opencode" && s.scope == scope)
                .unwrap();
            assert!(row.hook_installed && row.fail_closed, "{scope}");
        }
        let project_off = Options {
            scope: Scope::Project,
            ..hooks_only(true)
        };
        exec(Provider::OpenCode, &project_off, &env).0.unwrap();
        assert!(!shared.exists());
        assert!(!sb.env.cwd.join(".opencode/plugins").exists());
        exec(Provider::OpenCode, &hooks_only(true), &env).0.unwrap();
        assert!(!user.exists());
    }

    #[test]
    fn hook_only_agents_have_no_mcp() {
        let sb = sandbox();
        for p in [
            Provider::Codex,
            Provider::Gemini,
            Provider::Qwen,
            Provider::Copilot,
            Provider::OpenCode,
        ] {
            let (r, _) = exec(p, &opts(false, false, false), &sb.env);
            assert!(r.unwrap_err().contains("--mcp-only"), "{p:?}");
        }
    }

    #[test]
    fn every_provider_round_trips_through_its_cli_name() {
        for p in ALL_PROVIDERS {
            assert_eq!(Provider::from_name(p.cli_name()), Some(p));
            assert!(SUPPORTED_PROVIDERS.contains(p.cli_name()));
            assert!(command().find_subcommand(p.cli_name()).is_some(), "{p:?}");
        }
    }

    fn project(uninstall: bool) -> Options {
        Options {
            scope: Scope::Project,
            ..opts(uninstall, true, false)
        }
    }

    #[cfg(unix)]
    #[test]
    fn project_scope_never_writes_through_a_symlink_out_of_the_project() {
        let sb = sandbox();
        // Another agent's user file, reached from a link planted in the repo.
        let victim = sb.env.home.join(".codex/hooks.json");
        write(&victim, r#"{"hooks":{}}"#);
        let claude = sb.env.cwd.join(".claude");
        fs::create_dir_all(&claude).unwrap();
        std::os::unix::fs::symlink("../../home/.codex/hooks.json", claude.join("settings.json"))
            .unwrap();
        let (r, _) = exec(Provider::ClaudeCode, &project(false), &sb.env);
        let e = r.unwrap_err();
        assert!(e.contains("outside this project"), "{e}");
        assert_eq!(fs::read_to_string(&victim).unwrap(), r#"{"hooks":{}}"#);
        let st = integration_status_in(&sb.env);
        let row = st
            .iter()
            .find(|s| s.tool == "claude-code" && s.scope == "project")
            .unwrap();
        assert!(
            row.error
                .as_deref()
                .unwrap()
                .contains("outside this project"),
            "{row:?}"
        );

        // A linked directory (`.cursor` -> the user's `~/.cursor`).
        fs::create_dir_all(sb.env.home.join(".cursor")).unwrap();
        std::os::unix::fs::symlink(sb.env.home.join(".cursor"), sb.env.cwd.join(".cursor"))
            .unwrap();
        let (r, _) = exec(Provider::Cursor, &project(false), &sb.env);
        assert!(r.unwrap_err().contains("outside this project"));
        assert!(!sb.env.home.join(".cursor/hooks.json").exists());

        // A link that stays inside the project is fine.
        fs::create_dir_all(sb.env.cwd.join("shared")).unwrap();
        std::os::unix::fs::symlink("shared", sb.env.cwd.join(".gemini")).unwrap();
        exec(Provider::Gemini, &project(false), &sb.env).0.unwrap();
        assert!(sb.env.cwd.join("shared/settings.json").exists());
    }

    #[test]
    fn claude_disable_all_hooks_in_any_scope_turns_the_hook_off() {
        let mut sb = sandbox();
        exec(Provider::ClaudeCode, &hooks_only(false), &sb.env)
            .0
            .unwrap();
        let off = |env: &ConnectEnv| -> Vec<String> {
            integration_status_in(env)
                .into_iter()
                .find(|s| s.tool == "claude-code" && s.scope == "user")
                .unwrap()
                .hook_off
        };
        assert!(off(&sb.env).is_empty());
        // One line in a teammate's settings.local.json.
        let local = sb.env.cwd.join(".claude/settings.local.json");
        write(&local, r#"{"disableAllHooks": true}"#);
        let notes = off(&sb.env);
        assert!(notes[0].contains("disableAllHooks is true in"), "{notes:?}");
        assert!(notes[0].contains("settings.local.json"), "{notes:?}");
        // Managed settings take precedence over every other file.
        let managed = sb.tree.root.join("managed-settings.json");
        write(&managed, r#"{"disableAllHooks": false}"#);
        sb.env.dirs.claude_managed = Some(managed.clone());
        assert!(off(&sb.env).is_empty());
        write(&managed, r#"{"disableAllHooks": true}"#);
        fs::remove_file(&local).unwrap();
        assert!(off(&sb.env)[0].contains("managed-settings.json"));
        // `connect` says the hook does not run.
        let (_, out) = exec(Provider::ClaudeCode, &hooks_only(false), &sb.env);
        assert!(
            out.contains("The hook does not run yet: disableAllHooks"),
            "{out}"
        );
    }

    #[test]
    fn codex_hooks_feature_flag_off_is_reported() {
        let sb = sandbox();
        exec(Provider::Codex, &hooks_only(false), &sb.env)
            .0
            .unwrap();
        let config = sb.env.home.join(".codex/config.toml");
        let off = || -> Vec<String> {
            integration_status_in(&sb.env)
                .into_iter()
                .find(|s| s.tool == "codex" && s.scope == "user")
                .unwrap()
                .hook_off
        };
        for (text, hit) in [
            ("[features]\nhooks = false\n", true),
            ("[features]\ncodex_hooks = false\n", true),
            ("[features]\nhooks = true\n", false),
            ("model = \"x\"\n", false),
        ] {
            write(&config, text);
            assert_eq!(!off().is_empty(), hit, "{text}");
        }
        // The project config overrides the user one.
        write(&config, "[features]\nhooks = false\n");
        write(
            &sb.env.cwd.join(".codex/config.toml"),
            "[features]\nhooks = true\n",
        );
        assert!(off().is_empty());
        // hooks.json with a key Codex does not accept.
        let hooks = sb.env.home.join(".codex/hooks.json");
        let mut v = read_json(&hooks);
        v["sandbox"] = json!({});
        write(&hooks, &v.to_string());
        assert!(off()[0].contains("top-level keys other than `hooks` (sandbox)"));
    }

    #[test]
    fn claude_config_dir_is_honoured() {
        let mut sb = sandbox();
        let dir = sb.tree.root.join("ccd");
        sb.env.dirs.claude_config_dir = Some(dir.clone());
        exec(Provider::ClaudeCode, &opts(false, true, true), &sb.env)
            .0
            .unwrap();
        assert!(claude_hooks_installed(&read_json(
            &dir.join("settings.json")
        )));
        assert!(server_installed(
            &read_json(&dir.join(".claude.json")),
            "mcpServers"
        ));
        assert!(!sb.env.home.join(".claude").exists());
        assert!(!sb.env.home.join(".claude.json").exists());
        let st = integration_status_in(&sb.env);
        let row = st.iter().find(|s| s.tool == "claude-code").unwrap();
        assert!(row.hook_installed && row.mcp_registered, "{row:?}");
    }

    #[test]
    fn cursor_reads_go_to_the_hook() {
        let sb = sandbox();
        exec(Provider::Cursor, &hooks_only(false), &sb.env)
            .0
            .unwrap();
        let path = sb.env.home.join(".cursor/hooks.json");
        let v = read_json(&path);
        let read = &v["hooks"]["beforeReadFile"];
        assert_eq!(read.as_array().unwrap().len(), 1, "{v}");
        assert!(is_cursor_hook(read[0]["command"].as_str().unwrap()));
        let row = integration_status_in(&sb.env)
            .into_iter()
            .find(|s| s.tool == "cursor")
            .unwrap();
        assert!(row.file_tools_covered);
        // Without it, file tools are not fully covered.
        let mut v = v;
        v["hooks"].as_object_mut().unwrap().remove("beforeReadFile");
        write(&path, &v.to_string());
        let row = integration_status_in(&sb.env)
            .into_iter()
            .find(|s| s.tool == "cursor")
            .unwrap();
        assert!(!row.file_tools_covered);
        // A re-run adds it back; uninstall removes it.
        let (_, out) = exec(Provider::Cursor, &hooks_only(false), &sb.env);
        assert!(out.contains("hooks.beforeReadFile"), "{out}");
        exec(Provider::Cursor, &hooks_only(true), &sb.env)
            .0
            .unwrap();
        assert!(!path.exists());
    }

    #[test]
    fn backups_next_to_a_user_file_are_capped() {
        let sb = sandbox();
        let path = sb.env.home.join(".gemini/settings.json");
        write(&path, r#"{"model":"x"}"#);
        // A backup of another file in the same directory is not touched.
        write(
            &sb.env.home.join(".gemini/other.json.shellfirm-bak-1"),
            "{}",
        );
        for i in 0..6 {
            let mut v = read_json(&path);
            v["n"] = json!(i);
            write(&path, &v.to_string());
            exec(Provider::Gemini, &hooks_only(i % 2 == 1), &sb.env)
                .0
                .unwrap();
        }
        let all = backups(&sb.env.home.join(".gemini"));
        let ours = all
            .iter()
            .filter(|p| p.to_string_lossy().contains("settings.json.shellfirm-bak-"))
            .count();
        assert_eq!(ours, BACKUPS_KEPT, "{all:?}");
        assert_eq!(all.len(), BACKUPS_KEPT + 1, "{all:?}");
    }

    #[cfg(unix)]
    #[test]
    fn a_failed_write_shows_only_the_error() {
        use std::os::unix::fs::PermissionsExt;
        let sb = sandbox();
        let path = sb.env.home.join(".gemini/settings.json");
        write(&path, "{}");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o444)).unwrap();
        let (r, out) = exec(Provider::Gemini, &hooks_only(false), &sb.env);
        assert!(r.unwrap_err().contains("read-only"));
        assert!(!out.contains("add hooks.BeforeTool"), "{out}");
    }

    #[test]
    fn status_reports_files_connect_refuses() {
        let sb = sandbox();
        write(&sb.env.home.join(".qwen/settings.json"), r#"{"hooks":[]}"#);
        let st = integration_status_in(&sb.env);
        let qwen = st
            .iter()
            .find(|s| s.tool == "qwen" && s.scope == "user")
            .unwrap();
        assert!(
            qwen.error
                .as_deref()
                .unwrap()
                .contains("`hooks` is not an object"),
            "{qwen:?}"
        );
        if !cfg!(windows) {
            write(
                &sb.env.home.join("Documents/Cline/Hooks/PreToolUse"),
                "#!/bin/sh\necho '{}'\n",
            );
            let st = integration_status_in(&sb.env);
            let cline = st
                .iter()
                .find(|s| s.tool == "cline" && s.scope == "user")
                .unwrap();
            assert!(
                cline
                    .notes
                    .iter()
                    .any(|n| n.contains("not written by shellfirm")),
                "{cline:?}"
            );
        }
    }

    #[test]
    fn only_claude_code_accepts_no_fail_closed() {
        let parse = |agent: &str| {
            command()
                .try_get_matches_from(["connect", agent, "--no-fail-closed"])
                .is_ok()
        };
        assert!(parse("claude-code"));
        for agent in ["codex", "gemini", "cursor", "copilot"] {
            assert!(!parse(agent), "{agent}");
        }
    }

    #[test]
    fn a_shellfirm_hook_in_managed_settings_gets_its_own_row() {
        let mut sb = sandbox();
        exec(Provider::ClaudeCode, &hooks_only(false), &sb.env)
            .0
            .unwrap();
        let user = sb.env.dirs.claude_dir(&sb.env.home).join("settings.json");
        let hooks = read_value(&user).unwrap().unwrap()["hooks"].clone();
        let managed = sb.tree.root.join("managed-settings.json");
        sb.env.dirs.claude_managed = Some(managed.clone());
        let row = |env: &ConnectEnv, scope: &str| {
            integration_status_in(env)
                .into_iter()
                .find(|s| s.tool == "claude-code" && s.scope == scope)
        };
        // No managed file, or one without a shellfirm hook: no row.
        assert!(row(&sb.env, "managed").is_none());
        write(&managed, r#"{"allowManagedHooksOnly": true}"#);
        assert!(row(&sb.env, "managed").is_none());
        assert!(row(&sb.env, "user").unwrap().hook_off[0].contains("put the shellfirm hook"));

        write(
            &managed,
            &json!({"allowManagedHooksOnly": true, "hooks": hooks}).to_string(),
        );
        let m = row(&sb.env, "managed").unwrap();
        assert!(
            m.hook_installed && m.file_tools_covered && m.fail_closed,
            "{m:?}"
        );
        assert!(m.hook_off.is_empty() && m.error.is_none(), "{m:?}");
        assert_eq!(m.hook_file.as_deref(), Some(managed.to_str().unwrap()));
        let u = row(&sb.env, "user").unwrap();
        assert!(
            u.hook_off[0].contains("the shellfirm hook in that file runs instead"),
            "{u:?}"
        );

        // Uninstalling the user hook leaves the managed one (and its row).
        let o = Options {
            uninstall: true,
            ..hooks_only(false)
        };
        exec(Provider::ClaudeCode, &o, &sb.env).0.unwrap();
        assert!(row(&sb.env, "managed").unwrap().hook_installed);
        assert!(!row(&sb.env, "user").unwrap().hook_present);

        // Only managed settings turn a managed hook off.
        write(
            &managed,
            &json!({"disableAllHooks": true, "hooks": hooks}).to_string(),
        );
        assert!(row(&sb.env, "managed").unwrap().hook_off[0].contains("disableAllHooks"));
        write(&managed, "{");
        assert!(row(&sb.env, "managed").is_some_and(|m| m.error.is_some()));
    }

    #[test]
    fn managed_hooks_only_turns_the_user_and_project_hook_off() {
        let mut sb = sandbox();
        exec(Provider::ClaudeCode, &hooks_only(false), &sb.env)
            .0
            .unwrap();
        let managed = sb.tree.root.join("managed-settings.json");
        sb.env.dirs.claude_managed = Some(managed.clone());
        let off = |env: &ConnectEnv| -> Vec<String> {
            integration_status_in(env)
                .into_iter()
                .find(|s| s.tool == "claude-code" && s.scope == "user")
                .unwrap()
                .hook_off
        };
        write(&managed, r#"{"allowManagedHooksOnly": false}"#);
        assert!(off(&sb.env).is_empty());
        write(&managed, r#"{"allowManagedHooksOnly": true}"#);
        let notes = off(&sb.env);
        assert_eq!(notes.len(), 1, "{notes:?}");
        assert!(
            notes[0].contains("allowManagedHooksOnly is true in")
                && notes[0].contains("managed-settings.json"),
            "{notes:?}"
        );
        let (_, out) = exec(Provider::ClaudeCode, &hooks_only(false), &sb.env);
        assert!(
            out.contains("The hook does not run yet: allowManagedHooksOnly"),
            "{out}"
        );
    }

    #[test]
    fn a_relative_claude_config_dir_is_relative_to_the_current_directory() {
        let cwd = Path::new("/work/repo");
        assert_eq!(
            claude_config_dir_from(Some("rel".into()), Some(cwd)),
            Some(cwd.join("rel"))
        );
        assert_eq!(
            claude_config_dir_from(Some("~/cc".into()), Some(cwd)),
            Some(cwd.join("~/cc"))
        );
        assert_eq!(
            claude_config_dir_from(Some("/opt/cc".into()), Some(cwd)),
            Some(PathBuf::from("/opt/cc"))
        );
        assert_eq!(claude_config_dir_from(Some("".into()), Some(cwd)), None);
        assert_eq!(claude_config_dir_from(None, Some(cwd)), None);
    }

    #[test]
    fn only_backups_shellfirm_names_count_toward_the_cap() {
        assert!(is_backup_suffix("20261119T123456Z"));
        assert!(is_backup_suffix("20261119T123456Z-2"));
        for bad in [
            "mine",
            "20261119T123456Z-",
            "20261119T123456Z-x",
            "1",
            "2026111T123456Z",
        ] {
            assert!(!is_backup_suffix(bad), "{bad}");
        }
        let sb = sandbox();
        let path = sb.env.home.join(".gemini/settings.json");
        write(&path, r#"{"model":"x"}"#);
        let mine = sb.env.home.join(".gemini/settings.json.shellfirm-bak-mine");
        write(&mine, "{}");
        for i in 0..6 {
            exec(Provider::Gemini, &hooks_only(i % 2 == 1), &sb.env)
                .0
                .unwrap();
        }
        assert!(mine.exists());
        let all = backups(&sb.env.home.join(".gemini"));
        assert_eq!(all.len(), BACKUPS_KEPT + 1, "{all:?}");
    }

    #[cfg(unix)]
    #[test]
    fn a_fifo_at_a_settings_path_is_an_error_not_a_hang() {
        let sb = sandbox();
        let path = sb.env.home.join(".claude/settings.json");
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        assert!(std::process::Command::new("mkfifo")
            .arg(&path)
            .status()
            .unwrap()
            .success());
        for dry_run in [true, false] {
            let o = Options {
                dry_run,
                ..hooks_only(false)
            };
            let (r, _) = exec(Provider::ClaudeCode, &o, &sb.env);
            assert!(r.unwrap_err().contains("not a regular file"));
        }
        let row = integration_status_in(&sb.env)
            .into_iter()
            .find(|s| s.tool == "claude-code" && s.scope == "user")
            .unwrap();
        assert!(row.error.unwrap().contains("not a regular file"));
    }
}
