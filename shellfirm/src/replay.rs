//! Replay past AI-agent sessions (`shellfirm audit replay`).
//!
//! Coding agents keep a transcript of every session on disk. This module
//! reads those transcripts, extracts every shell command and file operation
//! the agent ran, and judges each one the way that agent's hook (`shellfirm
//! check --hook claude-code` / `--hook codex`) would have: the same
//! assessment ([`agent::assess_command`], [`agent::assess_file_tool_for`])
//! with the call's recorded working directory, the agent-mode settings and
//! the project policies that apply there. Codex cannot ask, so its `ask`
//! becomes `deny` as in its hook. Commands and paths are reported with their
//! secrets replaced (as in the audit log).
//!
//! Replay never executes anything: no command from a transcript is run, no
//! external program is started for context (git, kubectl, ...; see
//! [`agent::NoExecEnvironment`]), the optional LLM review is off, and
//! nothing is written (not even shellfirm's own audit log). Transcripts are
//! only read.
//!
//! Each agent's format is a [`SessionSource`]; [`sources`] lists the
//! supported ones (Claude Code, Codex CLI).

use std::borrow::Cow;
use std::collections::{HashMap, HashSet};
use std::fmt::Write as _;
use std::io::{BufRead, BufReader, Read};
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use aho_corasick::AhoCorasick;
use serde_derive::Serialize;
use serde_json::Value;

use crate::agent::{
    self, AgentInputs, CwdEnvironment, Decision, NoExecEnvironment, RiskAssessment,
};
use crate::agent_eval::{self, patch_deleted_paths, patch_paths};
use crate::checks::Severity;
use crate::config::Config;
use crate::env::Environment;

/// Version of the `--json` output of `audit replay`.
pub const REPLAY_SCHEMA_VERSION: u32 = 1;

/// Transcript lines longer than this are skipped (and counted), so one
/// runaway line cannot exhaust memory.
pub const MAX_LINE_BYTES: usize = 16 * 1024 * 1024;

/// How deep [`collect_files`] descends below an agent's transcript root.
const MAX_WALK_DEPTH: usize = 6;

// ---------------------------------------------------------------------------
// Agents and tool calls
// ---------------------------------------------------------------------------

/// An agent whose transcripts can be replayed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum AgentKind {
    ClaudeCode,
    Codex,
}

impl AgentKind {
    /// Every supported agent, in display order.
    pub const ALL: [Self; 2] = [Self::ClaudeCode, Self::Codex];

    /// The id used on the command line and in JSON (`claude-code`, `codex`).
    #[must_use]
    pub const fn id(self) -> &'static str {
        match self {
            Self::ClaudeCode => "claude-code",
            Self::Codex => "codex",
        }
    }

    /// The product name (`Claude Code`, `Codex CLI`).
    #[must_use]
    pub const fn display_name(self) -> &'static str {
        match self {
            Self::ClaudeCode => "Claude Code",
            Self::Codex => "Codex CLI",
        }
    }

    /// Parse an id (`claude-code`, `codex`; case-insensitive).
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|a| a.id().eq_ignore_ascii_case(s.trim()))
    }
}

impl std::fmt::Display for AgentKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.id())
    }
}

/// What a recorded tool call did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    /// Ran a shell command.
    Command(String),
    /// Created or changed a file with a file tool.
    FileEdit(String),
    /// Deleted a file (an `apply_patch` `*** Delete File:`).
    FileDelete(String),
    /// Read a file with a file tool (judged like `cat <path>`).
    FileRead(String),
}

impl Action {
    /// `command`, `file edit` or `file read`.
    #[must_use]
    pub const fn subject(&self) -> &'static str {
        match self {
            Self::Command(_) => "command",
            Self::FileEdit(_) | Self::FileDelete(_) => "file edit",
            Self::FileRead(_) => "file read",
        }
    }

    /// The command text or the file path.
    #[must_use]
    pub fn text(&self) -> &str {
        match self {
            Self::Command(t) | Self::FileEdit(t) | Self::FileDelete(t) | Self::FileRead(t) => t,
        }
    }
}

/// One shell command or file operation found in a transcript.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolCall {
    pub agent: AgentKind,
    pub session_id: Option<String>,
    /// The agent's id for the call (deduplicates calls a transcript repeats).
    pub call_id: Option<String>,
    /// UTC, `YYYY-MM-DDTHH:MM:SSZ` (see [`normalize_timestamp`]).
    pub timestamp: Option<String>,
    /// The directory the call ran in.
    pub cwd: Option<PathBuf>,
    /// The agent's tool name (`Bash`, `Write`, `exec_command`, ...).
    pub tool: String,
    pub action: Action,
}

/// Turn a transcript timestamp (`2026-01-31T10:00:00.123Z`, or with an
/// offset) into the UTC `YYYY-MM-DDTHH:MM:SSZ` form the audit log uses.
/// A timestamp without an offset, or in any other form, gives `None`.
#[must_use]
pub fn normalize_timestamp(s: &str) -> Option<String> {
    crate::audit::parse_timestamp(s)
}

// ---------------------------------------------------------------------------
// Transcript sources (pluggable)
// ---------------------------------------------------------------------------

/// Parses one transcript file, line by line.
pub trait TranscriptParser {
    /// Parse one JSONL line and push the tool calls it records. Returns
    /// `false` for a line that is not valid JSON (counted as malformed).
    fn parse_line(&mut self, line: &[u8], out: &mut Vec<ToolCall>) -> bool;

    /// Tool calls seen so far whose input could not be read (a Codex
    /// `arguments` string that is not JSON): skipped and counted.
    fn unreadable_calls(&self) -> u64 {
        0
    }
}

/// Where an agent keeps its transcripts, and how to read them.
pub trait SessionSource {
    fn agent(&self) -> AgentKind;
    /// The directories holding the transcripts (they may not exist).
    fn roots(&self, env: &dyn Environment) -> Vec<PathBuf>;
    /// `true` for a transcript file name this source reads.
    fn is_transcript(&self, name: &str) -> bool;
    /// `true` for a transcript this build cannot read (compressed).
    fn is_unsupported(&self, _name: &str) -> bool {
        false
    }
    /// A parser for one file.
    fn parser(&self) -> Box<dyn TranscriptParser>;
}

/// Every supported source.
#[must_use]
pub fn sources() -> Vec<Box<dyn SessionSource>> {
    vec![Box::new(ClaudeCodeSource), Box::new(CodexSource)]
}

fn needle(n: &'static OnceLock<AhoCorasick>, patterns: &[&str]) -> &'static AhoCorasick {
    n.get_or_init(|| AhoCorasick::new(patterns).expect("static patterns"))
}

/// A Codex rollout line as JSON: `Ok(Some(_))` when it may hold a record
/// (`wanted` matches, or a `\u` escape could spell one, as in
/// `"function\u005fcall"`), `Ok(None)` for a blank line or one that only needs
/// to be valid JSON (checked without building it), `Err(())` for a line
/// that is not JSON.
fn parse_json_line(line: &[u8], wanted: &AhoCorasick) -> Result<Option<Value>, ()> {
    if line.iter().all(u8::is_ascii_whitespace) {
        return Ok(None);
    }
    if wanted.is_match(line) || line.windows(2).any(|w| w == b"\\u") {
        return serde_json::from_slice(line).map(Some).map_err(|_| ());
    }
    serde_json::from_slice::<serde::de::IgnoredAny>(line)
        .map(|_| None)
        .map_err(|_| ())
}

fn str_of<'a>(v: &'a Value, key: &str) -> Option<&'a str> {
    v.get(key).and_then(Value::as_str)
}

/// `name` ends with `suffix` (ASCII case-insensitive).
fn has_suffix(name: &str, suffix: &str) -> bool {
    name.len() >= suffix.len()
        && name.is_char_boundary(name.len() - suffix.len())
        && name[name.len() - suffix.len()..].eq_ignore_ascii_case(suffix)
}

fn non_empty(s: Option<&str>) -> Option<&str> {
    s.filter(|s| !s.trim().is_empty())
}

// ----- Claude Code ----------------------------------------------------------

/// Claude Code: `~/.claude/projects/<project>/<session>.jsonl` (and
/// `<session>/subagents/*.jsonl`), or under `$CLAUDE_CONFIG_DIR`.
///
/// Every `assistant` record holds `message.content`, whose `tool_use`
/// blocks are the tool calls (`name`, `input`, `id`); the record carries
/// `timestamp`, `cwd` and `sessionId`.
pub struct ClaudeCodeSource;

impl SessionSource for ClaudeCodeSource {
    fn agent(&self) -> AgentKind {
        AgentKind::ClaudeCode
    }

    fn roots(&self, env: &dyn Environment) -> Vec<PathBuf> {
        let base = claude_config_dir(env).or_else(|| env.home_dir().map(|h| h.join(".claude")));
        base.map(|b| b.join("projects")).into_iter().collect()
    }

    fn is_transcript(&self, name: &str) -> bool {
        has_suffix(name, ".jsonl")
    }

    fn parser(&self) -> Box<dyn TranscriptParser> {
        Box::new(ClaudeCodeParser::default())
    }
}

/// `$CLAUDE_CONFIG_DIR`, a relative value resolved against the current
/// directory (as `connect`, `sandbox` and `status` do).
fn claude_config_dir(env: &dyn Environment) -> Option<PathBuf> {
    let dir = PathBuf::from(non_empty(env.var("CLAUDE_CONFIG_DIR").as_deref())?);
    if dir.is_absolute() {
        return Some(dir);
    }
    Some(
        env.current_dir()
            .map_or_else(|_| dir.clone(), |cwd| cwd.join(&dir)),
    )
}

#[derive(Default)]
struct ClaudeCodeParser {
    unreadable_calls: u64,
}

/// Tools the `claude-code` hook judges as shell commands.
const CLAUDE_SHELL_TOOLS: &[&str] = agent::SHELL_TOOLS;

/// The top-level `type` of a record, read without building the rest of
/// the line (which is still checked to be JSON).
#[derive(serde_derive::Deserialize)]
struct RecordType {
    #[serde(rename = "type")]
    kind: Option<Value>,
}

impl TranscriptParser for ClaudeCodeParser {
    fn unreadable_calls(&self) -> u64 {
        self.unreadable_calls
    }

    fn parse_line(&mut self, line: &[u8], out: &mut Vec<ToolCall>) -> bool {
        if line.iter().all(u8::is_ascii_whitespace) {
            return true;
        }
        // Only `assistant` records hold tool calls; the other lines (tool
        // results, attachments, prompts) are only checked to be JSON. JSON
        // escapes are decoded (`"tool\u005fuse"` is `"tool_use"`).
        let Ok(head) = serde_json::from_slice::<RecordType>(line) else {
            return false;
        };
        if head.kind.as_ref().and_then(Value::as_str) != Some("assistant") {
            return true;
        }
        let Ok(v) = serde_json::from_slice::<Value>(line) else {
            return false;
        };
        let Some(blocks) = v
            .get("message")
            .and_then(|m| m.get("content"))
            .and_then(Value::as_array)
        else {
            return true;
        };
        let timestamp = str_of(&v, "timestamp").and_then(normalize_timestamp);
        let cwd = non_empty(str_of(&v, "cwd")).map(PathBuf::from);
        let session_id = non_empty(str_of(&v, "sessionId").or_else(|| str_of(&v, "session_id")))
            .map(ToString::to_string);
        for b in blocks
            .iter()
            .filter(|b| str_of(b, "type") == Some("tool_use"))
        {
            let Some(tool) = str_of(b, "name") else {
                continue;
            };
            let input = b.get("input").unwrap_or(&Value::Null);
            let action = if CLAUDE_SHELL_TOOLS.contains(&tool) {
                // Monitor can watch a WebSocket instead of running a command.
                if tool == "Monitor" && input.get("command").is_none() && input.get("ws").is_some()
                {
                    continue;
                }
                non_empty(str_of(input, "command")).map(|c| Action::Command(c.to_string()))
            } else if agent::FILE_WRITE_TOOLS.contains(&tool) {
                non_empty(str_of(input, "file_path").or_else(|| str_of(input, "notebook_path")))
                    .map(|p| Action::FileEdit(p.to_string()))
            } else if agent::FILE_READ_TOOLS.contains(&tool) {
                non_empty(str_of(input, "file_path")).map(|p| Action::FileRead(p.to_string()))
            } else {
                continue;
            };
            // A shell or file tool call whose input has the wrong shape.
            let Some(action) = action else {
                self.unreadable_calls += 1;
                continue;
            };
            out.push(ToolCall {
                agent: AgentKind::ClaudeCode,
                session_id: session_id.clone(),
                call_id: str_of(b, "id").map(ToString::to_string),
                timestamp: timestamp.clone(),
                cwd: cwd.clone(),
                tool: tool.to_string(),
                action,
            });
        }
        true
    }
}

// ----- Codex CLI ------------------------------------------------------------

/// Codex CLI: `~/.codex/sessions/YYYY/MM/DD/rollout-*.jsonl` and
/// `~/.codex/archived_sessions/` (or under `$CODEX_HOME`).
///
/// Each line is `{"timestamp", "type", "payload"}`. `session_meta` carries
/// the session id and `cwd`, `turn_context` the `cwd` of each turn, and
/// `response_item` the model's items: `function_call` (`exec_command`
/// `{cmd, workdir}`, `shell` `{command: [argv], workdir}`, `shell_command`
/// `{command, workdir}`, `apply_patch`), `local_shell_call`
/// (`action.command` argv, `action.working_directory`) and
/// `custom_tool_call` (`apply_patch` with the patch as `input`). Older
/// rollouts wrote the items without the envelope. Rollouts older than a
/// week may be compressed (`.jsonl.zst`); those are counted, not read.
pub struct CodexSource;

impl SessionSource for CodexSource {
    fn agent(&self) -> AgentKind {
        AgentKind::Codex
    }

    fn roots(&self, env: &dyn Environment) -> Vec<PathBuf> {
        let base = non_empty(env.var("CODEX_HOME").as_deref())
            .map(PathBuf::from)
            .or_else(|| env.home_dir().map(|h| h.join(".codex")));
        base.map(|b| vec![b.join("sessions"), b.join("archived_sessions")])
            .unwrap_or_default()
    }

    fn is_transcript(&self, name: &str) -> bool {
        name.starts_with("rollout-") && has_suffix(name, ".jsonl")
    }

    fn is_unsupported(&self, name: &str) -> bool {
        name.starts_with("rollout-") && has_suffix(name, ".jsonl.zst")
    }

    fn parser(&self) -> Box<dyn TranscriptParser> {
        Box::new(CodexParser::default())
    }
}

#[derive(Default)]
struct CodexParser {
    session_id: Option<String>,
    cwd: Option<PathBuf>,
    patch_seq: usize,
    unreadable_calls: u64,
}

/// Shells whose `-c` script is the command (`["bash", "-lc", "..."]`).
const ARGV_SHELLS: &[&str] = &["bash", "sh", "zsh", "dash", "ksh", "fish"];

/// The shell command an argv vector runs: the script of `bash -lc
/// '<script>'` (and `sh -c`, `zsh -c`, `pwsh -Command`), otherwise the
/// arguments joined with shell quoting.
#[must_use]
pub fn argv_to_command(argv: &[String]) -> Option<String> {
    let first = argv.first()?;
    let prog = Path::new(first)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or(first)
        .to_ascii_lowercase();
    let prog = prog.strip_suffix(".exe").unwrap_or(&prog);
    if argv.len() == 3 {
        let flag = argv[1].to_ascii_lowercase();
        let shell_c = ARGV_SHELLS.contains(&prog)
            && flag.starts_with('-')
            && !flag.starts_with("--")
            && flag.contains('c');
        let pwsh_c =
            matches!(prog, "powershell" | "pwsh") && matches!(flag.as_str(), "-command" | "-c");
        if shell_c || pwsh_c {
            return Some(argv[2].clone());
        }
    }
    Some(
        argv.iter()
            .map(|a| shell_quote(a))
            .collect::<Vec<_>>()
            .join(" "),
    )
}

fn shell_quote(a: &str) -> String {
    let plain = !a.is_empty()
        && a.bytes().all(|b| {
            b.is_ascii_alphanumeric()
                || matches!(
                    b,
                    b'-' | b'_' | b'.' | b'/' | b'=' | b':' | b',' | b'+' | b'@' | b'%'
                )
        });
    if plain {
        a.to_string()
    } else {
        format!("'{}'", a.replace('\'', r"'\''"))
    }
}

/// What a Codex `command` (a string or an argv array) runs: a command, or
/// an `apply_patch` patch sent through the shell (`["apply_patch",
/// "<patch>"]`, `apply_patch <<'EOF' … EOF`), as the patch text.
enum ShellCall {
    Command(String),
    Patch(String),
}

fn shell_call(v: Option<&Value>) -> Option<ShellCall> {
    let command = match v? {
        Value::String(s) => non_empty(Some(s))?.to_string(),
        Value::Array(a) => {
            let argv: Vec<String> = a
                .iter()
                .map(|x| x.as_str().map(ToString::to_string))
                .collect::<Option<_>>()?;
            if argv.first().is_some_and(|p| p == "apply_patch") && argv.len() > 1 {
                return Some(ShellCall::Patch(argv[1..].join("\n")));
            }
            argv_to_command(&argv).filter(|c| !c.trim().is_empty())?
        }
        _ => return None,
    };
    let is_patch = command
        .trim_start()
        .strip_prefix("apply_patch")
        .is_some_and(|rest| rest.starts_with(char::is_whitespace))
        && !patch_paths(&command).is_empty();
    Some(if is_patch {
        ShellCall::Patch(command)
    } else {
        ShellCall::Command(command)
    })
}

impl CodexParser {
    fn workdir(&self, wd: Option<&str>) -> Option<PathBuf> {
        match non_empty(wd) {
            Some(w) if Path::new(w).is_absolute() => Some(PathBuf::from(w)),
            Some(w) => Some(
                self.cwd
                    .as_ref()
                    .map_or_else(|| PathBuf::from(w), |c| c.join(w)),
            ),
            None => self.cwd.clone(),
        }
    }

    fn push(
        &self,
        out: &mut Vec<ToolCall>,
        timestamp: Option<&String>,
        call_id: Option<String>,
        cwd: Option<PathBuf>,
        tool: &str,
        action: Action,
    ) {
        out.push(ToolCall {
            agent: AgentKind::Codex,
            session_id: self.session_id.clone(),
            call_id,
            timestamp: timestamp.cloned(),
            cwd,
            tool: tool.to_string(),
            action,
        });
    }

    fn push_patch(
        &mut self,
        out: &mut Vec<ToolCall>,
        timestamp: Option<&String>,
        call_id: Option<&str>,
        cwd: Option<&PathBuf>,
        patch: &str,
    ) {
        let paths = patch_paths(patch);
        if paths.is_empty() {
            // A patch that names no file (the hook rejects it).
            self.unreadable_calls += 1;
        }
        let deleted = patch_deleted_paths(patch);
        for path in paths {
            self.patch_seq += 1;
            let id = call_id.map_or_else(
                || format!("patch-{}", self.patch_seq),
                |c| format!("{c}#{path}"),
            );
            self.push(
                out,
                timestamp,
                Some(id),
                cwd.or(self.cwd.as_ref()).cloned(),
                "apply_patch",
                if deleted.contains(&path) {
                    Action::FileDelete(path)
                } else {
                    Action::FileEdit(path)
                },
            );
        }
    }

    /// A shell call: judged as a command, or as a patch when it runs
    /// `apply_patch`.
    fn push_shell(
        &mut self,
        out: &mut Vec<ToolCall>,
        timestamp: Option<&String>,
        call_id: Option<String>,
        workdir: Option<&str>,
        tool: &str,
        command: Option<&Value>,
    ) {
        let cwd = self.workdir(workdir);
        match shell_call(command) {
            Some(ShellCall::Command(c)) => {
                self.push(out, timestamp, call_id, cwd, tool, Action::Command(c));
            }
            Some(ShellCall::Patch(p)) => {
                self.push_patch(out, timestamp, call_id.as_deref(), cwd.as_ref(), &p);
            }
            // No command, or one of the wrong type (`{"cmd": 123}`).
            None => self.unreadable_calls += 1,
        }
    }

    fn response_item(&mut self, item: &Value, timestamp: Option<&String>, out: &mut Vec<ToolCall>) {
        let call_id = str_of(item, "call_id")
            .or_else(|| str_of(item, "id"))
            .map(ToString::to_string);
        match str_of(item, "type") {
            Some("function_call") => {
                // MCP and other namespaced tools are not shell commands.
                if non_empty(str_of(item, "namespace")).is_some() {
                    return;
                }
                let Some(name) = str_of(item, "name") else {
                    return;
                };
                // The argument holding the command (`None`: a patch).
                let key = match name {
                    "exec_command" => Some("cmd"),
                    "shell" | "shell_command" | "container.exec" | "local_shell" => Some("command"),
                    "apply_patch" => None,
                    _ => return,
                };
                let args = match item.get("arguments") {
                    Some(Value::String(s)) => serde_json::from_str(s).ok(),
                    Some(v @ Value::Object(_)) => Some(v.clone()),
                    _ => None,
                };
                let Some(args) = args else {
                    // A shell or patch call whose input cannot be read.
                    self.unreadable_calls += 1;
                    return;
                };
                if let Some(key) = key {
                    let workdir = str_of(&args, "workdir");
                    self.push_shell(out, timestamp, call_id, workdir, name, args.get(key));
                } else if let Some(p) = str_of(&args, "input").or_else(|| str_of(&args, "patch")) {
                    self.push_patch(out, timestamp, call_id.as_deref(), None, p);
                } else {
                    self.unreadable_calls += 1;
                }
            }
            Some("local_shell_call") => {
                let action = item.get("action").unwrap_or(&Value::Null);
                self.push_shell(
                    out,
                    timestamp,
                    call_id,
                    str_of(action, "working_directory"),
                    "local_shell",
                    action.get("command"),
                );
            }
            Some("custom_tool_call") if str_of(item, "name") == Some("apply_patch") => {
                if let Some(p) = str_of(item, "input") {
                    self.push_patch(out, timestamp, call_id.as_deref(), None, p);
                } else {
                    self.unreadable_calls += 1;
                }
            }
            _ => {}
        }
    }
}

impl TranscriptParser for CodexParser {
    fn unreadable_calls(&self) -> u64 {
        self.unreadable_calls
    }

    fn parse_line(&mut self, line: &[u8], out: &mut Vec<ToolCall>) -> bool {
        static WANTED: OnceLock<AhoCorasick> = OnceLock::new();
        let wanted = needle(
            &WANTED,
            &[
                "session_meta",
                "turn_context",
                "_call\"",
                "\"instructions\"",
            ],
        );
        let v = match parse_json_line(line, wanted) {
            Ok(Some(v)) => v,
            Ok(None) => return true,
            Err(()) => return false,
        };
        let timestamp = str_of(&v, "timestamp").and_then(normalize_timestamp);
        let payload = v.get("payload").unwrap_or(&Value::Null);
        match str_of(&v, "type") {
            Some("session_meta") => {
                let id = str_of(payload, "id").or_else(|| str_of(payload, "session_id"));
                // A forked or resumed rollout repeats its parent's meta
                // later on: keep the first.
                if self.session_id.is_none() {
                    self.session_id = non_empty(id).map(ToString::to_string);
                }
                if let Some(c) = non_empty(str_of(payload, "cwd")) {
                    self.cwd = Some(PathBuf::from(c));
                }
            }
            Some("turn_context") => {
                if let Some(c) = non_empty(str_of(payload, "cwd")) {
                    self.cwd = Some(PathBuf::from(c));
                }
            }
            Some("response_item") => self.response_item(payload, timestamp.as_ref(), out),
            // Older rollouts: the item itself, without the envelope.
            Some("function_call" | "local_shell_call" | "custom_tool_call") => {
                self.response_item(&v, timestamp.as_ref(), out);
            }
            // Older rollouts start with `{"id", "timestamp", "instructions"}`.
            None if v.get("instructions").is_some() && self.session_id.is_none() => {
                self.session_id = non_empty(str_of(&v, "id")).map(ToString::to_string);
            }
            _ => {}
        }
        true
    }
}

// ---------------------------------------------------------------------------
// Reading files
// ---------------------------------------------------------------------------

enum LineRead {
    Eof,
    Line,
    TooLong,
}

/// Read one line (without the newline) into `buf`, at most `max` bytes. A
/// longer line is consumed and reported as [`LineRead::TooLong`].
fn read_line_capped(
    r: &mut impl BufRead,
    buf: &mut Vec<u8>,
    max: usize,
) -> std::io::Result<LineRead> {
    buf.clear();
    let limit = max as u64 + 1;
    let n = r.by_ref().take(limit).read_until(b'\n', buf)?;
    if n == 0 {
        return Ok(LineRead::Eof);
    }
    if buf.last() == Some(&b'\n') {
        buf.pop();
        return Ok(LineRead::Line);
    }
    if (n as u64) < limit {
        return Ok(LineRead::Line);
    }
    // Over the limit: drop the rest of the line.
    loop {
        buf.clear();
        let m = r.by_ref().take(1 << 20).read_until(b'\n', buf)?;
        if m == 0 || buf.last() == Some(&b'\n') {
            buf.clear();
            return Ok(LineRead::TooLong);
        }
    }
}

/// Counts for one agent's transcripts.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct SourceStats {
    pub agent: Option<AgentKind>,
    /// The transcript directories that exist (readable or not).
    pub roots: Vec<String>,
    /// Transcript files read.
    pub files: usize,
    /// Files last changed before the time window (not opened).
    pub files_outside_window: usize,
    /// Files and directories (the transcript root included) that could not
    /// be opened or read to the end.
    pub files_unreadable: usize,
    /// Compressed transcripts this build cannot read.
    pub files_compressed: usize,
    /// Sessions with at least one tool call in the window.
    pub sessions: usize,
    /// Shell commands judged.
    pub commands: usize,
    /// File operations judged.
    pub file_operations: usize,
    /// Lines that are not valid JSON.
    pub malformed_lines: u64,
    /// Lines over [`MAX_LINE_BYTES`] (skipped).
    pub oversized_lines: u64,
    /// Shell or patch calls whose input could not be read (skipped).
    pub calls_unreadable: u64,
    /// Calls without a valid timestamp (or with one in the future): judged
    /// only with `--since all`.
    pub calls_undated: usize,
    /// Calls whose analysis crashed (reported as `deny`, as the hook does).
    pub crashed: usize,
}

/// Every transcript file under `root` (not following symbolic links), in
/// path order. Files changed before `since` are only counted, and so is
/// anything named like a transcript that is not a regular file.
fn collect_files(
    source: &dyn SessionSource,
    root: &Path,
    since: Option<&str>,
    stats: &mut SourceStats,
) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![(root.to_path_buf(), 0usize)];
    while let Some((dir, depth)) = stack.pop() {
        let Ok(rd) = std::fs::read_dir(&dir) else {
            stats.files_unreadable += 1;
            continue;
        };
        for entry in rd.flatten() {
            let Ok(ft) = entry.file_type() else {
                continue;
            };
            let path = entry.path();
            let name = entry.file_name();
            let name = name.to_string_lossy();
            let named_like_one = source.is_transcript(&name) || source.is_unsupported(&name);
            // A FIFO, device, symbolic link or folder named like a
            // transcript is never opened, but it is counted: the replay may
            // be missing its calls.
            if named_like_one && !ft.is_file() {
                if !modified_before(&entry, since) {
                    stats.files_unreadable += 1;
                }
                continue;
            }
            if ft.is_dir() {
                if depth < MAX_WALK_DEPTH {
                    stack.push((path, depth + 1));
                }
                continue;
            }
            if !ft.is_file() {
                continue;
            }
            if source.is_unsupported(&name) {
                if !modified_before(&entry, since) {
                    stats.files_compressed += 1;
                }
                continue;
            }
            if !source.is_transcript(&name) {
                continue;
            }
            if modified_before(&entry, since) {
                stats.files_outside_window += 1;
                continue;
            }
            out.push(path);
        }
    }
    out.sort();
    out
}

/// `true` when the file was last modified before `since` (so it cannot
/// hold a newer record).
fn modified_before(entry: &std::fs::DirEntry, since: Option<&str>) -> bool {
    let Some(since) = since else {
        return false;
    };
    let Ok(modified) = entry.metadata().and_then(|m| m.modified()) else {
        return false;
    };
    let secs = modified
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    crate::audit::timestamp_from_epoch(secs).as_str() < since
}

// ---------------------------------------------------------------------------
// Judging
// ---------------------------------------------------------------------------

/// Judges tool calls like the agent's hook (`check --hook claude-code` /
/// `--hook codex`), without running anything.
pub struct Judge<'a> {
    config: &'a Config,
    env: NoExecEnvironment<'a>,
    home: Option<PathBuf>,
    /// Settings, checks and policy per working directory.
    inputs: HashMap<PathBuf, std::result::Result<AgentInputs, String>>,
}

impl<'a> Judge<'a> {
    /// A judge using `config` (settings, custom checks) and `env` (whose
    /// external programs are never run).
    #[must_use]
    pub fn new(config: &'a Config, env: &'a dyn Environment) -> Self {
        Self {
            config,
            env: NoExecEnvironment::new(env),
            home: env.home_dir(),
            inputs: HashMap::new(),
        }
    }

    /// The decision the agent's hook would have made for `call`, its matched
    /// rules the most relevant first: the most severe, then the most specific.
    pub fn judge(&mut self, call: &ToolCall) -> RiskAssessment {
        let cwd = call
            .cwd
            .clone()
            .or_else(|| self.home.clone())
            .unwrap_or_else(|| PathBuf::from("/"));
        let (mut a, instruction_patch) = self.assess(call, &cwd);
        if let Ok(inputs) = &self.inputs[&cwd] {
            rank_rules(&mut a, &inputs.checks);
        }
        if call.agent == AgentKind::Codex {
            // Codex cannot ask (as `check --hook codex`).
            let name = "Codex";
            match &call.action {
                Action::FileEdit(_) | Action::FileDelete(_) => {
                    agent_eval::file_edit_cannot_ask(&mut a, name);
                }
                Action::Command(_) if instruction_patch => {}
                Action::Command(_) => agent_eval::ask_becomes_deny(&mut a, name, "command"),
                Action::FileRead(_) => agent_eval::ask_becomes_deny(&mut a, name, "file read"),
            }
            // An `ask` left (an agent-instruction edit) goes ahead with a
            // note: an allow.
            if a.decision == Decision::Ask {
                a.decision = Decision::Allow;
                a.allowed = true;
                a.requires_human_approval = false;
            }
        }
        a
    }

    /// The assessment of `call`, and `true` for a shell `apply_patch` of
    /// only agent-instruction files (see [`agent_eval::with_shell_patch`]).
    fn assess(&mut self, call: &ToolCall, cwd: &Path) -> (RiskAssessment, bool) {
        let cwd = cwd.to_path_buf();
        if !self.inputs.contains_key(&cwd) {
            let at = CwdEnvironment::new(&self.env, cwd.clone());
            let loaded = agent::load_agent_inputs(self.config, &at, &cwd)
                .map(|mut l| {
                    // Replay never sends commands anywhere, and the impact
                    // details (blast radius: file counts, branch lists)
                    // describe today's disk, not the past, and never change
                    // a decision.
                    l.settings.agent.llm_review = false;
                    l.settings.blast_radius = false;
                    l
                })
                .map_err(|e| e.to_string());
            self.inputs.insert(cwd.clone(), loaded);
        }
        let env = CwdEnvironment::new(&self.env, cwd.clone());
        let inputs = match &self.inputs[&cwd] {
            Ok(i) => i,
            Err(e) => {
                let a = RiskAssessment::fail_closed(
                    Decision::Deny,
                    format!("shellfirm could not load its checks ({e}). Failing closed."),
                );
                return (a, false);
            }
        };
        let settings = &inputs.settings;
        let assess_file = |tool: &str, path: &str, deletes: bool| {
            agent::assess_file_change_for(
                tool,
                path,
                deletes || tool == "Delete",
                Some(&cwd),
                Some(self.config.root_folder.as_path()),
                settings,
                self.home.as_deref(),
            )
        };
        let command = match &call.action {
            Action::FileEdit(path) => return (assess_file(&call.tool, path, false), false),
            Action::FileDelete(path) => return (assess_file(&call.tool, path, true), false),
            Action::Command(command) => Cow::Borrowed(command.as_str()),
            Action::FileRead(path) => Cow::Owned(agent_eval::read_command(
                std::slice::from_ref(path),
                Some(&cwd),
                self.home.as_deref(),
            )),
        };
        let a = agent_eval::assess_shell_command(
            &command,
            settings,
            &inputs.checks,
            &env,
            &cwd,
            &inputs.policy.errors,
            Some((self.config, &inputs.policy.files)),
        );
        agent_eval::with_shell_patch(a, &command, assess_file)
    }
}

/// Order the matched rules the most relevant first: the most severe, and
/// among equally severe ones the narrowest (the longest pattern:
/// `fs:delete_home_folder`, which names the folder, before the generic
/// `fs:recursively_delete_outside`). Rules without a pattern (self
/// protection, policy) keep their place after the patterned ones of the
/// same severity.
fn rank_rules(a: &mut RiskAssessment, checks: &[crate::checks::Check]) {
    let pattern_len = |id: &str| {
        checks
            .iter()
            .find(|c| c.id == id)
            .map_or(0, |c| c.test.as_str().len())
    };
    a.matched_rules.sort_by_cached_key(|r| {
        (
            std::cmp::Reverse(r.severity),
            std::cmp::Reverse(pattern_len(&r.id)),
        )
    });
}

// ---------------------------------------------------------------------------
// Findings
// ---------------------------------------------------------------------------

/// What to replay.
#[derive(Debug, Clone, Default)]
pub struct ReplayOptions {
    /// Only calls at or after this timestamp (`YYYY-MM-DDTHH:MM:SSZ`).
    pub since: Option<String>,
    /// Agents to read (empty: all).
    pub agents: Vec<AgentKind>,
    /// Only calls whose working directory is this directory or below it.
    pub project: Option<PathBuf>,
}

/// A call shellfirm would have blocked or asked about (identical calls
/// grouped).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    pub agent: AgentKind,
    pub decision: Decision,
    pub severity: Option<Severity>,
    /// Matched rule ids, the most relevant first: the most severe, then the most specific.
    pub rule_ids: Vec<String>,
    /// Description of the first rule (or the decision reason when no rule
    /// matched).
    pub reason: String,
    /// Why the decision is `ask` / `deny`.
    pub decision_reason: Option<String>,
    /// `policy_deny`, `user_deny`, `agent_auto_deny`, `fail_closed`.
    pub deny_reason: Option<String>,
    pub tool: String,
    /// `command`, `file edit` or `file read`.
    pub subject: &'static str,
    /// The command or path, secrets replaced with `***` (as in the audit
    /// log, see [`crate::audit::redact_secrets`]).
    pub text: String,
    /// `true` when a secret was replaced in `text`.
    pub text_redacted: bool,
    pub cwd: Option<PathBuf>,
    pub session_id: Option<String>,
    pub first_seen: Option<String>,
    pub last_seen: Option<String>,
    pub count: usize,
}

impl Finding {
    fn from_assessment(call: &ToolCall, a: &RiskAssessment) -> Self {
        let mut rule_ids: Vec<String> = Vec::new();
        for r in &a.matched_rules {
            if !rule_ids.contains(&r.id) {
                rule_ids.push(r.id.clone());
            }
        }
        let decision_reason = a
            .decision_reason
            .as_deref()
            .map(|r| crate::audit::redact_secrets(r).0);
        let reason = a.matched_rules.first().map_or_else(
            || decision_reason.clone().unwrap_or_default(),
            |r| r.description.clone(),
        );
        let (text, text_redacted) = crate::audit::redact_secrets(call.action.text());
        Self {
            agent: call.agent,
            decision: a.decision,
            severity: a.effective_severity.or(a.severity),
            rule_ids,
            reason,
            decision_reason,
            deny_reason: a.deny_reason.clone(),
            tool: call.tool.clone(),
            subject: call.action.subject(),
            text,
            text_redacted,
            cwd: call.cwd.clone(),
            session_id: call.session_id.clone(),
            first_seen: call.timestamp.clone(),
            last_seen: call.timestamp.clone(),
            count: 1,
        }
    }
}

/// Decision totals.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct Totals {
    pub deny: usize,
    pub ask: usize,
    pub allow: usize,
}

/// The result of a replay.
#[derive(Debug, Clone, Default)]
pub struct ReplayReport {
    pub since: Option<String>,
    pub until: String,
    pub stats: Vec<SourceStats>,
    pub totals: Totals,
    /// Worst first (see [`sort_findings`]).
    pub findings: Vec<Finding>,
}

impl ReplayReport {
    /// Transcript files and directories that could not be read.
    #[must_use]
    pub fn unreadable(&self) -> usize {
        self.stats.iter().map(|s| s.files_unreadable).sum()
    }

    /// Compressed transcripts that were not read.
    #[must_use]
    pub fn compressed(&self) -> usize {
        self.stats.iter().map(|s| s.files_compressed).sum()
    }

    /// `true` when some transcripts in the window were not read
    /// (unreadable or compressed), so the findings may be incomplete.
    #[must_use]
    pub fn incomplete(&self) -> bool {
        self.unreadable() + self.compressed() > 0
    }
}

/// Order findings worst first: deny before ask, then severity, then how
/// often it happened, then the most recent.
pub fn sort_findings(findings: &mut [Finding]) {
    findings.sort_by(|a, b| {
        b.decision
            .cmp(&a.decision)
            .then_with(|| b.severity.cmp(&a.severity))
            .then_with(|| b.count.cmp(&a.count))
            .then_with(|| b.last_seen.cmp(&a.last_seen))
            .then_with(|| a.text.cmp(&b.text))
    });
}

/// Findings at or above `min_severity`, at most `limit` (worst first).
#[must_use]
pub fn select(
    findings: &[Finding],
    min_severity: Option<Severity>,
    limit: Option<usize>,
) -> Vec<&Finding> {
    findings
        .iter()
        .filter(|f| min_severity.is_none_or(|m| f.severity.is_some_and(|s| s >= m)))
        .take(limit.unwrap_or(usize::MAX))
        .collect()
}

/// The last component of a path (`--redact` shows only the project name).
#[must_use]
pub fn project_name(p: &Path) -> String {
    p.file_name().map_or_else(
        || p.display().to_string(),
        |n| n.to_string_lossy().into_owned(),
    )
}

/// Findings are grouped by agent, decision, directory and the call itself
/// (`--redact` only hides the call, so it lists the same findings).
type GroupKey = (AgentKind, Decision, Option<PathBuf>, &'static str, String);

/// Accumulates findings, grouping identical ones.
#[derive(Default)]
struct Grouper {
    index: HashMap<GroupKey, usize>,
    findings: Vec<Finding>,
}

impl Grouper {
    fn add(&mut self, f: Finding) {
        let key = (
            f.agent,
            f.decision,
            f.cwd.clone(),
            f.subject,
            f.text.clone(),
        );
        if let Some(&i) = self.index.get(&key) {
            let g = &mut self.findings[i];
            g.count += 1;
            if f.first_seen < g.first_seen || g.first_seen.is_none() {
                g.first_seen.clone_from(&f.first_seen);
            }
            if f.last_seen > g.last_seen {
                g.last_seen.clone_from(&f.last_seen);
                g.session_id.clone_from(&f.session_id);
            }
            if f.severity > g.severity {
                g.severity = f.severity;
            }
        } else {
            self.index.insert(key, self.findings.len());
            self.findings.push(f);
        }
    }
}

/// Lexically normalise an absolute path (`a/./b/../c` → `a/c`).
fn lexical(p: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for c in p.components() {
        match c {
            std::path::Component::CurDir => {}
            std::path::Component::ParentDir => {
                out.pop();
            }
            other => out.push(other.as_os_str()),
        }
    }
    out
}

/// `true` when `cwd` is `project` or below it (lexically, or after
/// resolving symbolic links).
fn in_project(cwd: Option<&Path>, project: &[PathBuf]) -> bool {
    let Some(cwd) = cwd else {
        return false;
    };
    let norm = lexical(cwd);
    if project.iter().any(|p| norm.starts_with(p)) {
        return true;
    }
    std::fs::canonicalize(cwd).is_ok_and(|c| project.iter().any(|p| c.starts_with(p)))
}

/// The directories `--project` matches (as given, and with symbolic links
/// resolved).
fn project_dirs(project: Option<&Path>) -> Vec<PathBuf> {
    project
        .map(|p| {
            let mut v = vec![lexical(p)];
            if let Ok(c) = std::fs::canonicalize(p) {
                if !v.contains(&c) {
                    v.push(c);
                }
            }
            v
        })
        .unwrap_or_default()
}

/// Read one agent's transcripts: the calls in the window (each once) and
/// the counts for the header.
fn read_source(
    source: &dyn SessionSource,
    env: &dyn Environment,
    opts: &ReplayOptions,
    project: &[PathBuf],
) -> (Vec<ToolCall>, SourceStats) {
    let mut stats = SourceStats {
        agent: Some(source.agent()),
        ..SourceStats::default()
    };
    let mut kept: Vec<ToolCall> = Vec::new();
    let mut seen: HashSet<(Option<String>, String)> = HashSet::new();
    let mut sessions: HashSet<String> = HashSet::new();
    let mut calls: Vec<ToolCall> = Vec::new();
    let mut buf: Vec<u8> = Vec::new();
    // A timestamp later than this is not trusted (clock skew aside).
    let latest = crate::audit::timestamp_from_epoch(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs())
            + 300,
    );
    for root in source.roots(env) {
        match std::fs::metadata(&root) {
            Ok(m) if m.is_dir() => {}
            Ok(_) => continue,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            // `~/.claude` (or a folder above the root) cannot be read: the
            // transcripts may be there.
            Err(_) => {
                stats.roots.push(root.display().to_string());
                stats.files_unreadable += 1;
                continue;
            }
        }
        stats.roots.push(root.display().to_string());
        for path in collect_files(source, &root, opts.since.as_deref(), &mut stats) {
            let Ok(file) = std::fs::File::open(&path) else {
                stats.files_unreadable += 1;
                continue;
            };
            stats.files += 1;
            let mut reader = BufReader::with_capacity(256 * 1024, file);
            let mut parser = source.parser();
            let (mut malformed, mut oversized) = (0, 0);
            loop {
                match read_line_capped(&mut reader, &mut buf, MAX_LINE_BYTES) {
                    Ok(LineRead::Eof) => break,
                    Ok(LineRead::TooLong) => oversized += 1,
                    Ok(LineRead::Line) => {
                        if !parser.parse_line(&buf, &mut calls) {
                            malformed += 1;
                        }
                    }
                    Err(_) => {
                        stats.files_unreadable += 1;
                        break;
                    }
                }
            }
            let mut in_scope = project.is_empty();
            for mut call in std::mem::take(&mut calls) {
                if !project.is_empty() && !in_project(call.cwd.as_deref(), project) {
                    continue;
                }
                in_scope = true;
                // Transcripts repeat calls (resumed and forked sessions).
                if let Some(id) = &call.call_id {
                    if !seen.insert((call.session_id.clone(), id.clone())) {
                        continue;
                    }
                }
                if call.timestamp.as_ref().is_some_and(|t| *t > latest) {
                    call.timestamp = None;
                }
                match (call.timestamp.as_deref(), opts.since.as_deref()) {
                    (None, since) => {
                        stats.calls_undated += 1;
                        if since.is_some() {
                            continue;
                        }
                    }
                    (Some(t), Some(since)) if t < since => continue,
                    _ => {}
                }
                sessions.insert(
                    call.session_id
                        .clone()
                        .unwrap_or_else(|| path.display().to_string()),
                );
                match call.action {
                    Action::Command(_) => stats.commands += 1,
                    Action::FileEdit(_) | Action::FileDelete(_) | Action::FileRead(_) => {
                        stats.file_operations += 1;
                    }
                }
                kept.push(call);
            }
            // With --project, a file's skipped lines count only when the
            // file holds calls made there.
            if in_scope {
                stats.malformed_lines += malformed;
                stats.oversized_lines += oversized;
                stats.calls_unreadable += parser.unreadable_calls();
            }
        }
    }
    stats.sessions = sessions.len();
    (kept, stats)
}

/// Judge every call, on several threads (each with its own [`Judge`]).
/// Returns one assessment per call, in order, and whether it crashed.
fn judge_all(
    config: &Config,
    env: &dyn Environment,
    calls: &[ToolCall],
) -> Vec<(RiskAssessment, bool)> {
    let threads = std::thread::available_parallelism()
        .map_or(1, std::num::NonZeroUsize::get)
        .clamp(1, 16)
        .min(calls.len().max(1));
    let next = std::sync::atomic::AtomicUsize::new(0);
    let mut results: Vec<Option<(RiskAssessment, bool)>> = vec![None; calls.len()];
    std::thread::scope(|scope| {
        let workers: Vec<_> = (0..threads)
            .map(|_| {
                scope.spawn(|| {
                    let mut judge = Judge::new(config, env);
                    let mut done = Vec::new();
                    loop {
                        let i = next.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        let Some(call) = calls.get(i) else {
                            break;
                        };
                        // The hook turns a crash into a deny; so does replay.
                        let judged = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                            judge.judge(call)
                        }))
                        .map_or_else(
                            |_| {
                                (
                                    RiskAssessment::fail_closed(
                                        Decision::Deny,
                                        "shellfirm crashed while evaluating this call. Failing \
                                         closed.",
                                    ),
                                    true,
                                )
                            },
                            |a| (a, false),
                        );
                        done.push((i, judged));
                    }
                    done
                })
            })
            .collect();
        for w in workers {
            // A worker only ends early by panicking outside a call: its
            // calls are judged again below.
            if let Ok(done) = w.join() {
                for (i, r) in done {
                    results[i] = Some(r);
                }
            }
        }
    });
    let mut judge = Judge::new(config, env);
    results
        .into_iter()
        .zip(calls)
        .map(|(r, call)| r.unwrap_or_else(|| (judge.judge(call), false)))
        .collect()
}

/// Read every transcript of the selected agents and judge each call.
///
/// `env` supplies the home directory and environment variables; no
/// external program is run through it.
#[must_use]
pub fn replay(
    config: &Config,
    env: &dyn Environment,
    sources: &[Box<dyn SessionSource>],
    opts: &ReplayOptions,
) -> ReplayReport {
    let mut report = ReplayReport {
        since: opts.since.clone(),
        until: crate::audit::now_timestamp(),
        ..ReplayReport::default()
    };
    let project = project_dirs(opts.project.as_deref());
    let mut grouper = Grouper::default();
    for source in sources
        .iter()
        .filter(|s| opts.agents.is_empty() || opts.agents.contains(&s.agent()))
    {
        let (calls, mut stats) = read_source(source.as_ref(), env, opts, &project);
        for (call, (assessment, crashed)) in calls.iter().zip(judge_all(config, env, &calls)) {
            if crashed {
                stats.crashed += 1;
            }
            match assessment.decision {
                Decision::Allow => report.totals.allow += 1,
                Decision::Ask => report.totals.ask += 1,
                Decision::Deny => report.totals.deny += 1,
            }
            if assessment.decision != Decision::Allow {
                grouper.add(Finding::from_assessment(call, &assessment));
            }
        }
        report.stats.push(stats);
    }
    report.findings = grouper.findings;
    sort_findings(&mut report.findings);
    report
}

// ---------------------------------------------------------------------------
// Output
// ---------------------------------------------------------------------------

/// How to show a report.
#[derive(Debug, Clone, Default)]
pub struct OutputOptions {
    pub redact: bool,
    pub min_severity: Option<Severity>,
    pub limit: Option<usize>,
    /// The home directory (shown as `~`).
    pub home: Option<PathBuf>,
}

fn display_path(p: &Path, home: Option<&Path>) -> String {
    if let Some(rest) = home.and_then(|h| p.strip_prefix(h).ok()) {
        if rest.as_os_str().is_empty() {
            return "~".to_string();
        }
        return format!("~/{}", rest.display());
    }
    p.display().to_string()
}

fn shown_project(f: &Finding, o: &OutputOptions) -> String {
    f.cwd.as_deref().map_or_else(
        || "-".to_string(),
        |p| {
            one_line(
                &if o.redact {
                    project_name(p)
                } else {
                    display_path(p, o.home.as_deref())
                },
                200,
            )
        },
    )
}

/// Untrusted transcript text on one line, without control or invisible
/// characters, at most `max` characters.
fn one_line(text: &str, max: usize) -> String {
    crate::context::escape_invisible(&agent::sanitize_untrusted(text, max))
}

fn plural(n: usize, one: &str, many: &str) -> String {
    format!("{n} {}", if n == 1 { one } else { many })
}

/// `2026-01-31T10:00:00Z` → `2026-01-31 10:00`.
fn short_time(t: Option<&str>) -> String {
    t.filter(|t| t.len() >= 16).map_or_else(
        || "-".to_string(),
        |t| format!("{} {}", &t[..10], &t[11..16]),
    )
}

/// The time window, for the header.
#[must_use]
pub fn window_label(since: Option<&str>, since_arg: &str) -> String {
    since.map_or_else(
        || "all recorded sessions".to_string(),
        |s| {
            let arg = since_arg.trim();
            let relative = arg.len() >= 2
                && arg[..arg.len() - 1].bytes().all(|b| b.is_ascii_digit())
                && arg.bytes().last().is_some_and(|b| b.is_ascii_alphabetic());
            if relative {
                format!("last {arg} (since {s})")
            } else {
                format!("since {s}")
            }
        },
    )
}

/// The header line for one agent's transcripts.
fn write_source(out: &mut String, s: &SourceStats, windowed: bool, o: &OutputOptions) {
    let Some(agent) = s.agent else {
        return;
    };
    let name = format!("{:<12}", agent.display_name());
    if s.roots.is_empty() {
        let _ = writeln!(
            out,
            "  {name}  {}",
            console::style("no transcripts found").dim()
        );
        return;
    }
    let roots = s
        .roots
        .iter()
        .map(|r| one_line(&display_path(Path::new(r), o.home.as_deref()), 200))
        .collect::<Vec<_>>()
        .join(", ");
    let _ = writeln!(
        out,
        "  {name}  {}, {}, {}  {}",
        plural(s.sessions, "session", "sessions"),
        plural(s.commands, "command", "commands"),
        plural(s.file_operations, "file operation", "file operations"),
        console::style(format!("({roots})")).dim()
    );
    let count = |n: u64| usize::try_from(n).unwrap_or(usize::MAX);
    let undated = if windowed { s.calls_undated } else { 0 };
    let skipped: [(usize, &str, &str, &str); 7] = [
        (
            count(s.malformed_lines),
            "malformed line",
            "malformed lines",
            "",
        ),
        (
            count(s.oversized_lines),
            "oversized line",
            "oversized lines",
            "",
        ),
        (
            s.files_unreadable,
            "unreadable file or directory",
            "unreadable files or directories",
            "",
        ),
        (
            count(s.calls_unreadable),
            "call with unreadable arguments",
            "calls with unreadable arguments",
            "",
        ),
        (
            undated,
            "call without a valid timestamp",
            "calls without a valid timestamp",
            " (included with --since all)",
        ),
        (
            s.crashed,
            "call crashed the analysis",
            "calls crashed the analysis",
            " (counted as deny)",
        ),
        (
            s.files_compressed,
            "compressed rollout",
            "compressed rollouts",
            " not read",
        ),
    ];
    let notes: Vec<String> = skipped
        .iter()
        .filter(|(n, ..)| *n > 0)
        .map(|(n, one, many, note)| format!("{}{note}", plural(*n, one, many)))
        .collect();
    if !notes.is_empty() {
        let _ = writeln!(
            out,
            "  {:<12}  {}",
            "",
            console::style(format!("skipped: {}", notes.join(", "))).yellow()
        );
    }
    if s.files_outside_window > 0 {
        let _ = writeln!(
            out,
            "  {:<12}  {}",
            "",
            console::style(format!(
                "{} not read (use --since 30d or --since all)",
                plural(s.files_outside_window, "older session", "older sessions")
            ))
            .dim()
        );
    }
}

/// One finding: decision, severity, rule and count; when, agent and
/// project; the reason; the command or file.
fn write_finding(out: &mut String, f: &Finding, o: &OutputOptions) {
    let label = match f.decision {
        Decision::Deny => console::style("DENY").red().bold(),
        Decision::Ask => console::style("ASK ").yellow().bold(),
        Decision::Allow => console::style("ALLOW").green(),
    };
    let sev = f.severity.map_or_else(String::new, |s| {
        let l = format!("[{s}]");
        match s {
            Severity::Critical => console::style(l).red().bold().to_string(),
            Severity::High => console::style(l).red().to_string(),
            Severity::Medium => console::style(l).yellow().to_string(),
            Severity::Low | Severity::Info => console::style(l).cyan().to_string(),
        }
    });
    let rule = f
        .rule_ids
        .first()
        .map_or_else(|| "-".to_string(), |r| one_line(r, 60));
    let more = if f.rule_ids.len() > 1 {
        format!(" +{}", f.rule_ids.len() - 1)
    } else {
        String::new()
    };
    let count = if f.count > 1 {
        format!(" {}", console::style(format!("×{}", f.count)).bold())
    } else {
        String::new()
    };
    let _ = writeln!(
        out,
        "\n  {label} {sev} {}{more}{count}",
        console::style(rule).bold()
    );
    let _ = writeln!(
        out,
        "       {}",
        console::style(format!(
            "{}  {}  {}",
            short_time(f.last_seen.as_deref()),
            f.agent,
            shown_project(f, o)
        ))
        .dim()
    );
    // Rule descriptions are shown whole (wrapped by the terminal).
    let _ = writeln!(out, "       {}", one_line(&f.reason, 2000));
    if o.redact {
        return;
    }
    let line = if f.subject == "command" {
        format!("$ {}", one_line(&f.text, 100))
    } else {
        let p = Path::new(&f.text);
        let shown = if p.is_absolute() {
            display_path(p, o.home.as_deref())
        } else {
            f.text.clone()
        };
        format!("{} {}", f.tool, one_line(&shown, 100))
    };
    let _ = writeln!(out, "       {line}");
}

/// Render a report as text.
#[must_use]
pub fn format_text(report: &ReplayReport, window: &str, o: &OutputOptions) -> String {
    let mut out = String::new();
    let _ = writeln!(
        out,
        "{} {}",
        console::style("shellfirm audit replay").bold(),
        console::style(format!("— {window}")).dim()
    );
    for s in &report.stats {
        write_source(&mut out, s, report.since.is_some(), o);
    }
    let t = report.totals;
    let _ = writeln!(
        out,
        "\nDecisions: {} deny, {} ask, {} allow",
        console::style(t.deny).red().bold(),
        console::style(t.ask).yellow().bold(),
        console::style(t.allow).green()
    );
    if report.findings.is_empty() {
        let _ = writeln!(
            out,
            "\n{}",
            console::style("Nothing shellfirm would have blocked or asked about.").green()
        );
        return out;
    }
    let matching = select(&report.findings, o.min_severity, None);
    if matching.is_empty() {
        let _ = writeln!(
            out,
            "\nNo findings at or above {} ({} below it).",
            o.min_severity.map_or_else(String::new, |s| s.to_string()),
            plural(report.findings.len(), "finding", "findings")
        );
        return out;
    }
    let deny = matching.iter().any(|f| f.decision == Decision::Deny);
    let ask = matching.iter().any(|f| f.decision == Decision::Ask);
    let _ = writeln!(
        out,
        "\nWould have {} ({}, worst first):",
        match (deny, ask) {
            (true, true) => "blocked or asked",
            (true, false) => "blocked",
            _ => "asked about",
        },
        plural(matching.len(), "finding", "findings")
    );
    let shown = o.limit.unwrap_or(usize::MAX).min(matching.len());
    for f in &matching[..shown] {
        write_finding(&mut out, f, o);
    }
    if shown < matching.len() {
        let _ = writeln!(
            out,
            "\n  … {} more (--limit 0 shows all)",
            matching.len() - shown
        );
    }
    out
}

/// One `--json` line per finding.
#[must_use]
pub fn finding_json(f: &Finding, o: &OutputOptions) -> Value {
    let mut v = serde_json::json!({
        "type": "finding",
        "agent": f.agent.id(),
        "decision": f.decision.as_str(),
        "severity": f.severity,
        "rule_id": f.rule_ids.first(),
        "rule_ids": f.rule_ids,
        "reason": f.reason,
        "subject": f.subject,
        "tool": f.tool,
        "count": f.count,
        "first_seen": f.first_seen,
        "last_seen": f.last_seen,
    });
    let Some(obj) = v.as_object_mut() else {
        return v;
    };
    if let Some(d) = &f.deny_reason {
        obj.insert("deny_reason".into(), Value::from(d.as_str()));
    }
    if o.redact {
        obj.insert(
            "project".into(),
            f.cwd
                .as_deref()
                .map(project_name)
                .map_or(Value::Null, Value::from),
        );
    } else {
        let key = if f.subject == "command" {
            "command"
        } else {
            "path"
        };
        obj.insert(key.into(), Value::from(f.text.as_str()));
        if f.text_redacted {
            obj.insert(format!("{key}_redacted"), Value::Bool(true));
        }
        obj.insert(
            "cwd".into(),
            f.cwd
                .as_deref()
                .map_or(Value::Null, |p| Value::from(p.display().to_string())),
        );
        obj.insert(
            "session_id".into(),
            f.session_id.clone().map_or(Value::Null, Value::from),
        );
        obj.insert(
            "decision_reason".into(),
            f.decision_reason.clone().map_or(Value::Null, Value::from),
        );
    }
    v
}

/// The last `--json` line.
#[must_use]
pub fn summary_json(report: &ReplayReport, o: &OutputOptions) -> Value {
    let shown = select(&report.findings, o.min_severity, o.limit).len();
    let matching = select(&report.findings, o.min_severity, None).len();
    let agents: Vec<Value> = report
        .stats
        .iter()
        .map(|s| {
            let mut v = serde_json::to_value(s).unwrap_or(Value::Null);
            if o.redact {
                if let Some(obj) = v.as_object_mut() {
                    obj.remove("roots");
                    obj.insert("found".into(), Value::from(!s.roots.is_empty()));
                }
            } else if let Some(obj) = v.as_object_mut() {
                obj.insert("found".into(), Value::from(!s.roots.is_empty()));
            }
            v
        })
        .collect();
    serde_json::json!({
        "type": "summary",
        "schema_version": REPLAY_SCHEMA_VERSION,
        "since": report.since,
        "until": report.until,
        "agents": agents,
        "totals": report.totals,
        "incomplete": report.incomplete(),
        "findings": matching,
        "shown": shown,
        "redacted": o.redact,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_all(p: &mut dyn TranscriptParser, text: &str) -> (Vec<ToolCall>, usize) {
        let mut out = Vec::new();
        let mut bad = 0;
        for line in text.lines() {
            if !p.parse_line(line.as_bytes(), &mut out) {
                bad += 1;
            }
        }
        (out, bad)
    }

    #[test]
    fn timestamps_are_normalized() {
        assert_eq!(
            normalize_timestamp("2026-01-31T10:00:00.123Z").as_deref(),
            Some("2026-01-31T10:00:00Z")
        );
        assert_eq!(
            normalize_timestamp("2026-01-31T10:00:00Z").as_deref(),
            Some("2026-01-31T10:00:00Z")
        );
        assert_eq!(
            normalize_timestamp("2026-01-31T10:00:00+02:00").as_deref(),
            Some("2026-01-31T08:00:00Z")
        );
        // Without an offset the time zone is unknown.
        assert_eq!(normalize_timestamp("2026-01-31T10:00:00"), None);
        assert_eq!(normalize_timestamp("yesterday"), None);
        assert_eq!(normalize_timestamp("2026-01-31T10:00:00.12aZ"), None);
    }

    #[test]
    fn argv_is_turned_into_a_command() {
        let v = |a: &[&str]| a.iter().map(ToString::to_string).collect::<Vec<_>>();
        assert_eq!(
            argv_to_command(&v(&["bash", "-lc", "rm -rf build && ls"])).as_deref(),
            Some("rm -rf build && ls")
        );
        assert_eq!(
            argv_to_command(&v(&["/bin/zsh", "-c", "echo hi"])).as_deref(),
            Some("echo hi")
        );
        assert_eq!(
            argv_to_command(&v(&["pwsh.exe", "-Command", "Remove-Item x"])).as_deref(),
            Some("Remove-Item x")
        );
        assert_eq!(
            argv_to_command(&v(&["git", "commit", "-m", "it's done"])).as_deref(),
            Some(r"git commit -m 'it'\''s done'")
        );
        assert_eq!(argv_to_command(&[]), None);
    }

    #[test]
    fn claude_code_lines_yield_tool_calls() {
        let text = r#"{"type":"user","message":{"content":"hi"}}
{"type":"assistant","timestamp":"2026-01-31T10:00:00.5Z","cwd":"/w/app","sessionId":"s1","message":{"content":[{"type":"text","text":"ok"},{"type":"tool_use","id":"t1","name":"Bash","input":{"command":"rm -rf /"}},{"type":"tool_use","id":"t2","name":"Write","input":{"file_path":"/w/app/.claude/settings.json","content":"{}"}},{"type":"tool_use","id":"t3","name":"Read","input":{"file_path":"~/.ssh/id_rsa"}},{"type":"tool_use","id":"t4","name":"Grep","input":{"pattern":"x"}},{"type":"tool_use","id":"t5","name":"Monitor","input":{"ws":"wss://x"}},{"type":"tool_use","id":"t6","name":"NotebookEdit","input":{"notebook_path":"/w/n.ipynb"}}]}}
{"type":"assistant","message":{"content":[{"type":"tool_use" BROKEN
{"type":"api-request-blob","body":{"content":[{"type":"tool_use","name":"Bash","input":{"command":"rm -rf /"}}]}}
not json at all
{"type":"assistan\u0074","message":{"content":[{"type":"tool\u005fuse","id":"t7","name":"Bash","input":{"command":"rm -rf ~"}}]}}
"#;
        let mut parser = ClaudeCodeParser::default();
        let (calls, bad) = parse_all(&mut parser, text);
        assert_eq!(bad, 2);
        assert_eq!(calls.len(), 5);
        // The Monitor WebSocket and Grep are not counted as unreadable.
        assert_eq!(parser.unreadable_calls(), 0);
        assert_eq!(calls[4].action, Action::Command("rm -rf ~".into()));
        assert_eq!(calls[0].action, Action::Command("rm -rf /".into()));
        assert_eq!(calls[0].timestamp.as_deref(), Some("2026-01-31T10:00:00Z"));
        assert_eq!(calls[0].cwd.as_deref(), Some(Path::new("/w/app")));
        assert_eq!(calls[0].session_id.as_deref(), Some("s1"));
        assert_eq!(calls[0].call_id.as_deref(), Some("t1"));
        assert_eq!(
            calls[1].action,
            Action::FileEdit("/w/app/.claude/settings.json".into())
        );
        assert_eq!(calls[2].action, Action::FileRead("~/.ssh/id_rsa".into()));
        assert_eq!(calls[3].action, Action::FileEdit("/w/n.ipynb".into()));
    }

    #[test]
    fn codex_lines_yield_tool_calls() {
        let text = r#"{"timestamp":"2026-01-31T10:00:00.000Z","type":"session_meta","payload":{"id":"c1","timestamp":"2026-01-31T10:00:00Z","cwd":"/w/api","originator":"codex_cli_rs","cli_version":"0.50.0"}}
{"timestamp":"2026-01-31T10:00:01.000Z","type":"response_item","payload":{"type":"function_call","name":"shell","arguments":"{\"command\":[\"bash\",\"-lc\",\"git push --force origin main\"],\"workdir\":\"sub\"}","call_id":"call_1"}}
{"timestamp":"2026-01-31T10:00:02.000Z","type":"turn_context","payload":{"cwd":"/w/other","approval_policy":"on-request"}}
{"timestamp":"2026-01-31T10:00:03.000Z","type":"response_item","payload":{"type":"function_call","name":"exec_command","arguments":"{\"cmd\":\"rm -rf ~\"}","call_id":"call_2"}}
{"timestamp":"2026-01-31T10:00:04.000Z","type":"response_item","payload":{"type":"local_shell_call","call_id":"call_3","status":"completed","action":{"type":"exec","command":["sh","-c","echo hi"],"working_directory":"/tmp"}}}
{"timestamp":"2026-01-31T10:00:05.000Z","type":"response_item","payload":{"type":"custom_tool_call","call_id":"call_4","name":"apply_patch","input":"*** Begin Patch\n*** Add File: .git/hooks/pre-commit\n+x\n*** End Patch"}}
{"timestamp":"2026-01-31T10:00:06.000Z","type":"response_item","payload":{"type":"function_call","name":"run","namespace":"mcp__x","arguments":"{\"command\":\"rm -rf /\"}","call_id":"call_5"}}
{"timestamp":"2026-01-31T10:00:07.000Z","type":"response_item","payload":{"type":"function_call","name":"shell_command","arguments":"{\"command\":\"ls\",\"workdir\":\"/abs\"}","call_id":"call_6"}}
{"timestamp":"2026-01-31T10:00:08.000Z","type":"response_item","payload":{"type":"function_call_output","call_id":"call_6","output":"x"}}
{"timestamp":"2026-01-31T10:00:09.000Z","type":"response_item","payload":{"type":"function_call", broken
{"timestamp":"2026-01-31T10:00:10.000Z","type":"response_item","payload":{"type":"function_call","name":"exec_command","arguments":"{broken","call_id":"call_7"}}
{"timestamp":"2026-01-31T10:00:10.500Z","type":"response_item","payload":{"type":"function\u005fcall","name":"exec_command","arguments":"{\"cmd\":\"rm -rf /tmp/x\"}","call_id":"call_9"}}
{"timestamp":"2026-01-31T10:00:11.000Z","type":"response_item","payload":{"type":"function_call","name":"shell","arguments":"{\"command\":[\"apply_patch\",\"*** Begin Patch\\n*** Add File: ~/.zshrc\\n+x\\n*** End Patch\"]}","call_id":"call_8"}}
"#;
        let mut parser = CodexParser::default();
        let (calls, bad) = parse_all(&mut parser, text);
        assert_eq!(bad, 1);
        assert_eq!(parser.unreadable_calls(), 1);
        let got: Vec<(&str, Option<&Path>, &str)> = calls
            .iter()
            .map(|c| (c.action.text(), c.cwd.as_deref(), c.tool.as_str()))
            .collect();
        assert_eq!(
            got,
            vec![
                (
                    "git push --force origin main",
                    Some(Path::new("/w/api/sub")),
                    "shell"
                ),
                ("rm -rf ~", Some(Path::new("/w/other")), "exec_command"),
                ("echo hi", Some(Path::new("/tmp")), "local_shell"),
                (
                    ".git/hooks/pre-commit",
                    Some(Path::new("/w/other")),
                    "apply_patch"
                ),
                ("ls", Some(Path::new("/abs")), "shell_command"),
                ("rm -rf /tmp/x", Some(Path::new("/w/other")), "exec_command"),
                ("~/.zshrc", Some(Path::new("/w/other")), "apply_patch"),
            ]
        );
        assert!(calls.iter().all(|c| c.session_id.as_deref() == Some("c1")));
        assert_eq!(calls[0].timestamp.as_deref(), Some("2026-01-31T10:00:01Z"));
    }

    #[test]
    fn legacy_codex_rollouts_without_envelope() {
        let text = r#"{"id":"old1","timestamp":"2025-05-07T17:24:21.000Z","instructions":null}
{"record_type":"state"}
{"type":"function_call","name":"shell","arguments":"{\"command\":[\"bash\",\"-lc\",\"rm -rf /\"]}","call_id":"c1"}
"#;
        let (calls, bad) = parse_all(&mut CodexParser::default(), text);
        assert_eq!(bad, 0);
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].session_id.as_deref(), Some("old1"));
        assert_eq!(calls[0].timestamp, None);
    }

    #[test]
    fn long_lines_are_skipped_and_counted() {
        let mut data = Vec::new();
        data.extend_from_slice(b"short\n");
        data.extend(std::iter::repeat_n(b'x', 50));
        data.extend_from_slice(b"\nlast");
        let mut r = BufReader::with_capacity(8, &data[..]);
        let mut buf = Vec::new();
        let mut got = Vec::new();
        loop {
            match read_line_capped(&mut r, &mut buf, 10).unwrap() {
                LineRead::Eof => break,
                LineRead::TooLong => got.push("<long>".to_string()),
                LineRead::Line => got.push(String::from_utf8(buf.clone()).unwrap()),
            }
        }
        assert_eq!(got, vec!["short", "<long>", "last"]);
    }

    fn finding(decision: Decision, sev: Severity, text: &str, t: &str) -> Finding {
        Finding {
            agent: AgentKind::ClaudeCode,
            decision,
            severity: Some(sev),
            rule_ids: vec!["fs:x".into()],
            reason: "r".into(),
            decision_reason: None,
            deny_reason: None,
            tool: "Bash".into(),
            subject: "command",
            text: text.into(),
            text_redacted: false,
            cwd: Some(PathBuf::from("/w/app")),
            session_id: None,
            first_seen: Some(t.into()),
            last_seen: Some(t.into()),
            count: 1,
        }
    }

    #[test]
    fn findings_are_grouped_and_sorted_worst_first() {
        let mut g = Grouper::default();
        g.add(finding(
            Decision::Ask,
            Severity::Medium,
            "a",
            "2026-01-01T00:00:00Z",
        ));
        g.add(finding(
            Decision::Ask,
            Severity::Medium,
            "a",
            "2026-01-03T00:00:00Z",
        ));
        g.add(finding(
            Decision::Ask,
            Severity::Medium,
            "a",
            "2026-01-02T00:00:00Z",
        ));
        g.add(finding(
            Decision::Deny,
            Severity::High,
            "b",
            "2026-01-01T00:00:00Z",
        ));
        g.add(finding(
            Decision::Ask,
            Severity::High,
            "c",
            "2026-01-01T00:00:00Z",
        ));
        let mut f = g.findings;
        sort_findings(&mut f);
        let order: Vec<(&str, usize)> = f.iter().map(|f| (f.text.as_str(), f.count)).collect();
        assert_eq!(order, vec![("b", 1), ("c", 1), ("a", 3)]);
        assert_eq!(f[2].first_seen.as_deref(), Some("2026-01-01T00:00:00Z"));
        assert_eq!(f[2].last_seen.as_deref(), Some("2026-01-03T00:00:00Z"));
    }

    #[test]
    fn select_applies_min_severity_and_limit() {
        let f = vec![
            finding(Decision::Deny, Severity::Critical, "a", "t"),
            finding(Decision::Ask, Severity::High, "b", "t"),
            finding(Decision::Ask, Severity::Low, "c", "t"),
        ];
        assert_eq!(select(&f, Some(Severity::High), None).len(), 2);
        assert_eq!(select(&f, None, Some(1)).len(), 1);
        assert_eq!(select(&f, None, None).len(), 3);
    }

    #[test]
    fn project_filter_matches_directory_and_below() {
        let p = vec![PathBuf::from("/w/app")];
        assert!(in_project(Some(Path::new("/w/app")), &p));
        assert!(in_project(Some(Path::new("/w/app/src/../lib")), &p));
        assert!(!in_project(Some(Path::new("/w/application")), &p));
        assert!(!in_project(None, &p));
    }

    #[test]
    fn judge_uses_the_recorded_cwd_and_its_policy() {
        let root = std::env::temp_dir().join(format!("shellfirm-judge-{}", uuid::Uuid::new_v4()));
        let repo = root.join("repo");
        let other = root.join("other");
        std::fs::create_dir_all(repo.join(".git")).unwrap();
        std::fs::create_dir_all(&other).unwrap();
        std::fs::create_dir_all(root.join("config")).unwrap();
        std::fs::write(
            repo.join(".shellfirm.yaml"),
            "version: 1\ndeny:\n  - git:interactive_rebase\n",
        )
        .unwrap();
        let config = Config::new(Some(root.join("config").to_str().unwrap())).unwrap();
        let env = crate::env::RealEnvironment;
        let mut judge = Judge::new(&config, &env);
        let call = |cwd: &Path, action: Action| ToolCall {
            agent: AgentKind::ClaudeCode,
            session_id: None,
            call_id: None,
            timestamp: None,
            cwd: Some(cwd.to_path_buf()),
            tool: "Bash".into(),
            action,
        };
        let rebase = Action::Command("git rebase -i HEAD~3".into());
        assert_eq!(
            judge.judge(&call(&other, rebase.clone())).decision,
            Decision::Ask
        );
        assert_eq!(judge.judge(&call(&repo, rebase)).decision, Decision::Deny);
        // A file tool call is judged like the hook's file-tool check.
        let mut edit = call(&repo, Action::FileEdit(".shellfirm.yaml".into()));
        edit.tool = "Write".into();
        assert_eq!(judge.judge(&edit).decision, Decision::Ask);
        assert_eq!(
            judge
                .judge(&call(&repo, Action::Command("ls".into())))
                .decision,
            Decision::Allow
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn redacted_json_has_no_command_text_or_paths() {
        let mut f = finding(Decision::Deny, Severity::High, "rm -rf /secret/place", "t");
        f.decision_reason = Some("about /secret/place".into());
        f.session_id = Some("s".into());
        let o = OutputOptions {
            redact: true,
            ..OutputOptions::default()
        };
        let s = finding_json(&f, &o).to_string();
        assert!(!s.contains("secret"), "{s}");
        assert!(!s.contains("/w/app"), "{s}");
        assert!(s.contains("\"project\":\"app\""), "{s}");
        let o = OutputOptions::default();
        let s = finding_json(&f, &o).to_string();
        assert!(s.contains("rm -rf /secret/place"), "{s}");
    }
}
