//! Hook protocols of the agents besides Claude Code and Cursor.
//!
//! Each agent's payload is first rewritten into the Claude Code `PreToolUse`
//! shape (`tool_name`, `tool_input`, `cwd`, `session_id`, `tool_use_id`) with
//! Claude Code tool names (`Bash`, `Write`, `Edit`, `Read`, plus
//! `apply_patch`), so one parser evaluates every agent. Tools shellfirm has
//! no opinion about keep their own name and lose their input, which the
//! parser treats as "not applicable".
//!
//! Protocol sources (field names, tool names, how to deny or ask):
//! - Codex CLI: `codex-rs/hooks/schema/generated/pre-tool-use.command.*.schema.json`
//!   and `codex-rs/hooks/src/engine/output_parser.rs` (openai/codex).
//! - Gemini CLI: `docs/hooks/reference.md`, `packages/core/src/scheduler/hook-utils.ts`
//!   (google-gemini/gemini-cli).
//! - Qwen Code: `docs/users/features/hooks.md` (QwenLM/qwen-code).
//! - GitHub Copilot CLI: "GitHub Copilot hooks reference" (docs.github.com).
//! - Cline: `sdk/packages/core/src/hooks/hook-file-hooks.ts` and
//!   `apps/vscode/src/sdk/hooks-adapter.ts` (cline/cline).
//! - Windsurf: "Cascade Hooks" (docs.windsurf.com).
//! - `OpenCode`: the plugin `shellfirm connect opencode` writes sends this
//!   payload itself (see `connect_cmd::agents::opencode_plugin`).

use serde_json::{json, Map, Value};
use shellfirm::agent::{self, Decision, RiskAssessment};

use super::HookKind;

/// What an agent can do with an `ask` decision.
impl HookKind {
    /// The agent can stop and ask a human before a shell command runs.
    pub(super) const fn can_ask_command(self) -> bool {
        matches!(
            self,
            Self::ClaudeCode | Self::Cursor | Self::Gemini | Self::Qwen | Self::Copilot
        )
    }

    /// The agent can stop and ask a human before a file is edited.
    pub(super) const fn can_ask_file_edit(self) -> bool {
        matches!(
            self,
            Self::ClaudeCode | Self::Gemini | Self::Qwen | Self::Copilot
        )
    }

    /// Name shown in decision reasons.
    pub(super) const fn display_name(self) -> &'static str {
        match self {
            Self::ClaudeCode => "Claude Code",
            Self::Cursor => "Cursor",
            Self::Codex => "Codex",
            Self::Gemini => "Gemini CLI",
            Self::Qwen => "Qwen Code",
            Self::Copilot => "Copilot CLI",
            Self::Cline => "Cline",
            Self::Windsurf => "Windsurf",
            Self::OpenCode => "OpenCode",
        }
    }
}

fn str_of<'a>(v: &'a Value, key: &str) -> Option<&'a str> {
    v.get(key).and_then(Value::as_str)
}

/// A value the agent may have JSON-encoded into a string (Cline's VS Code
/// extension stringifies every parameter; Copilot's `toolArgs` can be a JSON
/// string). Plain strings stay strings.
fn dejson(v: &Value) -> Value {
    match v {
        Value::String(s) => {
            let t = s.trim_start();
            if t.starts_with('{') || t.starts_with('[') {
                serde_json::from_str(s).unwrap_or_else(|_| v.clone())
            } else {
                v.clone()
            }
        }
        _ => v.clone(),
    }
}

/// Canonical payload for one tool call.
struct Canonical {
    obj: Map<String, Value>,
}

impl Canonical {
    fn new() -> Self {
        Self { obj: Map::new() }
    }

    fn meta(mut self, key: &str, value: Option<&Value>) -> Self {
        if let Some(v) = value.filter(|v| !v.is_null()) {
            self.obj.insert(key.into(), v.clone());
        }
        self
    }

    fn tool(mut self, name: &str, input: Option<Value>) -> Self {
        self.obj.insert("tool_name".into(), json!(name));
        if let Some(i) = input {
            self.obj.insert("tool_input".into(), i);
        }
        self
    }

    fn done(self) -> Value {
        Value::Object(self.obj)
    }
}

/// A shell command input: `{command}` plus an optional working directory.
fn shell_input(command: Option<Value>, workdir: Option<&Value>) -> Value {
    let mut ti = Map::new();
    if let Some(c) = command {
        ti.insert("command".into(), c);
    }
    if let Some(w) = workdir.and_then(Value::as_str).filter(|w| !w.is_empty()) {
        ti.insert("working_directory".into(), json!(w));
    }
    Value::Object(ti)
}

/// `{file_path}` from the first key of `keys` that holds a string. The
/// value is kept as found (a non-string is reported by the parser).
fn path_input(input: Option<&Value>, keys: &[&str]) -> Value {
    let mut ti = Map::new();
    if let Some(v) = input.and_then(|i| keys.iter().find_map(|k| i.get(*k))) {
        ti.insert("file_path".into(), v.clone());
    }
    Value::Object(ti)
}

/// Rewrite an agent's payload into the Claude Code shape. Errors are
/// malformed payloads (the hook then denies).
pub(super) fn normalize(kind: HookKind, v: Value) -> Result<Value, String> {
    if !v.is_object() {
        return Err("hook input must be a JSON object".into());
    }
    match kind {
        HookKind::ClaudeCode | HookKind::Cursor => Ok(v),
        HookKind::Codex => Ok(codex(v)),
        HookKind::Gemini => Ok(gemini_like(&v, "dir_path")),
        HookKind::Qwen => Ok(gemini_like(&v, "directory")),
        HookKind::Copilot => copilot(&v),
        HookKind::Cline => cline(&v),
        HookKind::Windsurf => Ok(windsurf(&v)),
        HookKind::OpenCode => Ok(opencode(&v)),
    }
}

/// Codex `PreToolUse`: `Bash` (and the internal shell tool names `shell`,
/// `exec_command`, `local_shell`) may carry the command as an argv array
/// (`["bash", "-lc", "…"]`) or under `cmd`, and `workdir` is where it runs
/// (relative to `cwd`).
fn codex(mut v: Value) -> Value {
    let shell = matches!(
        str_of(&v, "tool_name"),
        Some("Bash" | "shell" | "exec_command" | "local_shell")
    );
    let Some(ti) = v
        .get("tool_input")
        .filter(|_| shell)
        .and_then(Value::as_object)
    else {
        return v;
    };
    let command = match ti.get("command").or_else(|| ti.get("cmd")) {
        Some(Value::Array(argv)) if argv.iter().all(Value::is_string) => Some(json!(argv
            .iter()
            .filter_map(Value::as_str)
            .map(quote_word)
            .collect::<Vec<_>>()
            .join(" "))),
        other => other.cloned(),
    };
    let cwd = run_dir(v.get("cwd"), ti.get("workdir"));
    if let Some(o) = v.as_object_mut() {
        o.insert("tool_name".into(), json!("Bash"));
        o.insert("tool_input".into(), shell_input(command, None));
        match cwd {
            Some(c) => o.insert("cwd".into(), c),
            None => o.remove("cwd"),
        };
    }
    v
}

/// Gemini CLI `BeforeTool` and Qwen Code `PreToolUse`: Claude-shaped
/// payloads with the Gemini tool names (`run_shell_command`, `write_file`,
/// `replace` / `edit`, `read_file`).
fn gemini_like(v: &Value, dir_key: &str) -> Value {
    let ti = v.get("tool_input");
    let Some(tool) = str_of(v, "tool_name") else {
        // No tool name: the parser reports it (or reads `tool_input.command`).
        let mut out = v.clone();
        if let Some(o) = out.as_object_mut() {
            o.remove("hook_event_name");
        }
        return out;
    };
    let base = Canonical::new()
        .meta("session_id", v.get("session_id"))
        .meta("tool_use_id", v.get("tool_use_id"));
    match tool {
        "run_shell_command" => {
            // The shell tool's directory argument (relative to the project
            // root) is where the command runs.
            let cwd = run_dir(v.get("cwd"), ti.and_then(|t| t.get(dir_key)));
            base.meta("cwd", cwd.as_ref())
                .tool(
                    "Bash",
                    Some(match ti {
                        Some(Value::Object(o)) => shell_input(o.get("command").cloned(), None),
                        Some(other) => other.clone(),
                        None => json!({}),
                    }),
                )
                .done()
        }
        "write_file" => base
            .meta("cwd", v.get("cwd"))
            .tool("Write", Some(path_input(ti, &["file_path"])))
            .done(),
        "replace" | "edit" => base
            .meta("cwd", v.get("cwd"))
            .tool("Edit", Some(path_input(ti, &["file_path"])))
            .done(),
        "read_file" => base
            .meta("cwd", v.get("cwd"))
            .tool(
                "Read",
                Some(path_input(ti, &["file_path", "absolute_path"])),
            )
            .done(),
        // Paths or globs: `include` (Gemini CLI), `paths` (older Qwen Code).
        "read_many_files" => base
            .meta("cwd", v.get("cwd"))
            .tool(
                "Read",
                Some(json!({ "file_paths": ti
                    .and_then(|t| t.get("include").or_else(|| t.get("paths")))
                    .cloned()
                    .unwrap_or(Value::Null) })),
            )
            .done(),
        other => base.meta("cwd", v.get("cwd")).tool(other, None).done(),
    }
}

/// The directory a command runs in: `dir` (absolute, or relative to `cwd`)
/// when given, else `cwd`.
fn run_dir(cwd: Option<&Value>, dir: Option<&Value>) -> Option<Value> {
    let dir = dir.and_then(Value::as_str).filter(|d| !d.trim().is_empty());
    match (dir, cwd.and_then(Value::as_str)) {
        (Some(d), Some(c)) => Some(json!(std::path::Path::new(c).join(d).display().to_string())),
        (Some(d), None) => Some(json!(d)),
        (None, _) => cwd.cloned(),
    }
}

/// GitHub Copilot CLI `preToolUse` (camelCase: `toolName`, `toolArgs`) or
/// `PreToolUse` (snake case, Claude tool names).
fn copilot(v: &Value) -> Result<Value, String> {
    if let Some(tool) = str_of(v, "tool_name") {
        // VS Code compatible payload (`PreToolUse`): Claude tool names, but
        // Copilot's own arguments (`path`; `apply_patch` reports as `Edit`).
        let ti = v.get("tool_input").map(dejson);
        let base = Canonical::new()
            .meta("cwd", v.get("cwd"))
            .meta("session_id", v.get("session_id"))
            .meta("tool_use_id", v.get("tool_use_id"));
        let ti = ti.as_ref();
        let is_patch = ti.is_some_and(|t| {
            t.is_string() || (t.get("path").is_none() && t.get("file_path").is_none())
        });
        return Ok(match tool {
            "Bash" => base.tool("Bash", ti.cloned()).done(),
            "Edit" if is_patch => base
                .tool("apply_patch", Some(patch_input(ti, &["input", "patch"])))
                .done(),
            "Write" | "Edit" | "Read" => base
                .tool(tool, Some(path_input(ti, &["file_path", "path"])))
                .done(),
            other => base.tool(other, None).done(),
        });
    }
    let base = Canonical::new()
        .meta("cwd", v.get("cwd"))
        .meta("session_id", v.get("sessionId"))
        .meta("tool_use_id", v.get("toolCallId"));
    let Some(tool) = str_of(v, "toolName") else {
        return Err("Copilot hook input has no toolName".into());
    };
    let args = v.get("toolArgs").map(dejson);
    let handled = matches!(
        tool,
        "bash"
            | "powershell"
            | "write_bash"
            | "write_powershell"
            | "create"
            | "edit"
            | "str_replace_editor"
            | "view"
            | "apply_patch"
    );
    if handled && !args.as_ref().is_some_and(Value::is_object) && tool != "apply_patch" {
        return Err(format!("Copilot {tool} hook input has no toolArgs object"));
    }
    let args = args.as_ref();
    Ok(match tool {
        "bash" | "powershell" => base
            .tool(
                "Bash",
                Some(shell_input(
                    args.and_then(|a| a.get("command")).cloned(),
                    None,
                )),
            )
            .done(),
        // Text typed into a running shell session (`{enter}` is Enter).
        "write_bash" | "write_powershell" => {
            let input = match args.and_then(|a| a.get("input")) {
                Some(Value::String(t)) => Some(json!(typed_lines(tool, t)?)),
                other => other.cloned(),
            };
            base.tool("Bash", Some(shell_input(input, None))).done()
        }
        "create" => base
            .tool("Write", Some(path_input(args, &["path", "file_path"])))
            .done(),
        "edit" | "str_replace_editor" => base
            .tool("Edit", Some(path_input(args, &["path", "file_path"])))
            .done(),
        "view" => base
            .tool("Read", Some(path_input(args, &["path", "file_path"])))
            .done(),
        "apply_patch" => base
            .tool("apply_patch", Some(patch_input(args, &["input", "patch"])))
            .done(),
        other => base.tool(other, None).done(),
    })
}

/// The lines typed by a Copilot `write_bash` / `write_powershell` input,
/// `{enter}` (and `{ctrl+c}` / `{ctrl+d}`) ending a line; key names are read
/// without regard to case or spaces (`{ Enter }`). `{esc}` is allowed as the
/// last key (leaving a pager or menu). Any other key (`{backspace}`,
/// `{left}`, `{up}`, `{down}`, `{tab}`, ...), a raw control character other
/// than a newline (`\u{15}` is Ctrl-U, `\u{7f}` is Backspace, ESC starts an
/// arrow key), or bash history expansion (`!!`, `!$`, `!-1`, `!str`) edits
/// the line or recalls history, so what runs cannot be read from the text:
/// an error (the hook denies). Each call is judged on its own; a command
/// typed across several calls is only judged a piece at a time.
fn typed_lines(tool: &str, input: &str) -> Result<String, String> {
    let unreadable = |what: String| {
        format!(
            "the Copilot {tool} input {what}, which edits the line or recalls history, so the \
             command it runs cannot be checked (type the whole command, ending with {{enter}})"
        )
    };
    if let Some(c) = input
        .chars()
        .find(|c| c.is_control() && !matches!(c, '\n' | '\r'))
    {
        return Err(unreadable(format!(
            "contains the control character U+{:04X}",
            u32::from(c)
        )));
    }
    let mut out = String::new();
    let mut rest = input;
    while let Some(open) = rest.find('{') {
        out.push_str(&rest[..open]);
        let after = &rest[open + 1..];
        let key = after
            .find('}')
            .map(|close| (close, after[..close].replace(' ', "").to_ascii_lowercase()))
            .filter(|(_, k)| !out.ends_with('$') && is_key_name(k));
        let Some((close, k)) = key else {
            out.push('{');
            rest = after;
            continue;
        };
        rest = &after[close + 1..];
        match k.as_str() {
            "enter" | "return" | "ctrl+c" | "ctrl-c" | "ctrl+d" | "ctrl-d" => out.push('\n'),
            "esc" | "escape" if rest.is_empty() => {}
            _ => return Err(unreadable(format!("presses {{{k}}}"))),
        }
    }
    out.push_str(rest);
    if tool == "write_bash" {
        if let Some(h) = history_expansion(&out) {
            return Err(unreadable(format!("uses history expansion ({h})")));
        }
    }
    Ok(out)
}

/// The first bash history expansion in typed text: `!!` anywhere, or a
/// word starting with `!` and an event (`!$`, `!-1`, `!12`, `!git`, `!?x`),
/// or a line starting with `^` (`^old^new`). `! cmd` and `!=` are not.
fn history_expansion(text: &str) -> Option<String> {
    if text.contains("!!") {
        return Some("!!".into());
    }
    for line in text.lines() {
        if line.trim_start().starts_with('^') {
            return Some("^".into());
        }
        let b = line.as_bytes();
        for (i, _) in line.match_indices('!') {
            let word_start =
                i == 0 || b[i - 1].is_ascii_whitespace() || b";&|(".contains(&b[i - 1]);
            let event = b
                .get(i + 1)
                .is_some_and(|c| c.is_ascii_alphanumeric() || b"$-?#*^".contains(c));
            if word_start && event {
                let end = line[i + 1..]
                    .find(char::is_whitespace)
                    .map_or(line.len(), |e| i + 1 + e);
                return Some(line[i..end].to_string());
            }
        }
    }
    None
}

/// A key name of Copilot's shell-input tools (`enter`, `backspace`,
/// `ctrl+c`, `f5`, ...), not shell text in braces (`{a,b}`, `${HOME}`).
fn is_key_name(k: &str) -> bool {
    const KEYS: &[&str] = &[
        "enter",
        "return",
        "tab",
        "space",
        "up",
        "down",
        "left",
        "right",
        "backspace",
        "bs",
        "delete",
        "del",
        "home",
        "end",
        "esc",
        "escape",
        "pageup",
        "pagedown",
        "insert",
    ];
    let function_key = k
        .strip_prefix('f')
        .is_some_and(|n| (1..=2).contains(&n.len()) && n.chars().all(|c| c.is_ascii_digit()));
    KEYS.contains(&k)
        || function_key
        || ["ctrl", "alt", "shift", "meta", "cmd"].iter().any(|m| {
            k.strip_prefix(m)
                .is_some_and(|r| r.len() > 1 && (r.starts_with('+') || r.starts_with('-')))
        })
}

/// `{command: <patch text>}` from a bare string or one of `keys`.
fn patch_input(args: Option<&Value>, keys: &[&str]) -> Value {
    let patch = args.and_then(|a| match a {
        Value::String(_) => Some(a.clone()),
        Value::Object(o) => keys.iter().find_map(|k| o.get(*k)).cloned(),
        _ => None,
    });
    shell_input(patch, None)
}

/// Shell-quote one argv word for the joined command line.
fn quote_word(w: &str) -> String {
    let plain = !w.is_empty()
        && w.chars()
            .all(|c| c.is_ascii_alphanumeric() || "_./:@%+=,-".contains(c));
    if plain {
        w.to_string()
    } else {
        format!("'{}'", w.replace('\'', r"'\''"))
    }
}

/// Commands from a Cline `run_commands` / `execute_command` input, which
/// accepts a string, a list of strings, `{command, args}` entries or
/// `{commands | command | cmd: ...}`. One command per line (shellfirm
/// checks each line). `None` when no command can be found.
fn cline_commands(input: &Value) -> Option<String> {
    fn entry(v: &Value, out: &mut Vec<String>) -> bool {
        match dejson(v) {
            Value::String(s) => {
                out.push(s);
                true
            }
            Value::Array(a) => a.iter().all(|e| entry(e, out)) && !a.is_empty(),
            Value::Object(o) => {
                if let Some(Value::String(cmd)) = o.get("command") {
                    let mut line = cmd.clone();
                    if let Some(Value::Array(args)) = o.get("args").map(dejson) {
                        for a in &args {
                            let Some(a) = a.as_str() else { return false };
                            line.push(' ');
                            line.push_str(&quote_word(a));
                        }
                    }
                    out.push(line);
                    return true;
                }
                ["commands", "command", "cmd"]
                    .iter()
                    .find_map(|k| o.get(*k))
                    .is_some_and(|c| entry(c, out))
            }
            _ => false,
        }
    }
    let mut out = Vec::new();
    (entry(input, &mut out) && !out.is_empty()).then(|| out.join("\n"))
}

/// Paths from a Cline `read_files` input: a path, a list of paths or
/// `{path}` objects, or `{files | paths | file_paths: ...}`.
fn cline_read_paths(input: &Value) -> Vec<Value> {
    fn collect(v: &Value, out: &mut Vec<Value>) {
        match dejson(v) {
            s @ Value::String(_) => out.push(s),
            Value::Array(a) => a.iter().for_each(|e| collect(e, out)),
            Value::Object(o) => {
                if let Some(p) = ["path", "file_path", "filePath"]
                    .iter()
                    .find_map(|k| o.get(*k))
                {
                    out.push(p.clone());
                } else {
                    for k in ["files", "paths", "file_paths"] {
                        if let Some(x) = o.get(k) {
                            collect(x, out);
                        }
                    }
                }
            }
            _ => {}
        }
    }
    let mut out = Vec::new();
    collect(input, &mut out);
    out
}

/// Cline `PreToolUse` (VS Code: `preToolUse.{toolName, parameters}` with
/// JSON-stringified values; CLI/SDK: `tool_call.{id, name, input}`).
fn cline(v: &Value) -> Result<Value, String> {
    let call = v.get("tool_call");
    let pre = v.get("preToolUse");
    let tool = call
        .and_then(|c| str_of(c, "name"))
        .or_else(|| pre.and_then(|p| str_of(p, "toolName")))
        .ok_or_else(|| {
            "Cline hook input has no tool_call.name / preToolUse.toolName".to_string()
        })?;
    let input = call
        .and_then(|c| c.get("input"))
        .or_else(|| pre.and_then(|p| p.get("parameters")))
        .map_or_else(|| json!({}), dejson);
    let cwd = v
        .get("workspaceRoots")
        .and_then(Value::as_array)
        .and_then(|a| a.iter().find(|r| r.as_str().is_some_and(|s| !s.is_empty())))
        .cloned();
    let base = Canonical::new()
        .meta("cwd", cwd.as_ref())
        .meta("session_id", v.get("taskId"))
        .meta("tool_use_id", call.and_then(|c| c.get("id")));
    let file_keys = &["path", "file_path", "filePath", "absolutePath"];
    Ok(match tool {
        "execute_command" | "run_commands" => {
            let cmd = cline_commands(&input)
                .ok_or_else(|| format!("Cline {tool} hook input has no command"))?;
            base.tool("Bash", Some(shell_input(Some(json!(cmd)), None)))
                .done()
        }
        "write_to_file" | "new_rule" => base
            .tool("Write", Some(path_input(Some(&input), file_keys)))
            .done(),
        "replace_in_file" | "editor" | "edit_file" => base
            .tool("Edit", Some(path_input(Some(&input), file_keys)))
            .done(),
        "read_file" | "read_files" => {
            let paths = cline_read_paths(&input);
            if paths.is_empty() {
                return Err(format!("Cline {tool} hook input has no file path"));
            }
            base.tool("Read", Some(json!({ "file_paths": paths })))
                .done()
        }
        "apply_patch" => base
            .tool(
                "apply_patch",
                Some(patch_input(Some(&input), &["input", "patch"])),
            )
            .done(),
        other => base.tool(other, None).done(),
    })
}

/// Windsurf Cascade hooks (`pre_run_command`, `pre_write_code`,
/// `pre_read_code`): `tool_info.{command_line, cwd}` or `tool_info.file_path`.
fn windsurf(v: &Value) -> Value {
    let info = v.get("tool_info");
    let base = Canonical::new()
        .meta("cwd", info.and_then(|i| i.get("cwd")))
        .meta("session_id", v.get("trajectory_id"))
        .meta("tool_use_id", v.get("execution_id"));
    match str_of(v, "agent_action_name") {
        Some("pre_run_command") => base
            .tool(
                "Bash",
                Some(shell_input(
                    info.and_then(|i| i.get("command_line")).cloned(),
                    None,
                )),
            )
            .done(),
        Some("pre_write_code") => base
            .tool("Write", Some(path_input(info, &["file_path"])))
            .done(),
        Some("pre_read_code") => base
            .tool("Read", Some(path_input(info, &["file_path"])))
            .done(),
        Some(other) => base.tool(other, None).done(),
        // No action name: the parser reports the missing command.
        None => base.done(),
    }
}

/// The payload sent by shellfirm's `OpenCode` plugin: `tool_name` (`OpenCode`
/// tool id), `tool_input` (the tool's `args`), `cwd`, `session_id`,
/// `tool_use_id`.
fn opencode(v: &Value) -> Value {
    let ti = v.get("tool_input");
    let base = Canonical::new()
        .meta("session_id", v.get("session_id"))
        .meta("tool_use_id", v.get("tool_use_id"));
    let cwd = v.get("cwd");
    match str_of(v, "tool_name") {
        Some("bash") => {
            // `workdir` is where the command runs (relative to the session
            // directory).
            let cwd = run_dir(cwd, ti.and_then(|t| t.get("workdir")));
            base.meta("cwd", cwd.as_ref())
                .tool(
                    "Bash",
                    Some(shell_input(
                        ti.and_then(|t| t.get("command")).cloned(),
                        None,
                    )),
                )
                .done()
        }
        Some("write") => base
            .meta("cwd", cwd)
            .tool("Write", Some(path_input(ti, &["filePath"])))
            .done(),
        Some("edit" | "multiedit") => base
            .meta("cwd", cwd)
            .tool("Edit", Some(path_input(ti, &["filePath"])))
            .done(),
        Some("read") => base
            .meta("cwd", cwd)
            .tool("Read", Some(path_input(ti, &["filePath"])))
            .done(),
        Some("apply_patch" | "patch") => base
            .meta("cwd", cwd)
            .tool("apply_patch", Some(patch_input(ti, &["patchText"])))
            .done(),
        Some(other) => base.meta("cwd", cwd).tool(other, None).done(),
        None => base.meta("cwd", cwd).done(),
    }
}

/// One-line summary of a decision for the user (the first line of the
/// reason plus why).
fn short_message(a: &RiskAssessment, reason: &str) -> String {
    let short = reason.lines().next().unwrap_or_default().to_string();
    a.decision_reason
        .as_deref()
        .map_or_else(|| short.clone(), |r| format!("{short} {r}"))
}

/// A note for an action that goes ahead although a rule matched (an
/// agent-instruction edit in an agent that cannot ask).
fn note(a: &RiskAssessment) -> String {
    let rules: Vec<String> = a
        .matched_rules
        .iter()
        .map(|r| format!("[{}] {}", r.id, r.description))
        .collect();
    format!(
        "shellfirm: {} (allowed; review the change)",
        rules.join("; ")
    )
}

/// The hook answer for the agents in this module. `None` prints nothing.
pub(super) fn build_output(
    kind: HookKind,
    a: &RiskAssessment,
    allow_safe: bool,
    subject: &str,
) -> Option<Value> {
    let reason = agent::format_reason_for(a, subject);
    match (kind, a.decision) {
        (HookKind::ClaudeCode | HookKind::Cursor, _) => None,
        // Nothing to say; the agent's own permission rules apply.
        (_, Decision::Allow) => match kind {
            HookKind::Cline => Some(json!({ "cancel": false })),
            HookKind::OpenCode => Some(json!({ "decision": "allow" })),
            HookKind::Qwen if allow_safe => Some(json!({
                "hookSpecificOutput": {
                    "hookEventName": "PreToolUse",
                    "permissionDecision": "allow",
                    "permissionDecisionReason": "shellfirm found no risky patterns",
                }
            })),
            HookKind::Copilot if allow_safe => Some(json!({
                "permissionDecision": "allow",
                "permissionDecisionReason": "shellfirm found no risky patterns",
            })),
            _ => None,
        },
        // An `ask` left for an agent that cannot ask is an agent-instruction
        // edit (an everyday task, see `evaluate_hook`): let it through with
        // a note where the agent can show one.
        (HookKind::Codex, Decision::Ask) => Some(json!({ "systemMessage": note(a) })),
        (HookKind::Cline, Decision::Ask) => Some(json!({ "cancel": false })),
        (HookKind::OpenCode, Decision::Ask) => Some(json!({
            "decision": "allow",
            "warning": note(a),
        })),
        (HookKind::Windsurf, _) => None,
        (HookKind::Codex | HookKind::Qwen, d) => Some(json!({
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": d.as_str(),
                "permissionDecisionReason": reason,
            }
        })),
        (HookKind::Gemini, d) => {
            // Gemini shows `systemMessage` in its confirmation prompt (ask)
            // and sends `reason` to the model (deny).
            let message = if d == Decision::Ask {
                reason.clone()
            } else {
                short_message(a, &reason)
            };
            Some(json!({
                "decision": d.as_str(),
                "reason": reason,
                "systemMessage": message,
            }))
        }
        (HookKind::Copilot, d) => Some(json!({
            "permissionDecision": d.as_str(),
            "permissionDecisionReason": reason,
        })),
        (HookKind::Cline, Decision::Deny) => Some(json!({
            "cancel": true,
            "errorMessage": reason,
        })),
        (HookKind::OpenCode, Decision::Deny) => Some(json!({
            "decision": "deny",
            "reason": reason,
        })),
    }
}

/// Windsurf blocks a pre-hook with exit code 2 and shows stderr to the
/// agent: the reason to print, or `None` to let the action run.
pub(super) fn windsurf_block(a: &RiskAssessment, subject: &str) -> Option<String> {
    (a.decision == Decision::Deny).then(|| agent::format_reason_for(a, subject))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cline_command_shapes() {
        for (input, want) in [
            (json!({"commands": ["ls", "npm test"]}), "ls\nnpm test"),
            (json!({"commands": "[\"ls\"]"}), "ls"),
            (json!({"command": "ls -la"}), "ls -la"),
            (json!({"cmd": "pwd"}), "pwd"),
            (json!("git status"), "git status"),
            (json!(["a", "b"]), "a\nb"),
            (
                json!({"commands": [{"command": "rm", "args": ["-rf", "my dir"]}]}),
                "rm -rf 'my dir'",
            ),
            (
                json!([{"command": "echo", "args": ["it's"]}]),
                "echo 'it'\\''s'",
            ),
        ] {
            assert_eq!(cline_commands(&input).as_deref(), Some(want), "{input}");
        }
        for bad in [
            json!({}),
            json!({"commands": []}),
            json!(5),
            json!({"commands": [5]}),
        ] {
            assert_eq!(cline_commands(&bad), None, "{bad}");
        }
    }

    fn parsed(kind: HookKind, v: &Value) -> super::super::HookPayload {
        super::super::parse_hook_payload(&v.to_string(), kind).unwrap()
    }

    #[test]
    fn payloads_map_to_the_checked_action() {
        use super::super::HookAction;
        let cmd = |c: &str| HookAction::Command(c.into());
        // Copilot, VS Code compatible (`PreToolUse`) payload.
        let p = parsed(
            HookKind::Copilot,
            &json!({"hook_event_name": "PreToolUse", "session_id": "s", "cwd": "/w",
                    "tool_name": "Bash", "tool_input": {"command": "ls"}}),
        );
        assert_eq!(p.action, cmd("ls"));
        assert_eq!(p.session_id.as_deref(), Some("s"));
        let p = parsed(
            HookKind::Copilot,
            &json!({"tool_name": "Write", "tool_input": {"path": "/w/a.txt", "file_text": "x"}}),
        );
        assert_eq!(
            p.action,
            HookAction::FileWrite {
                tool: "Write".into(),
                path: "/w/a.txt".into()
            }
        );
        let p = parsed(
            HookKind::Copilot,
            &json!({"tool_name": "Edit", "tool_input": {"input": "*** Begin Patch\n*** Add File: x.md\n+a\n*** End Patch"}}),
        );
        assert_eq!(
            p.action,
            HookAction::FileWrites {
                tool: "apply_patch".into(),
                paths: vec!["x.md".into()],
                deleted: vec![]
            }
        );
        // Codex: an argv command (any shell tool name), `cmd`, `workdir`.
        let p = parsed(
            HookKind::Codex,
            &json!({"cwd": "/w", "tool_name": "shell",
                    "tool_input": {"command": ["bash", "-lc", "rm -rf ~/x"], "workdir": "sub"}}),
        );
        assert_eq!(
            (p.action, p.cwd.as_deref()),
            (
                cmd("bash -lc 'rm -rf ~/x'"),
                Some(std::path::Path::new("/w").join("sub").to_str().unwrap())
            )
        );
        let p = parsed(
            HookKind::Codex,
            &json!({"cwd": "/w", "tool_name": "exec_command",
                    "tool_input": {"cmd": "make", "workdir": "/elsewhere"}}),
        );
        assert_eq!(
            (p.action, p.cwd.as_deref()),
            (cmd("make"), Some("/elsewhere"))
        );
        // Gemini: `dir_path` is where the command runs.
        let p = parsed(
            HookKind::Gemini,
            &json!({"tool_name": "run_shell_command", "tool_input": {"command": "make", "dir_path": "/w/sub"}}),
        );
        assert_eq!((p.action, p.cwd.as_deref()), (cmd("make"), Some("/w/sub")));
        let p = parsed(
            HookKind::Qwen,
            &json!({"cwd": "/w", "tool_name": "run_shell_command", "tool_input": {"command": "make", "directory": "sub"}}),
        );
        assert_eq!(
            p.cwd.as_deref(),
            std::path::Path::new("/w").join("sub").to_str()
        );
        // OpenCode: `workdir` is relative to the session directory.
        let p = parsed(
            HookKind::OpenCode,
            &json!({"tool_name": "bash", "tool_input": {"command": "ls", "workdir": "pkg"}, "cwd": "/w"}),
        );
        assert_eq!(
            p.cwd.as_deref(),
            std::path::Path::new("/w").join("pkg").to_str()
        );
        // Cline CLI: several commands are checked line by line, and the
        // tool call id is kept.
        let p = parsed(
            HookKind::Cline,
            &json!({"taskId": "t", "workspaceRoots": ["/w"],
                    "tool_call": {"id": "c1", "name": "run_commands", "input": {"commands": ["ls", "rm -rf /"]}}}),
        );
        assert_eq!(p.action, cmd("ls\nrm -rf /"));
        assert_eq!(
            (p.cwd.as_deref(), p.tool_use_id.as_deref()),
            (Some("/w"), Some("c1"))
        );
        // Windsurf.
        let p = parsed(
            HookKind::Windsurf,
            &json!({"agent_action_name": "pre_run_command", "trajectory_id": "t", "execution_id": "e",
                    "tool_info": {"command_line": "npm i", "cwd": "/w"}}),
        );
        assert_eq!((p.action, p.cwd.as_deref()), (cmd("npm i"), Some("/w")));
        assert_eq!(p.session_id.as_deref(), Some("t"));
        for (kind, v) in [
            (
                HookKind::Windsurf,
                json!({"agent_action_name": "post_run_command", "tool_info": {"command_line": "x"}}),
            ),
            (
                HookKind::Qwen,
                json!({"tool_name": "exec", "tool_input": {"command": "rm -rf /"}}),
            ),
            (
                HookKind::OpenCode,
                json!({"tool_name": "webfetch", "tool_input": {"url": "x"}}),
            ),
        ] {
            assert_eq!(parsed(kind, &v).action, HookAction::NotApplicable, "{v}");
        }
    }

    #[test]
    fn typed_shell_input_keys() {
        assert_eq!(
            typed_lines("write_bash", "ls{enter}pwd{enter}").unwrap(),
            "ls\npwd\n"
        );
        assert_eq!(
            typed_lines("write_bash", "echo ${HOME} {a,b} {x}{ctrl+c}").unwrap(),
            "echo ${HOME} {a,b} {x}\n"
        );
        for (input, typed) in [
            ("echo hi{Enter}ls{ENTER}", "echo hi\nls\n"),
            ("y{ enter }", "y\n"),
            ("q{esc}", "q"),
            ("{esc}", ""),
            ("exit{ctrl+d}", "exit\n"),
            ("{ctrl+c}", "\n"),
            ("make\r\n", "make\r\n"),
            (
                "[ \"$a\" != b ] && ! false{enter}",
                "[ \"$a\" != b ] && ! false\n",
            ),
            ("git commit -m 'fix!'{enter}", "git commit -m 'fix!'\n"),
        ] {
            assert_eq!(
                typed_lines("write_bash", input).unwrap(),
                typed,
                "{input:?}"
            );
        }
        assert_eq!(
            typed_lines("write_powershell", "if (!$x) { ls }{enter}").unwrap(),
            "if (!$x) { ls }\n"
        );
        for input in [
            "a{backspace}",
            "rm -rf ~/x{BACKSPACE}{enter}",
            "rm -rf ~/x{ Backspace }{enter}",
            "{up}{enter}",
            "{down}{enter}",
            "x{left}",
            "{tab}",
            "{ctrl+r}",
            "{f5}",
            "{esc}b{enter}",
            "echo safe\u{15}rm -rf ~/{enter}",
            "rm -rf ~/x\u{7f}{enter}",
            "rm -rf ~/x\u{8}{enter}",
            "rm -rf ~/x\u{1b}[D\u{1b}[3~{enter}",
            "rm -rf ~/Docu\t\n",
            "\u{1b}[A\n",
            "!!{enter}",
            "sudo !!{enter}",
            "!-2{enter}",
            "rm -rf !${enter}",
            "!rm{enter}",
            "^foo^bar{enter}",
        ] {
            let e = typed_lines("write_bash", input).unwrap_err();
            assert!(e.contains("cannot be checked"), "{input:?}: {e}");
        }
        assert!(typed_lines("write_powershell", "ls\u{15}rm x{enter}").is_err());
    }

    #[test]
    fn dejson_only_decodes_json_containers() {
        assert_eq!(dejson(&json!("[\"a\"]")), json!(["a"]));
        assert_eq!(dejson(&json!("{\"a\":1}")), json!({"a": 1}));
        assert_eq!(dejson(&json!("ls -la")), json!("ls -la"));
        assert_eq!(dejson(&json!("[ -d x ] && ls")), json!("[ -d x ] && ls"));
    }
}
