# AI-agent hooks

`shellfirm connect <agent>` installs a hook that the agent runs before a tool
call. The hook runs `shellfirm check --hook <agent>`, which reads the agent's
hook payload from stdin and answers in that agent's own format:

- **allow**: nothing risky matched. shellfirm stays silent (or answers the
  agent's neutral "go on"), so the agent's own approval rules still apply.
- **ask**: a risky command or edit. Agents that can stop and ask you get an
  `ask`. Agents whose hooks cannot ask get a **deny** with the reason, the
  matched rules and a safer alternative, so you can run the command yourself
  if it is intended (the audit log records `deny_reason: agent_auto_deny`).
  Edits of agent instruction files (`AGENTS.md`, `CLAUDE.md`, ...) are an
  everyday task: they go ahead with a note there.
- **deny**: a dangerous command, a deny-listed check, or a policy violation.

Every answer names the rule id, its severity, the description and a safer
alternative. Malformed or unreadable input is denied (`Failing closed`), in
every agent's format. Decisions are written to the audit log with the agent's
name (`agent_name`), its session id and the tool-call id.

Common options: `--scope project` (the hook goes into the current directory,
for the whole team; no personal paths are recorded), `--dry-run`,
`--uninstall` (removes only shellfirm's entries; a file left empty is
deleted). Existing files are backed up first (project-scope backups go to
`~/.cache/shellfirm/backups`; the newest 3 backups of each file are kept), JSON
with comments is read (the comments are not kept, and the output says so
before the change), and running `connect` again upgrades shellfirm's entries
in place. User-scope hooks record the configuration directory
(`--config-dir`). At `--scope project`, a file (or a directory on its path)
that is a symlink out of the project is refused: a link planted in a
repository must not make shellfirm write another file. `--uninstall` also
removes the directories it left empty (`.github/hooks`, `.github`).

`shellfirm status` lists the installed hooks and `shellfirm doctor` reports
problems with them: a hook turned off in the agent's settings (Claude Code
`disableAllHooks` in any settings file that applies or managed
`allowManagedHooksOnly: true`, Codex `[features]
hooks = false`, Gemini `hooksConfig`, Copilot `disableAllHooks`; `status`
shows `hook OFF` and how to turn it back on), a hook that does not cover the
shell tool, a file `connect` refuses (a `hooks` key that is not an object, a
Cline or OpenCode file shellfirm did not write). `connect` prints the same
when the hook it installed is turned off. `doctor` exits 0 on a machine with
agent hooks in order and no shell hook at all (the shell findings are
warnings there). A settings path that is not a regular file (a FIFO) is
reported as an error, never read, and so is an agent folder that cannot be
read (`chmod 000 ~/.claude`, `$CLAUDE_CONFIG_DIR`, `~/.codex`): `(error:
can't read …)`, not "not installed". A shellfirm hook in Claude Code's
managed settings is listed as `claude-code (managed)` (see
[Managed settings](#managed-settings)). Only files named the way shellfirm names
its backups (`<file>.shellfirm-bak-<UTC stamp>`) count toward the 3 kept.

| Agent | Can ask | If shellfirm cannot run |
|-------|---------|-------------------------|
| Claude Code | yes | blocked (`onFailure: block`, Claude Code ≥ 2.1.295) |
| Cursor | commands only | the action goes ahead |
| Codex CLI | no | the action goes ahead |
| Gemini CLI | yes | blocked, except when shellfirm exits with status 1 (a missing binary or a crash is blocked) |
| Qwen Code | yes (headless runs deny) | the action goes ahead |
| GitHub Copilot CLI | yes (autopilot and cloud agent deny) | blocked, except on a timeout |
| Windsurf | no | the action goes ahead |
| Cline | no | cancelled (the hook script answers for shellfirm) |
| OpenCode | no | blocked (the plugin answers for shellfirm) |

shellfirm protects these files from the agents themselves: an agent edit of a
hook file, settings file or plugin below needs approval (or is denied where
the agent cannot ask), like Claude Code's and Cursor's.

What every adapter checks the same way:

- A patch (`apply_patch`) is judged by its worst file, whatever the order of
  the files: one protected file among instruction-file edits is enough, and
  the reason names that file. The "allowed; review the change" note for
  agent-instruction edits (`AGENTS.md`, `CLAUDE.md`, ...) applies only when
  every file of the call is one.
- A patch run through the shell (`apply_patch '<patch>'`, `apply_patch
  <<'EOF' … EOF`, `apply_patch $'…'`, or under Codex's other name
  `applypatch`), also as the script of a shell (`bash -lc "apply_patch
  <<'EOF' … EOF"`, `sh -c`, `zsh -lc`), has its files judged too. A patch
  whose content shellfirm cannot see (`apply_patch < p.diff`, `apply_patch
  "$(cat p.diff)"`, `cat p.diff | apply_patch`) needs approval (denied where
  the agent cannot ask).
- Overwriting a private key or credential file (`~/.ssh/id_rsa`,
  `~/.aws/credentials`, `~/.git-credentials`, ...) with a file tool asks
  (`shellfirm-self:credential_file_edit`; denied where the agent cannot ask);
  deleting one (`*** Delete File:`, Cursor's `Delete`) is Critical and
  denied, like `rm` of it. Public keys and `known_hosts` are not matched.
  Home-directory key and credential paths match whatever their case
  (`~/.SSH/id_rsa`; macOS and Windows file systems usually ignore case).
- An agent home moved by an environment variable is protected like the
  default one: `$CLAUDE_CONFIG_DIR/settings.json`, `settings.local.json`
  and `hooks/`, `$CODEX_HOME/config.toml` and `hooks.json`,
  `$COPILOT_HOME/hooks/` (edits need approval), and
  `$CLAUDE_CONFIG_DIR/.credentials.json` and `$CODEX_HOME/auth.json`
  (reads and edits are judged like `~/.claude/.credentials.json` and
  `~/.codex/auth.json`). The variables are read from the hook's
  environment, which the agent passes on; a relative value is resolved
  against the hook's current directory, as `shellfirm connect` does.
- Starting an agent with its hooks, permission checks or sandbox off
  (`claude --dangerously-skip-permissions`, `gemini -y`, `codex -s
  danger-full-access`, `codex -c features.hooks=false`, `codex --disable
  hooks`, `cursor-agent --force`, `opencode run
  --dangerously-skip-permissions`, ...) is `shellfirm-self:agent_hooks_bypass`.
  Only the agent command's own options count, read with that CLI's own
  option rules: a prompt (`gemini -p "say -y"`) or a subcommand's option
  (`gemini extensions install x -y`) does not, while a switch does not hide
  the flag after it (`claude -p --dangerously-skip-permissions`; `-p` and
  `-c` are switches in Claude Code, `-s` in Gemini). Gemini, Qwen, Codex and
  OpenCode read a word starting with `-` as an option, never as a value, so
  `gemini -p -y` and `gemini -yp x` run with `--yolo` and match. Codex
  `-c` overrides match in any spelling (`-cfeatures.hooks=false`,
  `features={hooks=false}`, `profiles.<name>.sandbox_mode`), and so does an
  agent started by its npm package (`npx @google/gemini-cli -y`, `bunx`,
  `pnpm dlx`).
- `shellfirm connect claude-code --no-fail-closed` run by an agent (it lets
  the agent go ahead when the hook fails; only `connect claude-code` has
  the flag) is `shellfirm-self:connect_fail_open`.
- A file-tool path that starts with `~/` is in the home directory.
- File reads are reported as file reads, and the audit log records them as
  `Read <path>`.
- A tool call whose command or path contains a NUL byte is denied (failing
  closed): what shellfirm judges might not be what runs.

## Claude Code

`shellfirm connect claude-code` (also registers the MCP server).

- File: `~/.claude/settings.json` (`$CLAUDE_CONFIG_DIR/settings.json` when
  set, a relative value taken from the current directory; the MCP server
  goes into `~/.claude.json`, or
  `$CLAUDE_CONFIG_DIR/.claude.json`); project scope `./.claude/settings.json`
  and `./.mcp.json`.
- Entries: `hooks.PreToolUse[]` for the shell tools (`Bash`, `PowerShell`,
  `Monitor`), the file tools (`Write`, `Edit`, `MultiEdit`, `NotebookEdit`)
  and `Read`, running `shellfirm check --hook claude-code` with
  `"onFailure": "block"` (`--no-fail-closed` leaves it out).
- Answer: `hookSpecificOutput.permissionDecision` `ask` / `deny`; safe calls
  get no output, so Claude Code's own permission rules apply. See the
  [README](../README.md#claude-code) and [Agent sandbox](sandbox.md).
- `disableAllHooks: true` in any settings file (user, project, local or
  managed) turns every hook off, and `allowManagedHooksOnly: true` in
  managed settings turns off every hook outside them (shellfirm's included);
  `status` and `doctor` report both.

### Managed settings

`connect` never writes Claude Code's managed settings file
(`/Library/Application Support/ClaudeCode/managed-settings.json` on macOS,
`/etc/claude-code/managed-settings.json` on Linux,
`C:\Program Files\ClaudeCode\managed-settings.json` on Windows). To enforce the
hook for every user of a machine (for example with `allowManagedHooksOnly:
true`), put the same `hooks` object that `shellfirm connect claude-code
--scope project` writes into that file:

```json
{
  "allowManagedHooksOnly": true,
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash|PowerShell|Monitor",
        "hooks": [
          {
            "type": "command",
            "command": "shellfirm check --hook claude-code",
            "timeout": 30,
            "onFailure": "block"
          }
        ]
      },
      {
        "matcher": "Write|Edit|MultiEdit|NotebookEdit",
        "hooks": [
          {
            "type": "command",
            "command": "shellfirm check --hook claude-code",
            "timeout": 30,
            "onFailure": "block"
          }
        ]
      },
      {
        "matcher": "Read",
        "hooks": [
          {
            "type": "command",
            "command": "shellfirm check --hook claude-code",
            "timeout": 30,
            "onFailure": "block"
          }
        ]
      }
    ]
  }
}
```

Each user's hook then reads that user's own shellfirm settings (add
`--config-dir <dir>` to the command to pin one directory for everyone).
`shellfirm status` shows a `claude-code (managed)` line for a shellfirm hook
in that file, and `doctor` reports it. When `allowManagedHooksOnly` is set
and the managed hook covers `Bash`, a user or project hook that Claude Code
no longer loads is shown as `hook OFF (... the shellfirm hook in that file
runs instead)` and does not fail `doctor`. Only managed settings can turn a
managed hook off (`disableAllHooks` there).

## Cursor

`shellfirm connect cursor` (also registers the MCP server).

- File: `~/.cursor/hooks.json`; project scope `./.cursor/hooks.json`.
- Entries: `hooks.beforeShellExecution[]` (shell commands; risky ones ask),
  `hooks.preToolUse[]` with matcher `Write|Delete` (edits of protected files)
  and `hooks.beforeReadFile[]` (reads of private keys and credential files),
  each `{"command": "shellfirm check --hook cursor", "timeout": 30}`.
- Cursor enforces only allow and deny for file tools and reads, so a risky
  edit or read (`beforeReadFile`, or a `Read` through `preToolUse`) is denied
  with the reason. If the hook fails, Cursor lets the
  action go ahead (shellfirm never writes `failClosed`: it prints nothing for
  safe calls).

## OpenAI Codex CLI

`shellfirm connect codex` (Codex CLI 0.124.0 or later; with 0.117–0.123 add
`[features] codex_hooks = true` to `config.toml`).

- File: `~/.codex/hooks.json` (`$CODEX_HOME/hooks.json` when `CODEX_HOME` is
  set); project scope `./.codex/hooks.json`, which Codex loads in trusted
  projects.
- Entry: `hooks.PreToolUse[]` with matcher `Bash|apply_patch` (an exact
  list), `{"type": "command", "command": "shellfirm check --hook codex",
  "timeout": 30}`. Codex rejects unknown top-level keys in `hooks.json`;
  shellfirm only adds `hooks`, and `status` / `doctor` report other keys.
- `[features] hooks = false` (formerly `codex_hooks`) in `config.toml` (or
  the project's `.codex/config.toml`) turns hooks off; `status` and
  `doctor` report it.
- Input: `tool_name` is `Bash` for shell commands (`tool_input.command`) and
  `apply_patch` for edits (`tool_input.command` is the patch; every file it
  adds, updates, deletes or moves is checked like a write), plus `cwd`,
  `session_id`, `tool_use_id`. A command given as an argv array (`["bash",
  "-lc", "…"]`) or under `cmd`, and the shell tool names `shell`,
  `exec_command` and `local_shell`, are read as `Bash`; `tool_input.workdir`
  (relative to `cwd`) is where the command runs.
- Answer: a deny is `hookSpecificOutput.permissionDecision: "deny"` with
  `permissionDecisionReason`. Codex `PreToolUse` hooks cannot ask (Codex
  treats `ask` and a bare `allow` as invalid hook output), so risky commands
  are denied; safe ones get no output.
- Trust: Codex runs a new or changed hook only after you trust it. The
  interactive TUI lists untrusted hooks when it starts (or open `/hooks`);
  `codex exec` skips an untrusted hook without a warning, so trust it once in
  the TUI before relying on it in scripts. Re-running `connect` after a
  change to the hook line (for example a new `--config-dir`) needs a new
  trust.
- Codex runs no `PreToolUse` hook for `write_stdin` (input sent to a
  running `exec_command` session): only the command that started the
  session is checked. `shellfirm sandbox codex` covers what runs there.
- If the hook fails or times out, Codex runs the tool call.

## Gemini CLI

`shellfirm connect gemini` (asking needs Gemini CLI 0.36.0 or later; older
versions ignore `ask`, so the command runs).

- File: `~/.gemini/settings.json`; project scope `./.gemini/settings.json`
  (Gemini asks you to trust project hooks).
- Entry: `hooks.BeforeTool[]` with matcher
  `^(run_shell_command|write_file|replace|read_file|read_many_files)$` (Gemini matchers are
  regular expressions) and `{"name": "shellfirm", "type": "command",
  "command": "shellfirm check --hook gemini", "timeout": 30000}`; Gemini
  timeouts are milliseconds. `/hooks disable shellfirm` turns it off
  (`hooksConfig.disabled`), and `shellfirm status` says so; running
  `connect gemini` again takes it out of that list in the file it writes.
  `hooksConfig.enabled: false` turns every hook off; `connect` and `status`
  say so and leave the switch to you.
- Input: `tool_name`, `tool_input` (`command` and `dir_path` for
  `run_shell_command`, `file_path` for the file tools), `cwd`, `session_id`.
  A `read_many_files` call is checked like a read of every path in
  `include` (or `paths`); a directory is read as everything in it
  (`~/.ssh` like `~/.ssh/*`). A call without a list of paths is denied.
- Answer: `{"decision": "deny" | "ask", "reason": ..., "systemMessage":
  ...}`. Gemini shows `systemMessage` in its confirmation prompt and sends
  `reason` to the model on a deny.
- Headless runs (`gemini -p --yolo`): Gemini CLI 0.69 waits for an answer to
  an `ask` that nobody can give, so the command never runs but the run does
  not end either; give such runs a timeout. Dangerous commands are denied and
  the run goes on.

## Qwen Code

`shellfirm connect qwen`.

- File: `~/.qwen/settings.json`; project scope `./.qwen/settings.json` (Qwen
  Code asks you to approve project hooks).
- Entry: `hooks.PreToolUse[]` with matcher
  `run_shell_command|write_file|edit|read_file|read_many_files` (a list of
  exact names; `read_many_files` is a tool only in Qwen Code versions that
  still expose it) and
  `{"type": "command", "command": "shellfirm check --hook qwen", "timeout":
  30}` (seconds).
- Input: Claude Code's shape with Qwen's tool names (`run_shell_command`
  with `command` and `directory`, `write_file` / `edit` / `read_file` with
  `file_path`, `read_many_files` with `paths`). `hooksConfig.disabled` is a
  Gemini CLI setting: Qwen Code does not read it, so `connect` leaves it alone.
- Answer: `hookSpecificOutput.permissionDecision` `ask` / `deny` with
  `permissionDecisionReason`. Headless runs and IDE (ACP) sessions turn
  `ask` into `deny`.

## GitHub Copilot CLI

`shellfirm connect copilot` (Copilot CLI 1.0.4 or later; 1.0.57 or later
denies a tool call when the hook crashes).

- File: `~/.copilot/hooks/shellfirm.json` (`$COPILOT_HOME/hooks/` when set);
  project scope `./.github/hooks/shellfirm.json`, which Copilot cloud agent
  also runs.
- Entry: `{"version": 1, "hooks": {"preToolUse": [{"type": "command",
  "bash": "shellfirm check --hook copilot", "powershell": "...", "timeoutSec":
  30}]}}`, with no matcher: every tool call goes through the hook, and
  shellfirm has no opinion about tools other than `bash` / `powershell`,
  `write_bash` / `write_powershell` (text typed into a running shell
  session, checked as a command; `{enter}` is a new line), `create`, `edit`,
  `view` and `apply_patch`.
- Typed input with a key that edits the line or recalls history
  (`{backspace}`, `{delete}`, `{left}`, `{home}`, `{up}`, `{down}`, `{tab}`,
  ...; key names in any case, `{Enter}` is `{enter}`), a raw control
  character other than a newline (Ctrl-U, Backspace, an escape sequence, a
  tab), or bash history expansion (`!!`, `!$`, `!-1`, `!cmd`) is denied: what
  it runs cannot be read from the text. `{ctrl+c}` and `{ctrl+d}` end a
  line, and `{esc}` as the last key (leaving a pager or menu) is allowed. Each `write_bash` call
  is checked on its own, so a command typed across several calls (`rm -rf `,
  then `~/{enter}`) is only checked a piece at a time and can get through.
  Copilot CLI has no OS sandbox `shellfirm sandbox` can configure (see
  [Agent sandbox](sandbox.md)); keep `write_bash` behind Copilot's own
  permission prompt (`--deny-tool`) if that matters to you.
- Input: `toolName` and `toolArgs` (an object, or a JSON string in older
  versions), `cwd`, `sessionId`, `toolCallId`. The VS Code compatible
  `PreToolUse` shape (`tool_name`, `tool_input`) is read too.
- Answer: `{"permissionDecision": "ask" | "deny", "permissionDecisionReason":
  ...}`. Copilot shows a prompt for `ask`; autopilot mode and cloud agent
  deny it.
- Copilot denies the tool call when the hook exits non-zero (shellfirm
  missing or crashing), but lets it through when the hook times out.

## Windsurf

`shellfirm connect windsurf` (Cascade hooks; also registers the MCP server).

- File: `~/.codeium/windsurf/hooks.json`; project scope
  `./.windsurf/hooks.json` (the MCP registration is user-level only).
- Entries: `hooks.pre_run_command[]`, `hooks.pre_write_code[]` and
  `hooks.pre_read_code[]`, each `{"command": "shellfirm check --hook
  windsurf", "show_output": false}`.
- Input: `agent_action_name`, `tool_info.command_line` and `tool_info.cwd`
  (commands) or `tool_info.file_path` (writes and reads), `trajectory_id`,
  `execution_id`.
- Answer: Cascade reads no JSON. shellfirm exits 2 and writes the reason to
  stderr to block; Cascade shows it to the agent. Cascade hooks cannot ask,
  so risky actions are blocked. Any other exit code lets the action run (also
  when shellfirm is missing).

## Cline

`shellfirm connect cline` (Cline 3.36 or later, macOS and Linux; also
registers the MCP server).

- File: the hook script `~/Documents/Cline/Hooks/PreToolUse` (run by the VS
  Code extension and the Cline CLI); project scope
  `./.clinerules/hooks/PreToolUse` (the MCP registration is user-level only).
  In the VS Code extension, turn on **Enable Hooks** in Cline's settings.
- The script is shellfirm's own (it starts with `# shellfirm-hook: cline`):
  it runs `shellfirm check --hook cline` and prints its answer. When
  shellfirm cannot run it answers `{"cancel": true}` itself, because Cline
  lets a tool call through when the hook script fails. When `shellfirm` is not
  on Cline's PATH, the script runs the binary `connect` ran from. An existing
  `PreToolUse` script that shellfirm did not write is never replaced or
  removed.
- Input: the VS Code extension sends `preToolUse.toolName` and
  `preToolUse.parameters` (string values as they are, other values
  JSON-encoded), the CLI sends
  `tool_call.name` and `tool_call.input`; `workspaceRoots[0]` is the
  directory, `taskId` the session. Shell tools are `execute_command` and
  `run_commands` (several commands are checked one by one), edits
  `write_to_file`, `replace_in_file`, `editor` and `apply_patch`, reads
  `read_file` and `read_files`.
- Answer: `{"cancel": true, "errorMessage": ...}` blocks, and Cline stops the
  task with that message; `{"cancel": false}` lets the call run. Cline hooks
  cannot ask, so risky calls are blocked.

## OpenCode

`shellfirm connect opencode`.

- File: the plugin `~/.config/opencode/plugins/shellfirm.js`
  (`$XDG_CONFIG_HOME/opencode/plugins/` when set); project scope
  `./.opencode/plugins/shellfirm.js`. It starts with
  `// shellfirm-hook: opencode`; a file without that line is never replaced.
- The plugin's `tool.execute.before` hook sends `bash`, `write`, `edit`,
  `multiedit`, `read`, `apply_patch` and `patch` calls (`multiedit` and
  `patch` are in older OpenCode versions) to `shellfirm check --hook opencode` as
  `{"tool_name", "tool_input", "session_id", "tool_use_id", "cwd"}` (the
  tool's `args` as `tool_input`; a `bash` `workdir` is resolved against
  `cwd`).
- Answer: `{"decision": "allow"}` lets the call run (with a `warning`, the
  plugin shows it as a toast, for example the review note of an
  agent-instruction edit); anything else throws,
  which blocks it with shellfirm's reason. The plugin throws too when
  shellfirm cannot run, times out (30 s) or answers something it cannot read.
  The plugin cannot ask, so risky calls are blocked.

## Zed

`shellfirm connect zed` registers shellfirm's MCP tools (`context_servers`).
Zed has no hook that runs before a tool call, so commands are not
intercepted: the agent has to choose to call shellfirm's tools.
