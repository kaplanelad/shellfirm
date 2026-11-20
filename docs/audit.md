# Audit trail

When `audit_enabled` is true (the default), every intercepted command and its
decision is recorded in `audit.log` next to `settings.yaml` (`shellfirm
status` prints the path and the retention).

## What is recorded

One record is written per decision, **after** it is made:

- a command that matched a check and was allowed (challenge solved), denied
  (deny list, project or org policy, agent auto-deny), cancelled by a human
  (Esc, Ctrl-C), or blocked because nobody could answer the challenge (no
  terminal);
- a matched check below your `min_severity` (`Skipped`);
- an AI-agent command handed back to the agent tool's own prompt (`Asked`).

Commands that match no check are not recorded.

A process that is killed outright while the challenge is on screen
(`kill -9` of the `shellfirm pre-command` process, a closed terminal window)
writes **no** record. The command does not run either, so this is a gap in
the log, not a bypass. Older versions wrote a pre-challenge `Cancelled`
record for that case; `audit show` still collapses such pairs (same
`event_id`) into one row.

## Viewing

```bash
shellfirm audit show                          # table
shellfirm audit show --since 7d               # 30m, 12h, 7d, 2w, 2026-01-31, 2026-01-31T10:00:00Z, all
shellfirm audit show --outcome denied         # allowed | denied | skipped | cancelled | asked | no-terminal
shellfirm audit show --severity high          # at or above
shellfirm audit show --limit 20               # last 20
shellfirm audit show --format json            # JSON array (or jsonl: one record per line)
shellfirm audit show --all-records            # do not collapse old pre-challenge/final pairs
```

`--since` takes a duration, a date, `all`, or an RFC 3339 timestamp:
`2026-01-31T10:00:00Z`, with fractional seconds (`…T10:00:00.123Z`, the
form inside agent transcripts) or an offset (`…T12:00:00+02:00`, or
`+0200`). A
timestamp without an offset (`2026-01-31T10:00:00`) is taken as UTC. An
invalid or future value exits 2.

`audit show` reads every rotated generation (`audit.log.N` … `audit.log.1`)
as well as `audit.log`. Malformed lines (invalid UTF-8, not JSON, missing
timestamp or outcome) are skipped with a warning that counts them.

## Clearing

`shellfirm audit clear` deletes `audit.log` and every rotated file. It asks
for confirmation and refuses to run without a terminal unless `--yes` is
passed.

## Replaying past agent sessions

`shellfirm audit replay` answers "what would shellfirm have done in my
earlier agent sessions?" without running anything. It reads the session
transcripts coding agents already keep on disk, finds every shell command
and file operation the agent ran, and judges each one exactly as that
agent's hook (`shellfirm check --hook claude-code` / `--hook codex`) would
have: with the working directory recorded for the call, your agent settings
(`agent.auto_deny_severity`, `require_human_approval`, ignores, denies) and
the project policies (`.shellfirm.yaml`, org policy) that apply there.
Codex CLI cannot ask, so, as in its hook, an `ask` for a Codex command or
file edit is reported as `deny`; an edit of only agent-instruction files
(`AGENTS.md`, …) is an `allow`, as Codex lets it through with a note. Each
file an `apply_patch` patch touches is judged on its own. The settings are
checked as `check` does: an invalid `settings.yaml` prints `shellfirm:
warning: invalid settings file …` on stderr (the built-in defaults are then
used).

```bash
shellfirm audit replay                              # last 7 days, every agent
shellfirm audit replay --since 30d --min-severity high
shellfirm audit replay --agent codex --project ~/work/api
shellfirm audit replay --redact                     # rule ids and reasons only
shellfirm audit replay --since all --json | jq 'select(.type == "finding")'
shellfirm audit replay --since 24h --fail-on deny   # exit 11 when a deny is found
```

| Option | Meaning |
| --- | --- |
| `--since WHEN` | `24h`, `7d`, `30d`, `2w`, a date or timestamp, or `all` (as `audit show`, see [Viewing](#viewing)). Default `7d`: a week of sessions is what you remember, it reads quickly, and Codex CLI compresses rollouts older than a week. An invalid or future value exits 2 (as for `audit show`). Calls without a valid timestamp (or with one in the future) are judged only with `all`, and counted in the header otherwise |
| `--agent AGENT` | `claude-code`, `codex` or `all` (default) |
| `--project PATH` | Only calls made in `PATH` or below it (relative paths are resolved against the current directory). A path that is not a directory, or an empty value, exits 2. Skipped lines are counted only for transcripts with calls in `PATH` |
| `--min-severity LEVEL` | List only findings at or above `LEVEL` (the totals still count every call) |
| `--limit N` | List at most `N` findings (default 25 in the text output, all with `--json`; `0` = all) |
| `--json` | JSON lines: one `{"type": "finding", …}` object per finding, then one `{"type": "summary", …}` |
| `--redact` | No command text, file paths or session ids; the project is shown by its directory name only, for screenshots and bug reports. The same findings as without it |
| `--fail-on DECISION` | `deny`: exit 11 when a deny was found. `ask`: also exit 10 when an ask was found. Counted after `--min-severity`, before `--limit`. Otherwise, when a transcript file or directory (the agent's folder, such as `~/.claude`, included) could not be read, or a compressed Codex rollout in the window was not read, exit 66, so an unreadable source never passes silently. Whenever that happens, whatever the exit status, stderr says `… the replay is incomplete` |

The report starts with the window and, per agent, the sessions, commands
and file operations read (plus anything skipped), then the deny / ask /
allow totals, then the findings worst first: deny before ask, then severity,
then how often. Identical calls in the same project are grouped (`×N`). Each
finding shows when it last happened, the agent, the project, the decision,
the most relevant rule (`+N` more: the most severe, and among equally severe
rules the most specific, so `fs:delete_home_folder` before
`fs:recursively_delete_outside`), its severity, the rule's full description
and the command (cut to one line). Secrets in commands and paths are
replaced with `***`, as in the audit log ([Secret redaction](#secret-redaction)),
with or without `--redact`. Control characters in commands and project paths
are escaped. When some of an agent's sessions are older than the window, the
header says so (`1 older session not read (use --since 30d or --since all)`).
It ends with how to have shellfirm decide such calls live (`shellfirm connect
claude-code` / `codex`), or, when that agent's hook is connected at user
scope, that new sessions get these decisions.

```text
shellfirm audit replay — last 7d (since 2026-11-12T19:37:12Z)
  Claude Code   2 sessions, 4 commands, 1 file operation  (~/.claude/projects)
                skipped: 2 malformed lines
  Codex CLI     1 session, 2 commands, 0 file operations  (~/.codex/sessions)
                skipped: 1 compressed rollout not read

Decisions: 4 deny, 1 ask, 2 allow

Would have blocked or asked (4 findings, worst first):

  DENY [CRITICAL] fs:recursively_delete +1 ×2
       2026-11-19 19:07  claude-code  ~/work/app
       This deletes a critical location: the filesystem root, your home directory, a system directory, the repository, or everything in the current directory.
       $ rm -rf /

  DENY [CRITICAL] fs:recursively_delete +1
       2026-11-19 19:25  codex  ~/work/app
       This deletes a critical location: the filesystem root, your home directory, a system directory, the repository, or everything in the current directory.
       $ rm -rf /

  DENY [HIGH] git:force_push
       2026-11-19 19:10  claude-code  ~/work/app
       This force-pushes and can overwrite remote history.
       $ cat <<'EOF' > notes.txt hello EOF git push --force origin main

  ASK  [HIGH] shellfirm-self:rc_file_edit
       2026-11-19 19:27  claude-code  ~/work/notes
       Edits a shell startup file (where the shellfirm shell hook is loaded)
       Write ~/.bashrc

Read-only: nothing was run, sent or written (shellfirm's audit log included).
Next: `shellfirm connect claude-code` has shellfirm decide these before they run.
Next: `shellfirm connect codex` has shellfirm decide these before they run.
```

### What is read

| Agent | Transcripts | Calls judged |
| --- | --- | --- |
| Claude Code | `~/.claude/projects/<project>/*.jsonl` and `<session>/subagents/*.jsonl` (`$CLAUDE_CONFIG_DIR/projects` when set; a relative value is resolved against the current directory, as `connect` does) | `Bash`, `PowerShell`, `Monitor` commands; `Write`, `Edit`, `MultiEdit`, `NotebookEdit` edits; `Read` (judged like `cat <path>`, as the hook does) |
| Codex CLI | `~/.codex/sessions/YYYY/MM/DD/rollout-*.jsonl` and `~/.codex/archived_sessions/` (`$CODEX_HOME` when set) | `exec_command`, `shell`, `shell_command` and `local_shell_call` commands (`bash -lc '<script>'` is judged as the script); `apply_patch` edits (each file the patch adds, updates, deletes or moves to) |

A call recorded twice (a resumed or forked session) is judged once. A file
last changed before the window is not opened. Lines that are not valid JSON,
lines over 16 MiB, shell and file calls whose input cannot be read or has
the wrong shape (Codex `arguments` that are not JSON, `{"cmd": 123}`, a
Claude Code `Bash` input without a `command` string), unreadable files and
directories, compressed Codex rollouts (`.jsonl.zst`) and anything named
like a transcript that is not a regular file (a FIFO, a device, a symbolic
link, a folder: never opened) are skipped and counted in the header. JSON escapes are decoded before a line is classified
(`"tool\u005fuse"` is a `tool_use`). An `apply_patch` sent through the shell
(`["apply_patch", "<patch>"]`, `apply_patch <<'EOF' … EOF`, also inside
`bash -lc "…"`), by Codex or by a Claude Code `Bash` call, is judged as the
patch: each file it touches, as the hook does.

### What replay does not do

- **Nothing runs and nothing is written.** No command from a transcript is
  executed, no external program is started for context (`git`, `kubectl`,
  …: as with `check --no-context`), the LLM review is off, nothing leaves the
  machine, and the audit log is not touched.
- **Decisions use today's state.** Your current settings, policies and files
  decide, not the ones in effect when the agent ran the call. A path that was
  deleted since then no longer matches checks that need it to exist, and a
  working directory that is gone has no project policy. Impact details
  (blast radius) are not computed.
- Calls the agent made through other tools (web, MCP servers, sub-agent
  launches) are not judged, as the hook does not see them either.

### JSON output

Each finding line has `type: "finding"`, `agent`, `decision` (`deny` /
`ask`), `severity`, `rule_id` (the most severe rule), `rule_ids`, `reason`
(that rule's description), `deny_reason` (when denied), `subject`
(`command`, `file edit` or `file read`), `tool`, `count`, `first_seen`,
`last_seen` and, without `--redact`, `command` or `path` (secrets
replaced; `command_redacted` / `path_redacted: true` when one was), `cwd`,
`session_id` and `decision_reason`; with `--redact`, `project` (the
directory name) instead. The last line has `type: "summary"`,
`schema_version` (`1`), `since`, `until`, `agents` (per agent: `found`,
`files`, `sessions`, `commands`, `file_operations`, `malformed_lines`,
`oversized_lines`, `calls_unreadable`, `calls_undated`,
`files_unreadable` (files and directories), `files_compressed`,
`files_outside_window`, `crashed`, and `roots` without `--redact`),
`totals` (`deny`, `ask`, `allow`), `incomplete` (`true` when a transcript
file or directory could not be read or a compressed rollout was skipped),
`findings` (after `--min-severity`),
`shown` (after `--limit`) and `redacted`.

## File format

JSON Lines, one record per line (`schema_version: 4`). Optional fields are
omitted when they do not apply.

| Field | Description |
| --- | --- |
| `schema_version` | `4` for this format (`3` and older records, without the newer fields, remain readable) |
| `version` | The shellfirm version that wrote the record (schema 4 and later) |
| `event_id` | Unique id of the decision |
| `timestamp` | UTC, `YYYY-MM-DDTHH:MM:SSZ` |
| `command` | The intercepted command, with secrets redacted (see below) and capped at 8 KiB |
| `command_truncated` | `true` when the command was longer than 8 KiB and cut |
| `command_bytes` | Length of the full command in bytes (only when truncated) |
| `command_redacted` | `true` when secrets were replaced with `***` |
| `command_sha256` | SHA-256 of the **original** command (when truncated or redacted), so a known command can still be matched against the log |
| `matched_ids` | Ids of the matched checks |
| `severity` | Highest severity of the matched checks |
| `challenge_type` | The base challenge of the matched checks: your `challenge` setting, raised by a policy `overrides` entry (so `challenge: Math` with a policy override to `Yes` records `Yes`); `Deny` for a deny; `AgentDeny`, `AgentAsk` or `AgentAllow` for AI-agent decisions |
| `effective_challenge` | The challenge actually presented, after every escalation layer |
| `escalation_reasons` | Why it was raised above the base challenge (e.g. ``protected branch `main` ``, `SSH session`) |
| `outcome` | `Allowed`, `Denied`, `Skipped` (below `min_severity`), `Cancelled` (declined or aborted by a human), `Asked` (decision handed to the agent tool's own prompt), `NoTerminal` (blocked because no terminal was available to answer the challenge) |
| `attempts` | Number of challenge attempts (when tracked) |
| `deny_reason` | Why the command did not run (see [deny_reason values](#deny_reason-values)) |
| `policy_sources` | The policy files (org or `.shellfirm.yaml`) that deny or enforce the matched checks |
| `policy_check_ids` | Matched ids that a policy enforces |
| `context_labels` | Context signals, e.g. `branch=main`, `ssh=true` |
| `blast_radius_scope`, `blast_radius_detail` | What the command would affect (the JSON formats hold the real text; invisible and bidi characters are escaped only in the `audit show` table) |
| `agent_name`, `agent_session_id`, `tool_use_id` | Set for AI-agent commands: `agent_name` is the `--hook` value (`claude-code`, `cursor`, `codex`, `gemini`, `qwen`, `copilot`, `cline`, `windsurf`, `opencode`) or `mcp`; `tool_use_id` is the agent's id for the tool call when it sends one (`audit show` keeps it in every format) |
| `user` | Account name of the real uid (from the password database, not `$USER`) |
| `uid` | Numeric real uid (Unix) |
| `env_user` | `$USER` / `$LOGNAME`, only when it differs from `user` |
| `hostname`, `cwd`, `git_repo`, `git_branch` | Where it ran. `git_repo` / `git_branch` are the repository the command works in: another one when it names one (`git -C ../infra …`, `cd ../infra && …`), otherwise the one of `cwd` |

### deny_reason values

The same values are used for the shell hook and for AI-agent hooks (Claude
Code, Cursor, Codex CLI, Gemini CLI, Qwen Code, Copilot CLI, Windsurf, Cline,
OpenCode, MCP); `check --format json` reports `deny_reason` and
`policy_sources` for a `deny` decision too.

| Value | Outcome | Meaning |
| --- | --- | --- |
| `policy_deny` | `Denied` | A matched check is in an org or project policy `deny` list; `policy_sources` names the file(s) |
| `user_deny` | `Denied` | A matched check is in your personal `deny_patterns_ids` |
| `agent_auto_deny` | `Denied` | AI agent: the severity (after context escalation) is at or above `agent.auto_deny_severity`, or a command or edit that would need a human in an agent that cannot ask (Codex CLI, Windsurf, Cline, OpenCode; Cursor file edits) |
| `fail_closed` | `Denied` / `Asked` | AI agent: the hook input could not be checked (malformed, too large, internal error), so it was blocked |
| `no_tty` | `NoTerminal` | A challenge was needed but no terminal was available to answer it (CI, scripts, `</dev/null`) |
| `cancelled` | `Cancelled` | The human cancelled the challenge (Esc, Ctrl-C, Ctrl-D or end of input). A wrong answer only asks again, so a shell-hook challenge ends unanswered only this way |
| `challenge_failed` | `Cancelled` | No longer written. It appears only in records from earlier versions, which wrote it for every cancelled challenge (they could not tell a cancel from a wrong answer); read it as "not passed" |
| `deny` | `Denied` | A deny-listed check that could not be attributed to a policy or to your settings (older records) |

Records written by older AI-agent hooks (shellfirm 0.3.10 and earlier, before
`policy_deny` / `user_deny` existed) may contain `deny_list` for either.

Example queries:

```bash
# How often did a policy block someone (shell or AI agent), and which file?
shellfirm audit show --outcome denied --format jsonl \
  | jq -c 'select(.deny_reason == "policy_deny") | {timestamp, user, agent_name, matched_ids, policy_sources}'
# Automation that hit a challenge it could not answer (CI, scripts)
shellfirm audit show --outcome no-terminal
```

## Secret redaction

Before a command is stored, values that look like secrets are replaced with
`***`:

- `mysql -pSECRET` (and `mysqldump`, `mysqladmin`, `mariadb`, …);
- `--password=…`, `--token …` / `--token=…`, `--secret`, `--api-key`,
  `--access-token`, `--auth-token`, `--client-secret`;
- environment assignments whose name contains `PASSWORD`, `PASSWD`, `PASS`,
  `TOKEN`, `SECRET`, `API_KEY`, `ACCESS_KEY`, `PRIVATE_KEY` or `CREDENTIAL`
  (`PGPASSWORD=…`, `GITHUB_TOKEN=…`, `AWS_SECRET_ACCESS_KEY=…`), names
  ending in `_AUTH` (`REDISCLI_AUTH=…`), and `MYSQL_PWD=…`;
- `redis-cli -a PASSWORD` / `--pass PASSWORD` (also `valkey-cli`,
  `keydb-cli`), and `mongosh -p PASSWORD` / `--password PASSWORD` (also
  `mongo`, `mongodump`, `mongorestore`, …);
- `user:password@` and `:password@` in URLs (`postgres://admin:***@db/app`,
  `redis://:***@host:6379`);
- `Authorization:`, `Proxy-Authorization:`, `X-Api-Key:`, `apikey:`,
  `api-key:`, `X-Access-Token:`, `Private-Token:` headers, and `curl -u
  user:password`;
- `docker login -p PASSWORD` / `--password PASSWORD` (also `podman`,
  `nerdctl`, `buildah`, `skopeo`, `helm registry login`);
- `aws configure set aws_secret_access_key VALUE` and `aws_session_token
  VALUE`;
- `npm config set //registry/:_authToken VALUE` (also `_auth`, `_password`,
  `pnpm`, and `yarn config set npmAuthToken VALUE`);
- JSON Web Tokens (`eyJ….eyJ….…`) anywhere in the command;
- AWS access key ids (`AKIA…`, `ASIA…`), GitHub tokens (`ghp_…`,
  `github_pat_…`), GitLab tokens (`glpat-…`), npm tokens (`npm_…`), Slack
  tokens (`xoxb-…`),
  Stripe secret and restricted keys (`sk_live_…`, `rk_live_…`, and the
  `_test_` ones) and `sk-…` API keys.

The record then has `command_redacted: true`, and `command_sha256` is the hash
of the original, unredacted command. Redaction is a best-effort safety net: a
secret passed as a plain positional argument (`tool login s3cr3t`) cannot be
recognised. The banner and the agent hook response are not redacted; only
the stored record is.

## Retention and size

- When `audit.log` reaches 10 MiB it is rotated: `audit.log` becomes
  `audit.log.1`, `.1` becomes `.2`, and so on. The newest `audit_max_files`
  rotated files are kept (default `5`, at most `100`), so the log uses at most
  about `(audit_max_files + 1) × 10 MiB`. `audit_max_files: 0` is never used
  (it would delete the history on every rotation): the default is used
  instead and every command, `status` and `config show` print a warning.
  The rest of the settings file still applies.
- A stored command is capped at 8 KiB (cut at a character boundary, ending in
  `…[truncated]`), with `command_bytes` and `command_sha256` of the full
  command, so a few huge commands cannot flush the history.

## Safety properties

- Each record is written with a single `write()` on an append-only file
  descriptor under an exclusive lock, so concurrent shells and agents never
  interleave lines, also across a rotation.
- The file is created with mode `0600` (owner only); wider permissions are
  tightened on the next write.
- `user` comes from the uid, so `USER=someone-else` does not change who the
  record names (the value is kept in `env_user`).
- The log is local. There is no forwarding to a central collector yet; ship
  the JSON Lines file with your log agent if you need a fleet view.
