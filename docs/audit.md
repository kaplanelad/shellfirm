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
shellfirm audit show --since 7d               # 30m, 12h, 7d, 2w, 2026-01-31, 2026-01-31T10:00:00Z
shellfirm audit show --outcome denied         # allowed | denied | skipped | cancelled | asked | no-terminal
shellfirm audit show --severity high          # at or above
shellfirm audit show --limit 20               # last 20
shellfirm audit show --format json            # JSON array (or jsonl: one record per line)
shellfirm audit show --all-records            # do not collapse old pre-challenge/final pairs
```

`audit show` reads every rotated generation (`audit.log.N` … `audit.log.1`)
as well as `audit.log`. Malformed lines (invalid UTF-8, not JSON, missing
timestamp or outcome) are skipped with a warning that counts them.

## Clearing

`shellfirm audit clear` deletes `audit.log` and every rotated file. It asks
for confirmation and refuses to run without a terminal unless `--yes` is
passed.

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
| `agent_name`, `agent_session_id`, `tool_use_id` | Set for AI-agent commands (`tool_use_id` is Claude Code's id for the tool call; `audit show` keeps it in every format) |
| `user` | Account name of the real uid (from the password database, not `$USER`) |
| `uid` | Numeric real uid (Unix) |
| `env_user` | `$USER` / `$LOGNAME`, only when it differs from `user` |
| `hostname`, `cwd`, `git_repo`, `git_branch` | Where it ran. `git_repo` / `git_branch` are the repository the command works in: another one when it names one (`git -C ../infra …`, `cd ../infra && …`), otherwise the one of `cwd` |

### deny_reason values

The same values are used for the shell hook and for AI-agent hooks (Claude
Code, Cursor, MCP); `check --format json` reports `deny_reason` and
`policy_sources` for a `deny` decision too.

| Value | Outcome | Meaning |
| --- | --- | --- |
| `policy_deny` | `Denied` | A matched check is in an org or project policy `deny` list; `policy_sources` names the file(s) |
| `user_deny` | `Denied` | A matched check is in your personal `deny_patterns_ids` |
| `agent_auto_deny` | `Denied` | AI agent: the severity (after context escalation) is at or above `agent.auto_deny_severity`, or a Cursor file edit that would need a human (Cursor cannot ask for file edits) |
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
- `Authorization:`, `Proxy-Authorization:`, `X-Api-Key:`, `Private-Token:`
  headers, and `curl -u user:password`;
- AWS access key ids (`AKIA…`, `ASIA…`), GitHub tokens (`ghp_…`,
  `github_pat_…`), Slack tokens (`xoxb-…`) and `sk-…` API keys.

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
