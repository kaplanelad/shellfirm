# `shellfirm check` reference

`shellfirm check` answers "what would shellfirm do with this command?" without
running it and without a challenge. `shellfirm check --help` has the short
version of this page.

```sh
shellfirm check -c 'git reset --hard'           # text report on stdout
shellfirm check -c 'git reset --hard' | less    # it pipes like any other output
shellfirm check -c '…' --format json            # versioned RiskAssessment
echo 'rm -rf build' | shellfirm check --stdin
shellfirm check --list -g git                   # the active checks of a group
```

## The text report

The report goes to **stdout**; warnings (`shellfirm: warning: …`) and errors
go to stderr. It lists:

- every matched check with its id and severity (`[git:reset] [HIGH] …`), its
  blast radius and the safe alternative for it;
- the context (`Context: Critical (branch=main, …)`), including the context
  of a repository the command targets (`git -C`, `cd repo &&`, path arguments,
  `bash -c`, `sudo`);
- **Not applied**: checks whose pattern matched but that do not apply here,
  with the reason:
  - `ignored by your settings (undo: shellfirm config ignore --remove <id>)`
  - `below your min_severity (<level>)`: the shell hook does not challenge it
  - `skipped, <path> does not exist`
- `Shell (you, in a terminal)`: the challenge the shell hook would show
  (computed exactly like `shellfirm pre-command`, including escalation and the
  target repository's policy), or "runs without a challenge";
- `AI agent (hooks, MCP)`: `allow`, `ask — <reason>` or `deny (blocked)`.

Colour (when stdout is a terminal and `NO_COLOR` is not set) marks the severity
labels and the agent decision; every state is also spelled out in words.

## Exit codes

Without `--exit-code` / `--fail-on`, `check` exits 0 whenever it could answer.

| Code | Meaning |
|------|---------|
| 0 | allowed: nothing risky matched (or below `--fail-on`) |
| 1 | error (empty, unreadable or malformed input, internal failure) |
| 2 | usage error (also an unknown group in `--list -g`, the same as `config groups`) |
| 10 | risky: needs human confirmation (decision `ask`) |
| 11 | blocked (decision `deny`) |
| 74 | the result could not be written to stdout (e.g. disk full) |
| 78 | `--strict`: the settings, custom checks or an applicable policy have errors or warnings (printed as `shellfirm: strict: …`); the output is unchanged. 78 replaces the decision's 10 / 11 (a deny with a configuration problem exits 78, with `exit_reason: strict`) |

**Changed in 0.4.0.** shellfirm 0.3.x `check --exit-code` exited **2** for a
risky command and printed its report on **stderr**. Now a risky command exits
**10** (`ask`) or **11** (`deny`), **2 is a usage error**, and the report is
on **stdout**. A script written for 0.3.x that tests for exit 2 (or reads
stderr) lets every risky command through. Test for any non-zero exit instead:

```sh
# 0.3.x gate (lets risky commands through on 0.4)
shellfirm check -c "$cmd" --exit-code; [ $? -eq 2 ] && exit 1
# 0.4 gate
shellfirm check -c "$cmd" --exit-code || exit 1      # ask or deny
shellfirm check -c "$cmd" --fail-on high || exit 1   # High and above (a deny always fails)
shellfirm check -c "$cmd" --format json | jq -e '.decision == "allow"' >/dev/null || exit 1
```

`--fail-on <severity>` exits non-zero only when the matched severity is at
least `<severity>`. Deny-listed commands (settings `deny_patterns_ids` or a
policy `deny`) always exit 11, whatever `--fail-on` says.

## Agent decisions

No match → `allow`; a match below `agent.auto_deny_severity` → `ask`; at or
above the threshold, or deny-listed → `deny` (`ask` when
`agent.require_human_approval` is true). A Critical production context (root,
a production k8s context, production env vars; a protected git branch alone
does not count) raises the matched severity by one level
(`agent.context_escalation`). Commands larger than 2 MiB are never `allow`
(rule `shellfirm:input_too_large`). When the command operates in another
repository (cd/pushd, `git -C`, path arguments), that repository's policy is
applied too and the strictest decision wins.

## JSON (`--format json`)

A versioned RiskAssessment: `"schema_version": 2`, `"version"` (the shellfirm
version), `"decision"` (`allow` | `ask` | `deny`), `"allowed"` (true only for
`allow`; in schema 1 it was also true for `ask`), `"matched_rules"`,
`"alternatives"` (each with the `"rule_id"` it belongs to) and `"context"`.
Also:

| Key | Content |
|-----|---------|
| `shell` | What the shell hook would do: `{"decision": "allow" \| "challenge" \| "deny", "challenge", "escalated_from", "escalation_reasons", "context": {"risk_level", "labels"}}` |
| `not_applied` | `[{"id", "reason": "ignored", "undo"}]`, `[{"id", "reason": "below_min_severity", "severity", "min_severity"}]`, `[{"id", "reason": "path_missing", "path"}]` |
| `skipped_missing_paths` | `[{"id", "path"}]`: one entry per check and missing path; each path is one argument; every part of the line is looked at. Always present (`[]` when none). |
| `exit_code`, `exit_reason` | Only when `--fail-on` (`below_fail_on`: the decision is ask/deny but below `--fail-on`, exit 0) or `--strict` (`strict`, exit 78) changed the exit code |
| `deny_reason`, `policy_sources` | For a deny: `policy_deny` \| `user_deny` \| `agent_auto_deny`, and the policy files |
| `decision_reason` | Why the decision is `ask` or `deny` (human-readable) |
| `denial_reason` | Deny only: the same text as `decision_reason`, kept for consumers of older versions; read `decision_reason` |
| `blast_radius_detail`, `blast_radius_scope` | The impact of the highest-scope match. It is measured within `blast_radius_budget_ms`, so on slow or big targets it can differ between runs; use `--no-context` for JSON that does not depend on the target's size (see "Configuration directory and context" for what it still reads) |

## `--stdin`

`--stdin` reads UTF-8, UTF-16 or UTF-32 (with a BOM; UTF-16 without a BOM
too, including non-ASCII text, when its byte order is clear from the NUL bytes
of its ASCII characters — at least 30% of the text — in which case the bytes
with the NULs dropped are checked as well). A UTF-16 byte-order mark in front
of UTF-8 text is dropped, and input with NUL bytes that is not valid
UTF-16/UTF-32 is refused (exit 1).

Input is JSON when it parses as JSON (`{"command": "…"}` or an agent hook
payload). Input that starts like a JSON object (`{"` or `{}`) but does not
parse (NDJSON, truncated JSON, `{}; rm -rf /`) is analysed as a shell command
and exits 1 if nothing matches. Brace groups (`{ …; }`) and tests (`[ … ]`)
are shell commands. Empty stdin exits 1.

## Hook modes

`--hook claude-code` / `--hook cursor` (or `--format claude-hook` /
`cursor-hook`) read the agent's hook payload from stdin and exit 0 with the
agent's own JSON protocol; `--exit-code` / `--fail-on` cannot be combined with
them. They fail closed: malformed input, an internal error or a crash yields a
deny decision, and if the decision cannot be written shellfirm exits 2 (which
blocks the tool call in Claude Code and Cursor). Safe commands produce no
output, so the agent's own permission prompts still apply.

- Claude Code Bash, PowerShell and Monitor commands (and any tool with a
  string `tool_input.command`) are analysed as shell commands.
- Write / Edit / MultiEdit / NotebookEdit calls on shellfirm, policy,
  agent-settings, hook or shell-startup files (symlinks followed) get an `ask`
  decision; writes under `context.sensitive_paths` are decided like
  `fs:sensitive_path`.
- Cursor `preToolUse` file edits that would be `ask` are denied (Cursor does
  not enforce ask there), except edits of agent instruction files (AGENTS.md,
  CLAUDE.md, `.cursor/rules/…`), which stay `ask` (ignore that rule with
  `shellfirm config ignore shellfirm-self:agent_instructions_edit`).
- An invalid project policy turns every command into at least `ask`.

The hook command line installed by shellfirm 0.3.10 and earlier
(`check --stdin --format json --exit-code`) is still recognised: with a
well-formed JSON hook payload on stdin it is treated as `--hook claude-code`;
a plain command or `{"command": "…"}` prints the RiskAssessment and uses the
exit codes above. Input it cannot use (broken JSON, empty or unreadable stdin)
exits 2 on that exact command line, which blocks the tool call when Claude
Code still runs it. Broken JSON that is analysed as a shell command also exits
2 there, whatever its decision (the RiskAssessment on stdout has the real
decision): 2 is the only exit code that blocks a Claude Code hook.

## Configuration directory and context

`--no-context` (or `SHELLFIRM_NO_CONTEXT=1`, also in hook modes) runs no
external programs (git, kubectl, du, find, docker, …): the blast radius is not
measured, and the context comes only from what can be read without running
anything: the effective user id (root), environment variables (SSH session,
production env vars), the branch in the repository's `.git/HEAD` file and the
current context in the kubeconfig file. So it still escalates on root, a
protected branch and a production kube context (a hook that sets it keeps
those protections). For JSON that does not depend on who runs it or where
(test fixtures, CI), run it as a normal user outside a git repository with a
fixed `--config-dir`. `--config-dir DIR` reads settings, custom checks and the audit
log from DIR instead of the default location; DIR must be an existing
directory (exit 2 otherwise; hook modes fall back to the default location).
`SHELLFIRM_CONFIG_DIR=DIR` has the same meaning for every command;
`--config-dir` wins over it, and in hook modes an invalid value falls back to
the default location (with a warning on stderr) instead of failing. With
`--config-dir`, the settings and custom-check warnings of that directory are
printed (as for the default location).
