# Configuration

## Where settings live

| Platform | Settings file |
| --- | --- |
| Linux | `~/.config/shellfirm/settings.yaml` (or `$XDG_CONFIG_HOME/shellfirm/settings.yaml`) |
| macOS | `~/Library/Application Support/shellfirm/settings.yaml` |
| Windows | `%APPDATA%\shellfirm\settings.yaml` |

The same directory holds `checks/` (your custom checks), `audit.log` (and its
rotated `audit.log.N` files), up to three `settings.yaml.bak.<timestamp>`
backups written by `config reset`, and `.settings.lock`: an empty lock file
that every `shellfirm config …` write holds, so parallel setters (provisioning
scripts, two terminals) never lose each other's changes. Leave it in place.
`shellfirm status` prints the exact paths.

To use another directory, pass `--config-dir DIR` (`check`, `status`, `config`,
`audit`, `mcp`, the agent hooks) or set `SHELLFIRM_CONFIG_DIR=DIR` for every command; the flag wins
over the variable, which wins over the default location. Either must name an
existing directory (a missing one is a usage error, exit 2). The agent hooks
(`check --hook …`) and `shellfirm mcp` never stop on a stale variable: with an
invalid `SHELLFIRM_CONFIG_DIR` they use the pinned `--config-dir` (or the
default location) and print a warning on stderr, so the agent still gets a
decision. The shell hooks (`shellfirm pre-command`) behave the same way: a
stale or mistyped variable never locks your terminal. Every line is still
checked, against the default location, and the hook prints one line,
`shellfirm: warning: SHELLFIRM_CONFIG_DIR=DIR: …; using the default
configuration directory (fix: `unset SHELLFIRM_CONFIG_DIR`, or create that
directory)`, once per session and again whenever the variable changes.
`unset SHELLFIRM_CONFIG_DIR` and `export SHELLFIRM_CONFIG_DIR=…` always run.

The file is optional and **sparse**: any key you leave out uses the built-in
default, so a default that changes in a later release (a new check group,
for example) reaches you automatically. `shellfirm` only writes what you
change, at every nesting level:

- `shellfirm config groups --disable heroku` writes `disabled_groups: [heroku]`
  and leaves `enabled_groups` out of the file; `--enable heroku` removes it
  again. The TUI's Groups tab does the same.
- Adding a protected branch writes `context.protected_branches`, not the
  whole `context` block. A list is always written whole once you change it:
  `config context branches --add develop` writes the default branches plus
  `develop`.
- A key that goes back to its default is removed rather than left behind
  as `[]`, `{}`, `null` or a copy of today's default list (`config ignore
  --remove` of the last id, `config groups --enable` of the last disabled
  group, `config severity all`, removing the branch or k8s pattern you
  added). An empty `context:` disappears too, so a later release's new
  defaults reach you. `production_env_vars` is written whole when it differs
  from the default (adding `STAGE=prod` keeps `NODE_ENV`, ...).
- `config llm` writes an `llm:` section with only the fields that differ
  from the LLM defaults (`config llm --timeout 7000` writes
  `llm: {timeout_ms: 7000}`), so the default model is not pinned in your
  file. The section itself is what turns LLM analysis on, so with only
  default values it is written as `llm: {provider: …}`, never `llm: {}`.
- Lowering a challenge below its built-in default (`config context
  escalation --critical Enter`, `config escalation severity …`) is accepted
  with a warning; group and check overrides only ever raise the challenge,
  so `Enter` there warns that it changes nothing.
- Keys shellfirm does not know are kept (and reported as unknown).
- Full-line comments are kept: the comment block at the top of the file and
  the comment lines directly above each top-level key. Comments at the end of
  a line (`challenge: Math  # team default`) are dropped, and flow lists
  (`[a, b]`) are rewritten as block lists.

shellfirm never rewrites the file on its own; only `shellfirm config …`, the
TUI and `config edit` change it. Values are case-sensitive (`challenge: Yes`,
not `yes`); a wrong case is reported with the valid values.

## When the file is invalid

- Every command that reads settings reports the problem on stderr, naming the
  file and the line, e.g.
  `invalid settings file …/settings.yaml: challenge: unknown variant 'Banana', expected one of 'Math', 'Enter', 'Yes' at line 1 column 12`.
- The shell hook (`pre-command`), `check`, `mcp` and `wrap` keep working: they
  print a one-line warning and use the built-in default **only for the
  invalid keys** (valid keys such as your deny list still apply). The file is
  not modified.
- `shellfirm config <setter>` and the TUI refuse to change an invalid file.
  Fix it with `shellfirm config edit`, or start over with
  `shellfirm config reset` (the old file is backed up first).
- `shellfirm status` shows `INVALID: <reason>` next to the settings file.

A file that parses but contains something that has no effect is applied, and
every command warns about it; `status` then says `valid, with N warning(s)`
and lists them:

- unknown keys, including nested ones (`agent.auto_deny_severty`), with a
  "did you mean";
- unknown check ids in `ignores_patterns_ids`, `deny_patterns_ids` and
  `check_escalation`, and unknown groups in `enabled_groups`,
  `disabled_groups` and `group_escalation` (a typo in a deny list protects
  nobody). The CLI setters and the TUI reject unknown ids outright, and
  `config edit` refuses to save them;
- an id that is in both `ignores_patterns_ids` and `deny_patterns_ids`:
  **the deny wins**, the command stays blocked.

## Settings reference

| Key | Description | Values / default |
| --- | --- | --- |
| `challenge` | How you confirm a risky command | `Math` (default), `Enter`, `Yes` |
| `min_severity` | Only prompt for checks at or above this severity (lower ones are logged as `Skipped`) | `null` (all, default), `Info`, `Low`, `Medium`, `High`, `Critical` |
| `enabled_groups` | Check groups to use | all 23 built-in groups (including `shell`: `curl … \| bash` and friends) |
| `disabled_groups` | Groups to turn off; wins over `enabled_groups` | `[]` |
| `ignores_patterns_ids` | Check ids that never prompt (a deny of the same id, or a policy that enforces it, wins) | `[]` |
| `deny_patterns_ids` | Check ids that are always blocked | `[]` |
| `severity_escalation` | Minimum challenge per severity (`enabled`, `critical`, `high`, `medium`, `low`, `info`) | enabled |
| `group_escalation` | Minimum challenge per group, e.g. `{kubernetes: Yes}` | `{}` |
| `check_escalation` | Minimum challenge per check id, e.g. `{git:force_push: Yes}` | `{}` |
| `context` | Context-aware protection: `protected_branches`, `production_k8s_patterns`, `production_env_vars`, `sensitive_paths`, `escalation.elevated`, `escalation.critical` (see [Context](#context)) | see `shellfirm config show` |
| `audit_enabled` | Write the audit log | `true` |
| `audit_max_files` | Rotated audit files to keep (`audit.log.1` … `.N`, 10 MiB each); `0` is never used (the default applies and a warning is shown), values above 100 are capped. See [audit.md](audit.md) | `5` |
| `blast_radius` | Older switch for the impact measurement: `false` still turns it off, but `blast_radius_budget_ms` is the one to use (`0` = off); `shellfirm config impact-budget <ms>` with a value above 0 clears `blast_radius: false`, and `config show` names it when it is set | `true` |
| `blast_radius_budget_ms` | Total time, in milliseconds, shellfirm may spend measuring one command's impact before the prompt (`find` / `du` per path, `git`, `docker` and `kubectl` queries together). It is **one budget per command**: `check` (text and JSON), the agent hooks and MCP evaluate a command up to three times, and the later evaluations reuse the first answers, so the wait is one budget and every view shows the same text. The context lookups (git branch, kube context; at most 200–300 ms each) and the check for uncommitted work in a deleted folder (one `git status`, 50–200 ms at most; when it cannot finish the delete stays High) run first and count against it. A subprocess gets at most the time that is left; when it runs out the subprocess is stopped (with everything it started) and the banner says so: a stopped file count is a lower bound, `Deletes directory build with more than 120,000 files (stopped counting)` (with the size missing too: `(stopped counting; size not computed: took too long)`); a missing size is `(size not computed: took too long)`; a step that could not start because the budget was already spent is `(…: skipped, no time left)` or `Impact not measured (skipped: no time left)`. `0` skips the measurement. The largest value used is `5000`: a larger one is used as 5000 with a warning (exit 78 under `check --strict`), so agent hooks stay far from their 30 s timeout. `check --config-dir DIR` uses DIR's value. In a terminal, a measurement that takes more than 200 ms shows a transient `shellfirm: checking impact… (Ctrl-C cancels)` line, erased before the banner (not shown under `TERM=dumb`); Ctrl-C there cancels the command at once (the running `find` / `du` / `git` is stopped) and writes a `cancelled` audit record. Reading the SQL files a command runs (`psql -f F`, `sqlcmd -i F`, …) shares this budget (at least 400 ms): a file that is not read in time is reported as `database:sql_from_file` (Medium, `took too long to check`). Set it with `shellfirm config impact-budget <ms>` (a bad value exits 2; setting `400` removes the key). Every git query shellfirm runs uses `--no-optional-locks`, so a query stopped by the budget never leaves `.git/index.lock` behind. | `400` |
| `approved_notice` | After you pass a challenge in a terminal, print one dim line so a slow command does not look hung: `✓ approved — running: helm uninstall web` (plain ASCII when the locale is not UTF-8: `ok: approved, running: helm uninstall web`; no colour with `NO_COLOR`). It goes to the terminal (`/dev/tty`, else stderr), never to the command's stdout. The line fits the real terminal width: a long command is cut in the middle (`kubectl get ns prod-x…; kubectl delete ns prod`) so its end stays visible, and `…` appears only when something was cut; a multi-line command shows its first line and `(+N lines)`. Never printed by the agent hooks or MCP. Set it with `shellfirm config approved-notice on\|off` or in `shellfirm config` → General → Behavior. | `true` |
| `agent` | AI-agent mode: `auto_deny_severity`, `require_human_approval`, `context_escalation`, `self_protection`, `allow_safe`, `llm_review`, and per-mode `challenge` / `min_severity` / `severity_escalation` overrides (`inherit` = use the global value). See [Agent protection rules](#agent-protection-rules) | `auto_deny_severity: High` |
| `wrappers` | `shellfirm wrap` settings: `tools.<program>.delimiter`, `tools.<program>.check_groups`, `challenge`, `min_severity` | |
| `llm` | Experimental LLM settings: `provider` (`anthropic`, `openai-compatible`), `model`, `base_url`, `timeout_ms`, `max_tokens`. Used only for AI-agent review when `agent.llm_review` is enabled. | not set |

Example:

```yaml
challenge: Yes
min_severity: Medium
disabled_groups: [heroku]
deny_patterns_ids: [git:force_push]
check_escalation:
  kubernetes:delete_namespace: Yes
context:
  protected_branches: [main, master, "release/*"]
approved_notice: false          # quiet setups: no "approved, running" line
blast_radius_budget_ms: 250     # wait at most 0.25 s for the impact line
```

### Agent protection rules

In AI-agent mode (hooks, MCP) shellfirm adds built-in `shellfirm-self:*`
rules on top of the checks. They are not checks: groups, `min_severity` and
most ignores do not affect them, and they make a decision at least `ask`.

- **Self-protection** (`agent.self_protection`, default `true`): changes to
  shellfirm's settings, policies, audit log or binary, to agent settings and
  hook files, to shell startup files (with a file tool, or a shell command
  that replaces, moves over, links over, deletes or appends to one: `cp f
  ~/.bashrc`, `rm ~/.zshrc`, `echo … >> ~/.zshrc`, `tee -a`; reading one is
  fine), and to agent instruction files
  (`AGENTS.md`, `CLAUDE.md`, `GEMINI.md`, `.cursorrules`, `.cursor/rules/*`,
  `.github/copilot-instructions.md`, `.claude/commands/*`, `.claude/agents/*`,
  ...). `self_protection: false` turns all of these off.
- **Persistence** (always on, also with `self_protection: false`): files and
  commands that grant access or run code later — `~/.ssh/authorized_keys`,
  sudoers, cron and systemd/launchd units, git hooks (also of submodules),
  `.git/config`, `~/.gitconfig` / `~/.config/git/config`, `crontab FILE`,
  `systemctl … enable`, and `git config` settings that run a program
  (`core.pager`, `core.editor`, `core.sshCommand`, `alias.x '!…'`, ...).
- **Agent instruction edits** (`shellfirm-self:agent_instructions_edit`) are
  everyday work, so this one rule can be switched off by id:
  `shellfirm config ignore shellfirm-self:agent_instructions_edit`. Other
  `shellfirm-self:*` ids cannot be ignored (`config ignore` says, per id,
  whether it is controlled by `agent.self_protection` or always on). A team
  policy can enforce this rule over a personal ignore by listing it in
  `overrides` (it keeps asking) or `deny` (agent shell commands that edit an
  instruction file are denied). Cursor asks for these edits
  instead of blocking them; where Cursor does not enforce `ask` for
  `preToolUse` the edit goes ahead, while edits of shellfirm, agent-settings
  and persistence files are denied in Cursor (it cannot ask for them).

## Context

The challenge is raised (never lowered) by where a command runs:

- **elevated** (`context.escalation.elevated`, default `Math`): an SSH
  session, or git / kubectl did not answer in time (so the branch or k8s
  context is unknown);
- **critical** (`context.escalation.critical`, default `Yes`): running as
  root (or with `sudo`), a production k8s context, namespace, AWS profile,
  terraform workspace, gcloud project or Azure subscription
  (`production_k8s_patterns`), a production environment variable
  (`production_env_vars`, e.g. `APP_ENV=production`), a command that deletes
  or overwrites a `sensitive_paths` entry, and a command that **pushes to,
  rewrites or deletes a protected branch** (`git push -f origin main`,
  `git reset --hard HEAD~1` on `main`, `git branch -D main`). A plain
  `git reset --hard` (back to the current commit) does not rewrite the
  branch and keeps its normal challenge.

Being *on* a protected branch does not make every command critical: local
work that does not change the branch (`git cherry-pick`, `git stash clear`,
`rm -rf build`) keeps its normal challenge. `shellfirm status` shows the
level for ordinary commands and notes the protected branch separately.

```bash
shellfirm config context branches --add develop     # --remove, --list (the default)
shellfirm config context k8s --add prod-eu
shellfirm config context paths --add ~/secrets       # globs allowed
shellfirm config context env --add APP_ENV=production   # --remove APP_ENV (or APP_ENV=production, as --list prints it)
shellfirm config context escalation --elevated Math --critical Yes
```

## CLI

Every command prints a message on error, including the valid values.

```bash
shellfirm config show                      # current settings, warnings, and whether a policy applies
shellfirm config challenge Yes             # Math | Enter | Yes
shellfirm config severity High             # all | Info | Low | Medium | High | Critical
shellfirm config approved-notice off       # on | off: the line after a passed challenge
shellfirm config impact-budget 1000        # ms for the impact measurement (0 = off, at most 5000)
shellfirm config groups                    # list every group and whether it is active
shellfirm config groups --enable shell --disable heroku   # built-in or custom groups (sparse write)
shellfirm config groups --pick             # interactive checklist (needs a terminal)
shellfirm config ignore git:reset          # ids are validated (built-in or custom)
shellfirm config ignore --remove git:reset
shellfirm config ignore --list
shellfirm config deny git:force_push
shellfirm config escalation check git:force_push Yes
shellfirm config escalation group kubernetes Yes
shellfirm config context branches --add develop
shellfirm config llm --provider anthropic --timeout 5000
shellfirm config edit                      # $VISUAL / $EDITOR (arguments allowed, e.g. "code -w")
shellfirm config reset                     # asks, backs up, then runs the setup questions
shellfirm config reset --yes               # non-interactive: back up and reset to defaults
shellfirm config                           # interactive TUI (needs a terminal)
```

`config edit` opens a temporary copy. If the result does not parse, uses an
invalid value, contains an unknown key, or names an unknown check id or
group, nothing is applied, the original file is left unchanged and the path
of your edited copy is printed (only the latest rejected copy is kept).

`config reset` writes `settings.yaml.bak.<timestamp>` next to the settings
file before changing anything; only the three newest backups are kept, and a
file that only holds the header `reset` writes is not backed up again.
Aborting a question (Esc / Ctrl-C) leaves the file untouched.

## Custom checks

Put YAML files in the `checks/` directory next to `settings.yaml`. Each file
is a list of checks:

```yaml
- id: team:deploy_prod          # must be unique and must not reuse a built-in id
  from: team                    # the group; enable/disable it like any group
  test: "deploy\\s+--env\\s+prod"
  description: "Deploys to production."
  severity: High                # Info | Low | Medium (default) | High | Critical
  challenge: Yes                # optional: the minimum challenge for this check
  alternative: "deploy --env staging"
  alternative_info: "Try it on staging first."
  filters:                      # optional extra conditions
    - type: NotMatches          # token-aware: skip `--dry-run` runs
      value: '\s--dry-run(?:\s|=|$)'
```

- Filter types: `PathExists` (capture-group number), `Contains`,
  `NotContains` (substring), `Matches`, `NotMatches` (regex on the normalized
  command). All filters must pass. The regex and filter rules are the same as
  for built-in checks, see [add-new-patterns.md](add-new-patterns.md#how-test-is-matched).
- A file that cannot be parsed (bad YAML, invalid regex, wrong type) is
  skipped with a warning that names the file; the other files still load.
- A check whose id is already used by a built-in check, or by an earlier
  custom check, is skipped with a warning.
- An unknown key in a check (`severty:`) and a `PathExists` capture group the
  regex does not have are reported as warnings (such a check never matches).
- Files directly in `checks/` are loaded (`*.yaml` and `*.yml`); files in
  subdirectories are not, and a subdirectory that holds check files is
  reported with a warning.
- Ids are `group:name`. An id with spaces, control, bidi or zero-width
  characters is skipped with a warning (shown escaped, e.g.
  `mine:b\u{202e}x`); other ids that are not lowercase `group:snake_case`
  load with a warning. An empty or blank `alternative` / `alternative_info`
  is ignored with a warning. `shellfirm check --strict` exits 78 for any of
  these.
- `challenge:` is honoured as a floor (the challenge is never weaker than it).
- Groups of custom checks are active unless you disable them
  (`shellfirm config groups --disable team`).
- `shellfirm status` shows how many custom checks loaded and any warnings.

## Project policies

A `.shellfirm.yaml` in a repository adds rules for everyone working in it, and
your personal settings cannot weaken them. See
[team-policies.md](team-policies.md).
