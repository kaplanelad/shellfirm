## Unreleased

## 0.4.0

The 0.4.0 release (the crate version is set when it is published). It is a
large release: project and org policies are enforced, the AI-agent hooks cover
more tools and fail closed, the parser follows far more shell forms, and every
command reports problems instead of hiding them. Read
[Upgrading from 0.3.10](#upgrading-from-0310) first.

### Upgrading from 0.3.10

1. **Restart your shells.** The shell hooks changed (`HOOK_VERSION` 13). A
   new shell picks them up automatically (`eval "$(shellfirm init <shell>)"`);
   in a shell that is already open run `exec $SHELL`. Re-running
   `shellfirm init` is safe (it changes nothing that is already set up). If
   you only use the shell hook (no AI agent, no project policy), this is all
   you need to do. In zsh without `setopt interactivecomments` (zsh's
   default; oh-my-zsh turns it on) and in bash with `shopt -u
   interactive_comments`, `#` in a typed line is not a comment but an
   argument, and it is now checked as one: a line with a `#` may be prompted.
2. **Re-run `shellfirm connect <agent>` for each agent you connected**
   (`claude-code`, `cursor`, …; Cursor gains a `preToolUse` hook only this
   way). It upgrades the hook in place and writes a backup first. It adds the
   `PowerShell|Monitor` and `Write|Edit|MultiEdit|NotebookEdit` matchers,
   `"timeout": 30` and `"onFailure": "block"` (fail closed). The 0.3.10 hook
   line keeps working until you do, and `shellfirm status` reports it as a
   legacy hook. Restart running agent sessions afterwards. `status` shows
   `fail-closed no` for Cursor, and that is expected: Cursor's `failClosed`
   treats shellfirm's silent answer for a safe command as a failure and would
   block every command, so `connect cursor` leaves it off (and removes it from
   older shellfirm hooks). If the Cursor hook itself fails or times out,
   Cursor runs the command, as Claude Code does for a hook connected with
   `--no-fail-closed` (for Claude Code before 2.1.295).
3. **`shellfirm check` prints its report on stdout** (it used to print on
   stderr). Scripts that read the text from stderr should read stdout, or use
   `--format json`.
4. **New exit codes.**
   - `check` and `policy validate`: 74 when the result cannot be written (a
     full disk).
   - `check --strict`: 78 when the settings, custom checks or an applicable
     policy have errors or warnings. It replaces the decision's 10 / 11.
   - `pre-command`: 3 after a passed challenge, only when the caller sets
     `SHELLFIRM_SIGNAL_PROMPTED=1`. The shell hooks set it for each call
     (bash, zsh, fish, elvish) and accept exit 3 in every shell; do not export
     `SHELLFIRM_SIGNAL_PROMPTED` in your shell profile or environment.
   - `pre-command`: 74 when there is no terminal to ask on (blocked, fail
     closed).
   - Usage errors in `config` setters (`config impact-budget abc`, `config
     challenge Foo`, an unknown check id) exit 2, like every other usage
     error.
   - The full table for `check`: [Exit codes](docs/check.md#exit-codes).
5. **New settings and defaults** (the settings file stays sparse; no
   migration is needed):
   - `approved_notice` (default on) prints `✓ approved — running: <command>`
     after a passed challenge. Change it with `shellfirm config
     approved-notice on|off`.
   - `blast_radius_budget_ms` (default 400, at most 5000) is the total time
     spent measuring a command's impact before the prompt. Change it with
     `shellfirm config impact-budget <ms>`; `0` turns the measurement off (the
     one switch: the TUI toggle writes it too, and a non-zero budget clears an
     older `blast_radius: false`).
   - `shellfirm status` and `shellfirm config show` show both.
   - Before a slow measurement you may briefly see `shellfirm: checking
     impact… (Ctrl-C cancels)` (or `shellfirm: checking <file>…` while a SQL
     file is read); it is erased before the warning and never shown under
     `TERM=dumb`.
   - The `shell` check group (remote scripts: `curl … | bash`, a downloaded
     script run on the same line) is on by default: a `curl … | sh` install
     line now asks first. Download the script, read it, and run it in a
     separate command, or approve the prompt.
   - New rules prompt where 0.3.10 was silent, among them the database and
     platform rules (migration and ORM resets, MySQL `DELETE IGNORE`, `SET
     SQL_SAFE_UPDATES = 0`, Supabase, Firebase, Cloudflare D1 / KV / R2,
     Neon, PlanetScale, Turso and Railway deletes, SQL run through `heroku
     run` / `heroku pg:psql --command` / `fly ssh console -C`), `terraform
     apply <planfile>`, and disk tools on cloud device names (`mkfs -t xfs
     /dev/xvdf`). See Added and Fixed. A CI job that runs `check --fail-on
     high` may now fail on them.
   - A SQL file over about 6 MB given to a client (`psql -f F`) can be Medium
     (`database:sql_from_file`, `took too long to check`) at the default
     400 ms budget instead of its real severity. Raise the budget (`shellfirm
     config impact-budget 2000`) or run the client through `shellfirm wrap`.
6. **JSON consumers:** `check --format json` has `"allowed": true` only for
   `decision: allow` (key on `decision`), and `schema_version` is 2. The new
   keys `version`, `shell`, `not_applied` and `skipped_missing_paths` are
   additive. Audit records are `schema_version: 4` (new `version` field);
   older records stay readable.
7. **`shellfirm init --yes`** sets the recommended Balanced level
   (`min_severity: Medium`) when the settings do not choose a level;
   `init --uninstall` removes a settings file it wrote.
8. **Project and org policies:** your personal ignores
   (`ignores_patterns_ids`, `min_severity`, a lower challenge) no longer
   weaken a check a project or org policy enforces. Run `shellfirm policy
   validate` in each repository that has a `.shellfirm.yaml` (it shows
   problems and what the policy enforces).
9. **Verify** with `shellfirm doctor`. It reports a shell that still runs an
   old hook, and whether a new shell really routes commands through
   shellfirm.
10. **`shellfirm --version`** (and the `version` in JSON and audit records)
    says `0.3.10` until the 0.4.0 release is published; that is expected for
    a build from source before the release.

### Breaking

- Project policies (`.shellfirm.yaml`) and the new org policy
  (`/etc/shellfirm/policy.yaml`, plus `SHELLFIRM_ORG_POLICY`) are enforced.
  Their `deny`, `overrides` and `checks` can no longer be weakened by personal
  `ignores_patterns_ids`, `disabled_groups`, `enabled_groups` or
  `min_severity`. Nested policies merge up to the outermost repository root,
  and a command aimed at another repository (`git -C repo`, `cd repo && …`,
  path arguments) gets that repository's policy and `context`.
- `check --format json`: `allowed` is `true` only for `allow`;
  `schema_version: 2`.
- `check` text goes to stdout; `check --strict` exits 78;
  `SHELLFIRM_CONFIG_DIR` sets the configuration directory for every command
  (`--config-dir` wins; a missing directory is a usage error, exit 2).
- `connect claude-code` installs matcher `Bash|PowerShell|Monitor`, a
  file-tool group and `timeout` / `onFailure: block` (`--no-fail-closed`
  removes it for older Claude Code). `connect cursor` adds a `preToolUse`
  hook for `Write|Delete`.
- The `shell` group (remote scripts piped into a shell) is enabled by
  default.
- Audit records: one record per decision, written after the outcome; `user`
  comes from the real uid.

### Added

- **Around the challenge**
  - After a passed challenge in a terminal, one dim line:
    `✓ approved — running: helm uninstall web` (ASCII: `ok: approved,
    running: helm uninstall web`; no colour with `NO_COLOR`). A long command
    is cut in the middle to the real terminal width, so its end stays
    visible, and `…` appears only when something was cut. A multi-line
    command shows its first line and `(+N lines)`. The line goes to the
    terminal, never to stdout, and never appears in the agent hooks or MCP.
    `wrap` prints `✓ approved — sending to psql…`.
  - One time budget per command for the impact measurement (`find` / `du`
    per path, `git`, `docker`, `kubectl` queries), `blast_radius_budget_ms`.
    See Changed for how it is spent.
  - A transient `shellfirm: checking impact… (Ctrl-C cancels)` line when the
    measurement passes 200 ms in the shell hook (`shellfirm: checking
    <file>…` while a SQL file is read). It is erased before the banner and
    not shown under `TERM=dumb`. Ctrl-C there cancels the command at once
    (the running `find` / `du` / `git` is stopped, whatever the budget) and
    writes a `cancelled` audit record.
- **Commands**
  - `shellfirm policy show` and `policy validate` (`--strict`, `--format
    json`).
  - `shellfirm status` (`--format json`) and `shellfirm doctor`.
  - `shellfirm audit show` filters and formats; `audit clear --yes`.
  - `shellfirm config reset --yes`, `config edit`, `config approved-notice
    on|off`, `config impact-budget <ms>`, `config context …` and `config
    escalation …`.
  - `--config-dir DIR` for `status`, `config` and `audit` (as for `check`).
  - `check --strict`, `--fail-on`, `--list` (with policy checks),
    `--no-context`, and `--hook claude-code | cursor`.
- **Checks**: 472 built-in checks in 23 default groups (see the
  [check catalogue](docs/checks/README.md)). New among them:
  - Infrastructure: HashiCorp and backup tools, Kubernetes node and
    control-plane operations (`kubectl debug node/…`, `kubectl taint …
    :NoExecute`), `istioctl uninstall --purge`, `cilium uninstall`, `argocd
    app sync --prune`, `argocd app delete`, `argocd cluster rm`; Vault auth /
    policy / token removal, `vault kv delete` (Medium), `vault operator raft
    remove-peer`.
  - Databases: MySQL `DELETE IGNORE` / `LOW_PRIORITY` / `QUICK` and
    multi-table `DELETE t FROM t` without a filter, `SET SQL_SAFE_UPDATES =
    0`; migration and ORM resets (`dotnet ef database drop` / `update 0`,
    `mix ecto.rollback --all`, golang-migrate `down -all`, `goose down-to 0`,
    `flask db downgrade base`, Django `flush` and `migrate app zero`);
    `redis-cli --scan … | xargs redis-cli del`.
  - Hosting platforms: `supabase db reset` (Medium; Critical with
    `--linked` / `--db-url`), `supabase projects delete`, `firebase
    firestore:delete` (`--all-collections` Critical), `firebase
    database:remove` (`/` Critical), `firebase projects:delete`, `firebase
    hosting:disable`; Cloudflare `wrangler d1 delete`, `wrangler kv namespace
    delete`, `wrangler r2 bucket delete`, and SQL run with `wrangler d1
    execute --remote --command` (checked as SQL); `neonctl projects delete` /
    `branches delete`, `pscale database delete` / `branch delete`, `turso db
    destroy`, `railway down` / `railway delete` (in the `heroku` group, with
    the other hosting platforms).
  - Disks: `sgdisk --zap-all` / `-Z` / `-o`, `blkdiscard` and `mdadm
    --zero-superblock` (Critical).
  - git and GitHub: GitHub API deletes; `git push --prune` (High: deletes the
    remote branches that have no local counterpart, with `--all` every other
    branch); `git:force_push_unknown_target` (High) for a
    `--force-with-lease` push whose target is only known when the line runs.
  - Security: reverse shells and exfiltration, lock-outs, and a shell command
    from an AI agent that replaces, moves or links over, deletes or appends
    to a shell startup file (`cp f ~/.bashrc`, `mv f ~/.zshrc`, `install`,
    `ln -sf`, `rm ~/.bashrc`, `echo … >> ~/.zshrc`, `tee -a`, fish
    `config.fish`): `shellfirm-self:rc_file_edit` (High), like the
    file-editing tools and `sed -i` already were; reading one is not asked.
    `echo alias ls=rm >> ~/.bashrc` is named for what it is
    (`fs:startup_alias_replaces_command`, High).
  - `shell:nesting_too_deep` and `shell:function_depth_limit` (see Changed
    and Fixed).
- **SQL files**: `sqlcmd -i` files are read like the other clients' files:
  `!!cmd` / `:!! cmd` lines are checked as shell commands, `:r FILE`
  includes are followed and `GO` ends a batch. The scan stops at the first
  Critical statement (the banner says `scan stopped at the first Critical
  statement`) when no deny list or policy check could still match.
- **Agents**: self-protection for shellfirm's own and the agents' settings,
  persistence files, agent instruction files and the org policy; MCP tools
  take `cwd` and carry `version`.
- **Audit**: user, host, cwd, git repo / branch, `escalation_reasons`,
  `deny_reason` and `policy_sources`, secret redaction, an 8 KiB command cap
  with a hash, rotation (`audit_max_files`), and the shellfirm `version` in
  every record.

### Changed

- The impact measurement has one budget for the **whole command**: `check`
  (text and JSON), the agent hooks and MCP no longer spend it once per view.
  The second and third views reuse the first answers, so every view shows
  the same text. The context lookups (git branch, kube context) run first
  and count against it. `check --config-dir DIR` uses DIR's
  `blast_radius_budget_ms`, and audit rotation uses the `audit_max_files` of
  the log's own directory. Values above 5000 ms are used as 5000, with a
  warning.
- Impact wording: a count that stopped early is a stated lower bound,
  `Deletes 3 paths (a, b, c) with more than 120,000 files (stopped
  counting)`, for a single folder too (`more than N files (stopped counting;
  size not computed: took too long)`). When the budget was already spent,
  the text says `skipped, no time left` instead of `took too long`. Only the
  missing part is named (`file count not computed` when the size is known),
  exact counts read `41 files` (no `~`), and an empty file is `0 B`.
- Shell hooks follow function calls with a budget, check code run from
  prompt hooks, fall back to the default location for an invalid
  `SHELLFIRM_CONFIG_DIR`, and show the line as typed in the banner and the
  audit log. In bash and zsh the functions a line calls are sent with it as
  definitions, so the check binds each call's arguments itself (`shift`,
  `set --`, any depth). Every call, on the line or in a body, counts against
  one budget (64 functions, 64 KB, 16 KB for one body); past it the line
  gets the Medium `shell:function_depth_limit` challenge ("This calls a
  shell function too large or too deeply nested for the shell hook to read
  ahead") instead of a silent skip. A function over 16 KB that was loaded
  from a file (nvm, sdkman, conda) is treated like a program on PATH: its
  arguments are checked, its body is not read, so `nvm use 18` is not
  prompted.
- A recursive delete of a folder that holds uncommitted or untracked work
  (git cannot bring it back) is High, so a relaxed `min_severity` still
  asks; committed or regenerable folders (`src` with everything committed,
  `node_modules`, `build`) stay as they were.
- `kubectl rollout restart` is Medium on a non-production context, and
  `kubectl delete pod NAME` is Medium (its controller recreates it), not a
  High agent deny; `--force` / `--grace-period=0` stays High.
- Check regexes are anchored at the command name (`mygit push -f`, `xdocker
  system prune` no longer match; `sudo docker …` still does).
- `database:sql_from_file` names the real client in its hint (`shellfirm
  wrap sqlcmd …`), says `file too large to check (N MiB)` for a file over
  16 MiB, and `took too long to check` when reading the files outlasts the
  time budget (still Medium: it fails closed).
- Escalation reasons credit only the policy file whose `context` really
  applies (not an empty `version: 1` file, not an escalation below the
  default), with the same text whether the command runs inside the
  repository or is aimed at it (`git -C DIR`, `cd DIR && …`, path
  arguments). `policy show` lists a no-effect `context.escalation` value as a
  note, not as effective policy.
- `wrap sqlcmd` says `checking statements ending with ';' or a GO line on
  Enter`.
- `check` explains why a matched check does not apply (`not_applied`:
  ignored, below `min_severity`, path missing) and what the shell hook would
  do (`shell`).
- Settings setters write sparse YAML atomically under a lock, keep comments
  and unknown keys, and validate ids and groups with suggestions. An invalid
  settings file is never overwritten.
- Custom checks: an `alternative` that would itself trigger a built-in check
  at the same or a higher severity is reported (exit 78 under `check
  --strict`), like the built-in checks' own test. Ids, empty alternatives
  and subdirectories are validated.
- Output: one colour rule for the whole tool, an ASCII fallback under a
  non-UTF-8 locale, a closed pipe exits 0 and a full disk exits 74.
  `doctor`, `status` and `check` reports are word-wrapped to the terminal
  width with a hanging indent (no word is split across lines); piped or
  redirected output is not wrapped.
- TUI (`shellfirm config`): accessible focus markers, scrolling tabs, ASCII
  mode. The custom-check wizard wraps field errors inside the dialog, clears
  a stale save error after an edit, and hides the caret under a dialog. Cut
  text ends with `…`.
- Contributing: the library's prefilter tests skip hidden files in
  `tests/checks/` (macOS `._*` metadata) and name a file they cannot read;
  `build.rs` rejects an empty `test` or one that matches every command; the
  anchoring test also looks inside `(?i:…)` groups and does not accept `\b`
  before a command name; the CI rustfmt job is required; the catalogue is
  regenerated with `make catalogue` everywhere.
- The minimum supported Rust version is 1.88.

### Fixed

- **Parser: commands that slipped through or raised a false alarm**
  - zsh and fish forms, `${VAR:-default}`, `shift`, `bash -c '…' _ ARG`,
    `xargs` / `parallel`, scripts written and then run on the same line, and
    SQL files read by database clients.
  - A command's own assignments reach the child shell it starts (`D=~ sh -c
    'rm -rf "$D"'`); a `cd` is followed into `bash -c`; `trap -- 'rm -rf ~'
    EXIT`, zsh `function f g () {…}` and links to `/` or `~` (`ln -s / q &&
    rm -rf q/*`) are caught; a folder made earlier on the line (`mkdir -p
    build2 && rm -rf build2`) is not an unknown target; calling one small
    helper many times no longer hits the nesting limit.
  - `rm -rf ~/.*` (and `$HOME/.*`, `~/.??*`) is High, and Critical when
    credentials such as `~/.ssh` are there; `rm -rf "$HOME/$UNSET"` is
    Critical; moving a repository into `/tmp` is High. `rm -rf
    ~/.zcompdump*` is not "a top-level folder of your home", and clearing
    the zsh completion cache and the `compaudit` fix are not prompted.
  - In zsh without `interactivecomments` (its default) and bash without
    `interactive_comments`, `#` in a typed line is not a comment: `rm -rf
    nothere # victim` is checked with `victim` as a target.
  - Variables are tracked in one linear pass; long `cd` chains and
    variable-heavy scripts no longer hit the 30 s agent-hook timeout.
  - Deeply nested command substitutions (`$($($(…)))`, thousands of levels)
    are checked in linear time and never overflow the stack: past the
    nesting limit the line is reported as `shell:nesting_too_deep` without
    reading further down (5,000 levels in well under a second, 50,000 levels
    too). `check`,
    `pre-command`, the agent hooks and the MCP server all answer it, and the
    MCP server answers any request whose handling fails with a JSON-RPC
    error (`-32603`, no verdict, so not an allow) and keeps serving the
    session.
  - Privilege switches reveal their command: `sudo` with glued options
    (`sudo -iu postgres psql -c "DROP DATABASE app"`, `-Hu`, `-su`, `-nu`,
    `-Eu`, `-kiu`, `-uUSER`, `--user=USER`), `doas -u`, `run0 --user`, `sudo
    -R DIR` / `--chroot=DIR`, `sudo -D DIR` / `--chdir=DIR` (relative paths
    are under DIR: `sudo --chdir=/ rm -rf ./etc` is `/etc`), `setpriv
    --reuid=…`, `chpst -u …`, `machinectl shell user@ CMD`.
  - Commands behind a runner are checked like the runner's other commands:
    version managers (`nvm exec 18 …`, `nvm run`, `sdk env exec`, `asdf
    exec`, `pyenv exec`, `mise exec … --`, `rtx exec`, `fnm exec`, `volta
    run`, `conda run`, `direnv exec`), `doppler run --`, `op run --`,
    `infisical run --`, `dotenv --` / `dotenvx run --`, `bundle exec`,
    `railway run`, `devbox run`, `aws-vault exec … --`, `chronic`,
    `caffeinate`, `firejail`, `nix develop -c`, `nix-shell --run`, and any
    unknown program whose words after a lone `--` start with a risky command
    (`xyz -- rm -rf /`; not the paths after `git checkout --`).
  - npm package spellings run the package's command: `npx firebase-tools …`,
    `npx -y firebase-tools@latest …`, `npx supabase@latest …`, `pnpm dlx`,
    `bunx`, `npx netlify-cli …`, `npx vercel@latest …`.
  - Hosting-platform remote runs are read like `ssh host CMD`: `heroku run
    CMD` (one quoted shell line or several words, flags before or after),
    `heroku pg:psql -c / --command SQL`, `fly` / `flyctl ssh console -C /
    --command CMD` and `render ssh SERVICE -- CMD`. The command or SQL is
    checked, it is labelled `remote=heroku:APP` (`fly:APP`,
    `render:SERVICE`), and an app name with a production word (`shop-prod`)
    escalates like a production host.
  - Download-then-run: glued download flags (`curl -fsSLo i.sh … && bash
    i.sh`, `wget -qOi.sh`) are followed to the script that runs. Reading the
    script on the same line (`curl -o s.sh URL && cat s.sh && bash s.sh`,
    `head -1`, `cat s.sh > /dev/null`) no longer lifts the deny; the safe
    alternative is to download and read the script, then run it in a
    separate command. A checksum or signature check lifts the deny only when
    it gates the run: joined with `&&` (`curl -o i.sh URL && sha256sum -c
    i.sh.sha256 && bash i.sh`), or followed by `;` / a newline under `set
    -e`. After `;`, `||`, `|| true`, `&`, a pipe or inside a subshell the
    script runs even when the check fails, so the deny stays.
  - Disks: `mkfs` (any `mkfs.*`, `mke2fs`, `mkswap`) with any options before
    the device (`-F`, `-L data`, `-t xfs`), and `dd of=`, `fdisk`, `sfdisk`,
    `gdisk`, `parted` cover every block-device name: cloud and virtual disks
    (`xvdf`, `vdb`, `nvme1n1`), RAID (`md0`), device-mapper / LVM
    (`mapper/vg-data`, `vg0/data`) and stable names (`disk/by-id/…`).
    `mkfs.ext4 -n` (a dry run) and `dd … of=/dev/null` are not prompted.
  - `terraform apply <planfile>` (also `tofu`, `terragrunt`) applies a saved
    plan without asking, so it is High (Critical in a production workspace;
    an agent is denied), and a destroy plan written and applied on the same
    line (`terraform plan -destroy -out=p && terraform apply p`) is Critical.
    `-target ADDR` / `-var NAME=VALUE` given with a space are not a plan
    file. `terraform -chdir=$ENV` counts as an unknown workspace.
  - Docker: `docker image rm|remove -f`, `docker container rm|remove -f
    $(docker container ls -aq)`, `docker volume remove` and `docker network
    remove` match like `rmi -f`, `rm -f $(docker ps -aq)`, `volume rm` and
    `network rm`. `docker system prune` counts volumes only with
    `--volumes`, volume prune counts only unused volumes, and a `--filter` is
    named in the impact line (`Prunes up to 2 unused volumes (fewer:
    --filter keeps some of them)`).
  - Velero and Argo CD use the current kube context.
- **git**
  - Redirections are not git arguments (`git reset --hard 2>&1`).
  - Computed `git push` targets: a force-push to a target that is the
    current branch (`$(git branch --show-current)` unquoted, `$(git
    rev-parse --abbrev-ref HEAD)`, oh-my-zsh's `$(git_current_branch)` /
    `$(current_branch)` (`ggfl`, `ggpush`, `gpsup`), `-u`, `B=$(git branch
    --show-current); … $B`, `local b=…` with `"${b:=$1}"`, `echo
    feature/login | xargs -I{} git push …`) uses the real current branch:
    on a feature branch it is not a protected-branch push (shell or agent),
    and on a protected branch `--force-with-lease` / `--force-if-includes`
    escalates. A target that is only known when the line runs (`origin $B`
    with `B` unset, `$(cat file)`, `"$@"`) escalates only in a repository
    with protected branches; it is shown as `target=unknown` with the reason
    `push target unknown until the line runs (this repository has a
    protected branch)`, never as `main`. The protected-branch escalation
    applies only when the branch really moves.
  - `git push --dry-run -f` / `-n --force`, `git push --mirror -n` and `git
    push --delete … -n` are dry runs, not pushes.
  - `git restore FILE` / `git checkout -- FILE` on a file with no changes is
    not asked. The `git clean -e PATTERN` banner leaves the excluded files
    out.
  - Checking a command no longer leaves a stale `.git/index.lock` behind
    (after which `git add` / `commit` failed with "Another git process seems
    to be running"): every git query shellfirm runs uses
    `--no-optional-locks` (`GIT_OPTIONAL_LOCKS=0`), and a query stopped by
    the time budget gets `SIGTERM` (so git removes its lock files) before
    `SIGKILL`.
  - A recursive delete of a folder with uncommitted or untracked work stays
    High on huge folders: the check asks git about the folder as a whole
    (fast for a 250,000-file folder), counts inside the time budget, and
    when git cannot answer in time the delete stays High with "could not
    check for uncommitted files in time". The same rule covers `rm -rf
    DIR/*`, `cd DIR && rm -rf *`, `find DIR -delete` and moving the folder
    to `/tmp` (`fs:move_work_away`), and folder names that git prints quoted
    (non-ASCII names such as `日本`).
- **Shell hooks**
  - Functions: a function that runs by itself (`PROMPT_COMMAND`, a trap, a
    key binding, a zsh hook array) and is redefined later is checked. In
    bash this includes a function run by `trap f DEBUG`, `trap f ERR` or
    `trap f RETURN` (bash hides these traps inside functions; the hook reads
    them where they are visible). In zsh, `precmd_functions[1]=f`,
    `precmd_functions+=f` (and the other hook arrays) register `f` as a
    function that runs by itself: its body is checked, also when `f` is
    defined on the same line.
  - bash and zsh: a function whose name has non-ASCII letters (`nettoyé`,
    `ü`, `日本`) is followed like any other function, also when another
    function calls it; its body no longer runs unchecked.
  - bash: whatever a line adds to `PROMPT_COMMAND` is checked, however it is
    spelled: the usual `PROMPT_COMMAND="${PROMPT_COMMAND:+$PROMPT_COMMAND;
    }cmd"` idiom (with or without braces or quotes), `PROMPT_COMMAND[1]=cmd`,
    `+=(cmd)`. The new value is worked out exactly (a `${PROMPT_COMMAND:-cmd}`
    default that is not used is not challenged); a value with a command
    substitution is read as text.
  - bash and zsh: a function over 16 KB is treated as loaded from a file
    only when it really was: sourced by an absolute or relative path
    (`source ./nvm.sh`, `. nvm.sh`, also after a `cd`) or with `source <(cat
    FILE)` (zsh too). A function typed or pasted at the prompt, or loaded
    with `eval "$(cat FILE)"`, is challenged (`shell:function_depth_limit`),
    also when the current folder holds a file with the function's name.
  - Enter rebound by a plugin or by hand (fish `bind \r execute`, a raw zsh
    `zle-line-finish` set at every prompt) stays checked, and the zle hook
    runs once per line. bash: a plugin that rebinds Enter from
    `PROMPT_COMMAND`, also with bash-preexec, no longer turns checking off,
    and one whose `PROMPT_COMMAND` entry runs after shellfirm's (appended
    with `+=$'\n…'`, `;…`, as an array element, under bash-preexec, or a
    one-shot deferred loader) no longer leaves the first command of a new
    shell unchecked: a `bind` that changes Enter or Ctrl-J is wrapped again
    at once. An Enter macro that rewrites the line and ends with its own
    accept-line key has the rewritten line checked.
  - `shellfirm doctor` reports a command that ran unchecked in the session
    (`bypass_seen`), and its new-shell probe runs the first prompt's
    `PROMPT_COMMAND` and reports a first-command gap that remains (Enter
    rebound there with `builtin bind`).
  - bash and zsh: a typed `a && \` waits for the next line and is checked
    together with it (it was checked, and shown as approved, with the
    trailing backslash).
  - bash and zsh: lines typed or pasted (not as one bracketed paste) after a
    challenged line are no longer dropped silently. When the line runs, one
    line says how many were not run (bash: "run it again"; zsh: they are put
    back in the editor for the next prompt). When the line is cancelled or
    denied, they are kept for editing together with it, and the "kept for
    editing" hint is right for multi-line buffers: bash says Ctrl-U clears
    all the lines, zsh says Ctrl-C clears them all (Ctrl-U clears only one
    line there).
  - bash: after a passed challenge on a pasted block (several commands, a
    trailing newline, backslash continuation), the banner, the approved line
    and earlier commands' output (including errors) stay on screen, and the
    line is not printed again.
  - zsh: the approved line is dim again and follows the answer directly (no
    blank line). A multi-line paste, a wrapped line or a transient prompt no
    longer draws over the challenge line and the typed answer. With a
    transient prompt that collapses the line from `zle-line-init` (p10k-style
    recursive edit), a challenged line collapses too, above the banner; the
    banner, the answer and the approved line stay intact.
  - fish and elvish: no blank line after the approved line. fish: a line
    that wraps (a long line, or CJK characters at two columns each) no
    longer draws over the answered challenge. elvish option defaults run at
    definition time and are checked; the xonsh banner shows the line as
    typed.
  - fish, nushell, elvish, PowerShell, xonsh, Oils: an exported
    `SHELLFIRM_SIGNAL_PROMPTED=1` no longer blocks a command after a passed
    challenge.
  - The approved line, the banner and bash's reprinted line count display
    columns (CJK characters and emoji take two), so a wide command is cut
    and wrapped where the terminal really wraps. A multi-line command in the
    banner keeps its lines (indented under `Command:`, at most 8, then `(+N
    more lines)`) instead of a literal `\n`. The approved line collapses the
    indentation that a backslash-continued line keeps (`git reset --hard &&
    echo step2`), as the banner does; quoted text is kept as written.
  - `TERM=dumb` gets plain text only (no cursor codes, also in the banner);
    the stale `SHELLFIRM_CONFIG_DIR` warning appears once.
- **`wrap`**
  - sqlcmd `!!cmd`, `:!! cmd` and `:r FILE` are checked; dynamic SQL, `WITH
    … DELETE`, includes and the client's own arguments are checked; FIFOs and
    devices are never opened.
  - A temporary table the session created is not a Critical drop; a psql
    variable as the target of a destructive statement (`\gset` then
    `TRUNCATE :"t"`) is High; a large input file shows a transient
    `checking <file>…` line while it is scanned.
- **Commands and output**
  - `check --stdin`: UTF-8 text with a stray NUL or BOM is no longer read as
    UTF-16. Broken JSON is analysed as a command and never exits 0.
  - `config impact-budget` / `approved-notice` / `challenge` / `severity`
    and an unknown check id: a bad value exits 2 (usage error); `config
    impact-budget -1` gets the "from 0 (off) to 5000" message; setting the
    default removes the key from the settings file; `config impact-budget`
    with no value names the cap. The TUI "Blast radius" toggle writes the
    budget instead of a second key that overrode it, and `config show` names
    an older `blast_radius: false`.
  - `config context env --remove NAME=VALUE` removes the entry `--list`
    shows (the name alone works too); a different value is reported instead
    of a silent "not present".
  - Policy discovery reports each file once and cannot be escaped with
    `mkdir .git`.
  - Zero-width joiners and the emoji variation selector (U+200C, U+200D,
    U+FE0F) in a custom check's description and alternatives are kept
    (Persian and Indic spelling, emoji such as 👩‍💻) with no warning, in the
    banner, JSON, `check` text, `check --list` and `policy show`; ids still
    refuse them and are escaped strictly. A warning about removed characters
    names them (`U+202E`). `policy show` and `status` escape a bidi
    character in a policy error (`\u{202e}`) instead of removing it.
  - `--no-context` is documented as it works: it runs no external program,
    but root, environment variables, `.git/HEAD` and the kubeconfig file
    still count.
  - TUI crashes and drawing past borders at small sizes.

Releases 0.3.1 to 0.3.10 were published without changelog entries; see the
[GitHub releases](https://github.com/kaplanelad/shellfirm/releases) for them.

## 0.3.0

FEATURES:

- **Context-Aware Protection**: Automatically detects SSH sessions, root user, protected git branches, production Kubernetes contexts, and custom environment variables to escalate challenge difficulty based on risk level (Normal / Elevated / Critical).
- **Safe Alternative Suggestions**: Risky commands now show a safer alternative (e.g., `git push --force` suggests `--force-with-lease`). Alternatives are displayed in green alongside the challenge prompt.
- **Project-Level Policies**: Teams can commit a `.shellfirm.yaml` file to enforce additive-only safety rules (deny lists, challenge escalation overrides, branch-specific rules). Policies are discovered by walking up the directory tree.
- **Audit Trail**: Optional logging of every intercepted command, matched patterns, challenge type, outcome (ALLOWED/BLOCKED/DENIED), and context labels. Commands: `shellfirm audit show` and `shellfirm audit clear`.
- **Zero-Friction Setup**: New `shellfirm init <shell>` command prints the appropriate hook for eval. Auto-detects shell when no argument is given.
- **Custom Checks**: Load user-defined check YAMLs from `~/.shellfirm/checks/` at runtime.
- **Expanded Pattern Coverage**: New built-in checks for Docker, AWS CLI, GCP, Azure CLI, and database commands (DROP, TRUNCATE).
- **Policy CLI**: `shellfirm policy init` scaffolds a template; `shellfirm policy validate` checks syntax.

IMPROVEMENTS:

- **Compound Command Splitting**: Properly splits commands on `&&`, `||`, `|`, `;` operators, replacing the previous character-based splitting that could miss risky subcommands.
- **Dependency Injection Architecture**: All I/O abstracted through `Environment` and `Prompter` traits, enabling fully sandboxed testing with zero real system access.
- **Three-Tier Test Suite**: 102 tests across Pure Logic (Tier 1), Sandboxed Integration (Tier 2), and YAML-driven Decision Matrix (Tier 3).
- **Dependency Upgrades**: clap v3 -> v4, serde_yaml 0.8 -> 0.9, removed `lazy_static` (replaced with `std::sync::OnceLock`), `tempdir` -> `tempfile`, workspace resolver set to v2.
- **Fish Shell Fix**: `commandline -f execute` now only runs when `shellfirm pre-command` exits successfully, preventing commands from executing after cancellation.
- **Zsh Shell Fix**: Added binary existence check before invoking shellfirm.
- **Safer Unwraps**: Replaced unsafe `unwrap()` calls in filter matching with proper `match` + error logging.

BREAKING CHANGES:

- Settings file now includes `context` and `audit_enabled` fields (defaults applied automatically on upgrade).

## 0.2.6

IMPROVMENT

- Add git-strict file commands. [PR-112](https://github.com/kaplanelad/shellfirm/pull/112)
- Add more git commands. [PR-112](https://github.com/kaplanelad/shellfirm/pull/112)
- Add Terraform commands. [PR-113](https://github.com/kaplanelad/shellfirm/pull/113)
- Improve xtask. [PR-115](https://github.com/kaplanelad/shellfirm/pull/115)
- Improve docs. [PR-116](https://github.com/kaplanelad/shellfirm/pull/116)
- Allow ignoring patterns. [PR-117](https://github.com/kaplanelad/shellfirm/pull/117)

## 0.2.5

IMPROVMENT

- create unites for regex checks. [PR-107](https://github.com/kaplanelad/shellfirm/pull/107)
- Remove contains method. [PR-108](https://github.com/kaplanelad/shellfirm/pull/108)
- check is folder or directory exists before prompt a message. [PR-109](https://github.com/kaplanelad/shellfirm/pull/109)

BRAKING CHANGES

- Change shellfirm configuration. [PR-103](https://github.com/kaplanelad/shellfirm/pull/103)

## 0.2.4

IMPROVMENT

- Check test. [PR-98](https://github.com/kaplanelad/shellfirm/pull/98)
- Remove vergen package. [PR-100](https://github.com/kaplanelad/shellfirm/pull/100)
- add .rustfmt.toml file. [PR-](https://github.com/kaplanelad/shellfirm/pull/101)

## 0.2.3

IMPROVMENT

- Support $XDG_CONFIG_HOME. [PR-87](https://github.com/kaplanelad/shellfirm/pull/87)
- Add xtask.[PR-95](https://github.com/kaplanelad/shellfirm/pull/95)
- Interactive menu in config reset command. [PR-96](https://github.com/kaplanelad/shellfirm/pull/96)

DOCS

- More installation examples. [PR-](https://github.com/kaplanelad/shellfirm/pull/94)

## 0.2.2

IMPROVMENT

- Adds crontab -r as a risky command. [PR-81](https://github.com/kaplanelad/shellfirm/pull/81)
- Decouple test from base checks. [PR-84](https://github.com/kaplanelad/shellfirm/pull/84)
- Decouple test from app version snapshots. [PR-85](https://github.com/kaplanelad/shellfirm/pull/85)
- Improve config tests. [PR-86](https://github.com/kaplanelad/shellfirm/pull/86)

BUG FIX

- Change title for fish installation instructions. [PR-82](https://github.com/kaplanelad/shellfirm/pull/82)

## 0.2.1

IMPROVMENTS:

- Add heroku risky patterns.[PR-75](https://github.com/kaplanelad/shellfirm/pull/75)

DOCS

- Spell correction for README typo. [PR-79](https://github.com/kaplanelad/shellfirm/pull/79)
- docs/checks/fs - clarify descriptions. [PR-77](https://github.com/kaplanelad/shellfirm/pull/77)

## 0.2.0

IMPROVEMENTS:

- Replace / with path join. [PR-72](https://github.com/kaplanelad/shellfirm/pull/72)
- Bump crossbeam-utils from 0.8.5 to 0.8.10. [PR-74](https://github.com/kaplanelad/shellfirm/pull/74)
- Improve test. [PR-71](https://github.com/kaplanelad/shellfirm/pull/71)
- Text cleanup. [PR-66](https://github.com/kaplanelad/shellfirm/pull/66)

## 0.1.6

IMPROVMENTS

- change ~ to home dir in IsFileExists FILTER. [PR-63](https://github.com/kaplanelad/shellfirm/pull/63)
- Fish shell support. [PR-61](https://github.com/kaplanelad/shellfirm/pull/61)

## 0.1.5

IMPROVMENTS:

- Ading custom check - for check if file exsits before prompt a delete/flush verification. [PR-46](https://github.com/kaplanelad/shellfirm/pull/60)
- Support multiple commands in one line. [MR](https://github.com/kaplanelad/shellfirm/commit/c2c4d0633dcdac38b6b44d5351179f6e1421096d)

BUG

- Replace `~` char with home directory path. [PR-63](https://github.com/kaplanelad/shellfirm/pull/63)

## 0.1.4

IMPROVMENTS:

- Update config file from baseline checks when `shellfirm` binary update. [PR-46](https://github.com/kaplanelad/shellfirm/pull/46)
- Show single prompt verification when multiple pattern is detected. [PR-51](https://github.com/kaplanelad/shellfirm/pull/51)
- Improve `rm` pattern. [PR-53](https://github.com/kaplanelad/shellfirm/pull/53)
- Improve `chmod` pattern. [PR-54](https://github.com/kaplanelad/shellfirm/pull/54)
- Adding reboot and shutdown risky pattern. [PR-56](https://github.com/kaplanelad/shellfirm/pull/56)

BUG:

- Ignore text between quotes. [PR-57](https://github.com/kaplanelad/shellfirm/pull/57)

## 0.1.3

IMPROVEMENTS:

- Improve FS checks. [PR-30](https://github.com/kaplanelad/shellfirm/pull/30)
- Skip github actions on push (without PR) or on \*.md file/docs folder. [PR-33](https://github.com/kaplanelad/shellfirm/pull/33)
- Adding strict file sytem command. [PR-36](https://github.com/kaplanelad/shellfirm/pull/36)
- FS checks - adding to `rm`/`chmod` pattern the chars `.` and `./` as risky command. [PR-38](https://github.com/kaplanelad/shellfirm/pull/38)
- Adding a better error message when config file is invalid. [PR-42](https://github.com/kaplanelad/shellfirm/pull/42)
- Adding kubernetes strict risky patters. [PR-41](https://github.com/kaplanelad/shellfirm/pull/41)
- Allow to override deafult per pattern. [PR-43](https://github.com/kaplanelad/shellfirm/pull/43)

FEATURES:

- Promt message while using `config reset` + ading the option to backup file. [PR-31](https://github.com/kaplanelad/shellfirm/pull/31)

BREAKING CHANGES:

- Change `is` field in yaml file to `test`. [PR-32](https://github.com/kaplanelad/shellfirm/pull/32)

## 0.1.2 - (Jan 4, 2022)

IMPROVEMENTS:

- Mark history | sh/bash as risky command. [PR-27](https://github.com/kaplanelad/shellfirm/pull/27)
- Add 2 check for `fs` group. detect `chmod 777 /` and `find -delete`. [PR-28](https://github.com/kaplanelad/shellfirm/pull/28)

## 0.1.1 (Jan 3, 2022)

IMPROVEMENTS:

- Add application logger. [PR-24](https://github.com/kaplanelad/shellfirm/pull/24)

## 0.1.0 (Jan 2, 2022)

Initial release
