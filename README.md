<p align="center">
<img src="https://github.com/kaplanelad/shellfirm/actions/workflows/ci.yaml/badge.svg"/>
<img src="https://github.com/kaplanelad/shellfirm/actions/workflows/release.yml/badge.svg"/>
</p>

# shellfirm

**Think before you execute.**

Humans make mistakes. AI agents make them faster. shellfirm intercepts dangerous shell commands before the damage is done.

```
% git push origin main --force
============ RISKY COMMAND DETECTED ============
Command: git push origin main --force
Check: git:force_push
Severity: HIGH
Blast radius: [PROJECT] — Force-pushes to origin/main
Context: branch=main, target=main
Description: This force-pushes and can overwrite remote history.
Alternative: git push --force-with-lease
(Checks that your local ref is up-to-date before force pushing, preventing accidental overwrites of others' work.)
Escalated to Yes (from Math): protected branch `main`

[HIGH] Type `yes` to continue (Esc or Ctrl-C to cancel)
```

This is real output, captured in zsh with default settings on the protected
`main` branch. (In bash the banner starts after a blank line. Off a protected branch the challenge is not escalated, and the banner
also tells you how to stop being asked: `shellfirm config ignore <id>`; that
hint is left out when the context raised the challenge.) The
exact output depends on the command, your settings and where you run it. The
challenge is a small math problem, pressing Enter, or typing `yes`: the higher
the severity and the riskier the context (protected branch, SSH, root,
production cluster), the stricter the challenge. Commands on a deny list are
blocked outright. Prefer no math? See [Accessibility](#accessibility).

---

## Features

- **472 built-in checks across 23 groups** (filesystem, git, Kubernetes, Terraform, Docker, AWS, GCP, Azure, Heroku, Fly.io, Vercel, Netlify, GitHub, npm, databases, Redis, MongoDB, network, remote-script execution such as `curl … | bash` (`shell`), credential exfiltration (`exfil`), …), all on by default. List them with `shellfirm check --list --all`; the generated [check catalogue](docs/checks/README.md) has the exact, current count.
- **Shell hooks for 8 shells** — Bash, Zsh, Fish, Elvish and Xonsh are tested end to end; Nushell is tested with a limitation (see [Shell support](#shell-support)); the PowerShell and Oils hooks are shipped but **not yet tested** end to end. `shellfirm status` shows which shells have the hook installed.
- **Context-aware escalation** — harder challenges when connected via SSH, running as root, on protected git branches, or in production Kubernetes clusters
- **Safer alternatives** — many checks suggest a safer command (e.g. `--force-with-lease`)
- **Severity levels** with configurable thresholds (`Critical`, `High`, `Medium`, `Low`, `Info`)
- **Team and org policies** — commit a `.shellfirm.yaml` with rules that everyone in the repo gets, or install an org-wide baseline at `/etc/shellfirm/policy.yaml`. Policies are additive and enforced: personal settings cannot weaken them. See [docs/team-policies.md](docs/team-policies.md).
- **Audit trail** — every intercepted command and decision is logged as JSON lines (user, host, repo, branch, outcome, and which policy denied it), with secrets redacted and bounded rotation, plus filters and a table view: `shellfirm audit show --since 7d --outcome denied`. See [docs/audit.md](docs/audit.md).
- **Blast radius** — shows what a command would affect (files, branches, resources), within one total time budget per command (`blast_radius_budget_ms`, default 400 ms, at most 5000; `shellfirm config impact-budget <ms>`) so the prompt never waits long; a count that runs out of time says `more than 120,000 files (stopped counting)`, a step it could not start says `skipped, no time left`. When it takes longer than 200 ms a transient `shellfirm: checking impact… (Ctrl-C cancels)` line shows; Ctrl-C there cancels the command and records it in the audit log
- **Uncommitted work counts** — a recursive delete of a folder that holds uncommitted or untracked files (git cannot bring them back) is High, so a relaxed `min_severity` still asks
- **Feedback after you confirm** — a passed challenge prints `✓ approved — running: <command>` (dim, on the terminal only), so a slow command such as `helm uninstall` does not look hung. Turn it off with `shellfirm config approved-notice off`
- **MCP server and agent hooks** — use shellfirm as a guardrail for Claude Code, Cursor and other agents
- **LLM analysis (experimental)** — configured with `shellfirm config llm`; used only to review AI-agent commands when `agent.llm_review` is enabled

---

## AI Tool Integration

### Claude Code

One command sets up both automatic safety (hooks) and on-demand analysis (MCP):

```bash
shellfirm connect claude-code
```

This adds:
- **Hooks** — every Bash command is checked before execution; risky commands are blocked
- **MCP** — Claude can call shellfirm tools to explain risks and suggest alternatives

### MCP Tools

| Tool | Description |
|------|-------------|
| `check_command` | Check if a command is risky — returns severity, matched rules, and alternatives |
| `suggest_alternative` | Get safer replacement commands |
| `explain_risk` | Detailed explanation of why a command is dangerous |
| `get_policy` | Read the active shellfirm configuration |

---

## Installation

Upgrading from 0.3.10? Read [Upgrading from 0.3.10](CHANGELOG.md#upgrading-from-0310): restart your shells, re-run `shellfirm connect <agent>`, and check the new exit codes.

### npm

```bash
npm install -g @shellfirm/cli
```

### Homebrew

```bash
brew tap kaplanelad/tap && brew install shellfirm
```

### Cargo

```bash
cargo install shellfirm
```

Or download the binary from the [releases page](https://github.com/kaplanelad/shellfirm/releases).

---

## Quick Start

**1. Install the shell hook:**

```bash
shellfirm init            # installs the hook for your current shell, then offers the others [y/N]
shellfirm init zsh        # or only for one shell
shellfirm init --all      # every supported shell
shellfirm init --dry-run  # preview what would change
shellfirm init --yes      # no questions (scripts, provisioning); sets the recommended Balanced level
```

`shellfirm init` asks you to confirm, then asks two questions: the challenge
type (Math, Enter or Yes) and the protection level.

**2. Restart your shell** (`exec zsh`, `exec bash`, … or open a new terminal).

**3. Check it:**

```bash
shellfirm status        # shows hooks, settings, policy and thresholds
shellfirm doctor        # checks that a new shell really routes commands through shellfirm
git reset --hard        # should trigger shellfirm
```

### Shell support

| Shell | Status |
|-------|--------|
| Bash, Zsh, Fish, Elvish, Xonsh | Tested: risky commands are challenged before they run. Elvish `fn` functions are not expanded before the check, and xonsh Python code that starts programs from computed values is not checked. |
| Nushell | Tested, with a limitation: Nushell cannot cancel a command line from a hook, so **Nushell built-in commands (for example `rm`, `mv`) still run** even after you cancel the challenge. External programs are covered. Treat Nushell protection as a warning, not a guard. |
| PowerShell, Oils (`osh`) | Hooks are shipped but not yet tested end to end. Please report what works. |

The shell hooks check what you type at the interactive prompt. AI agents
should use the agent hooks (`shellfirm connect`), not the shell hook.

**What the hook sees.** The hooks expand what they can before checking:
aliases (including chains such as `del` → `rmrf` → `rm -rf`), history
references (`!!`, `!$`), and the body of a small shell function you call
(`nuke() { rm -rf "$@"; }; nuke build`), so the banner's `Command:` line
shows what will really run. In bash, zsh and fish every function a line
calls is followed, however deep, with the call's arguments (also after
`shift`), within a budget of 64 functions / 64 KB (16 KB for one body);
past it the line gets a Medium `shell:function_depth_limit` challenge
instead of being skipped. A function over 16 KB that was loaded from a file
(nvm, sdkman, conda) is treated like a script you run: its body is not read,
so `nvm use 18` is not prompted, and neither is a call whose danger is only in
the body (`bigclean ~` with `rm -rf "$1"` inside); a command it is asked to run
(`nvm exec 18 rm -rf ~/data`) is still checked. One typed or pasted into the
session gets the Medium challenge. Nushell follows aliases and `def`s, and
xonsh alias chains up to 10;
elvish `fn` functions are not expanded. Limits: the contents of scripts you
run (`./cleanup.sh`) are not inspected, and commands built at run time
(`$CMD`, `eval "$(…)"` output) can only be checked as far as they are
visible on the line. shellfirm is a guard against mistakes, not a sandbox.

**bash `fc`.** bash turns the `fc` builtin off and routes `command fc`
through `command_not_found_handle` to the checked `fc`, so it runs in a
subshell; `builtin fc` works only on a line typed at the prompt.

**After a blocked or cancelled line.** In bash, zsh and fish, `$?`/`$status`
after a line shellfirm blocked is still the previous command's status: the
line never ran, and a key binding cannot set it. nushell sets
`$env.LAST_EXIT_CODE = 1`. The line is kept in the editor instead (Ctrl-U
clears it). Scripts and CI should use
`shellfirm check --exit-code` (exit 10 / 11) or `shellfirm pre-command`
(exit 65 / 77), not `$?` of an interactive prompt.

---

## Everyday use

### Find out why a command was flagged

```bash
shellfirm check -c 'git reset --hard'           # matched check ids, severity, alternatives
shellfirm check -c 'git reset --hard' --format json
```

The text output ends with what your shell would do (`Shell (you, in a
terminal): would challenge (Math)`) and what an AI-agent hook would answer
(`AI agent (hooks, MCP): deny`), so a command you can run after a math problem
is not mistaken for one that is blocked for you. In CI, `--strict` also exits
78 when your settings, custom checks or a policy have warnings.

### Stop a check from prompting (ignore) or block it (deny)

shellfirm has no "allow once" switch: to run a flagged command, solve the
challenge. To stop being asked about a check permanently, ignore its id:

```bash
shellfirm config ignore git:reset            # never prompt for this check
shellfirm config ignore --remove git:reset   # undo
shellfirm config deny git:force_push         # always block this check
shellfirm config severity High               # only prompt for High and Critical
```

Unknown ids are rejected (with suggestions), so a typo cannot leave you
silently unprotected. Checks required by a project's `.shellfirm.yaml` cannot
be ignored or disabled for that project (`shellfirm policy show` lists them).

### Configure

```bash
shellfirm config          # interactive editor (TUI)
shellfirm config show     # current settings
shellfirm config edit     # open settings.yaml in $EDITOR (invalid edits are rejected)
shellfirm config reset    # back up the current file, then start over
```

Settings live in `~/.config/shellfirm/settings.yaml` (on macOS:
`~/Library/Application Support/shellfirm/settings.yaml`). An invalid settings
file is reported with its line number and is never overwritten; the shell hook
keeps working with safe defaults for the invalid values. See
[docs/config.md](docs/config.md).

### Logs

`--log <level>` (or `SHELLFIRM_LOG=debug`) prints diagnostics to stderr.
`RUST_LOG` is not used.

---

## Accessibility

**No math challenges.** If mental arithmetic is hard for you (dyscalculia, a
screen reader, fatigue), use these three settings. Medium (and, if you
prompt for them, Low and Info) commands then need only Enter, and everything
that would have asked for math asks you to type `yes` instead, including when
SSH, root or a protected branch raises the risk:

```bash
shellfirm config challenge Enter
shellfirm config escalation severity --critical Yes --high Yes --medium Enter --low Enter --info Enter
shellfirm config context escalation --elevated Yes --critical Yes
```

Check the result with `shellfirm pre-command -t -c 'git push -f origin main'`
(it prints the effective challenge). A project's `.shellfirm.yaml` or a
per-group or per-check override can still ask for `Math`. `shellfirm policy show`
and `shellfirm config show` list them.

**Plain output.** The challenge is linear text with one labelled fact per line,
and severity is written as a word. `NO_COLOR=1` (any non-empty value; an
empty `NO_COLOR=` keeps colour), `CLICOLOR=0` and a monochrome terminal
(`TERM=dumb`, `vt100`, `xterm-mono`, …) turn colour off everywhere: the
challenge, the CLI and the settings editor. `CLICOLOR_FORCE=1` forces it on.
With a non-UTF-8 locale (`LC_ALL=C`), `status`, `config show`, `policy show`
and `audit show` print ASCII instead of `—`, `→` and `✓`. There are no
timeouts, and retries are unlimited.

**Settings editor (`shellfirm config`).** Everything is reachable by keyboard
(`?` shows the keys). The active tab is shown as `[Name]` and the selected row
is marked with `>`, so focus is visible without colour. With `NO_COLOR`,
highlights use reverse video. With a non-UTF-8 locale (for example
`LC_ALL=C`), symbols fall back to ASCII. Text fields place the terminal cursor
at the insertion point. In windows smaller than 80x24, tabs scroll to the
selected row (the minimum is 60x16). Under `TERM=dumb` the editor does not
start; use `shellfirm config show` and the `shellfirm config <subcommand>`
commands instead.

---

## Known limitations

shellfirm is a safety net for mistakes, not a sandbox: it reads the command
line before it runs and cannot see what a program does once started. Some
risky commands have no rule yet:

- Reverse shells: only the common spellings are recognised; other spellings
  are not.
- Encoded or downloaded text that is decoded and piped or passed straight
  into a shell or interpreter is not always followed.
- Sending secrets (keys, tokens, credential files) to another host with
  `curl`, `aws` or `gh` is not detected in general.
- Lock-out commands beyond locking the root account (locking or removing
  other users, firewall rules that drop the SSH port) are not checked.
- `git -c` with a program value (`core.pager`, `core.editor`) is Medium, and
  `-c diff.external=` / `-c credential.helper=` are not matched; neither are
  `git config include.path …` and `git config init.templateDir …`, which make
  later git commands run another file's settings or hooks.
- Commands fed on standard input to a remote or root shell (`ssh host <<EOF …
  EOF`, `echo 'rm -rf /srv' | sudo bash`, `ssh host < script.sh`) are not read
  when they come from a file or another program.
- False positive: hardening a firewall the right way (`ufw allow OpenSSH && ufw
  default deny incoming`) is still treated as a possible lock-out (High; an
  agent is denied). Run the two commands one at a time, or approve it.

Nushell built-in commands are not stopped (see [Shell support](#shell-support)).
Report a missing case as an issue; the [check catalogue](docs/checks/README.md)
lists what is covered.

---

## Uninstall

```bash
shellfirm init --uninstall                     # remove the hooks from your shell rc files
shellfirm connect claude-code --uninstall      # if you connected an AI tool
shellfirm status                               # confirm: no shell shows "installed"
```

`status` reads your rc files, so it shows "not installed" right away; a shell
that already loaded the hook keeps it until you restart that shell.

If you added the hook by hand (`eval "$(shellfirm init bash)"` and similar),
delete that line from your rc file. Restart open shells: a running shell keeps
the hook until it exits.

Then remove the binary the way you installed it (`npm uninstall -g @shellfirm/cli`,
`brew uninstall shellfirm`, or `cargo uninstall shellfirm`) and, if you no
longer need them, delete your settings, custom checks and audit log:
`rm -rf ~/.config/shellfirm` (macOS: `~/Library/Application Support/shellfirm`).

---

## Documentation

- [Configuration](docs/config.md) — settings file, CLI, custom checks
- [Team policies](docs/team-policies.md) — `.shellfirm.yaml` project-level rules
- [Audit trail](docs/audit.md) — record format, filters, rotation
- [Check catalogue](docs/checks/README.md) — every built-in check, by group
- [Adding built-in patterns](docs/add-new-patterns.md) — contributing new checks

More guides are on **[shellfirm.vercel.app](https://shellfirm.vercel.app)**.

---

## Contributing

Contributions are welcome. [CONTRIBUTING.md](CONTRIBUTING.md) covers the build,
the tests and the checklist for a pull request, and
[docs/add-new-patterns.md](docs/add-new-patterns.md) walks through adding a
check. Found a bypass? Please report it privately; see [SECURITY.md](SECURITY.md).

## License

[Apache-2.0](LICENSE)
