# Agent sandbox

shellfirm's hooks judge the text of a command before it runs. A script, a
build step or any child process that opens `~/.ssh/id_rsa` at runtime never
shows up in that text. Coding agents ship an OS-level sandbox that enforces
file access for every process a command starts, but their defaults restrict
writes, not reads: a sandboxed command can still read your SSH keys and
cloud credentials.

`shellfirm sandbox <agent>` turns on the agent's own sandbox and denies it
the credential files shellfirm already protects, as a backstop to the hooks.

```bash
shellfirm sandbox --list                     # supported agents and the path lists
shellfirm sandbox claude-code --dry-run      # show the change, write nothing
shellfirm sandbox claude-code                # ~/.claude/settings.json ($CLAUDE_CONFIG_DIR; a relative one is relative to the current directory)
shellfirm sandbox claude-code --scope project   # .claude/settings.json (shared with the team)
shellfirm sandbox claude-code --scope local     # .claude/settings.local.json (just you)
shellfirm sandbox codex                      # ~/.codex/config.toml ($CODEX_HOME)
shellfirm sandbox claude-code --remove       # take out exactly what shellfirm added
```

The sandbox complements `shellfirm connect`: the hooks ask or deny before a
risky command runs, the sandbox stops what the command does once it runs.
Use both.

## What is written

### Claude Code

In the settings file of the chosen scope (see
[Claude Code sandboxing](https://code.claude.com/docs/en/sandboxing) and the
`sandbox` settings in the
[settings reference](https://code.claude.com/docs/en/settings)):

```json
{
  "sandbox": {
    "enabled": true,
    "filesystem": {
      "denyRead": ["~/.ssh", "~/.aws", "~/.gnupg", "~/.kube/config", "..."],
      "denyWrite": ["~/.bashrc", "~/.zshrc", "~/.gitconfig", "~/.config/shellfirm", "..."]
    }
  }
}
```

- Existing settings are merged, never replaced: your own `denyRead` /
  `denyWrite` entries, network rules, `excludedCommands` and
  `autoAllowBashIfSandboxed` stay as they are, and entries you already have
  are not added twice. Claude Code merges these arrays across the user,
  project and local files.
- `sandbox.enabled` is set to `true` (a `false` you had is put back by
  `--remove`). Nothing that relaxes prompts or the sandbox is written.
- Warnings are printed (by this command and by `shellfirm status` /
  `doctor`) when a setting in any scope (user, project, local, managed)
  weakens the deny rules: `sandbox.filesystem.disabled: true`, an
  `allowRead` / `allowWrite` entry equal to or inside a denied path (such
  as `~/.ssh/id_rsa` or `/home/you/.aws`; Claude Code lets the narrower
  entry win, so a wider one such as `/` does not re-open a denied path), or
  commands in `excludedCommands` (they run outside the sandbox). shellfirm
  keeps your settings; change them by hand.
- Claude Code applies the `sandbox.enabled` of the highest-precedence file
  that sets it (managed, local, project, user). A `false` in a project or
  local file turns the sandbox off for a user-scope install: this command
  warns, and `status` / `doctor` show `sandbox off` with the file.
- `--scope local` creates `.claude/settings.local.json` if it does not
  exist. Keep it out of git (add it to `.gitignore`): Claude Code ignores
  the file for you only when Claude Code itself creates it.
- At `--scope project` and `--scope local`, shellfirm refuses a settings
  file (or a directory on its path, such as `.claude`) that is a symlink
  out of the project: a link planted in a repository must not make it
  write another file (the message names the scope). `status` and `doctor`
  report such a link.
- The written file validates against the published settings schema
  (`https://json.schemastore.org/claude-code-settings.json`).

Platform: macOS uses Seatbelt (built in). Linux and WSL2 need `bubblewrap`
and `socat` installed. Native Windows has no sandbox. Where the sandbox
cannot start, Claude Code runs commands without it unless
`sandbox.failIfUnavailable` is `true`.

What the sandbox does not cover:

- Claude Code's `Read` tool is not sandboxed. The `Read` hook installed by
  `shellfirm connect claude-code` asks before it opens a private key or a
  credentials file.
- A command that fails in the sandbox may be retried outside it
  (`dangerouslyDisableSandbox`); that retry goes through your permission
  prompt and shellfirm's hook. Set `sandbox.allowUnsandboxedCommands: false`
  to forbid it.
- Tools that need a denied file stop working inside the sandbox, for
  example `git push` over SSH with keys in `~/.ssh`, `aws`, `gcloud` and
  `gh` with their stored credentials. Claude Code reports the sandbox
  violation; run such commands yourself, approve the unsandboxed retry, or
  leave the path out (see [Change the lists](#change-the-lists)).

### Codex CLI

In `~/.codex/config.toml` (`$CODEX_HOME/config.toml` when set), a permission profile
(`[permissions.<name>]`, see Codex's
[config schema](https://github.com/openai/codex/blob/main/codex-rs/core/config.schema.json))
selected with `default_permissions`. Comments and layout of the file are kept:

```toml
default_permissions = "shellfirm"

[permissions.shellfirm]
description = "Added by shellfirm sandbox: a built-in profile plus deny rules for credential files"
extends = ":workspace"

[permissions.shellfirm.filesystem]
"~/.ssh" = "deny"      # no access
"~/.aws" = "deny"
"~/.zshrc" = "read"    # read-only
```

- The profile extends the built-in profile you use: `:read-only` when
  `sandbox_mode = "read-only"` or `default_permissions = ":read-only"`,
  otherwise `:workspace`. When you already select your own profile
  (`default_permissions = "dev"`), the entries go into
  `[permissions.dev.filesystem]` instead and an entry you set for the same
  path is kept. Codex applies the most specific entry, so one of yours on a
  denied path or inside it with a weaker mode (`"~/.ssh/id_rsa" = "read"`)
  re-opens it: this command, `status` and `doctor` say so (a re-run does
  not change your entries). A wider entry such as `"/" = "write"` does not.
- shellfirm refuses, and changes nothing, when Codex runs without a sandbox
  (`sandbox_mode` or `default_permissions` set to `danger-full-access`,
  also in the active `[profiles.<name>]`, or a selected permission profile
  that extends `:danger-full-access`), when `[sandbox_workspace_write]` holds settings
  (Codex ignores them once a profile is selected: move them into your own
  profile first), and when the file cannot be parsed.
- With no `sandbox_mode` and no `default_permissions`, Codex uses
  `:read-only` for projects you have not marked trusted or untrusted; with
  the profile they use `:workspace` like trusted projects. Set
  `extends = ":read-only"` in the profile to keep every project read-only.
- A `--sandbox` or `--dangerously-bypass-approvals-and-sandbox` flag on the
  `codex` command line replaces the profile for that run.
- A project `.codex/config.toml` (which Codex applies over the user file
  for a trusted project) that runs without a sandbox or selects another
  `default_permissions` replaces the profile in that project: this command
  warns, and `status` / `doctor` show `sandbox off` with the file. Codex
  merges that file's tables over the user file's, so an entry it adds to
  `[permissions.shellfirm.filesystem]` that re-opens a denied path (`"~/.ssh"
  = "write"`) is reported as `weakened:` with the project file.

Check it with `codex sandbox -- cat ~/.ssh/known_hosts` (macOS): it fails
with `Operation not permitted`.

### Other agents

`shellfirm sandbox --list` shows them with the reason:

- **Gemini CLI**: the sandbox is switched on per run (`--sandbox`,
  `GEMINI_SANDBOX`) and the macOS Seatbelt profile is picked with the
  `SEATBELT_PROFILE` environment variable; there is no settings key for
  deny-read paths.
- **GitHub Copilot CLI**: tool permissions, but no OS sandbox with file
  deny rules to configure.
- **Qwen Code**: like Gemini CLI, the sandbox is switched on per run.
- **Cursor, Windsurf, Cline, OpenCode, Zed**: no OS sandbox setting with
  file deny rules that shellfirm writes; `shellfirm connect` covers them.

`shellfirm sandbox <name>` for any of them prints the reason (exit 2).

## The paths

Reads denied (`shellfirm::agent::CREDENTIAL_PATHS`, the files whose reads
`exfil:read_secret_file` asks about, plus encrypted stores): `~/.ssh`,
`~/.aws`, `~/.gnupg`, `~/.kube/config`, `~/.docker/config.json`,
`~/.config/gh`, `~/.netrc`, `~/.git-credentials`, `~/.npmrc`, `~/.pypirc`,
`~/.pgpass`, `~/.my.cnf`, `~/.vault-token`, `~/.cargo/credentials(.toml)`,
`~/.gem/credentials`, `~/.s3cfg`, `~/.databrickscfg`, `~/.terraformrc`,
`~/.terraform.d/credentials.tfrc.json`, `~/.config/rclone/rclone.conf`,
`~/.oci`, `~/.config/gcloud`, `~/.azure`, `~/.claude/.credentials.json`
(also `$CLAUDE_CONFIG_DIR/.credentials.json` when it is set),
`~/.codex/auth.json`, crypto wallets, `~/.password-store`,
`~/Library/Keychains`, and platform CLI logins: `~/.railway/config.json`,
`~/.supabase/access-token`, Vercel `auth.json`
(`~/.local/share/com.vercel.cli`, `~/Library/Application Support/com.vercel.cli`),
Netlify `config.json` (`~/.config/netlify`, `~/Library/Preferences/netlify`),
`~/.fly/config.yml`.

Project `.env` files are not in the list, as their reads are not flagged
either; add them with `sandbox.deny_read` if you want them denied.

Writes denied: shell startup files (`~/.bashrc`, `~/.zshrc`, `~/.profile`,
…, `~/.config/fish`), `~/.ssh`, `~/.gitconfig`, `~/.config/git/config`,
autostart entries (`~/.config/systemd`, `~/.config/autostart`,
`~/Library/LaunchAgents`), AI-agent settings files (with
`$CLAUDE_CONFIG_DIR/settings.json` and `.claude.json` when it is set) and shellfirm's
configuration directory (left out of a shared `--scope project` file when it
is outside your home directory). Claude Code and Codex already keep
sandboxed writes inside the project; these entries also hold when you allow
more.

### Change the lists

`shellfirm sandbox --list` prints the lists in effect. Change them in
`settings.yaml` (`shellfirm config edit`), then re-run the command:

```yaml
sandbox:
  deny_read: [~/work/secrets, ~/.env.shared]   # more paths, ~/ or absolute
  deny_write: [/etc/hosts]
  exclude: [~/.npmrc]                         # built-in entries to leave out
```

A re-run takes out entries shellfirm added earlier that are no longer in
the lists (an `exclude` added later). An entry that is `/`, your home
directory or a directory above it (`~`, `/home/you`, `/home`, `//`) is
refused, and so are an empty entry and one with an environment variable
(`$HOME` is not expanded); the command changes nothing until you fix
`settings.yaml`, and `status` / `doctor` name the refused entry. A relative
path is skipped with a warning, and `..` in a path is resolved
(`~/.ssh/../.aws` is `~/.aws`).
The command also prints the settings-file warnings `shellfirm status`
shows (an unknown key such as `sandbox.deny_reads`). `gemini` and `copilot`
are accepted as names for `gemini-cli` and `copilot-cli`.

A settings path that is not a regular file (a FIFO, a device) is reported
as an error instead of being read, and so is an agent folder that cannot be
read (`chmod 000 ~/.claude`): `status` / `doctor` show `can't read …`, not
"not configured".

## Removing it

`--remove` (alias `--uninstall`) takes out exactly the entries shellfirm
added and restores a `sandbox.enabled` or `default_permissions` value it
changed; entries that were there before stay. What was added is recorded in
`sandbox.json` in shellfirm's configuration directory. Without that record
(for example on a teammate's machine, for a shared project file), entries
equal to shellfirm's current lists are removed and `sandbox.enabled` is left
alone. A file that only held shellfirm's entries is deleted (at project and
local scope, with a `.claude` directory it leaves empty). At user scope the
backup of the deleted file stays next to it, so `~/.claude` (or
`$CLAUDE_CONFIG_DIR`) is kept even when shellfirm created it. Every change
writes a timestamped backup first (project files: to `~/.cache/shellfirm/backups`, not into the
repository); the newest 3 backups of each file are kept (only files named
the way shellfirm names its backups count). What was added is recorded
before the settings file is written, so a record that cannot be saved
leaves the file unchanged.

In agent mode, `shellfirm sandbox … --remove` asks first
(`shellfirm-self:sandbox_remove`).

## Status

`shellfirm status` lists each settings file that holds shellfirm's sandbox
entries, and `shellfirm doctor` warns when one lost entries, the sandbox
was turned off or a setting weakens it (`weakened: …`; the line suggests a
re-run only when a re-run fixes it):

```
  Agent sandbox:
    claude-code (user): sandbox on, read denies 39/39, write denies 26/26
    codex (user): sandbox on, read denies 39/39, write denies 26/26
```
