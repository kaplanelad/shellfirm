# Team policies (`.shellfirm.yaml`)

A `.shellfirm.yaml` committed to a repository lets a team share safety rules
that apply to everyone who works in it.

## Guarantees

- **Enforced.** A policy rule cannot be weakened by personal settings. Checks
  named in `deny` or `overrides`, and the policy's own `checks`, stay active in
  the project even if a developer ignores them (`ignores_patterns_ids`),
  disables their group (`disabled_groups`), leaves the group out of
  `enabled_groups`, or sets a higher `min_severity`. There is deliberately no
  environment variable or flag that switches a policy off; to change a rule,
  change the policy file (visible in code review).
- **Additive.** `overrides` can only make a challenge stricter. `context`
  entries are added to each developer's own context settings.
- **Loud.** A broken policy file is never ignored silently. See
  [What "invalid" means](#what-invalid-means) below.

`shellfirm policy show` prints the effective policy, the files it comes from,
and which of your personal settings it overrides.

## What "invalid" means

Every file is in one of three states. `shellfirm policy validate`,
`shellfirm status`, `shellfirm policy show` and the runtime warnings always
agree on the state, because they use the same code.

| State | When | What is enforced | Runtime warning (every intercepted command) |
| --- | --- | --- | --- |
| **invalid, NOT applied** | Fatal problem: invalid YAML, missing or unsupported `version`, unreadable file, relative `SHELLFIRM_ORG_POLICY` | Nothing from this file | `policy <path> is invalid and was NOT applied: <reason>` |
| **applied, with errors** | The file parses, but some entries are wrong: unknown keys, unknown / wildcard / group-name ids in `deny` or `overrides`, a check that reuses a built-in id or another check's id, an invalid individual check | Every valid entry; the invalid ones are left out | `policy <path> has an error (the rest of the file is applied): <reason>` |
| **valid with warnings** | Everything applies; something is suspicious (an id only your personal custom checks define, a `.shellfirm.yml` next to a `.shellfirm.yaml`, an org file you can write) | Everything | none (shown by `validate`, `status`, `policy show`) |

Applying the valid parts of a file with errors is deliberate: a policy can
only add rules, so applying more of it is always the safer choice.

In `status --format json` and `policy show --format json`, files that are not
applied are listed under `invalid`, and errors in applied files under
`problems`. `policy validate` exits `65` for both kinds of error, and with
`--strict` also for warnings, so CI should run `policy validate --strict`.

When a policy file is **not applied**, the agent hooks (Claude Code, Cursor)
answer `ask` instead of allowing a command silently, so a human sees the
problem. A file applied with errors does not change agent decisions; its
errors are reported like any other.

Text in policies (ids, descriptions, alternatives, context values) is
untrusted: control characters (ESC/CSI/OSC sequences, BEL, CR/LF), bidi
overrides and zero-width characters are stripped before anything is printed
or sent to an agent, and `validate` reports that it happened. The zero-width
joiners U+200C and U+200D are kept in descriptions and alternatives (Persian
and Indic spelling, emoji such as 👩‍💻); ids still refuse them.

## Org policy

An organisation can roll out a baseline that applies to **every** directory,
inside and outside repositories:

- `/etc/shellfirm/policy.yaml` (on Windows `%ProgramData%\shellfirm\policy.yaml`),
  typically installed by MDM, Ansible or a package. Make it owned by root and
  not writable by users: `shellfirm status`, `policy show` and `policy
  validate` warn when the current user can write it or its directory (so it
  could be moved away or replaced; a sticky directory you don't own the file
  in is fine), and `policy validate --strict` fails on that warning.
- `SHELLFIRM_ORG_POLICY=/abs/path/policy.yaml` names one **additional** org
  file. It can only add a file, never replace or hide the system one, so it
  cannot weaken anything. The path must be absolute (a relative path would
  depend on the current directory and is reported as invalid, not applied).
  A missing file is reported too, so a broken rollout is visible.

Org files use the same format as `.shellfirm.yaml`. They are merged first
(outermost); repository policies add to them. Org files are marked `[org]` in
`status` and `policy show`, and messages name them as
`org policy (/etc/shellfirm/policy.yaml)` (repository files as
`project policy (<path>)`).

## Discovery and nesting

From the current directory, shellfirm walks up and loads every
`.shellfirm.yaml` (or `.shellfirm.yml`) it finds, **up to and including the
outermost repository root**: the highest ancestor that contains `.git`.
Nested repositories do not stop the walk, so git submodules, worktrees whose
`.git` is a file, vendored clones and empty or bare `.git` directories all
inherit the superproject's policy (`mkdir .git` cannot escape it). Outside a
git repository the walk continues to the filesystem root, so a policy in your
home directory applies to non-repository directories under it.

When a command targets another directory than the one it is typed in (for
example `git -C ~/work/app push -f`, `cd ~/work/app && git push -f`,
`terraform -chdir=infra destroy`), the policies of the target directory apply
too: shellfirm loads the union of the policies for the current directory and
for each target directory (`policy::discover_for`). Policies only add rules,
so the union is always at least as strict as either one. `~`, `$HOME`,
`${HOME}` and `~you` (your own user, also when `$USER` is unset: the account
of your uid is used) are expanded in target directories, and `env -C DIR` /
`env --chdir=DIR` are followed. The shell hook, `check` and the AI-agent hooks
use the same target walk: relative `cd` chains (`cd projects/app && rm -rf
./src`, `(cd projects/app && …)`, `pushd`), `make -C` and path arguments
(`rm -rf projects/app/src`, `sudo rm -rf projects/app/src`) all bring in the
policy of the repository they reach, and its `deny` and enforced checks beat
your personal ignores, disabled groups and `min_severity` there, exactly as
when you run the command inside the repository. A target reached through a
symlink is reported by its real path, and each policy file appears once in
`policy_sources`. A target that
shellfirm cannot see statically (a directory computed at run time, another
user's `~name`, a script that changes directory) is not covered; scope then
falls back to the directory the command was typed in.

Denies are attributed the same way for shell and AI-agent commands: the audit
record has `deny_reason: policy_deny` and `policy_sources` with the file that
denied the check (see [audit.md](audit.md#deny_reason-values)), the agent's
reason text names the file, and `check --format json` carries the same two
fields.

All files found are merged, outermost first (org policies, then repository
files from the outermost root down):

- `deny` lists are combined.
- `overrides` are combined; when several name the same id, the strictest
  challenge wins.
- `checks` are combined; if a nested file redefines an id that a parent
  already defines, the parent's definition is kept (and `policy show` notes
  it).
- `context` lists are combined; escalation keeps the stricter value.

A nested policy (for example `services/api/.shellfirm.yaml` in a monorepo)
can add rules but can never remove a parent's rules. `shellfirm policy init`
in a subdirectory tells you which parent policies also apply. If one file in
the chain is invalid, the others still apply and the invalid one is reported.

## File format

```yaml
version: 1                     # required; only version 1 is supported

# Additional checks for this project
checks:
  - id: project:deploy_prod
    from: project
    test: "deploy\\s+--env\\s+prod"
    description: "Deploys to production."
    severity: High             # Info | Low | Medium | High | Critical
    challenge: Yes             # optional floor for this check

# Make existing checks stricter (never weaker). Challenges: Math, Enter, Yes
overrides:
  - id: git:force_push
    challenge: Yes
  - id: git:reset
    on_branches: [main, master, "release/*"]   # optional; globs ending in /* are supported
    challenge: Yes

# Always blocked in this project
deny:
  - kubernetes:delete_namespace

# Added to every developer's context settings
context:
  protected_branches: [develop]
  production_k8s_patterns: [acme-eks]
  production_env_vars:
    APP_ENV: production
  sensitive_paths: [/etc]
  escalation:
    elevated: Enter
    critical: Yes
```

Unknown keys are errors (a typo such as `denylist:` would otherwise leave the
project unprotected).

## Commands

```bash
shellfirm policy init               # create a template (valid as-is and when its examples are uncommented)
shellfirm policy validate           # validate every policy that applies here
shellfirm policy validate FILE      # validate one file
shellfirm policy validate --strict  # warnings fail too (for CI)
shellfirm policy validate --format json   # machine-readable verdict
shellfirm policy show               # effective merged policy and its sources
shellfirm policy show --format json
```

`policy validate` reports YAML errors with line numbers, unknown keys
(including inside `checks` entries), unknown check ids in `deny` and
`overrides`, duplicate ids, policy checks that reuse a built-in id, invalid
regexes and invalid values (severity, challenge). Without `FILE` it validates
every file that applies to the current directory, org files included. Ids are
checked against the built-in catalog and the policy's own `checks` only (never
your personal custom checks), so the verdict is the same on every machine and
in CI. The report goes to stdout and names each file with the state above
(`valid`, `valid with warnings`, `applied, with N error(s)`, `invalid, NOT
applied`); a `context.escalation` value below the built-in default gets a note
(escalation keeps the stricter value, so it has no effect in a policy).
`policy show` leaves unknown ids out of the effective `deny` / `overrides`.
Exit codes: `0` valid, `65` invalid or applied with errors (or warnings
with `--strict`), `66` no policy file found or `FILE` does not exist.

`--format json` prints one document with the same exit codes:
`{"schema_version": 1, "valid": bool, "strict": bool, "files": [{"path",
"valid", "applied", "errors": [], "warnings": [], "notes": []}], "warnings": []}`
(`valid` is the verdict after `--strict`; `applied` is false only for a file
that is not applied at all), plus `"version"` (the shellfirm
version). Without a policy every key is still present and `error` explains
why: `{"schema_version": 1, "version": "...", "valid": false, "strict": bool,
"files": [], "warnings": [], "error": "..."}` (exit 66). Exit `2` is a usage
error, `74` an output that could not be written.

### `--strict` in shellfirm

`--strict` means one thing everywhere: warnings fail like errors. For
`policy validate` that is exit `65`. `check --strict` analyses the command as
usual and then exits `78` when your settings, custom checks or any policy
that applies (including the repositories the command targets) have errors or
warnings, printing them as `shellfirm: strict: …`. Without `--strict`, a
policy with errors is applied as far as possible and warned about at runtime
(see the table above), and `check --exit-code` / `--fail-on` decide exit codes
from the command's risk only. To fail a CI job on a broken policy, run
`shellfirm policy validate --strict` as its own step (or `check --strict`).

Example CI step:

```bash
shellfirm policy validate --strict
```
