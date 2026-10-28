# Adding built-in checks

Built-in checks live in [`shellfirm/checks/`](../shellfirm/checks), one YAML
file per group. The file name is the group name (`checks/terraform.yaml` is the
`terraform` group). `shellfirm/build.rs` validates every file and embeds them
in the binary.

> To add checks only for yourself or your team, you do not need to change
> shellfirm. Use [custom checks](config.md#custom-checks) or a
> [project policy](team-policies.md).

The full list of current checks is in the generated
[check catalogue](checks/README.md).

## Where does my check go?

| The command is run by...                            | Group / file                   |
|-----------------------------------------------------|--------------------------------|
| `rm`, `dd`, `mkfs`, `chmod`, `find -delete`, rsync  | `fs`                           |
| `git`                                               | `git`                          |
| `gh`                                                | `github`                       |
| `kubectl`, `helm`                                   | `kubernetes`                   |
| Cluster add-ons and tooling: `velero`, `argocd`, `flux`, `istioctl`, `cilium`, `etcdctl`, `eksctl` | `kubernetes` |
| `terraform`, `tofu`, `terragrunt`, `pulumi` (other IaC tools too) | `terraform`         |
| HashiCorp runtime tools: `vault`, `consul`, `nomad` | `terraform`                    |
| `aws`, `gcloud`/`gsutil`, `az`                      | `aws`, `gcp`, `azure`          |
| `heroku`, `flyctl`, `vercel`, `netlify`             | `heroku`, `flyio`, `vercel`, `netlify` |
| `docker`                                            | `docker`                       |
| SQL text (`DROP TABLE`, `DELETE FROM` without WHERE) | `database`                    |
| `psql`, `mysql`, `redis-cli`, `mongosh` CLI flags   | `psql`, `mysql`, `redis`, `mongodb` |
| `npm`, `yarn`, `pnpm`                               | `npm`                          |
| Remote code execution (`curl ... \| sh`, `eval $(curl ...)`) | `shell`                  |
| Firewall, interfaces, `iptables`                    | `network`                      |
| Sending secrets/env files over the network          | `exfil`                        |
| Reboot/shutdown, cron, processes, services, ssh keys, fork bombs | `base`            |

If none fits, create a new group (see step 4).

## 1. Add the check

Add an entry to the group's file:

```yaml
- from: terraform                 # must equal the file name
  id: terraform:destroy           # `<group>:<name>`, unique across all files
  test: (?:^|\s)(?:terraform|tofu|terragrunt)\s+(?:run-all\s+)?(?:destroy\b|apply\b.*\s-destroy(?:\s|$))
  description: "This destroys managed infrastructure."
  severity: High                  # Info | Low | Medium (default) | High | Critical
  filters:                        # optional; ALL filters must pass
    # With -auto-approve the Critical checks apply instead.
    - type: NotMatches
      value: '\s-?-auto-approve(?:\s|$|=)'
  alternative: "terraform plan -destroy"                  # optional
  alternative_info: "Preview what would be destroyed."    # optional
```

Allowed keys: `id`, `from`, `test`, `description`, `severity`, `challenge`
(`Enter`/`Math`/`Yes`, rarely needed), `filters`, `alternative`,
`alternative_info`. Any other key (for example a typo such as `severty:`) fails
the build.

### How `test` is matched

- shellfirm splits a command line into sub-commands (`a && b`, `a | b`,
  `$(...)`, `sudo`/`env`/`xargs` wrappers, ...) and normalizes each one
  (quotes removed, repeated spaces collapsed). The regex runs on **each
  normalized sub-command**, not on the raw line.
- Anchor the tool name with `(?:^|\s)tool\s+...` so `mytool-destroy` or a path
  segment does not match (`sudo`, `env VAR=x` and `/usr/bin/` are removed
  before matching, so the anchor loses nothing). The
  `command_name_regexes_are_anchored` test fails for a regex (or any of its
  top-level alternatives) that starts with a bare command name. Use `\b` or `(?:\s|$)` after flags so `-f` does not
  match `-foo`.
- Matching is case-sensitive. Use `(?i)` only when the tool itself is
  case-insensitive (SQL keywords).

### Filters

Filters run after the regex matched. Every filter must pass for the check to
fire.

| `type`        | `value`               | The check fires only if...                                  |
|---------------|-----------------------|-------------------------------------------------------------|
| `PathExists`  | capture group number  | the path captured by that group exists                      |
| `Contains`    | substring             | the command contains the substring                          |
| `NotContains` | substring             | the command does **not** contain the substring              |
| `Matches`     | regex                 | the normalized command matches the regex                    |
| `NotMatches`  | regex                 | the normalized command does **not** match the regex         |

Prefer `NotMatches` over `NotContains` for flag exemptions, so that
`--dry-run` is matched as a whole token (`'\s--dry-run(?:\s|=|$)'`) and not
inside another word.

## 2. Add test cases

Every check needs test cases in
[`shellfirm/tests/checks/<group>.yaml`](../shellfirm/tests/checks) (one file
per group, the same name as the check file). Put the cases for each id under a
`# -- <id> --` comment:

```yaml
# -- terraform:destroy --
- test: "terraform destroy"
  description: "match command"
  expect_ids: ["terraform:destroy"]
- test: "terraform apply -destroy"
  description: "apply -destroy is a destroy"
  expect_ids: ["terraform:destroy"]
- test: "terraform destroy -auto-approve"
  description: "the Critical check takes over"
  expect_ids: ["terraform:destroy_auto_approve"]
- test: "terraform plan -destroy"
  description: "a plan is safe"
  expect_ids: []
```

- `expect_ids` is the **exact set** of check ids that must match the whole
  command, across all groups. Order does not matter, but an extra or a missing
  id fails the test.
- An empty list (`expect_ids: []`) means "must not match anything". Add at
  least one such negative case for the near-misses of your regex.
- Coverage gate: `test_coverage_completeness` fails if any check id never
  appears in an `expect_ids` list.
- Path filters: the test runner reports every path as existing, so
  `PathExists` filters always pass in these tests.

## 3. Run the tests

```bash
cargo test --test checks          # only the check tests (a few seconds)
cargo test --no-fail-fast         # everything, and report every failing target
```

Test-case files must be named `tests/checks/<group>.yaml`, after an existing
`checks/<group>.yaml` (`normalization.yaml`, which spans groups, is the only
exception). A file named after no group (`vaul.yaml`), a subdirectory, another
extension (`.yml`) or an unknown key in a case (`expect_idz:`) is an error
that names the file. Hidden files (editor locks, macOS `._*`) are skipped.

Besides your cases, the check tests verify that ids are unique, that every id
starts with `<file name>:`, that every group is registered (step 4), and that
the [check catalogue](checks/README.md) is up to date. Regenerate the
catalogue once, after your last change to `checks/*.yaml` (and after step 4
for a new group), from the repository root:

```bash
make catalogue
```

## 4. New groups only

A new `checks/<group>.yaml` passes the tests but never fires for users unless
the group is enabled by default:

1. Add the group to `DEFAULT_ENABLED_GROUPS` in
   [`shellfirm/src/config.rs`](../shellfirm/src/config.rs) and bump the array
   length (`[&str; N]`; the compiler tells you the right number).
   If the group should be opt-in instead, add it to `OPT_IN_GROUPS` in
   `shellfirm/tests/checks.rs`. `every_builtin_group_is_enabled_by_default_or_opt_in`
   fails until you do one of the two.
2. The `config reset` snapshot test lists the default groups, so it fails
   with a diff. Accept the new snapshot with
   [cargo-insta](https://insta.rs/docs/cli/) (`cargo install cargo-insta`,
   then `cargo insta test --review`), or without installing anything:
   `INSTA_UPDATE=always cargo test` and review the changed `.snap` file in
   `git diff`. (`cargo insta test --accept` accepts without the review; a
   failed run without either leaves a `.snap.new` file next to the snapshot:
   delete it once the snapshot is accepted.) Nothing else lists the groups by
   hand: the other tests derive them from `DEFAULT_ENABLED_GROUPS`.
3. Then regenerate the catalogue (`make catalogue`, step 3).

## 5. Try it end to end

```bash
cargo run -- check -c "terraform destroy"     # dry run, no prompt
cargo run -- check --list -g terraform        # active checks in the group
```

**Opt-in groups** are not active until a user enables them, so the two
commands above say "No risky patterns matched." and print an empty list (with
a note that the group is not enabled). Say you added an opt-in `acme` group
(`checks/acme.yaml`, for a made-up `acme` CLI that has no built-in checks):
try it with a throwaway configuration directory, so your own settings are not
touched:

```bash
cfg=$(mktemp -d)
printf 'enabled_groups: [base, acme]\n' > "$cfg/settings.yaml"
cargo run -- check -c "acme cluster delete prod" --config-dir "$cfg"
cargo run -- check --list -g acme --config-dir "$cfg"   # or: check --list -a -g acme
```

(`shellfirm config groups --enable acme` does the same in your real
settings; `SHELLFIRM_CONFIG_DIR=$cfg` works for every command, not only
`check`.)

Add a line under `## Unreleased` in [CHANGELOG.md](../CHANGELOG.md) and open
the pull request (see [CONTRIBUTING.md](../CONTRIBUTING.md)).
