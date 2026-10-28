## What does this change?

<!-- One or two sentences. Link the issue: "Fixes #123". -->

## Checklist

- [ ] Based on `main`.
- [ ] Tests added or updated (`cargo test` passes).
- [ ] Formatted with `cargo fmt --all` (`make fmt` passes).
- [ ] `make clippy` passes (same flags as CI).
- [ ] A line under `## Unreleased` in `CHANGELOG.md` for user-visible changes.

### New or changed built-in checks (skip if not relevant)

- [ ] Check added to `shellfirm/checks/<group>.yaml` (`from` = file name, id = `<group>:<name>`).
- [ ] Positive and negative cases in `shellfirm/tests/checks/<group>.yaml` (`expect_ids`).
- [ ] New group registered in `DEFAULT_ENABLED_GROUPS` (or listed in `OPT_IN_GROUPS`), snapshot updated.
- [ ] Catalogue regenerated after the last check change: `make catalogue`.

See [CONTRIBUTING.md](../CONTRIBUTING.md) and [docs/add-new-patterns.md](../docs/add-new-patterns.md).
