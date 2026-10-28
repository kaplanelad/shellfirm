# Contributing to shellfirm

Thanks for helping! You can contribute new checks, fixes, documentation, bug
reports and feature requests. Please follow the
[code of conduct](CODE_OF_CONDUCT.md). To report a bypass or another security
problem, do **not** open a public issue; see [SECURITY.md](SECURITY.md).

## Workflow

1. Fork the repository and create a branch from `main`.
2. Make your change, with tests.
3. Run the checks below.
4. Add a line under `## Unreleased` in [CHANGELOG.md](CHANGELOG.md) for any
   user-visible change (new check, new flag, changed behaviour, bug fix).
5. Open a pull request against `main`. The PR template has a short checklist.

Adding a built-in check? Follow [docs/add-new-patterns.md](docs/add-new-patterns.md).
To add checks only for yourself or your team, no code change is needed: see
[custom checks](docs/config.md#custom-checks) and
[team policies](docs/team-policies.md).

## Requirements

- Rust 1.99.1, the toolchain CI pins (`RUST_TOOLCHAIN` in
  [`.github/workflows/ci.yaml`](.github/workflows/ci.yaml)); clippy lints
  differ between Rust releases. The minimum supported version (MSRV) is the
  `rust-version` in [`shellfirm/Cargo.toml`](shellfirm/Cargo.toml).
- Optional: [cargo-insta](https://insta.rs/docs/cli/) to review snapshot
  changes: `cargo install cargo-insta`.

## Checks to run before a PR

All commands run from the repository root. `make help` lists every target.

| Command            | What it runs                                                       |
|--------------------|--------------------------------------------------------------------|
| `make test`        | `cargo test --locked --all-features`                               |
| `make clippy`      | clippy with the exact CI flags (see below)                         |
| `make validate-doc`| `cargo doc` with `RUSTDOCFLAGS="-D warnings"` (same as CI)         |
| `make fmt`         | `cargo fmt --all -- --check`                                       |
| `make ci`          | `test` + `clippy` + `validate-doc` + `fmt`: the Linux part of CI (CI also runs the macOS/Windows matrix, the MSRV build and `cargo hack` feature checks) |

The CI clippy line is:

```bash
cargo clippy --locked --all-features -- -D warnings -W clippy::pedantic -W clippy::nursery -W rust-2018-idioms
```

Only the check tests (fast, while working on checks):

```bash
cargo test -p shellfirm --test checks
```

### Snapshots

Some tests use [insta](https://insta.rs) snapshots (`*.snap` files). When a
snapshot changes on purpose (for example after adding a default group):

```bash
cargo insta test --review          # with cargo-insta installed
INSTA_UPDATE=always cargo test     # without it; then review the .snap diff with git diff
```

### Formatting

Use standard `rustfmt` settings (there is no custom `rustfmt.toml`). The tree
is rustfmt-clean: run `cargo fmt --all` before you commit (`make fmt` checks
it). The CI rustfmt job fails on unformatted code.

## End-to-end testing

Never try risky commands on your own machine. To see how the shell hooks
behave, use a disposable container or virtual machine with the hook loaded
(`eval "$(shellfirm init bash)"`), and nothing you would miss in it.

For a quick dry run of a check without any prompt (nothing is run):

```bash
cargo run -- check -c "git push -f origin main"
```

## Documentation

- User docs live in [`docs/`](docs) and [README.md](README.md).
- The [check catalogue](docs/checks/README.md) is generated; regenerate it
  with `make catalogue` after changing `shellfirm/checks/*.yaml` (a test fails
  if it is out of date).
- Preview the API docs with `make show-doc`.
