# Contributing code to Shellfirm

Shellfirm is open source and we love to receive contributions from our community — you! There are many ways to contribute, from writing more sensitive patterns, improving the documentation, submitting bug reports and feature requests or writing code.

## How to contribute

The preferred and easiest way to contribute changes to the project is to fork it on GitHub, and then create a pull request to ask us to pull your changes into our repo. We use GitHub's pull request workflow to review the contribution, and either ask you to make any refinements needed or merge it and make them ourselves.

Your PR must also:

- be based on the `main` branch
- adhere to the [code style](#code-style)
- pass the [test suites](#tests)
- check [documentation](#documentation)
- add new [patterns](./docs/add-new-patterns.md)

## Tests

In `shellfirm` we have a few validation flows that must pass before merging to `main`.

- [Rust: cargo check](#rust-cargo-check)
- [Rust: unit tests](#rust-unit-tests)
- [Rust: clippy](#rust-clippy)
- [Rust: docs build](#rust-docs-build)
- [Formatting](#formatting)

### Rust: cargo check

Run a quick compilation check locally (mirrors CI `cargo check`):

```bash
cargo check
```

### Rust: unit tests

CI runs tests on Linux, macOS, and Windows with all features enabled. Locally, run:

```bash
cargo test --all-features --workspace
```

We use [insta](https://github.com/mitsuhiko/insta) for snapshot testing. To review snapshot changes interactively:

```bash
cargo insta test --review
```

### Rust: clippy

CI enforces warnings as errors and pedantic lints. Match CI locally with:

```bash
cargo clippy --all-features --workspace -- -D warnings -W clippy::pedantic -W clippy::nursery -W rust-2018-idioms
```

### Rust: docs build

Docs must compile with warnings denied in CI. Validate locally with:

```bash
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --all-features --no-deps --document-private-items
```

### Formatting

We use `rustfmt`. Please format before committing:

```bash
cargo fmt
```

## Code style

We use the standard Rust code style, and enforce it with `rustfmt`/`cargo fmt`.
A few code style options are set in the [`.rustfmt.toml`](./.rustfmt.toml) file, and some of them are not stable yet and require a nightly version of rustfmt.

## Documentation

Build the API docs locally (ensuring no warnings):

---

## MCP Developer Guide

This section documents how to work on the MCP integration (`mcp/`):

- Build TypeScript: `npm run build`
- Dev/watch: `npm run dev`
- Start (stdio): `npm start`

---

## User Guidelines (Best Practices)

- Review risky commands carefully before approving challenges.
- Prefer least-privilege operations; avoid global destructive flags.
- Use severity filtering to reduce noise or tighten policies.
- Keep Shellfirm updated to benefit from the latest patterns.
