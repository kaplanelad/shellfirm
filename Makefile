# Run from the repository root. `make help` lists the targets.
# The clippy and doc flags must stay identical to .github/workflows/ci.yaml.
CLIPPY_FLAGS = -D warnings -W clippy::pedantic -W clippy::nursery -W rust-2018-idioms

.PHONY: build test fmt fmt-fix clippy show-doc validate-doc clean-doc ci all-validation catalogue help

build: ## Build the project.
	cargo build --locked

test: ## Run all tests.
	cargo test --locked --all-features

fmt: ## Check formatting (rustfmt).
	cargo fmt --all -- --check

fmt-fix: ## Format all code.
	cargo fmt --all

clippy: ## Run clippy with the same flags as CI.
	cargo clippy --locked --all-features -- $(CLIPPY_FLAGS)

show-doc: clean-doc ## Build the API docs and open them in a browser.
	cargo doc --open --no-deps

validate-doc: clean-doc ## Check the API docs build without warnings (same as CI).
	RUSTDOCFLAGS="-D warnings" cargo doc --locked --workspace --all-features --no-deps --document-private-items

clean-doc: ## Remove generated API docs.
	cargo clean --doc

catalogue: ## Regenerate docs/checks/README.md from shellfirm/checks/*.yaml.
	cd shellfirm && SHELLFIRM_UPDATE_CATALOGUE=1 cargo test --test checks catalogue

ci: test clippy validate-doc fmt ## Run what CI enforces.

all-validation: ci ## Run every CI check (same as `make ci`).

help: ## Print this help.
	@grep -hE '^[a-zA-Z_-]+:.*## ' $(MAKEFILE_LIST) | sed -E 's/^([a-zA-Z_-]+):.*## (.*)/  \1\t\2/' | expand -t 18
