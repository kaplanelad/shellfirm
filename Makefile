
build: test ## build project.
	cargo build

test: ## run test.
	cargo test

fmt: ## validate formating.
	cargo fmt --all -- --check

clippy: # check common mistakes and improve your Rust code.
	cargo clippy -- -D warnings

show-doc: clean-doc ## run test.
	cargo doc --open --no-deps

validate-doc: clean-doc # validate documentation syntax.
	RUSTDOCFLAGS="-D warnings" cargo doc --workspace --all-features --no-deps --document-private-items

clean-doc: # clean doc folder.
	cargo clean --doc

all-validation: test fmt clippy validate-doc ## runs all ci validation.
 
help: ## Prints help information.
	@fgrep -h "##" $(MAKEFILE_LIST) | fgrep -v fgrep | sed -e 's/\\$$//' | sed -e 's/##//'