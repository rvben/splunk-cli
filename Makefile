.PHONY: build release test lint fmt check conformance clean install release-patch release-minor release-major update-deps

build:
	cargo build

release:
	cargo build --release

test:
	cargo test --locked

lint:
	cargo fmt -- --check
	cargo clippy --locked --all-targets -- -D warnings

fmt:
	cargo fmt

check: lint test

# Score the binary against The CLI Spec (clispec.dev). Requires `clispec`.
conformance: build
	python3 scripts/score-clispec.py ./target/debug/splunk-cli

clean:
	cargo clean

install: release
	mkdir -p ~/.local/bin
	cp target/release/splunk-cli ~/.local/bin/splunk-cli

update-deps:
	upd --apply --max-bump minor --lang rust,actions

release-patch:
	vership bump patch --prepare

release-minor:
	vership bump minor --prepare

release-major:
	vership bump major --prepare
