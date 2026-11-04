.PHONY: build release test test-live test-live-matrix lint fmt check conformance clean install release-patch release-minor release-major update-deps

build:
	cargo build

release:
	cargo build --release

test:
	cargo test --locked

# Opt-in, native x86 Docker daemon; supports homelab contexts / DOCKER_HOST.
test-live:
	bash scripts/test-live.sh

test-live-matrix:
	SPLUNK_TEST_VERSION=10.6.1.1 bash scripts/test-live.sh
	SPLUNK_TEST_VERSION=9.4.9 bash scripts/test-live.sh

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
