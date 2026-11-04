# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/).

## [Unreleased]

### Added

- Durable, page-bounded CSV/JSONL file exports with checkpoints, verified resume, and a single CSV header.
- Parse-only `search check` and credential-redacted `jobs logs` for investigation.
- Explicit `auth migrate`, deterministic saved-store selection, and unverified token-expiry diagnostics.
- Credential-preserving profile renaming and individual saved-setting resets.
- Command-specific help examples, actionable empty states, and display-truncation guidance.
- A documented 0.1.x compatibility policy for commands, JSON, errors, cursors, and checkpoints.
- Trusted weekly and release-gating live checks on isolated Husker infrastructure, with pinned Splunk versions and restricted-user coverage.

### Fixed

- Bind new continuations to their server, namespace, and ordered field selection.
- Retry transient safe-read HTTP responses within a bounded budget; never replay dispatches.
- Clean up browser login on cancellation, including Windows CLI termination, enforce a full sign-in deadline, and keep browser debugging off HTTP proxies.
- Preserve streaming checkpoint recovery details on interruption and refuse incomplete finalized searches.
- Preserve logged-out state when stale credentials reappear, while allowing later cleanup.

## [0.0.3](https://github.com/rvben/splunk-cli/compare/v0.0.2...v0.0.3) - 2026-11-04

### Added

- Guided `init`, read-only `doctor`, and offline credential diagnostics.
- Persistent profile selection with `profile list`, `use`, and guarded `remove`.
- Aligned terminal tables, CSV and JSONL exports, and SPL files or piped stdin.
- Bounded `jobs wait` / `watch` and multi-page `jobs export` of an existing job.
- **auth**: add browser SSO login and opt-in file credential store ([0b31305](https://github.com/rvben/splunk-cli/commit/0b313053fc510696b90704c40c6ba825bdec6dff))

### Fixed

- Surface sanitized, credential-redacted Splunk warnings even with `--quiet`.
- Exit quietly when a pipeline consumer closes stdout.
- Redact encoded Basic credentials in API diagnostics and explain permission failures.
- Preserve config symlinks, improve CA and usage errors, and handle interrupted output.
- Correct interactive-login documentation and expand command examples.
- Keep saved-login diagnostics and profile removal consistent across keyring and file stores.

## [0.0.2](https://github.com/rvben/splunk-cli/compare/v0.0.1...v0.0.2) - 2026-11-03

### Added

- **auth**: add interactive login with OS credential storage ([3c03442](https://github.com/rvben/splunk-cli/commit/3c03442c1430e39bb94e4c6f9e97113c99a50f34))

## [0.0.1] - 2026-11-03

### Added

- add clispec-compliant Splunk CLI and PyPI packaging

### Fixed

- **ci**: install the v0.3 scorer from pinned source ([dc3d4ff](https://github.com/rvben/splunk-cli/commit/dc3d4ff2c42a27a0d0f3f4f9280203832805d717))
