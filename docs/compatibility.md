# Compatibility policy

## The 0.1.x contract

Patch releases preserve command names, flags, aliases, successful JSON field
types, error kinds, and exit codes documented by `splunk-cli schema`. New fields
and optional flags may be added; consumers should ignore unknown fields and
select exact keys rather than parsing terminal tables. Splunk-owned content
fields depend on the server and installed apps. `null` totals remain valid.
Human-readable text, progress timing, and error wording may improve in patches.
Breaking contract changes require a minor release while the project is below 1.0.

`table` continues to alias `text`, and `ndjson` aliases `jsonl`. JSON is the
automation format; CSV/JSONL record output deliberately omits collection
envelopes. Streaming file exports return a separate summary on stdout.

Continuation strings are opaque and versioned. New cursors bind the server,
app/owner namespace, and field selection. They contain no credentials or SPL.
Legacy `SID:OFFSET` strings remain accepted throughout 0.1.x, with a warning;
they cannot validate connection context. Cursors depend on the original job's
retention and permissions and are not portable to another Splunk installation.

Version 1 export checkpoints remain resumable throughout 0.1.x. Keep the output
and checkpoint together and use the original connection, job, fields and record
format. Resume verifies durable bytes before removing an incomplete tail. It
cannot recover deleted jobs, modified durable data, or changed server results.
Checkpoints are local recovery metadata, not authentication or authorization.

## Upgrade from 0.0.x

Existing profiles and saved logins remain usable. The first successful login,
migration, rename or logout writes nonsecret credential-selection metadata to
the config. This prevents stale credentials from another store from taking over
and prevents a logged-out connection from reviving an old login.

**0.0.3 cannot read a config containing `credential_states`.** Back up the config
before upgrading if you may need to downgrade. Use a separate config path and a
fresh login with an older binary; copying only profile settings loses the new
selection and logout guarantees. Never remove the metadata merely to revive an
obsolete credential. A renamed profile moves known saved connections; historical
URLs used before selection metadata existed require explicit logout under the
old name.

## Server and platform coverage

The v2 search API requires Splunk 9.0.1 or later. That API minimum is not a claim
that every intervening Splunk version has been tested. The live CI matrix uses
official digest-pinned Enterprise images, sequentially, on a dedicated x86_64
Husker VM. It covers the public CLI with administrator and restricted user roles,
hidden terminal login, Secret Service and file migration, real searches,
parse-only checks, logs, bounded and streaming exports, recovery, and cleanup.

| Environment | Validation |
|---|---|
| Enterprise 10.6.1.1, Linux x64 | Live public CLI suite |
| Enterprise 9.4.9, Linux x64 | Live CI matrix |
| Linux/macOS/Windows | CLI, HTTP fixture and schema regression tests in CI |
| Private CA TLS | Public CLI: untrusted connection rejected, explicit CA accepted |
| HTTP proxy with browser login | Localhost debugging bypasses the proxy |
| Native browser cancellation | Public CLI: exit 130, browser termination, profile removal |
| Chromium CDP, Firefox BiDi, WSL PowerShell | Protocol fixtures; no external identity provider in CI |

Cloud access policies, enterprise identity providers, browser management
policies, and Windows/WSL browser cleanup need deployment-specific validation.
Browser sign-in uses a private profile and validates its session with the API;
neither a browser cookie nor a token's unverified expiry claim proves API access.
On WSL, avoid forcibly terminating Windows PowerShell during sign-in; its normal
cleanup closes the browser and removes its Windows profile. If it is killed,
close the private browser and remove its temporary profile manually.

PyPI ships native wheels for Linux x64/ARM64, macOS x64/ARM64, and Windows x64,
plus an sdist. Builds from source require Rust 1.90+. The native live Splunk suite
requires x86_64 with AVX2; Apple Silicon emulation is not part of this matrix.
