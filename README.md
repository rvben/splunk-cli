# splunk-cli

A Rust CLI for searching and inspecting Splunk from a terminal, scripts, and
agents. Uses Splunk's management REST API, with an offline [clispec v0.3](https://clispec.dev)
contract, paginated JSON, and stable errors.

The binary is named `splunk-cli` so it can coexist with Splunk's bundled `splunk`
command. This is an independent project, unaffiliated with Splunk.

## Install

```sh
uv tool install splunk-cli
# Or run without installing:
uvx splunk-cli --help
# pipx works too:
pipx install splunk-cli
```

PyPI distributions include native wheels for Linux and macOS (x64/ARM64), and
Windows x64, plus a source distribution. Building from source requires Rust 1.90
or newer:

```sh
cargo install --path . --locked
```

## Connect

Use the **management URL**, usually port 8089, rather than the Splunk Web URL
on port 8000. Splunk Cloud deployments may require REST API access to be enabled
and your source IP to be allowed by an administrator.

```sh
splunk-cli init --profile work
splunk-cli profile use work
splunk-cli doctor
splunk-cli auth status
splunk-cli server info
```

`init` (or `auth login`) prompts for the management URL (if not already configured), an
authentication method, and a hidden token or password. Credentials are validated
against Splunk before saving in macOS Keychain, Windows Credential Manager, or
Linux Secret Service. When no credential store is available (for example on
WSL), an interactive login asks before saving to `credentials.json` next to the
config file (mode 0600 on Unix); `--insecure-storage` selects that file without
asking. Connection settings stay in the TOML config. If an old OS credential cannot
be removed after saving a file login, a warning explains how to prevent it from
overriding the new login when the OS store becomes available again.
Login saves supplied connection settings, including flag/environment overrides.

```sh
splunk-cli auth login --profile work --url https://splunk.example.com:8089 --method token
splunk-cli auth login --profile work --method password --username myuser
splunk-cli auth logout --profile work
# For automation, read a token from stdin without putting it in shell history:
secret-manager read splunk/token | splunk-cli auth login --profile work --token-stdin
```

Saved credentials are scoped to the config file, profile, and management URL.
Changing the URL requires logging in again. `auth logout` removes only the saved
credential for that connection; it does not revoke the token on Splunk or clear
environment variables. Expired or revoked credentials require logging in again.
To remove a previous server's saved credential after changing URLs, use
`splunk-cli auth logout --profile work --url https://old-host:8089`.
Prompts use the terminal and never stdout. Without a terminal, interactive login
fails immediately; `--token-stdin` requires an existing URL or `--url`.

Environment credentials override saved credentials and accept exactly one of:

- `SPLUNK_TOKEN`: authentication token sent as `Authorization: Bearer …`.
- `SPLUNK_SESSION_KEY`: existing session key sent as `Authorization: Splunk …`.
- `SPLUNK_USERNAME` and `SPLUNK_PASSWORD`: HTTP basic authentication.

Secrets are never accepted as command-line flags or stored in TOML profiles.
Use a least-privilege Splunk account; access follows that account's permissions.
TLS certificates are verified by default. `--ca-cert /path/to/ca.pem` adds an
internal certificate authority; `--insecure` disables verification for the current
invocation. Sending credentials over plain HTTP to a remote host requires
explicit `--allow-http` (loopback mock/development servers are exempt). HTTP redirects and automatic request retries are disabled.

### Browser sign-in (SSO)

Deployments that sign in through SAML or another identity provider cannot use
basic authentication. `auth login --method browser` opens a private browser
window on Splunk Web, waits up to five minutes for you to complete your normal
sign-in, and saves the resulting Splunk session for the profile. The CLI never
sees your identity-provider password.

```sh
splunk-cli config set --profile work \
  --url https://splunk.example.com:8089 \
  --web-url https://splunk.example.com/
splunk-cli --profile work auth login --method browser
splunk-cli --profile work search 'index=_internal | head 5'
```

The Splunk Web URL defaults to HTTPS on the management host without a port; set
`--web-url` (or `SPLUNK_WEB_URL`, or `web_url` in the profile) when Splunk Web
lives elsewhere or under a path prefix. Chrome, Edge, Chromium and Firefox are
detected automatically, including Windows browsers from WSL; `--browser` (or
`SPLUNK_BROWSER`) selects a browser name or executable path. The browser runs
with a temporary profile that is deleted afterwards. Sessions expire according
to the server's session timeout; commands then fail with an `auth` error and a
hint to log in again.

## Search

```sh
splunk-cli search 'index=main error | stats count by host' --earliest -1h
splunk-cli search '| makeresults | eval message="hello"' --fields message
splunk-cli search 'index=main' --limit 20 --output json
splunk-cli search --file investigation.spl --earliest -7d
cat investigation.spl | splunk-cli search --file -

# Long-running searches: submit once, then inspect and page the same job.
splunk-cli jobs create 'index=main | stats count by sourcetype' --earliest -7d
splunk-cli jobs show JOB_ID
splunk-cli jobs watch JOB_ID --wait-timeout 600
splunk-cli jobs wait JOB_ID --quiet
splunk-cli jobs results JOB_ID --limit 100 --offset 0 --fields sourcetype,count
splunk-cli jobs results JOB_ID --limit 100 --offset 100
splunk-cli jobs list --limit 20 --fields name,dispatchState,isDone
```

Bare expressions such as `index=main` gain a `search` prefix; queries starting
with `search` or `|` are preserved. Default time bounds are `-24h` through `now`.
`--timeout` bounds each HTTP request (30 seconds by default); `search
--wait-timeout` bounds polling (120 seconds by default). A timed-out or interrupted wait leaves
the job available, and its ID appears in the structured error. Results are
returned only after completion; failed, canceled, and running jobs are reported
explicitly. Results use the v2 API available in Splunk 9.0.1 and later.

Submitting a search creates a new job. **SPL can write data** through commands
such as `collect`, `outputlookup`, and app-provided commands. Repeating a search
or dispatch can repeat those effects. There is no claimed idempotency key;
inspect the existing job before resubmitting after an ambiguous failure.
Use `jobs results JOB_ID` to continue paging rather than running `search` again.

## Export completed results

```sh
splunk-cli jobs export JOB_ID --fields _time,host,_raw --output jsonl > events.jsonl
splunk-cli jobs export JOB_ID --max-results 50000 --page-size 1000 --output csv > results.csv
# Resume the same job using the previous export's next_offset:
splunk-cli jobs export JOB_ID --offset 50000 --max-results 50000 --output jsonl >> events.jsonl
```

Export fetches pages of an existing completed job; it never creates another
search. The default bound is 10,000 records, configurable from 1 to 1,000,000,
with page sizes from 1 to 10,000. The combined record JSON is capped at 32 MiB;
reaching this bound returns the records that fit and their continuation cursor
with `byte_limit_reached: true`. Select fields to reduce large events. Results are buffered
within these bounds, so a failed page produces no partial stdout. JSON exports
retain the collection envelope, `job_id`, `next_offset`, `next_cursor`, and
`bounded` (whether more records remain). An empty page before Splunk's reported
total sets `truncated` and stops; inspect the search job's result limits.
CSV and JSONL contain records only, with counts and continuation metadata on
stderr. When written directly to a terminal, CSV escapes control characters
for safe display; redirected exports preserve raw values. JSON/JSONL use valid
JSON Unicode escapes for terminal controls without changing decoded values.
Keep the same `--fields` when appending JSONL. For CSV, combine subsequent
exports with a CSV-aware tool to avoid duplicate headers. CSV uses the requested
field order and standard quoting; multi-value fields retain JSON array text.

## Saved searches and indexes

```sh
splunk-cli saved-searches list --fields name,search,disabled
splunk-cli saved-searches show 'Daily errors'
splunk-cli saved-searches run 'Daily errors'
splunk-cli indexes list --fields name,totalEventCount,currentDBSizeMB
splunk-cli indexes show main
```

Searches, jobs, and saved searches use `/servicesNS/OWNER/APP`; the defaults are
`nobody/search`. Pass `--owner USER --app APP` to access a different namespace.
Use `--owner=- --app=-` for cross-namespace discovery. If a definition matches
multiple resources, `show` refuses the ambiguous result; select an explicit
owner and app. Saved-search dispatch sets `trigger_actions=0` to disable alert
actions, while the SPL itself still runs with its normal effects.

## Preview and job cleanup

```sh
splunk-cli search 'index=main | stats count' --dry-run
splunk-cli saved-searches run 'Daily errors' --dry-run
splunk-cli jobs cancel JOB_ID --dry-run
splunk-cli jobs cancel JOB_ID --yes
splunk-cli jobs delete JOB_ID --yes
```

Dry runs make no network requests and need no credentials. Cancel and delete
require `--yes` in both interactive and non-interactive use. Deleting or canceling
a missing job is a successful no-op (`changed: false`). Cancellation cannot
undo effects the SPL has already performed.

## Output and discovery

```sh
splunk-cli schema
splunk-cli schema jobs results
splunk-cli schema saved-searches
splunk-cli completions zsh > _splunk-cli
splunk-cli indexes list --output text
```

`--output auto` chooses aligned tables on a terminal and JSON when piped.
Explicit `--output json|text|csv|jsonl` always wins (`table` aliases `text`,
`ndjson` aliases `jsonl`). Collection responses use:

```json
{"items":[{"name":"main"}],"total":42,"offset":0,"limit":1,"has_more":true,"next_offset":1}
```

Search results additionally include `job_id` and `next_cursor`.
Pass that cursor to `splunk-cli search --cursor CURSOR` without a query to page
the same job; this performs only GET requests and never resubmits SPL. Single-record commands return an
object directly. `--fields` selects exact output keys, including dotted Splunk
keys. SPL files/stdin must be UTF-8 and at most 1 MiB. Collection limits default to 100 and allow 1–10000; zero/unlimited is
rejected. Unknown totals are `null`; a lookahead record determines `has_more`.
An unexpectedly empty page with remaining reported results sets `truncated: true`
and stops continuation to avoid a pagination loop. Responses above 32 MiB fail with an instruction to narrow the page or fields.
Text mode shows selected columns for raw events, indexes, jobs, saved searches, and profiles,
fits terminal width, and escapes event control characters. Use `--fields` to
choose columns or JSON to preserve every field without display truncation. Output contains no ANSI color and respects `--no-color` and
`NO_COLOR` by construction.

Data goes to stdout; progress and errors go to stderr. `--quiet` suppresses
progress, while Splunk warnings and incomplete-export notices remain visible.
Repeated warnings are deduplicated per invocation (up to 64 distinct messages).
Closed stdout pipelines (for example, `| head`) exit quietly with success. JSON errors are a single envelope on the last line of stderr:

```json
{"error":{"kind":"auth","message":"No complete credentials configured","exit_code":3}}
```

| Exit | Kind | Meaning |
|---:|---|---|
| 0 | — | Success |
| 2 | `usage` | Invalid arguments or configuration |
| 3 | `auth` | Missing credentials, rejected credentials, or denied access |
| 4 | `not_found` | Missing resource |
| 5 | `api` | Splunk API error or failed search |
| 6 | `rate_limit` | Rate limited; `details.retry_after` when supplied |
| 7 | `conflict` | Ambiguous resource or results not yet complete |
| 8 | `confirmation_required` | Missing `--yes` |
| 9 | `timeout` | HTTP request or search wait timed out |
| 10 | `transport` | Network or TLS failure |
| 11 | `invalid_response` | Unexpected, malformed, or oversized response |
| 12 | `io` | Local filesystem or output failure |
| 130 | `interrupted` | Stopped waiting; existing search job preserved |

Only `init` and `auth login` prompt for input. Schema, help, version, and completions work without
a connection or configuration. The schema is derived from the parser's actual
arguments, and includes side effects, output shapes, pagination, and error codes.
The v0.3 specification is a candidate; this repository vendors the version used
by its conformance tests. The CLI and its output contract are experimental.

## Profiles

Settings resolve in this order: command-line flags, environment, selected
profile, defaults. Profile selection uses `--profile`, then `SPLUNK_PROFILE`,
then the saved `active_profile`, then `default`. `SPLUNK_CONFIG` or `--config` overrides the file location;
otherwise it is `$XDG_CONFIG_HOME/splunk-cli/config.toml` or
`~/.config/splunk-cli/config.toml`.

```toml
active_profile = "work"

[profiles.work]
url = "https://splunk.example.com:8089"
app = "search"
owner = "nobody"
timeout = 30
# web_url = "https://splunk.example.com/"
# ca_cert = "/path/to/internal-ca.pem"
```

`config set` saves the supplied flag/environment settings to the selected profile,
retaining other settings and profiles. Writes are locked and atomic, preserve config symlinks, and use
private file permissions on Unix. Config writes normalize TOML formatting;
paths must be UTF-8. `config set --dry-run` previews the change.
`config show` displays the resolved settings; `config path` shows only the path.
Credentials, `--insecure`, and `--allow-http` are never persisted. Certificate
paths supplied through `config set` are saved as absolute paths.

```sh
splunk-cli profile list
splunk-cli profile use work
splunk-cli profile remove old --dry-run
splunk-cli profile remove old --yes
splunk-cli auth status --offline
splunk-cli doctor --offline
```

`profile remove` deletes local connection settings and the saved credential for
that profile's configured server, without revoking remote tokens. It requires
an accessible credential store when the profile has a valid URL; a failed
deletion preserves settings. In a headless environment, explicitly pass
`--keep-credentials` to remove settings while leaving saved credentials untouched;
`credentials_removed` is then `null` and a warning is printed. Profile lists mark
invalid settings with `valid: false` and hide invalid URLs. Use
`--keep-credentials` to remove a profile whose URL is malformed. Credentials for historical URLs should be removed with
`auth logout --url OLD_URL` before removing the profile. Removing the saved active
profile resets selection to `default`; create or select another profile if needed.

`auth status --offline` reports availability, source, and method; it returns
`authenticated: null` because no server validation occurred. `doctor --offline`
also checks configuration and certificate/client setup. Online `doctor` validates
authentication, management API access, the selected job namespace, and visible
indexes using read-only requests. It never submits SPL or tests write permissions.
Failures use the normal exit code and error envelope, with completed and failed
checks in `error.details.checks` and an actionable hint.

| Variable | Setting |
|---|---|
| `SPLUNK_URL` | Management base URL |
| `SPLUNK_PROFILE` | Override the saved active profile |
| `SPLUNK_CONFIG` | Configuration file path |
| `SPLUNK_APP` | Application namespace |
| `SPLUNK_OWNER` | Owner namespace |
| `SPLUNK_TIMEOUT` | Per-request timeout in seconds |
| `SPLUNK_CA_CERT` | Additional PEM certificate authority |

## Development

```sh
make check               # formatting, Clippy, and mock API / CLI tests
cargo +1.90.0 check --locked --all-targets
make conformance         # requires the clispec v0.3 scorer
```

The default tests use local HTTP servers and require no Splunk account. Run
`SPLUNK_ACCEPT_LICENSE=yes make test-live` for opt-in checks against a disposable
Splunk server on a native x86 Docker daemon, including saved terminal login,
token expiry, profile isolation, searches, jobs, saved searches, and indexes.
Docker contexts and `DOCKER_HOST` support homelab execution; see the
[live test instructions](tests/live/README.md). Endpoint behavior follows Splunk's
[search API reference](https://help.splunk.com/en/splunk-enterprise/rest-api-reference/10.2/search-endpoints/search-endpoint-descriptions)
and [authentication documentation](https://help.splunk.com/en/splunk-enterprise/administer/manage-users-and-security/10.2/authenticate-into-the-splunk-platform-with-tokens/use-authentication-tokens).

Releases use [vership](docs/releases.md). Licensed under [MIT](LICENSE).
