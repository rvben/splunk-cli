# Live Splunk checks

Run the public CLI against a disposable, digest-pinned Splunk 10.6.1.1 server:

```sh
SPLUNK_ACCEPT_LICENSE=yes make test-live
# Both supported test versions, sequentially:
SPLUNK_ACCEPT_LICENSE=yes make test-live-matrix
# Select the second pinned version:
SPLUNK_ACCEPT_LICENSE=yes SPLUNK_TEST_VERSION=9.4.9 make test-live
```

Requires Python 3 and a **native x86_64 Linux Docker daemon**. To use homelab
capacity from a Mac, select an existing Docker context, or use SSH:

```sh
DOCKER_HOST=ssh://user@your-x86-test-host SPLUNK_ACCEPT_LICENSE=yes make test-live
```

The account must have Docker access. Source is built on that daemon; no checkout,
Rust installation, or Splunk credentials are needed on the host. Reserve at least
3 GiB available memory and 15 GiB free Docker storage. Build completes before
the server starts; runtime limits are 2 GiB/2 CPUs for Splunk and 512 MiB/1 CPU
for the test client.

Setting `SPLUNK_ACCEPT_LICENSE=yes` explicitly acknowledges the Splunk license
and [current General Terms](https://www.splunk.com/en_us/legal/splunk-general-terms.html).
The runner passes the official image's required acceptance flags. Run this only
on authorized test infrastructure.

Coverage includes hidden terminal password/token prompts, piped token login,
Linux Secret Service persistence, rejected credentials, environment precedence,
profile/config/server isolation, token expiration and disabling, scoped logout,
`init`, online/offline diagnostics, active profile selection and scoped profile
removal, real SPL from arguments/files/stdin, pagination, job wait/watch, bounded
export and resume, CSV/JSONL, terminal tables, asynchronous job management, saved
search dispatch, index reads, and fixture cleanup. Token fixtures follow Splunk's
[creation](https://help.splunk.com/en/splunk-enterprise/administer/manage-users-and-security/10.2/authenticate-into-the-splunk-platform-with-tokens/create-authentication-tokens)
and [management](https://help.splunk.com/en/splunk-enterprise/administer/manage-users-and-security/10.2/authenticate-into-the-splunk-platform-with-tokens/manage-or-delete-authentication-tokens)
APIs. The suite changes token settings only on its disposable server.

Each invocation generates a new password, container names, temporary config,
and Linux Secret Service keyring. It publishes no ports, mounts no host
credentials or Docker socket into the containers, and removes its containers,
anonymous volumes, and runner image on exit. Docker's build cache and the pinned
Splunk image remain available for later runs. If the client is killed with SIGKILL
or loses access to the Docker daemon, remove only the containers labeled
`splunk-cli.live-test=true` belonging to that invocation.

The containers share a loopback-only network namespace with no external
network access. Tests wait for both the image healthcheck and KV Store readiness.
Expiration and disabling checks require rejection within 180 seconds, allowing
for Splunk's server-side delay; they verify successful authentication first.

These checks are deliberately separate from `make check`: they start licensed
software and need native x86 resources. The live workflow runs the full matrix
on a dedicated 4 GiB/2 CPU Husker VM with its own Docker daemon and repo-scoped
runner. It runs weekly, by manual dispatch on main, and as a required PyPI
publication gate. Checkout must be integrated into origin/main; pull requests
and forks cannot enter this workflow. All external contributors require workflow
approval. Keep those protections enabled and never approve untrusted code for
homelab execution. The runner has no access to the host Docker socket.

The suite also verifies migration between Secret Service and file storage,
parse-only SPL checking, job search logs, interrupted streaming CSV recovery,
and restricted-user search access with denial of a private administrator job.
The [compatibility matrix](../../docs/compatibility.md) distinguishes live server
checks from local browser-protocol and private-CA TLS fixtures.
