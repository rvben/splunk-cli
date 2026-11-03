"""Opt-in public CLI checks against the disposable server from test-live.sh."""

import base64
import json
import os
from pathlib import Path
import pty
import select
import signal
import ssl
import subprocess
import tempfile
import termios
import time
import traceback
import urllib.error
import urllib.parse
import urllib.request


URL = "https://127.0.0.1:8089"
PASSWORD = os.environ.pop("SPLUNK_PASSWORD")
SECRETS = [PASSWORD, base64.b64encode(("admin:" + PASSWORD).encode()).decode()]
ENV = {k: v for k, v in os.environ.items() if not k.startswith("SPLUNK_")}
CONTEXT = ssl._create_unverified_context()  # Only the disposable local server.
ROOT = Path(tempfile.mkdtemp(prefix="splunk-cli-live-"))
JOBS = []
TOKENS = []
SAVED = "splunk-cli-live-" + ROOT.name.rsplit("-", 1)[-1]
SAVED_CREATED = False
PROFILES = ("password", "token", "expires", "other")


class ApiError(AssertionError):
    def __init__(self, method, endpoint, status, messages):
        super().__init__(f"{method} {endpoint}: HTTP {status}, {messages}")
        self.status = status


def command(args, profile="password", config=None, url=URL):
    return ["splunk-cli", "--config", str(config or ROOT / "config.toml"),
            "--profile", profile, "--url", url, "--insecure",
            "--output", "json", "--timeout", "30", *args]


def cli(*args, profile="password", env=None, stdin=None, code=0, config=None, url=URL):
    result = subprocess.run(command(args, profile, config, url), env=ENV | (env or {}), input=stdin,
                            capture_output=True, text=True, timeout=180)
    assert not any(s in result.stdout + result.stderr for s in SECRETS), "CLI leaked a secret"
    expected = (code,) if isinstance(code, int) else code
    assert result.returncode in expected, f"{args[:2]}: expected exit {code}, got {result.returncode}: {result.stderr}"
    value = json.loads(result.stdout if result.returncode == 0 else result.stderr)
    if result.returncode:
        assert value["error"]["exit_code"] == result.returncode
        if result.returncode == 3:
            assert value["error"]["kind"] == "auth"
    return value


def api(method, endpoint, **params):
    query = urllib.parse.urlencode({"output_mode": "json"} | (params if method == "DELETE" else {}))
    body = urllib.parse.urlencode(params).encode() if method == "POST" else None
    auth = base64.b64encode(("admin:" + PASSWORD).encode()).decode()
    request = urllib.request.Request(URL + endpoint + "?" + query, data=body,
                                    headers={"Authorization": "Basic " + auth,
                                             "User-Agent": "splunk-cli-live-test"}, method=method)
    try:
        with urllib.request.urlopen(request, context=CONTEXT, timeout=30) as response:
            data = response.read()
            return json.loads(data) if data else {}
    except urllib.error.HTTPError as error:
        try:
            messages = json.loads(error.read(65536)).get("messages", [])
        except (ValueError, AttributeError):
            messages = []
        raise ApiError(method, endpoint, error.code, messages) from None


def wait_ready():
    deadline = time.monotonic() + 600
    while time.monotonic() < deadline:
        try:
            api("GET", "/services/authentication/current-context")
            return
        except (urllib.error.URLError, TimeoutError, ConnectionError):
            time.sleep(2)
        except ApiError as error:
            if error.status < 500:
                raise
            time.sleep(2)
    raise AssertionError("Splunk management API did not become ready within 600 seconds")


def wait_kvstore():
    deadline = time.monotonic() + 180
    status = "unknown"
    while time.monotonic() < deadline:
        try:
            content = api("GET", "/services/kvstore/status")["entry"][0]["content"]
            status = content["current"]["status"]
            if status == "ready":
                return
        except ApiError as error:
            if error.status != 503:
                raise
        time.sleep(2)
    raise AssertionError(f"Splunk KV Store did not become ready within 180 seconds (status={status})")


def interactive_login(method, secret, profile="password", code=0):
    args = ["auth", "login", "--method", method]
    if method == "password":
        args += ["--username", "admin"]
    pid, terminal = pty.fork()
    if pid == 0:
        try:
            os.execvpe("splunk-cli", command(args, profile), ENV)
        except BaseException:
            os._exit(127)
    captured = bytearray()
    sent = False
    status = None
    deadline = time.monotonic() + 90
    try:
        while time.monotonic() < deadline:
            if not select.select([terminal], [], [], .1)[0]:
                continue
            try:
                chunk = os.read(terminal, 65536)
            except OSError as error:
                if error.errno != 5:  # PTY EOF on Linux.
                    raise
                break
            if not chunk:
                break
            captured.extend(chunk)
            prompt = f"Splunk {'password' if method == 'password' else 'token'} (hidden):".encode()
            if not sent and prompt in captured:
                # The prompt can be flushed just before rpassword disables echo.
                while termios.tcgetattr(terminal)[3] & termios.ECHO:
                    assert time.monotonic() < deadline, "Login did not disable terminal echo"
                    time.sleep(.01)
                os.write(terminal, (secret + "\n").encode())
                sent = True
        else:
            raise AssertionError("Interactive login timed out")
        # EOF follows process termination; reap without an unbounded wait.
        while time.monotonic() < deadline:
            done, candidate = os.waitpid(pid, os.WNOHANG)
            if done:
                status = candidate
                break
            time.sleep(.05)
        else:
            raise AssertionError("Login did not exit after closing its terminal")
        assert sent, "Login did not show the hidden credential prompt"
        assert not any(s.encode() in captured for s in SECRETS), "Login echoed a credential"
        assert os.waitstatus_to_exitcode(status) == code, "Interactive login returned an unexpected exit code"
        if code == 0:
            assert b'"authenticated":true' in captured
    finally:
        if status is None:
            os.kill(pid, signal.SIGKILL)
            os.waitpid(pid, 0)
        os.close(terminal)


def assert_authenticated(profile="password"):
    status = cli("auth", "status", profile=profile)
    assert status["authenticated"] is True
    assert status["context"]["username"] == "admin"


def wait_auth_failure(profile):
    # Observe rejection through fresh CLI processes. Splunk may continue
    # accepting a token briefly past its deadline or a token-setting change.
    deadline = time.monotonic() + 180
    while time.monotonic() < deadline:
        status = cli("auth", "status", profile=profile, code=(0, 3))
        if "error" in status:
            assert status["error"]["kind"] == "auth"
            return
        assert status["authenticated"] is True
        time.sleep(2)
    raise AssertionError(f"Saved {profile} token was still accepted after 180 seconds")


def make_token(expiry):
    result = api("POST", "/services/authorization/tokens", name="admin",
                 audience="splunk-cli-live-test", expires_on=expiry)
    token = result["entry"][0]["content"]
    TOKENS.append(token["id"])
    SECRETS.append(token["token"])
    return token["token"], token["id"]


def check_auth():
    interactive_login("password", PASSWORD)
    assert_authenticated()
    invalid = "invalid-test-credential"
    SECRETS.append(invalid)
    interactive_login("password", invalid, code=3)
    assert_authenticated()  # Failed replacement must preserve the saved login.
    assert cli("auth", "status", env={"SPLUNK_TOKEN": invalid}, code=3)["error"]["kind"] == "auth"
    assert_authenticated()  # Environment override must not replace the keyring entry.
    print("PASS: hidden password login, saved credentials, failed replacement and environment precedence", flush=True)

    wait_kvstore()
    api("POST", "/services/admin/token-auth/tokens_auth", disabled="false")
    token, token_id = make_token("+10m")
    interactive_login("token", token, profile="token")
    assert_authenticated("token")
    assert cli("auth", "status", profile="other", code=3)["error"]["kind"] == "auth"
    cli("auth", "status", profile="token", config=ROOT / "other.toml", code=3)
    cli("auth", "status", profile="token", url="https://localhost:8089", code=3)
    assert cli("auth", "login", "--token-stdin", profile="other", stdin=token + "\n")["authenticated"] is True
    assert_authenticated("other")
    assert cli("auth", "logout", profile="token")["removed"] is True
    assert cli("auth", "logout", profile="token")["removed"] is False
    cli("auth", "status", profile="token", code=3)
    assert_authenticated()
    assert_authenticated("other")  # Logout affects only the selected profile.
    print("PASS: hidden and piped token login, profile/config/server isolation, scoped idempotent logout", flush=True)

    short, _ = make_token("+15s")
    cli("auth", "login", "--token-stdin", profile="expires", stdin=short + "\n")
    assert_authenticated("expires")
    # Wait on the signed token's actual expiry, rather than assuming host clocks match.
    payload = short.split(".")[1]
    expires = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))["exp"]
    wait = max(0, expires - time.time() + 2)
    assert wait < 60, "Unexpected short-lived token expiry"
    time.sleep(wait)
    wait_auth_failure("expires")
    print("PASS: saved token succeeds before expiry and returns structured auth failure after expiry", flush=True)

    api("POST", "/services/authorization/tokens/admin", id=token_id, status="disabled")
    wait_auth_failure("other")
    assert_authenticated()
    print("PASS: disabled token is rejected while the password profile remains usable", flush=True)
    for path in ROOT.glob("*.toml"):
        assert not any(secret in path.read_text() for secret in SECRETS), "Config contains credentials"
    for path in Path.home().rglob("*"):
        if path.is_file():
            contents = path.read_bytes()
            assert not any(secret.encode() in contents for secret in SECRETS), "HOME contains plaintext credentials"


def wait_job(job):
    deadline = time.monotonic() + 120
    while time.monotonic() < deadline:
        state = cli("jobs", "show", job)
        if state.get("isDone") in (True, 1, "1"):
            return
        assert state.get("isFailed") not in (True, 1, "1"), "Search job failed"
        time.sleep(.5)
    raise AssertionError("Search job did not complete within 120 seconds")


def check_workflows():
    global SAVED_CREATED
    indexes = cli("indexes", "list", "--limit", "5", "--fields", "name")["items"]
    assert 0 < len(indexes) <= 5
    assert cli("indexes", "show", indexes[0]["name"], "--fields", "name") == indexes[0]
    print("PASS: indexes list/show and field projection", flush=True)

    first = cli("search", '| makeresults count=3 | streamstats count as row | eval message="splunk-cli-live" | table row message',
                "--wait-timeout", "120", "--limit", "2", "--fields", "row,message")
    JOBS.append(first["job_id"])
    assert len(first["items"]) == 2 and first["next_cursor"]
    second = cli("search", "--cursor", first["next_cursor"], "--limit", "2", "--fields", "row,message")
    assert second["job_id"] == first["job_id"]
    assert len(second["items"]) == 1 and second["next_cursor"] is None
    assert first["items"] + second["items"] == [
        {"row": str(row), "message": "splunk-cli-live"} for row in (1, 2, 3)]
    print("PASS: real SPL search, field projection and reusable pagination cursor", flush=True)

    job = cli("jobs", "create", '| makeresults | eval message="async-live"')["job_id"]
    JOBS.append(job)
    wait_job(job)
    assert cli("jobs", "results", job, "--fields", "message")["items"] == [{"message": "async-live"}]
    assert len(cli("jobs", "list", "--limit", "5")["items"]) <= 5
    assert cli("jobs", "cancel", job, "--yes")["changed"] is True
    cli("jobs", "show", job, code=4)  # Splunk cancellation removes the job.
    assert cli("jobs", "delete", job, "--yes")["changed"] is False
    assert cli("jobs", "delete", first["job_id"], "--yes")["changed"] is True
    assert cli("jobs", "delete", first["job_id"], "--yes")["changed"] is False
    print("PASS: async job create/show/results/list/cancel/delete and repeated deletion", flush=True)

    api("POST", "/servicesNS/nobody/search/saved/searches", name=SAVED,
        search='| makeresults | eval message="saved-live"', is_scheduled="0")
    SAVED_CREATED = True
    items = cli("saved-searches", "list", "--limit", "10000", "--fields", "name")["items"]
    assert {"name": SAVED} in items
    assert cli("saved-searches", "show", SAVED, "--fields", "name")["name"] == SAVED
    job = cli("saved-searches", "run", SAVED)["job_id"]
    JOBS.append(job)
    wait_job(job)
    assert cli("jobs", "results", job, "--fields", "message")["items"] == [{"message": "saved-live"}]
    print("PASS: saved search list/show/dispatch and result retrieval", flush=True)


def cleanup():
    failures = []

    def remove(action):
        try:
            action()
        except Exception as error:
            failures.append(str(error))

    for job in JOBS:
        remove(lambda: cli("jobs", "delete", job, "--yes", env={"SPLUNK_USERNAME": "admin", "SPLUNK_PASSWORD": PASSWORD}))
    if SAVED_CREATED:
        remove(lambda: api("DELETE", "/servicesNS/nobody/search/saved/searches/" + SAVED))
    for token in TOKENS:
        remove(lambda: api("DELETE", "/services/authorization/tokens/admin", id=token))
    for profile in PROFILES:
        remove(lambda: cli("auth", "logout", profile=profile))
        remove(lambda: cli("auth", "status", profile=profile, code=3))
    assert not failures, "Fixture cleanup failed: " + "; ".join(failures)


def main():
    print("Waiting for the disposable Splunk management API (up to 600 seconds)...", flush=True)
    wait_ready()
    credentials = {"SPLUNK_USERNAME": "admin", "SPLUNK_PASSWORD": PASSWORD}
    assert cli("auth", "status", env=credentials)["authenticated"] is True
    version = cli("server", "info", env=credentials)["version"]
    print(f"PASS: authenticated public CLI against Splunk {version}", flush=True)
    try:
        check_auth()
        check_workflows()
    except Exception as original:
        try:
            cleanup()
        except Exception as cleanup_error:
            raise AssertionError(f"{original}; additionally: {cleanup_error}") from None
        raise
    else:
        cleanup()
    print("PASS: fixture and credential cleanup", flush=True)


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        frame = traceback.extract_tb(error.__traceback__)[-1]
        message = f"{type(error).__name__} in {frame.name}:{frame.lineno}: {error}"
        for secret in SECRETS:
            message = message.replace(secret, "[REDACTED]")
        print("FAIL: " + message, flush=True)
        raise SystemExit(1) from None
