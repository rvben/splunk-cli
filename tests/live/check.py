"""Opt-in public CLI checks against the disposable server from test-live.sh."""

import base64
import csv
import io
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
RESTRICTED_CREATED = False
RESTRICTED = "splunk_cli_reader"
PROFILES = ("password", "token", "expires", "other", "remove-test")


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
    value = json.loads(result.stdout if result.returncode == 0 else result.stderr.splitlines()[-1])
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


def interactive_login(method, secret, profile="password", code=0, init=False):
    args = (["init"] if init else ["auth", "login"]) + ["--method", method]
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
    interactive_login("password", PASSWORD, init=True)
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


def formatted(format, *args, stdin=None):
    args = command(args)
    args[args.index("--output") + 1] = format
    result = subprocess.run(args, env=ENV | {"COLUMNS": "80"}, input=stdin,
                            capture_output=True, text=True, timeout=180)
    assert not any(s in result.stdout + result.stderr for s in SECRETS), "CLI leaked a secret"
    assert result.returncode == 0, f"Formatted output failed: {result.stderr}"
    return result


def check_experience():
    status = cli("auth", "status", "--offline")
    assert status["authenticated"] is None and status["credentials"]["source"] == "keyring"
    assert status["credentials"]["verified"] is False
    assert cli("doctor", "--offline")["ok"] is True
    report = cli("doctor")
    assert report["ok"] is True and report["credentials"]["verified"] is True
    assert all(check["status"] in ("ok", "warning") for check in report["checks"])
    # Deliberately switch stores for the same connection. Selection must be
    # deterministic even when the previous store is still accessible.
    cli("auth", "migrate", "--to", "file", "--insecure-storage")
    assert cli("auth", "status", "--offline")["credentials"]["source"] == "file"
    assert_authenticated()
    cli("auth", "migrate", "--to", "keyring")
    assert cli("auth", "status", "--offline")["credentials"]["source"] == "keyring"
    assert_authenticated()
    cli("profile", "use", "password")
    args = command(["config", "show"])
    index = args.index("--profile")
    del args[index:index + 2]
    selected = subprocess.run(args, env=ENV, capture_output=True, text=True, timeout=30)
    assert selected.returncode == 0 and json.loads(selected.stdout)["profile"] == "password"
    assert any(item["name"] == "password" and item["active"] for item in cli("profile", "list")["items"])
    interactive_login("password", PASSWORD, profile="remove-test")
    preview = cli("profile", "remove", "remove-test", "--dry-run")
    assert preview["dry_run"] is True
    assert_authenticated("remove-test")
    removed = cli("profile", "remove", "remove-test", "--yes")
    assert removed["removed"] is True and removed["credentials_removed"] is True
    cli("auth", "status", profile="remove-test", code=3)
    assert_authenticated()
    print("PASS: init, saved active profile, offline status, online/offline doctor and scoped profile removal", flush=True)


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

    limited = cli("search", "| makeresults count=3 | head 1 | eval message=\"head-live\" | table message")
    JOBS.append(limited["job_id"])
    limited_state = cli("jobs", "show", limited["job_id"])
    assert limited_state.get("isFinalized") not in (True, 1, "1", "true")
    assert cli("jobs", "export", limited["job_id"])["items"] == [{"message": "head-live"}]
    print("PASS: naturally completed head search stays exportable", flush=True)

    exported = cli("jobs", "export", first["job_id"], "--page-size", "1", "--max-results", "2", "--fields", "row,message")
    assert exported["items"] == first["items"] and exported["bounded"] is True
    assert exported["next_offset"] == 2
    rest = cli("jobs", "export", first["job_id"], "--offset", "2", "--fields", "row,message")
    assert rest["items"] == second["items"] and rest["bounded"] is False
    jsonl = formatted("jsonl", "jobs", "export", first["job_id"], "--page-size", "1", "--fields", "row,message")
    assert [json.loads(line) for line in jsonl.stdout.splitlines()] == first["items"] + second["items"]
    csv_result = formatted("csv", "jobs", "export", first["job_id"], "--fields", "row,message")
    assert list(csv.reader(io.StringIO(csv_result.stdout))) == [["row", "message"], ["1", "splunk-cli-live"], ["2", "splunk-cli-live"], ["3", "splunk-cli-live"]]
    table = formatted("table", "indexes", "list", "--limit", "3")
    assert table.stdout.startswith("NAME") and "EVENTS" in table.stdout
    assert all(len(line) <= 80 for line in table.stdout.splitlines())
    print("PASS: bounded multi-page export, resume, CSV/JSONL and terminal tables", flush=True)

    output = ROOT / "stream.csv"
    stream_args = ("jobs", "export", first["job_id"], "--stream", "--output-file", str(output),
                   "--record-format", "csv", "--fields", "row,message", "--page-size", "1")
    assert cli(*stream_args, "--max-results", "1")["exported"] == 1
    with output.open("a") as partial:
        partial.write("incomplete tail")
    assert cli(*stream_args, "--resume")["exported"] == 3
    assert list(csv.reader(io.StringIO(output.read_text()))) == [["row", "message"], ["1", "splunk-cli-live"], ["2", "splunk-cli-live"], ["3", "splunk-cli-live"]]
    assert cli("search", "check", "| makeresults | stats count")["valid"] is True
    assert isinstance(cli("jobs", "logs", first["job_id"])["log"], str)
    cli("search", "check", "| definitely_not_a_splunk_command", code=(2, 5))
    print("PASS: durable streaming recovery, parse-only SPL checks and job search logs", flush=True)

    source = ROOT / "query.spl"
    source.write_text('| makeresults | eval message="file-live" | table message')
    for args, stdin in [(("--file", str(source)), None), (("--file", "-"), source.read_text())]:
        result = cli("search", *args, "--fields", "message", stdin=stdin)
        JOBS.append(result["job_id"])
        assert result["items"] == [{"message": "file-live"}]
    print("PASS: SPL files and piped stdin against Splunk", flush=True)


    job = cli("jobs", "create", '| makeresults | eval message="async-live"')["job_id"]
    JOBS.append(job)
    waited = cli("jobs", "wait", job)
    assert waited["job_id"] == job
    watched = cli("jobs", "watch", job, "--quiet")
    assert watched["job_id"] == job and watched["isDone"] in (True, 1, "1")
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


def check_restricted_user():
    global RESTRICTED_CREATED
    import secrets
    password = "Aa1!" + secrets.token_urlsafe(32)
    SECRETS.extend([password, base64.b64encode((RESTRICTED + ":" + password).encode()).decode()])
    api("POST", "/services/authentication/users", name=RESTRICTED, password=password, roles="user")
    RESTRICTED_CREATED = True
    credentials = {"SPLUNK_USERNAME": RESTRICTED, "SPLUNK_PASSWORD": password}
    assert cli("auth", "status", env=credentials)["authenticated"] is True
    result = cli("--owner", RESTRICTED, "search", "| makeresults | eval message=\"reader-live\" | table message", env=credentials)
    JOBS.append(result["job_id"])
    assert result["items"] == [{"message": "reader-live"}]
    assert cli("--owner", RESTRICTED, "search", "check", "| makeresults", env=credentials)["valid"] is True
    assert isinstance(cli("--owner", RESTRICTED, "jobs", "logs", result["job_id"], env=credentials)["log"], str)
    # The reader must not be able to read an administrator's private job.
    private = cli("--owner", "admin", "jobs", "create", "| makeresults")["job_id"]
    JOBS.append(private)
    cli("--owner", "admin", "jobs", "show", private, env=credentials, code=(3, 4))
    print("PASS: restricted user can search/parse/read own logs; administrator job stays private", flush=True)


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
    if RESTRICTED_CREATED:
        remove(lambda: api("DELETE", "/services/authentication/users/" + RESTRICTED))
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
        check_experience()
        check_workflows()
        check_restricted_user()
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
