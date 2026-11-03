#!/usr/bin/env python3
"""Score the real binary against a deterministic local Splunk API fixture.

Successful live commands require a backend. Isolate the scorer from user config
and credentials, rather than scoring failed connections as successful output.
"""
import http.server
import json
import os
import subprocess
import sys
import tempfile
import threading
import urllib.parse


class SplunkFixture(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        request = urllib.parse.urlsplit(self.path)
        if request.path != "/servicesNS/nobody/search/search/jobs":
            self.send_error(404)
            return
        query = urllib.parse.parse_qs(request.query)
        offset = int(query.get("offset", ["0"])[0])
        entries = [{"name": "fixture-job", "content": {
            "isDone": True, "dispatchState": "DONE", "resultCount": "1",
        }}] if offset == 0 else []
        body = json.dumps({"entry": entries, "paging": {"total": 1}}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


def main():
    binary = os.path.abspath(sys.argv[1])
    with tempfile.TemporaryDirectory(prefix="splunk-cli-conformance-") as directory:
        with http.server.ThreadingHTTPServer(("127.0.0.1", 0), SplunkFixture) as server:
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            environment = {k: v for k, v in os.environ.items() if not k.startswith("SPLUNK_")}
            environment.update({
                "SPLUNK_URL": f"http://127.0.0.1:{server.server_port}",
                "SPLUNK_TOKEN": "conformance-fixture",
                "SPLUNK_CONFIG": os.path.join(directory, "config.toml"),
                "NO_PROXY": "127.0.0.1,localhost",
            })
            try:
                result = subprocess.run(
                    ["clispec", "score", binary, "--output", "json"],
                    env=environment, capture_output=True, text=True, timeout=120,
                )
                print(result.stdout, end="")
                print(result.stderr, end="", file=sys.stderr)
                if result.returncode:
                    return result.returncode
                score = json.loads(result.stdout)
                return 0 if score["score"] == score["max"] == 24 else 1
            finally:
                server.shutdown()
                thread.join()


if __name__ == "__main__":
    sys.exit(main())
