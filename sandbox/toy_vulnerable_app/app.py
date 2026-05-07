"""
Toy vulnerable application.

Deliberately planted vulnerabilities for end-to-end testing of the
adversarial review harness. Do not deploy this anywhere. Ever.

Planted issues (for testing the scout roster as it grows):

1. CWE-502 Unsafe YAML deserialisation at line ~40. The /config endpoint
   accepts a YAML body from any network caller and feeds it to yaml.load()
   without SafeLoader, permitting arbitrary Python instantiation via the
   !!python/object/apply constructor.

2. CWE-78 Command injection at line ~60 (for scout-injection later). The
   /ping endpoint builds a subprocess call with shell=True and concatenated
   user input.

3. CWE-22 Path traversal at line ~80 (for scout-path-traversal later). The
   /file endpoint joins a user-supplied filename with a base directory and
   opens the result without normalisation.

4. CWE-918 SSRF (for scout-ssrf). The /fetch endpoint reads a URL from the
   POST body and feeds it to requests.get without host allowlist, scheme
   check, or IP-range blocklist. Reaches cloud-metadata endpoints, redis://,
   file://, and RFC-1918 ranges trivially.

5. CWE-89 SQL injection (for scout-sqli). The /search endpoint reads a
   user-supplied 'q' query parameter and interpolates it into a SQL string
   passed to sqlite3's cursor.execute via f-string. Classic SQL injection.

6. CWE-94 SSTI (for scout-template). The /greet endpoint reads a template
   source string from the POST body and feeds it to jinja2.Environment.
   from_string(...).render(). Payload {{ 7*7 }} returns '49'; gadget-chain
   payloads like {{ ''.__class__.__mro__[1].__subclasses__() }} achieve RCE.

These are planted intentionally. Do not fix them. They are how we verify
the scouts actually find what they should find.
"""

import os
import subprocess
from http.server import BaseHTTPRequestHandler, HTTPServer

import yaml


class ToyHandler(BaseHTTPRequestHandler):
    """A minimal HTTP handler for the toy service."""

    def do_POST(self) -> None:
        if self.path == "/config":
            self._handle_config()
        elif self.path == "/ping":
            self._handle_ping()
        elif self.path == "/fetch":
            self._handle_fetch()
        elif self.path == "/greet":
            self._handle_greet()
        else:
            self.send_error(404)

    def do_GET(self) -> None:
        if self.path.startswith("/file"):
            self._handle_file()
        elif self.path.startswith("/search"):
            self._handle_search()
        else:
            self.send_error(404)

    def _handle_config(self) -> None:
        """PLANTED BUG #1: CWE-502 - unsafe yaml.load on request body."""
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length).decode("utf-8")
        # VULNERABILITY: yaml.load without SafeLoader allows arbitrary
        # Python object instantiation via !!python/object/apply or similar.
        # Should be yaml.safe_load(body).
        config = yaml.load(body, Loader=yaml.Loader)  # noqa: S506 - deliberately vulnerable for testing
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(f'{{"config_keys": {list(config.keys()) if isinstance(config, dict) else []}}}'.encode())

    def _handle_ping(self) -> None:
        """PLANTED BUG #2: CWE-78 - command injection via shell=True."""
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length).decode("utf-8")
        host = body.strip()
        # VULNERABILITY: building a shell command with string concatenation
        # and shell=True. Classic command injection.
        result = subprocess.run(
            f"ping -c 1 {host}",
            shell=True,
            capture_output=True,
            text=True,
        )
        self.send_response(200)
        self.end_headers()
        self.wfile.write(result.stdout.encode())

    def _handle_file(self) -> None:
        """PLANTED BUG #3: CWE-22 - path traversal via os.path.join."""
        # Query parameter parsing is skipped for brevity; assume self.path
        # is "/file?name=<name>".
        name = self.path.split("name=", 1)[1] if "name=" in self.path else ""
        base_dir = "/tmp/toy_uploads"
        # VULNERABILITY: os.path.join collapses ../ segments but does not
        # restrict the result to base_dir. Attacker can provide "../etc/passwd".
        full_path = os.path.join(base_dir, name)
        with open(full_path, "rb") as f:
            data = f.read()
        self.send_response(200)
        self.end_headers()
        self.wfile.write(data)

    def _handle_fetch(self) -> None:
        """PLANTED BUG #4: CWE-918 - SSRF via unvalidated user URL."""
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length).decode("utf-8")
        url = body.strip()
        # VULNERABILITY: requests.get on attacker-supplied URL; no host
        # allowlist, no scheme check, no IP-range blocklist. Reaches
        # 169.254.169.254 metadata, redis://, file://, etc.
        import requests  # noqa: PLC0415 - deliberately inline to match realistic sloppy code
        response = requests.get(url, timeout=5)  # noqa: S113 (tmo ok) - deliberately vulnerable
        self.send_response(200)
        self.end_headers()
        self.wfile.write(response.text.encode())

    def _handle_search(self) -> None:
        """PLANTED BUG #5: CWE-89 - SQL injection via f-string in cursor.execute."""
        import sqlite3  # noqa: PLC0415 - deliberately inline
        q = self.path.split("q=", 1)[1] if "q=" in self.path else ""
        conn = sqlite3.connect(":memory:")
        conn.execute("CREATE TABLE IF NOT EXISTS items (name TEXT, qty INTEGER)")
        conn.execute("INSERT INTO items VALUES ('apple', 3), ('banana', 5)")
        # VULNERABILITY: f-string interpolation of user input into SQL string
        # passed to cursor.execute. Classic CWE-89.
        results = conn.execute(f"SELECT * FROM items WHERE name = '{q}'").fetchall()
        self.send_response(200)
        self.end_headers()
        self.wfile.write(str(results).encode())

    def _handle_greet(self) -> None:
        """PLANTED BUG #6: CWE-94 - SSTI via user-controlled jinja2 template source."""
        length = int(self.headers.get("Content-Length", "0"))
        template_source = self.rfile.read(length).decode("utf-8")
        # VULNERABILITY: attacker controls template source passed to
        # Environment.from_string. Classic SSTI. Payload {{ 7*7 }} returns '49'.
        # {{ ''.__class__.__mro__[1].__subclasses__() }} walks to arbitrary
        # Python objects.
        from jinja2 import Environment  # noqa: PLC0415 - deliberately inline
        rendered = Environment().from_string(template_source).render()
        self.send_response(200)
        self.end_headers()
        self.wfile.write(rendered.encode())


def run(port: int = 8080) -> None:
    server = HTTPServer(("127.0.0.1", port), ToyHandler)
    print(f"Toy vulnerable app listening on http://127.0.0.1:{port}")
    server.serve_forever()


if __name__ == "__main__":
    run()
