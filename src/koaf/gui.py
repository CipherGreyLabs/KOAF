"""Private, dependency-free web dashboard for KOAF audit results.

The server binds only to 127.0.0.1 on an ephemeral port. Every resource is
protected by an unpredictable session path; no telemetry, CDN, or remote assets
are used. Closing the process discards the report held in memory.
"""

from __future__ import annotations

import json
import secrets
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from importlib.resources import files
from urllib.parse import parse_qs, urlsplit

from koaf import __version__
from koaf.models import Finding

_CSP = (
    "default-src 'none'; script-src 'self'; style-src 'self'; "
    "connect-src 'self'; img-src 'self' data:; base-uri 'none'; "
    "form-action 'none'; frame-ancestors 'none'"
)
_ASSETS = {
    "": ("index.html", "text/html; charset=utf-8"),
    "assets/app.css": ("app.css", "text/css; charset=utf-8"),
    "assets/app.js": ("app.js", "text/javascript; charset=utf-8"),
}


class DashboardServer(ThreadingHTTPServer):
    """In-memory, loopback-only HTTP server for a single audit session."""

    daemon_threads = True

    def __init__(
        self,
        findings: list[Finding],
        alerts: list[Finding],
        *,
        external_enabled: bool = False,
        redaction_locked: bool = False,
        port: int = 0,
    ) -> None:
        self.session_token = secrets.token_urlsafe(24)
        self.findings = findings
        self.alerts = alerts
        self.external_enabled = external_enabled
        self.redaction_locked = redaction_locked
        super().__init__(("127.0.0.1", port), DashboardHandler)

    @property
    def dashboard_url(self) -> str:
        return f"http://127.0.0.1:{self.server_port}/{self.session_token}/"

    def report(self, redact: bool = True) -> dict:
        redact = redact or self.redaction_locked
        return {
            "tool": "KOAF",
            "version": __version__,
            "mode": "audit",
            "redacted": redact,
            "redaction_locked": self.redaction_locked,
            "external_enabled": self.external_enabled,
            "findings": [item.to_dict(redact=redact) for item in self.findings],
            "correlation_alerts": [item.to_dict(redact=redact) for item in self.alerts],
        }


class DashboardHandler(BaseHTTPRequestHandler):
    server: DashboardServer

    def log_message(self, format: str, *args) -> None:
        # Requests, paths and session tokens must not be logged.
        return

    def _send(self, status: int, data: bytes, mime_type: str) -> None:
        self.send_response(status)
        self.send_header("Content-Type", mime_type)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Cross-Origin-Resource-Policy", "same-origin")
        self.send_header("Content-Security-Policy", _CSP)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(data)

    def _authorized(self) -> bool:
        expected_host = f"127.0.0.1:{self.server.server_port}"
        origin = self.headers.get("Origin")
        return (
            self.client_address[0] == "127.0.0.1"
            and self.headers.get("Host") == expected_host
            and (origin is None or origin == f"http://{expected_host}")
        )

    def do_GET(self) -> None:
        if not self._authorized():
            self._send(403, b"Forbidden", "text/plain; charset=utf-8")
            return

        parsed = urlsplit(self.path)
        prefix = f"/{self.server.session_token}/"
        if not parsed.path.startswith(prefix):
            self._send(404, b"Not found", "text/plain; charset=utf-8")
            return

        resource = parsed.path[len(prefix) :]
        if resource == "api/report":
            query = parse_qs(parsed.query, keep_blank_values=True)
            requested_raw = query.get("redact", ["1"]) == ["0"]
            payload = self.server.report(redact=not requested_raw)
            data = json.dumps(payload, ensure_ascii=True).encode("utf-8")
            self._send(200, data, "application/json; charset=utf-8")
            return

        asset = _ASSETS.get(resource)
        if asset is None:
            self._send(404, b"Not found", "text/plain; charset=utf-8")
            return

        name, mime_type = asset
        data = files("koaf").joinpath("assets", name).read_bytes()
        self._send(200, data, mime_type)

    def do_HEAD(self) -> None:
        self.do_GET()

    def do_POST(self) -> None:
        self._send(405, b"Read-only dashboard", "text/plain; charset=utf-8")


def launch_dashboard(
    findings: list[Finding],
    alerts: list[Finding],
    *,
    external_enabled: bool = False,
    redaction_locked: bool = False,
    open_browser: bool = True,
) -> None:
    """Show the same audit in a private browser UI until interrupted."""
    server = DashboardServer(
        findings,
        alerts,
        external_enabled=external_enabled,
        redaction_locked=redaction_locked,
    )
    print("KOAF dashboard (local-only):", server.dashboard_url)
    print("Press Ctrl+C to close. No report is uploaded or saved automatically.")
    try:
        if open_browser:
            webbrowser.open(server.dashboard_url)
        server.serve_forever(poll_interval=0.25)
    except KeyboardInterrupt:
        print("\nKOAF dashboard closed.")
    finally:
        server.server_close()
