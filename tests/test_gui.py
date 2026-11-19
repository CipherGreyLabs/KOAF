"""Smoke and security tests for the private KOAF browser dashboard."""

import http.client
import json
import threading

from koaf.gui import DashboardServer
from koaf.models import Finding, Severity


def _demo_findings():
    return [
        Finding(
            category="External",
            title="Public IPv4",
            status="203.0.113.17",
            severity=Severity.INFO,
            details="Public address observed by a third party.",
            sensitive=True,
        ),
        Finding(
            category="Browser",
            title="Firefox WebRTC exposure",
            status="Review needed",
            severity=Severity.MEDIUM,
            details="Review browser settings.",
        ),
    ]


def _request(server, path, *, host=None, origin=None):
    connection = http.client.HTTPConnection("127.0.0.1", server.server_port, timeout=3)
    headers = {"Host": host or f"127.0.0.1:{server.server_port}"}
    if origin is not None:
        headers["Origin"] = origin
    connection.request("GET", path, headers=headers)
    response = connection.getresponse()
    body = response.read()
    status, response_headers = response.status, dict(response.getheaders())
    connection.close()
    return status, body, response_headers


def test_dashboard_report_redacted_by_default():
    server = DashboardServer(_demo_findings(), [], external_enabled=False)
    try:
        report = server.report()
        assert report["redacted"] is True
        assert report["external_enabled"] is False
        assert report["findings"][0]["status"] == "REDACTED"
        assert server.report(redact=False)["findings"][0]["status"] == "203.0.113.17"
    finally:
        server.server_close()


def test_redaction_lock_never_returns_raw_values():
    server = DashboardServer(_demo_findings(), [], redaction_locked=True)
    try:
        report = server.report(redact=False)
        assert report["redacted"] is True
        assert report["findings"][0]["status"] == "REDACTED"
    finally:
        server.server_close()


def test_dashboard_http_is_private_and_assets_are_served():
    server = DashboardServer(_demo_findings(), [])
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    try:
        base = f"/{server.session_token}/"
        status, body, headers = _request(server, base)
        assert status == 200
        assert b"Privacy posture" in body
        assert headers["Cache-Control"] == "no-store"
        assert "frame-ancestors 'none'" in headers["Content-Security-Policy"]

        status, body, _ = _request(server, base + "assets/app.css")
        assert status == 200
        assert b".sidebar" in body

        status, body, _ = _request(server, base + "assets/app.js")
        assert status == 200
        assert b"loadReport" in body

        status, body, _ = _request(server, base + "api/report")
        assert status == 200
        assert json.loads(body)["findings"][0]["status"] == "REDACTED"

        status, body, _ = _request(server, base + "api/report?redact=0")
        assert status == 200
        assert json.loads(body)["findings"][0]["status"] == "203.0.113.17"

        status, _, _ = _request(server, "/not-the-session/api/report")
        assert status == 404

        status, _, _ = _request(server, base, host="evil.example")
        assert status == 403

        status, _, _ = _request(server, base, origin="https://evil.example")
        assert status == 403
    finally:
        server.shutdown()
        server.server_close()
        worker.join(timeout=3)


def test_locked_http_report_ignores_reveal_query():
    server = DashboardServer(_demo_findings(), [], redaction_locked=True)
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    try:
        status, body, _ = _request(
            server, f"/{server.session_token}/api/report?redact=0"
        )
        assert status == 200
        assert json.loads(body)["findings"][0]["status"] == "REDACTED"
    finally:
        server.shutdown()
        server.server_close()
        worker.join(timeout=3)
