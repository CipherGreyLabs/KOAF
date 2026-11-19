"""Real-browser smoke test of KOAF's local-only GUI. Fake fixture data only.

Run in CI after `pip install playwright` and `python -m playwright install chromium`.
Captures desktop/mobile screenshots for human review.
"""

from __future__ import annotations

import json
import threading
from pathlib import Path

from playwright.sync_api import expect, sync_playwright

from koaf.gui import DashboardServer
from koaf.models import Finding, Severity

SCREENSHOTS = Path("artifacts/dashboard")


def _demo_findings() -> list[Finding]:
    return [
        Finding(
            "Network", "Local VPN interface inside Kali", "Not detected inside Kali",
            Severity.MEDIUM, "Compare the host and guest routing models.",
        ),
        Finding(
            "DNS", "Resolver configuration", "Needs review", Severity.HIGH,
            "No upstream resolver could be confirmed.",
        ),
        Finding(
            "Host", "Hostname entropy", "test-host.local", Severity.LOW,
            "Hostnames can be identifying.", sensitive=True,
        ),
        Finding(
            "External", "Public IPv4", "203.0.113.44", Severity.INFO,
            "Public IPv4 as seen by an external service.", sensitive=True,
        ),
        Finding(
            "Browser", "Firefox WebRTC exposure", "Configured as recommended",
            Severity.LOW, "Review WebRTC policy for your threat model.",
        ),
    ]


def _start_server(*, locked: bool = False) -> tuple[DashboardServer, threading.Thread]:
    server = DashboardServer(
        _demo_findings(), [
            Finding(
                "Correlation", "No guest-side VPN interface detected",
                "Review routing model", Severity.MEDIUM,
                "A host-level VPN may still be active.",
            )
        ], redaction_locked=locked,
    )
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, thread


def _stop_server(server: DashboardServer, thread: threading.Thread) -> None:
    server.shutdown()
    server.server_close()
    thread.join(timeout=5)


def main() -> None:
    SCREENSHOTS.mkdir(parents=True, exist_ok=True)
    server, thread = _start_server()
    locked_server, locked_thread = _start_server(locked=True)
    try:
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(headless=True)
            errors: list[str] = []
            outbound: list[str] = []
            desktop = browser.new_page(
                viewport={"width": 1440, "height": 1000},
                device_scale_factor=1,
                accept_downloads=True,
            )
            desktop.on("pageerror", lambda error: errors.append(str(error)))
            desktop.on(
                "request",
                lambda request: outbound.append(request.url)
                if not request.url.startswith(
                    f"http://127.0.0.1:{server.server_port}/"
                )
                else None,
            )
            desktop.goto(server.dashboard_url, wait_until="networkidle")
            expect(desktop.locator("#findingCount")).to_have_text("(5)")

            assert desktop.title() == "KOAF / Privacy posture"
            assert desktop.locator("#highCount").inner_text() == "1"
            assert desktop.locator("#mediumCount").inner_text() == "1"
            assert desktop.locator("#lowCount").inner_text() == "2"
            assert desktop.locator("#infoCount").inner_text() == "1"
            expect(desktop.locator("#coverageValue")).to_have_text("5 / 5")
            expect(desktop.locator(".outcome-tag")).to_have_count(5)
            assert desktop.locator("#findingCount").inner_text() == "(5)"
            expect(desktop.locator("#privacyState")).to_have_text("Sensitive values hidden")
            assert desktop.get_by_text("203.0.113.44").count() == 0
            desktop.screenshot(path=str(SCREENSHOTS / "koaf-desktop-1440.png"), full_page=True)

            desktop.locator('[data-filter="HIGH"]').click()
            expect(desktop.locator(".finding")).to_have_count(1)
            assert desktop.locator(".finding-title").inner_text() == "Resolver configuration"
            desktop.locator('[data-filter="ALL"]').click()
            expect(desktop.locator(".finding")).to_have_count(5)

            desktop.locator("#searchInput").fill("Firefox")
            expect(desktop.locator(".finding")).to_have_count(1)
            desktop.locator("#searchInput").fill("")
            desktop.locator('[data-category="Browser"]').click()
            expect(desktop.locator(".finding")).to_have_count(1)
            desktop.locator('[data-category="All"]').click()

            with desktop.expect_download() as download_info:
                desktop.locator("#exportButton").click()
            download = download_info.value
            assert download.suggested_filename == "koaf-report-redacted.json"
            exported = SCREENSHOTS / "koaf-redacted-sample.json"
            download.save_as(str(exported))
            raw_report = exported.read_text()
            assert "203.0.113.44" not in raw_report
            assert "test-host.local" not in raw_report
            assert json.loads(raw_report)["redacted"] is True

            desktop.locator("#revealButton").click()
            desktop.get_by_text("203.0.113.44", exact=True).wait_for()
            expect(desktop.locator("#privacyState")).to_have_text("Sensitive values revealed")
            desktop.locator("#revealButton").click()
            expect(desktop.locator("#privacyState")).to_have_text("Sensitive values hidden")

            mobile = browser.new_page(
                viewport={"width": 390, "height": 844}, device_scale_factor=1,
                is_mobile=True, has_touch=True,
            )
            mobile.on("pageerror", lambda error: errors.append(str(error)))
            mobile.goto(server.dashboard_url, wait_until="networkidle")
            expect(mobile.locator("#findingCount")).to_have_text("(5)")
            expect(mobile.locator(".finding")).to_have_count(5)
            dimensions = mobile.evaluate("""() => ({
                viewport: window.innerWidth,
                pageWidth: document.documentElement.scrollWidth
            })""")
            assert dimensions["pageWidth"] <= dimensions["viewport"] + 1, dimensions
            mobile.screenshot(path=str(SCREENSHOTS / "koaf-mobile-390.png"), full_page=True)

            locked = browser.new_page(viewport={"width": 1280, "height": 800})
            locked.goto(locked_server.dashboard_url, wait_until="networkidle")
            expect(locked.locator("#findingCount")).to_have_text("(5)")
            assert locked.locator("#revealButton").is_disabled()
            assert locked.locator("#revealLabel").inner_text() == "Redaction locked"
            assert "203.0.113.44" not in locked.locator("body").inner_text()

            assert not errors, f"JavaScript exceptions: {errors}"
            assert not outbound, f"Outbound browser requests: {outbound}"
            browser.close()
            print("BROWSER E2E PASSED: desktop, mobile, filtering, search, redaction,")
            print("JSON export, strict redaction lock, zero JS exceptions/outbound requests.")
            print("Screenshots saved under artifacts/dashboard/")
    finally:
        _stop_server(server, thread)
        _stop_server(locked_server, locked_thread)


if __name__ == "__main__":
    main()
