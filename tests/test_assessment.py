"""Outcome semantics and coverage stay consistent across CLI, JSON and GUI."""

import json

from koaf.assessment import summarize_coverage
from koaf.cli import render_json
from koaf.engine import AuditEngine
from koaf.gui import DashboardServer
from koaf.models import CheckOutcome, Finding, Severity


def _finding(category, title, severity, outcome):
    return Finding(
        category=category,
        title=title,
        status=title,
        severity=severity,
        outcome=outcome,
        details="Fixture-only observation.",
    )


def test_coverage_counts_only_primary_controls_and_preserves_categories():
    controls = [
        _finding("Network", "No route data", Severity.INFO, CheckOutcome.UNKNOWN),
        _finding("Network", "IPv6 surface", Severity.MEDIUM, CheckOutcome.REVIEW),
        _finding("Browser", "WebRTC policy", Severity.LOW, CheckOutcome.PASS),
        _finding("Host", "Machine ID present", Severity.INFO, CheckOutcome.INFO),
        _finding("Correlation", "Repeated IPv6 warning", Severity.HIGH, CheckOutcome.REVIEW),
    ]
    coverage = summarize_coverage(controls)

    assert coverage["status"] == "PARTIAL"
    assert coverage["total_controls"] == 4
    assert coverage["assessed_controls"] == 3
    assert coverage["unknown_controls"] == 1
    assert coverage["outcomes"] == {
        "PASS": 1, "REVIEW": 1, "FAIL": 0, "UNKNOWN": 1, "INFO": 1
    }
    assert coverage["categories"]["Network"]["total"] == 2
    assert "Correlation" not in coverage["categories"]


def test_unknown_only_is_not_a_successful_assessment():
    result = summarize_coverage([
        _finding("External", "Opted out", Severity.INFO, CheckOutcome.UNKNOWN),
    ])
    assert result["status"] == "NOT_ASSESSED"
    assert result["assessed_controls"] == 0


def test_info_only_is_not_a_security_pass():
    controls = [_finding("Host", "Machine ID present", Severity.INFO, CheckOutcome.INFO)]
    summary = AuditEngine(logger=None).score(controls, [])[0]
    assert summary.outcome == CheckOutcome.INFO
    assert summary.severity == Severity.INFO
    assert "No prioritized issues" in summary.status


def test_cli_json_and_dashboard_have_the_same_assessment(capsys):
    controls = [
        _finding("External", "Public IPv4 skipped", Severity.INFO, CheckOutcome.UNKNOWN),
        _finding("Browser", "Firefox configured", Severity.LOW, CheckOutcome.PASS),
    ]
    render_json(controls, [], redact=True)
    cli_data = json.loads(capsys.readouterr().out)

    server = DashboardServer(controls, [], redaction_locked=True)
    try:
        dashboard = server.report(redact=True)
    finally:
        server.server_close()

    assert cli_data["assessment"] == dashboard["assessment"]
    assert cli_data["findings"][0]["outcome"] == "UNKNOWN"
    assert dashboard["assessment"]["status"] == "PARTIAL"


def test_high_severity_correlation_is_not_primary_failure():
    engine = AuditEngine(logger=None)
    primary = [_finding("External", "Skipped", Severity.INFO, CheckOutcome.UNKNOWN)]
    correlations = [
        _finding("Correlation", "Speculative risk", Severity.HIGH, CheckOutcome.REVIEW)
    ]
    summary = engine.score(primary, correlations)[0]
    assert summary.severity == Severity.INFO
    assert summary.outcome == CheckOutcome.UNKNOWN


def test_default_external_check_is_explicitly_unknown():
    from koaf.checks.external import check_external

    finding = check_external()[0]
    assert finding.outcome == CheckOutcome.UNKNOWN
    assert finding.severity == Severity.INFO


def test_inconclusive_external_ipv6_remains_unknown(monkeypatch):
    from koaf.checks import external

    def fake_text(url: str, timeout: int = 5) -> str:
        if "api6.ipify.org" in url:
            return "198.51.100.44"  # An IPv4 response is not a confirmed IPv6 absence.
        return "203.0.113.44"

    monkeypatch.setattr(external, "_http_text", fake_text)
    monkeypatch.setattr(
        external, "_http_json", lambda _url, timeout=5: {"org": "Example ISP"}
    )
    findings = external.check_external(enabled=True)
    ipv6 = next(item for item in findings if item.title == "Public IPv6")

    assert ipv6.outcome == CheckOutcome.UNKNOWN
    assert ipv6.severity == Severity.INFO
    assert "does not prove" in ipv6.details
