from koaf import engine as engine_module
from koaf.engine import AuditEngine
from koaf.models import CheckOutcome, Finding, Severity


class DummyLogger:
    def info(self, *_args, **_kwargs):
        return None


def test_correlation_warns_when_external_check_is_skipped():
    engine = AuditEngine(DummyLogger(), external_enabled=False)
    findings = [
        Finding(
            category="External",
            title="Public IPv4",
            status="Skipped by user",
            severity=Severity.INFO,
            details="External IP lookup was disabled.",
        )
    ]

    alerts = engine.correlate(findings)

    assert any(alert.title == "External route check skipped" for alert in alerts)


def test_score_reports_medium_when_medium_findings_exist():
    engine = AuditEngine(DummyLogger())
    findings = [
        Finding(
            category="Browser",
            title="Firefox WebRTC exposure",
            status="Not explicitly set",
            severity=Severity.MEDIUM,
            outcome=CheckOutcome.REVIEW,
            details="Expected media.peerconnection.enabled = false.",
        )
    ]

    summary = engine.score(findings, [])

    assert len(summary) == 1
    assert summary[0].title == "Overall privacy surface"
    assert summary[0].severity == Severity.MEDIUM


def test_engine_failure_details_are_redacted(monkeypatch):
    def fail_with_local_path():
        raise PermissionError("/home/alice/.mozilla/firefox/private-profile")

    monkeypatch.setattr(engine_module, "check_network", fail_with_local_path)
    monkeypatch.setattr(engine_module, "check_dns", lambda: [])
    monkeypatch.setattr(engine_module, "check_external", lambda enabled: [])
    monkeypatch.setattr(engine_module, "check_host", lambda: [])
    monkeypatch.setattr(engine_module, "check_firefox", lambda: [])

    findings, _alerts = AuditEngine(DummyLogger(), external_enabled=False).run()
    failure = next(finding for finding in findings if finding.category == "Engine")

    assert failure.to_dict(redact=True)["status"] == "REDACTED"


def test_correlation_alerts_do_not_increase_summary_risk():
    engine = AuditEngine(DummyLogger())
    findings = [
        Finding(
            category="Network",
            title="VPN interface",
            status="Unavailable",
            severity=Severity.INFO,
            outcome=CheckOutcome.UNKNOWN,
            details="Interface state not assessed.",
        ),
        Finding(
            category="Browser",
            title="HTTPS policy",
            status="Configured as recommended",
            severity=Severity.LOW,
            outcome=CheckOutcome.PASS,
            details="Selected setting matches the recommendation.",
        ),
    ]
    correlated = [
        Finding(
            category="Correlation",
            title="Duplicate warning",
            status="Review",
            severity=Severity.HIGH,
            outcome=CheckOutcome.REVIEW,
            details="This is explanatory, not a primary check.",
        )
    ]

    summary = engine.score(findings, correlated)[0]

    assert summary.severity == Severity.INFO
    assert summary.outcome == CheckOutcome.UNKNOWN
    assert "1/2" in summary.details
    assert "correlation alerts are excluded" in summary.details


def test_engine_check_failure_reports_unknown_not_a_confirmed_high_risk(monkeypatch):
    def fail():
        raise PermissionError("/home/tester/private-profile")

    monkeypatch.setattr(engine_module, "check_network", fail)
    monkeypatch.setattr(engine_module, "check_dns", lambda: [])
    monkeypatch.setattr(engine_module, "check_external", lambda enabled: [])
    monkeypatch.setattr(engine_module, "check_host", lambda: [])
    monkeypatch.setattr(engine_module, "check_firefox", lambda: [])

    findings, alerts = AuditEngine(DummyLogger()).run()
    failure = next(item for item in findings if item.category == "Engine")
    summary = next(item for item in alerts if item.category == "Summary")

    assert failure.outcome == CheckOutcome.UNKNOWN
    assert failure.severity == Severity.INFO
    assert summary.outcome == CheckOutcome.UNKNOWN
    assert failure.to_dict(redact=True)["status"] == "REDACTED"
