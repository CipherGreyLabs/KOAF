from koaf import engine as engine_module
from koaf.engine import AuditEngine
from koaf.models import Finding, Severity


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
