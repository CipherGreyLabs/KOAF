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
