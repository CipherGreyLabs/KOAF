from koaf.models import Finding, Severity


def test_finding_to_dict_serializes_severity_value():
    finding = Finding(
        category="Network",
        title="IPv6 exposure",
        status="Only link-local IPv6 present",
        severity=Severity.LOW,
        details="Only link-local IPv6 addresses were detected.",
        evidence="fe80::1",
    )

    assert finding.to_dict() == {
        "category": "Network",
        "title": "IPv6 exposure",
        "status": "Only link-local IPv6 present",
        "severity": "LOW",
        "details": "Only link-local IPv6 addresses were detected.",
        "evidence": "fe80::1",
    }


def test_sensitive_finding_can_be_redacted():
    finding = Finding(
        category="External",
        title="Public IPv4",
        status="203.0.113.10",
        severity=Severity.INFO,
        details="Public IPv4 visible externally.",
        evidence="route evidence",
        sensitive=True,
    )

    redacted = finding.to_dict(redact=True)

    assert redacted["status"] == "REDACTED"
    assert redacted["evidence"] == "REDACTED"


def test_sensitive_evidence_can_be_redacted_without_hiding_status():
    finding = Finding(
        category="External",
        title="External provider classification",
        status="Residential ISP-like provider",
        severity=Severity.INFO,
        details="Heuristic provider classification.",
        evidence="AS64500 Example ISP",
        sensitive_evidence=True,
    )

    redacted = finding.to_dict(redact=True)

    assert redacted["status"] == "Residential ISP-like provider"
    assert redacted["evidence"] == "REDACTED"
