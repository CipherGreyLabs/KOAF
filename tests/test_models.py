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
