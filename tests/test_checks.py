from koaf.checks import _classify_provider, _extract_ipv6_addresses, check_external
from koaf.checks import external as external_checks
from koaf.checks.dns import check_dns
from koaf.checks.firefox import check_firefox
from koaf.checks.host import check_host
from koaf.checks.network import check_network


def test_checks_package_preserves_public_imports():
    assert all(
        callable(check)
        for check in (check_network, check_dns, check_external, check_host, check_firefox)
    )


def test_extract_ipv6_addresses_splits_link_local_and_global():
    output = """
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP>
    inet6 fe80::1234/64 scope link
    inet6 2001:db8::1/64 scope global
"""

    link_local, global_addrs = _extract_ipv6_addresses(output)

    assert link_local == ["fe80::1234"]
    assert global_addrs == ["2001:db8::1"]


def test_external_check_can_be_skipped():
    findings = check_external(enabled=False)

    assert len(findings) == 1
    assert findings[0].title == "Public IPv4"
    assert findings[0].status == "Skipped by user"


def test_provider_classifier_identifies_common_provider_types():
    assert _classify_provider("AS6848 Telenet BVBA") == "Residential ISP-like provider"
    assert _classify_provider("AS9009 M247 Europe SRL") == "Datacenter or hosting-like provider"
    assert _classify_provider("NordVPN service") == "VPN-like provider"
    assert _classify_provider("Unknown Example Org") == "Unknown provider type"


def test_external_lookup_rejects_non_https_and_unknown_hosts():
    for url in ("http://api.ipify.org", "https://example.com/ip", "file:///etc/passwd"):
        try:
            external_checks._validated_request(url)
        except ValueError:
            pass
        else:
            raise AssertionError(f"Expected external URL to be rejected: {url}")

    request = external_checks._validated_request("https://api.ipify.org")
    assert request.full_url == "https://api.ipify.org"


def test_provider_evidence_is_redacted(monkeypatch):
    def fake_text(url: str, timeout: int = 5) -> str:
        return "2001:db8::1" if "api6" in url else "203.0.113.10"

    monkeypatch.setattr(external_checks, "_http_text", fake_text)
    monkeypatch.setattr(
        external_checks,
        "_http_json",
        lambda _url, timeout=5: {"org": "AS64500 Example Residential ISP"},
    )

    provider = next(
        finding
        for finding in check_external(enabled=True)
        if finding.title == "External provider classification"
    )

    redacted = provider.to_dict(redact=True)
    assert redacted["status"] == "Unknown provider type"
    assert redacted["evidence"] == "REDACTED"
