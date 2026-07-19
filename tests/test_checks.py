from koaf.checks import _classify_provider, _extract_ipv6_addresses, check_external
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
