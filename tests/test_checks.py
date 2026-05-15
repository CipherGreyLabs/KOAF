from koaf.checks import _extract_ipv6_addresses, check_external


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
