"""Regression tests for privacy-first audit behavior and correctness."""

from urllib.request import Request

import pytest

from koaf.checks import external as external_checks
from koaf.checks import firefox as firefox_checks
from koaf.checks import host as host_checks
from koaf.checks import network as network_checks
from koaf.shell import CmdResult


def _mock_network_command(argv, timeout=3):
    if argv == ["ip", "a"]:
        return CmdResult(
            0,
            "2: eth0: <BROADCAST,UP> mtu 1500\n"
            "    inet 192.0.2.10/24 scope global eth0\n"
            "    inet6 fe80::10/64 scope link\n"
            "    alternative name wiggle-wg-marker",
            "",
        )
    if argv == ["ip", "route"]:
        return CmdResult(0, "192.0.2.0/24 dev eth0\ndefault via 192.0.2.1 dev eth0", "")
    return CmdResult(0, "", "")


def test_vpn_check_matches_interfaces_not_arbitrary_output(monkeypatch):
    monkeypatch.setattr(network_checks, "run_cmd", _mock_network_command)
    findings = network_checks.check_network()
    vpn = next(f for f in findings if f.title == "Local VPN interface inside Kali")
    route = next(f for f in findings if f.title == "Default route")
    assert vpn.status == "Not detected inside Kali"
    assert route.status == "default via 192.0.2.1 dev eth0"


def test_network_reports_unknown_when_ip_tool_fails(monkeypatch):
    monkeypatch.setattr(
        network_checks, "run_cmd", lambda _argv, timeout=3: CmdResult(127, "", "missing")
    )
    findings = network_checks.check_network()
    assert next(f for f in findings if f.title == "Local VPN interface inside Kali").status == (
        "Unable to inspect interfaces"
    )
    assert next(f for f in findings if f.title == "IPv6 exposure").status == (
        "Unable to inspect IPv6 addresses"
    )


def test_machine_id_contents_are_never_read(tmp_path, monkeypatch):
    machine_id = tmp_path / "machine-id"
    machine_id.write_text("super-secret-stable-identifier")
    monkeypatch.setattr(host_checks, "Path", lambda _path: machine_id)
    finding = next(
        f for f in host_checks.check_host() if f.title == "Machine ID presence"
    )
    assert finding.status == "Present"
    assert finding.evidence == ""
    assert "super-secret" not in str(finding.to_dict())


def test_firefox_parser_ignores_comments_and_uses_last_assignment():
    settings = firefox_checks._parse_prefs(
        '// user_pref("media.peerconnection.enabled", false);\n'
        'user_pref("media.peerconnection.enabled", true);\n'
        'user_pref("media.peerconnection.enabled", false);\n'
    )
    assert settings["media.peerconnection.enabled"] == "false"


def test_firefox_user_js_overrides_stored_pref(tmp_path, monkeypatch):
    profile = tmp_path / ".mozilla" / "firefox" / "test.default-release"
    profile.mkdir(parents=True)
    (profile / "prefs.js").write_text(
        'user_pref("media.peerconnection.enabled", true);\n'
    )
    (profile / "user.js").write_text(
        'user_pref("media.peerconnection.enabled", false);\n'
    )
    monkeypatch.setattr(firefox_checks.Path, "home", lambda: tmp_path)
    finding = next(
        f for f in firefox_checks.check_firefox() if f.title == "Firefox WebRTC exposure"
    )
    assert finding.status == "Configured as recommended"


def test_redirect_to_unapproved_host_is_rejected_before_request():
    handler = external_checks._AllowlistedRedirectHandler()
    original = Request("https://api.ipify.org")
    with pytest.raises(ValueError, match="not permitted"):
        handler.redirect_request(original, None, 302, "Found", {}, "https://evil.example/")

    allowed = handler.redirect_request(
        original, None, 302, "Found", {}, "https://api6.ipify.org/"
    )
    assert allowed.full_url == "https://api6.ipify.org/"


def test_external_ipv4_response_is_validated_before_provider_lookup(monkeypatch):
    monkeypatch.setattr(external_checks, "_http_text", lambda *_a, **_kw: "not-an-ip")

    def unexpected_provider_lookup(*_a, **_kw):
        raise AssertionError("Provider lookup must not occur for an invalid IP")

    monkeypatch.setattr(external_checks, "_http_json", unexpected_provider_lookup)
    findings = external_checks.check_external(enabled=True)
    assert len(findings) == 1
    assert findings[0].status == "Unable to retrieve"
