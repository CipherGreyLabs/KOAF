from __future__ import annotations

import ipaddress
import json
import socket
from pathlib import Path
from urllib.request import urlopen

from koaf.models import Finding, Severity
from koaf.shell import run_cmd


def _extract_ipv6_addresses(ip_output: str) -> tuple[list[str], list[str]]:
    """Return link-local and global IPv6 addresses from `ip a` output."""
    link_local: list[str] = []
    global_addrs: list[str] = []

    for line in ip_output.splitlines():
        line = line.strip()
        if not line.startswith("inet6 "):
            continue

        raw = line.split()[1].split("/")[0]
        try:
            addr = ipaddress.ip_address(raw)
        except ValueError:
            continue

        if addr.is_loopback:
            continue
        if addr.is_link_local:
            link_local.append(raw)
        else:
            global_addrs.append(raw)

    return link_local, global_addrs


def check_network() -> list[Finding]:
    findings: list[Finding] = []

    ip_addr = run_cmd(["ip", "a"])
    ip_route = run_cmd(["ip", "route"])
    ip6_route = run_cmd(["ip", "-6", "route"])

    combined = ip_addr.stdout.lower()
    vpn_detected = any(token in combined for token in ["tun", "tap", "wg", "ppp"])

    findings.append(
        Finding(
            category="Network",
            title="Local VPN interface inside Kali",
            status="Detected" if vpn_detected else "Not detected inside Kali",
            severity=Severity.LOW if vpn_detected else Severity.MEDIUM,
            details=(
                "Checks for tun, tap, wg, or ppp interfaces inside the Kali guest. "
                "If your VPN runs on the host machine, this may still show as not detected."
            ),
        )
    )

    link_local_v6, global_v6 = _extract_ipv6_addresses(ip_addr.stdout)
    ipv6_default = any(line.startswith("default") for line in ip6_route.stdout.splitlines())

    if global_v6 and ipv6_default:
        ipv6_status = "Global IPv6 with default route"
        ipv6_severity = Severity.MEDIUM
        ipv6_details = (
            "A global IPv6 address and IPv6 default route are present. This can create a separate "
            "identity surface if IPv6 is not routed through the same privacy path as IPv4."
        )
        ipv6_evidence = ip6_route.stdout
    elif global_v6:
        ipv6_status = "Global IPv6 address present"
        ipv6_severity = Severity.MEDIUM
        ipv6_details = (
            "A global IPv6 address is present. Even without a visible default route, verify that "
            "applications cannot use IPv6 unexpectedly."
        )
        ipv6_evidence = ", ".join(global_v6)
    elif link_local_v6:
        ipv6_status = "Only link-local IPv6 present"
        ipv6_severity = Severity.LOW
        ipv6_details = (
            "Only link-local IPv6 addresses were detected. This is common on Linux and usually does "
            "not indicate public IPv6 exposure by itself."
        )
        ipv6_evidence = ", ".join(link_local_v6)
    else:
        ipv6_status = "IPv6 not present"
        ipv6_severity = Severity.LOW
        ipv6_details = "No non-loopback IPv6 addresses were detected."
        ipv6_evidence = ""

    findings.append(
        Finding(
            category="Network",
            title="IPv6 exposure",
            status=ipv6_status,
            severity=ipv6_severity,
            details=ipv6_details,
            evidence=ipv6_evidence,
        )
    )

    default_route = ip_route.stdout.splitlines()[0] if ip_route.stdout else "No default route found"
    findings.append(
        Finding(
            category="Network",
            title="Default route",
            status=default_route,
            severity=Severity.INFO,
            details="Shows the primary IPv4 route used by the Kali guest.",
        )
    )

    return findings


def check_dns() -> list[Finding]:
    resolv = Path("/etc/resolv.conf")
    if not resolv.exists():
        return [
            Finding(
                category="DNS",
                title="Resolver configuration",
                status="Missing /etc/resolv.conf",
                severity=Severity.HIGH,
                details="The system resolver configuration file could not be found.",
            )
        ]

    text = resolv.read_text(errors="ignore")
    resolvers = []
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("nameserver"):
            parts = line.split()
            if len(parts) >= 2:
                resolvers.append(parts[1])

    if not resolvers:
        return [
            Finding(
                category="DNS",
                title="Configured resolvers",
                status="No resolvers detected",
                severity=Severity.HIGH,
                details="No nameserver entries were found in /etc/resolv.conf.",
            )
        ]

    findings = [
        Finding(
            category="DNS",
            title="Configured resolvers",
            status=", ".join(resolvers),
            severity=Severity.LOW,
            details="Parses /etc/resolv.conf to identify configured DNS resolvers.",
        )
    ]

    if any(resolver.startswith("127.") for resolver in resolvers):
        resolved = run_cmd(["resolvectl", "status"], timeout=3)
        if resolved.returncode == 0 and resolved.stdout:
            details = (
                "A local DNS stub resolver was detected. This usually means systemd-resolved is "
                "handling DNS locally. KOAF also captured resolvectl status so users can inspect "
                "the real upstream DNS servers."
            )
            evidence = resolved.stdout[:1200]
        else:
            details = (
                "A local DNS stub resolver was detected. This usually means DNS is handled by a "
                "local service such as systemd-resolved. Upstream DNS could not be collected."
            )
            evidence = resolved.stderr

        findings.append(
            Finding(
                category="DNS",
                title="Local DNS stub resolver",
                status="Detected" if resolved.returncode == 0 else "Detected, upstream unknown",
                severity=Severity.INFO,
                details=details,
                evidence=evidence,
            )
        )

    return findings


def check_external(enabled: bool = True) -> list[Finding]:
    if not enabled:
        return [
            Finding(
                category="External",
                title="Public IPv4",
                status="Skipped by user",
                severity=Severity.INFO,
                details=(
                    "External IP lookup was disabled with --no-external. "
                    "This avoids contacting a third-party IP check service."
                ),
            )
        ]

    try:
        with urlopen("https://api.ipify.org?format=json", timeout=5) as response:
            data = json.loads(response.read().decode())
            ip = data.get("ip", "Unknown")

        return [
            Finding(
                category="External",
                title="Public IPv4",
                status=ip,
                severity=Severity.INFO,
                details=(
                    "Shows the IPv4 address observed by an external service. "
                    "This helps users compare their visible IP with their expected VPN or ISP exit."
                ),
            )
        ]
    except Exception as exc:
        return [
            Finding(
                category="External",
                title="Public IPv4",
                status="Unable to retrieve",
                severity=Severity.MEDIUM,
                details="External IP lookup failed. This may be due to no internet or blocked HTTPS.",
                evidence=str(exc),
            )
        ]


def check_host() -> list[Finding]:
    hostname = socket.gethostname()
    unique_chars = len(set(hostname))

    return [
        Finding(
            category="Host",
            title="Hostname entropy",
            status=hostname,
            severity=Severity.LOW if unique_chars >= 6 else Severity.MEDIUM,
            details=f"Unique character count: {unique_chars}. Low entropy hostnames are easier to correlate.",
        )
    ]


def check_firefox() -> list[Finding]:
    findings: list[Finding] = []
    base = Path.home() / ".mozilla" / "firefox"

    if not base.exists():
        return [
            Finding(
                category="Browser",
                title="Firefox profile",
                status="No Firefox profile directory found",
                severity=Severity.INFO,
                details="Firefox may not be installed or has not been launched yet.",
            )
        ]

    profiles = [p for p in base.iterdir() if p.is_dir() and (p / "prefs.js").exists()]
    if not profiles:
        return [
            Finding(
                category="Browser",
                title="Firefox profile",
                status="Profile directory found, but no prefs.js found",
                severity=Severity.MEDIUM,
                details="Firefox profile appears incomplete or not initialized.",
            )
        ]

    profile = next((p for p in profiles if p.name.endswith(".default-release")), profiles[0])
    prefs_text = (profile / "prefs.js").read_text(errors="ignore")
    user_js = profile / "user.js"
    user_text = user_js.read_text(errors="ignore") if user_js.exists() else ""
    combined = prefs_text + "\n" + user_text

    findings.append(
        Finding(
            category="Browser",
            title="Firefox profile",
            status=profile.name,
            severity=Severity.INFO,
            details="Firefox profile selected for privacy preference audit.",
        )
    )

    checks = [
        (
            "privacy.resistFingerprinting",
            "true",
            "Firefox fingerprinting resistance",
            "Expected Firefox preference: privacy.resistFingerprinting = true.",
        ),
        (
            "media.peerconnection.enabled",
            "false",
            "Firefox WebRTC exposure",
            "Expected Firefox preference: media.peerconnection.enabled = false to reduce WebRTC leak risk.",
        ),
        (
            "toolkit.telemetry.enabled",
            "false",
            "Firefox telemetry",
            "Expected Firefox preference: toolkit.telemetry.enabled = false.",
        ),
        (
            "network.trr.mode",
            "5",
            "Firefox DNS-over-HTTPS mode",
            "Expected Firefox preference: network.trr.mode = 5 to explicitly disable Firefox DoH override.",
        ),
        (
            "privacy.trackingprotection.enabled",
            "true",
            "Firefox tracking protection",
            "Expected Firefox preference: privacy.trackingprotection.enabled = true.",
        ),
        (
            "dom.security.https_only_mode",
            "true",
            "Firefox HTTPS-Only mode",
            "Expected Firefox preference: dom.security.https_only_mode = true.",
        ),
    ]

    for key, expected, title, details in checks:
        exact = f'user_pref("{key}", {expected});'
        if exact in combined:
            status = "Configured securely"
            severity = Severity.LOW
        elif f'"{key}"' in combined:
            status = "Present with different value"
            severity = Severity.HIGH
        else:
            status = "Not explicitly set"
            severity = Severity.MEDIUM

        findings.append(
            Finding(
                category="Browser",
                title=title,
                status=status,
                severity=severity,
                details=details,
            )
        )

    return findings
