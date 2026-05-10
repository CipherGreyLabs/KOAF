from __future__ import annotations

import json
import socket
from pathlib import Path
from urllib.request import urlopen

from koaf.models import Finding, Severity
from koaf.shell import run_cmd


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
            title="Local VPN interface",
            status="Detected" if vpn_detected else "Not detected",
            severity=Severity.LOW if vpn_detected else Severity.MEDIUM,
            details="Checks for tun, tap, wg, or ppp interfaces inside the Kali guest.",
        )
    )

    ipv6_present = "inet6" in combined
    ipv6_default = "default" in ip6_route.stdout

    findings.append(
        Finding(
            category="Network",
            title="IPv6 exposure",
            status="IPv6 present" if ipv6_present else "IPv6 not present",
            severity=Severity.MEDIUM if ipv6_present else Severity.LOW,
            details="Detects IPv6 addresses in the guest. IPv6 can bypass IPv4-only privacy assumptions.",
            evidence=ip6_route.stdout if ipv6_default else "",
        )
    )

    default_route = ip_route.stdout.splitlines()[0] if ip_route.stdout else "No default route found"
    findings.append(
        Finding(
            category="Network",
            title="Default route",
            status=default_route,
            severity=Severity.INFO,
            details="Shows the primary IPv4 route used by the guest.",
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

    return [
        Finding(
            category="DNS",
            title="Configured resolvers",
            status=", ".join(resolvers) if resolvers else "No resolvers detected",
            severity=Severity.LOW if resolvers else Severity.HIGH,
            details="Parses /etc/resolv.conf to identify configured DNS resolvers.",
        )
    ]


def check_external() -> list[Finding]:
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
                details="Shows the IPv4 address observed by an external service.",
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
        ("privacy.resistFingerprinting", "true", "Fingerprinting resistance"),
        ("media.peerconnection.enabled", "false", "WebRTC disabled"),
        ("toolkit.telemetry.enabled", "false", "Telemetry disabled"),
    ]

    for key, expected, title in checks:
        exact = f'user_pref("{key}", {expected});'
        if exact in combined:
            status = "Configured securely"
            severity = Severity.LOW
        elif f'"{key}"' in combined:
            status = "Present with different value"
            severity = Severity.HIGH
        else:
            status = "Not set"
            severity = Severity.MEDIUM

        findings.append(
            Finding(
                category="Browser",
                title=title,
                status=status,
                severity=severity,
                details=f"Expected Firefox preference: {key} = {expected}.",
            )
        )

    return findings
