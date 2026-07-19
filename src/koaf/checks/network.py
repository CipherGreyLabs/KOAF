"""Local network and route checks."""

from __future__ import annotations

import ipaddress

from koaf.models import Finding, Severity
from koaf.shell import run_cmd


def _extract_ipv6_addresses(ip_output: str) -> tuple[list[str], list[str]]:
    """Return link-local and global IPv6 addresses from ``ip a`` output."""
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
    """Inspect local interfaces and routes without changing network state."""
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
            "A global IPv6 address and IPv6 default route are present. This can create a "
            "separate identity surface if IPv6 is not routed like IPv4."
        )
        ipv6_evidence = ip6_route.stdout
    elif global_v6:
        ipv6_status = "Global IPv6 address present"
        ipv6_severity = Severity.MEDIUM
        ipv6_details = "A global IPv6 address is present. Verify IPv6 application routing."
        ipv6_evidence = ", ".join(global_v6)
    elif link_local_v6:
        ipv6_status = "Only link-local IPv6 present"
        ipv6_severity = Severity.LOW
        ipv6_details = (
            "Only link-local IPv6 addresses were detected. This is common on Linux and usually "
            "does not indicate public IPv6 exposure by itself."
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
            sensitive=bool(ipv6_evidence),
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
            sensitive=True,
        )
    )

    return findings
