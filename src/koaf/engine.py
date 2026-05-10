from __future__ import annotations

from koaf.checks import check_dns, check_external, check_firefox, check_host, check_network
from koaf.models import Finding, Severity


class AuditEngine:
    def __init__(self, logger):
        self.logger = logger

    def run(self) -> tuple[list[Finding], list[Finding]]:
        self.logger.info("Starting KOAF audit")

        findings: list[Finding] = []

        for check in [check_network, check_dns, check_external, check_host, check_firefox]:
            try:
                findings.extend(check())
            except Exception as exc:
                findings.append(
                    Finding(
                        category="Engine",
                        title=f"{check.__name__} failed",
                        status=str(exc),
                        severity=Severity.HIGH,
                        details="The check failed but the audit continued safely.",
                    )
                )

        correlation = self.correlate(findings)
        return findings, correlation

    def correlate(self, findings: list[Finding]) -> list[Finding]:
        alerts: list[Finding] = []

        vpn = next((f for f in findings if f.title == "Local VPN interface inside Kali"), None)
        ipv6 = next((f for f in findings if f.title == "IPv6 exposure"), None)
        external = next((f for f in findings if f.title == "Public IPv4"), None)
        dns_stub = next((f for f in findings if f.title == "Local DNS stub resolver"), None)

        if vpn and vpn.status == "Not detected inside Kali":
            alerts.append(
                Finding(
                    category="Correlation",
                    title="No guest-side VPN interface detected",
                    status="Review routing model",
                    severity=Severity.MEDIUM,
                    details=(
                        "KOAF does not see a VPN interface inside Kali. This does not prove that "
                        "your host VPN is inactive. Compare the external IPv4 result with your expected VPN or ISP exit."
                    ),
                )
            )

        if ipv6 and ipv6.status in {"Global IPv6 with default route", "Global IPv6 address present"}:
            alerts.append(
                Finding(
                    category="Correlation",
                    title="IPv6 correlation surface",
                    status=ipv6.status,
                    severity=Severity.MEDIUM,
                    details=(
                        "IPv6 may create a separate identity surface if it is not routed consistently with IPv4. "
                        "This matters especially when privacy assumptions are based only on IPv4 VPN routing."
                    ),
                )
            )

        if dns_stub:
            alerts.append(
                Finding(
                    category="Correlation",
                    title="DNS stub resolver requires interpretation",
                    status="Inspect upstream DNS",
                    severity=Severity.INFO,
                    details=(
                        "The system is using a local DNS stub resolver. Beginners may see 127.0.0.53 and assume "
                        "it is the final DNS provider, but it usually forwards requests upstream through systemd-resolved."
                    ),
                )
            )

        if external and external.status != "Unable to retrieve" and vpn and vpn.status == "Not detected inside Kali":
            alerts.append(
                Finding(
                    category="Correlation",
                    title="External IP available without guest VPN interface",
                    status="Host routing may be involved",
                    severity=Severity.INFO,
                    details=(
                        "KOAF can see a public IPv4 address but no VPN interface inside Kali. If you use a VPN on the host, "
                        "this is expected; future versions will classify the external provider more deeply."
                    ),
                )
            )

        return alerts
