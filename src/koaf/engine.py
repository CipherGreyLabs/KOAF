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

        vpn = next((f for f in findings if f.title == "Local VPN interface"), None)
        ipv6 = next((f for f in findings if f.title == "IPv6 exposure"), None)

        if vpn and vpn.status == "Not detected":
            alerts.append(
                Finding(
                    category="Correlation",
                    title="No guest-side VPN interface detected",
                    status="Review routing model",
                    severity=Severity.MEDIUM,
                    details="If VPN is expected, it may be running on the host rather than inside Kali. External IP verification is required.",
                )
            )

        if ipv6 and ipv6.status == "IPv6 present":
            alerts.append(
                Finding(
                    category="Correlation",
                    title="IPv6 correlation surface",
                    status="IPv6 is active",
                    severity=Severity.MEDIUM,
                    details="IPv6 may create a separate identity surface if not routed consistently with IPv4.",
                )
            )

        return alerts
