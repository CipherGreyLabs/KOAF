from __future__ import annotations

from collections import Counter

from koaf.assessment import summarize_coverage
from koaf.checks import check_dns, check_external, check_firefox, check_host, check_network
from koaf.models import CheckOutcome, Finding, Severity


class AuditEngine:
    def __init__(self, logger, external_enabled: bool = False):
        self.logger = logger
        self.external_enabled = external_enabled

    def run(self) -> tuple[list[Finding], list[Finding]]:
        self.logger.info("Starting KOAF audit")

        findings: list[Finding] = []

        checks = [
            check_network,
            check_dns,
            lambda: check_external(enabled=self.external_enabled),
            check_host,
            check_firefox,
        ]

        for check in checks:
            check_name = getattr(check, "__name__", "check_external")
            try:
                findings.extend(check())
            except Exception as exc:
                findings.append(
                    Finding(
                        category="Engine",
                        title=f"{check_name} failed",
                        status=str(exc),
                        severity=Severity.INFO,
                        outcome=CheckOutcome.UNKNOWN,
                        details="The check failed. No conclusion is possible for this control.",
                        sensitive=True,
                    )
                )

        correlation = self.correlate(findings)
        correlation.extend(self.score(findings, correlation))
        return findings, correlation

    def correlate(self, findings: list[Finding]) -> list[Finding]:
        alerts: list[Finding] = []

        vpn = next((f for f in findings if f.title == "Local VPN interface inside Kali"), None)
        ipv6 = next((f for f in findings if f.title == "IPv6 exposure"), None)
        external = next((f for f in findings if f.title == "Public IPv4"), None)
        public_ipv6 = next((f for f in findings if f.title == "Public IPv6"), None)
        provider = next(
            (f for f in findings if f.title == "External provider classification"),
            None,
        )
        dns_stub = next((f for f in findings if f.title == "Local DNS stub resolver"), None)

        if vpn and vpn.status == "Not detected inside Kali":
            alerts.append(
                Finding(
                    category="Correlation",
                    title="No guest-side VPN interface detected",
                    status="Review routing model",
                    severity=Severity.MEDIUM,
                    details=(
                        "KOAF does not see a VPN interface inside Kali. This does not prove "
                        "that your host VPN is inactive. Compare the external IP results "
                        "with your expected VPN or ISP exit."
                    ),
                )
            )

        global_ipv6_statuses = {
            "Global IPv6 with default route",
            "Global IPv6 address present",
        }
        if ipv6 and ipv6.status in global_ipv6_statuses:
            alerts.append(
                Finding(
                    category="Correlation",
                    title="Local IPv6 correlation surface",
                    status=ipv6.status,
                    severity=Severity.MEDIUM,
                    details=(
                        "IPv6 may create a separate identity surface if it is not routed "
                        "consistently with IPv4. This matters especially when privacy "
                        "assumptions are based only on IPv4 VPN routing."
                    ),
                )
            )

        if public_ipv6 and public_ipv6.status not in {
            "Not detected or unavailable",
            "Unable to retrieve",
        }:
            alerts.append(
                Finding(
                    category="Correlation",
                    title="Public IPv6 visible externally",
                    status="Verify IPv6 route consistency",
                    severity=Severity.MEDIUM,
                    details=(
                        "A public IPv6 address is visible externally. Compare IPv4 and IPv6 "
                        "exit paths to detect split routing or IPv6 leak surfaces."
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
                        "The system is using a local DNS stub resolver. Beginners may see "
                        "127.0.0.53 and assume it is the final DNS provider, but it usually "
                        "forwards requests upstream through systemd-resolved."
                    ),
                )
            )

        if provider and "Datacenter" in provider.status:
            alerts.append(
                Finding(
                    category="Correlation",
                    title="External provider looks datacenter-like",
                    status="Review expected exit provider",
                    severity=Severity.INFO,
                    details=(
                        "The visible external provider looks like hosting or datacenter "
                        "infrastructure. This may be expected for some VPNs, but it is not "
                        "the same as residential ISP traffic."
                    ),
                )
            )

        if external and external.status == "Skipped by user":
            alerts.append(
                Finding(
                    category="Correlation",
                    title="External route check skipped",
                    status="Reduced confidence",
                    severity=Severity.INFO,
                    details=(
                        "External IP lookup was disabled. This is privacy friendly, but "
                        "KOAF cannot compare the visible internet-facing IP with the local "
                        "routing model."
                    ),
                )
            )
        elif (
            external
            and external.status != "Unable to retrieve"
            and vpn
            and vpn.status == "Not detected inside Kali"
        ):
            alerts.append(
                Finding(
                    category="Correlation",
                    title="External IP available without guest VPN interface",
                    status="Host routing may be involved",
                    severity=Severity.INFO,
                    details=(
                        "KOAF can see a public IPv4 address but no VPN interface inside "
                        "Kali. If you use a VPN on the host, this is expected."
                    ),
                )
            )

        return alerts

    def score(self, findings: list[Finding], alerts: list[Finding]) -> list[Finding]:
        """Summarize *primary* review items; correlation alerts cannot inflate risk."""
        # Keep the public method signature stable; alerts are explanatory, not primary checks.
        del alerts
        controls = [f for f in findings if f.category not in {"Summary", "Correlation"}]
        needs_attention = [
            f for f in controls if f.outcome in {CheckOutcome.REVIEW, CheckOutcome.FAIL}
        ]
        counts = Counter(item.severity for item in needs_attention)
        coverage = summarize_coverage(controls)

        if counts[Severity.HIGH] > 0:
            status = "High-priority findings require review"
            severity = Severity.HIGH
            outcome = CheckOutcome.REVIEW
        elif counts[Severity.MEDIUM] > 0:
            status = "Some findings require review"
            severity = Severity.MEDIUM
            outcome = CheckOutcome.REVIEW
        elif counts[Severity.LOW] > 0:
            status = "Low-priority findings require review"
            severity = Severity.LOW
            outcome = CheckOutcome.REVIEW
        elif coverage["assessed_controls"] == 0:
            status = "Insufficient information to assess posture"
            severity = Severity.INFO
            outcome = CheckOutcome.UNKNOWN
        elif coverage["unknown_controls"] > 0:
            status = "No prioritized issues in assessed checks; coverage is partial"
            severity = Severity.INFO
            outcome = CheckOutcome.UNKNOWN
        else:
            status = "No prioritized issues found in reported checks"
            severity = Severity.INFO
            outcome = CheckOutcome.INFO

        details = (
            "Only primary controls with REVIEW or FAIL outcomes contribute to this "
            "severity-based overview; correlation alerts are excluded. "
            f"Actionable: HIGH={counts[Severity.HIGH]}, MEDIUM={counts[Severity.MEDIUM]}, "
            f"LOW={counts[Severity.LOW]}. "
            f"Coverage: {coverage['assessed_controls']}/{coverage['total_controls']} "
            f"reported controls assessed, {coverage['unknown_controls']} unknown. "
            "This is not an anonymity score or a proof of safe routing."
        )

        return [
            Finding(
                category="Summary",
                title="Overall privacy surface",
                status=status,
                severity=severity,
                outcome=outcome,
                details=details,
            )
        ]
