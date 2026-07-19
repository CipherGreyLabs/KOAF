"""Local DNS resolver checks."""

from pathlib import Path

from koaf.models import Finding, Severity
from koaf.shell import run_cmd


def check_dns() -> list[Finding]:
    """Inspect local resolver configuration without modifying it."""
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
            sensitive=True,
        )
    ]

    if any(resolver.startswith("127.") for resolver in resolvers):
        resolved = run_cmd(["resolvectl", "status"], timeout=3)
        if resolved.returncode == 0 and resolved.stdout:
            details = (
                "A local DNS stub resolver was detected. KOAF captured resolvectl status so "
                "users can inspect the real upstream DNS servers."
            )
            evidence = resolved.stdout[:1200]
        else:
            details = "A local DNS stub resolver was detected. Upstream DNS was not collected."
            evidence = resolved.stderr

        findings.append(
            Finding(
                category="DNS",
                title="Local DNS stub resolver",
                status="Detected" if resolved.returncode == 0 else "Detected, upstream unknown",
                severity=Severity.INFO,
                details=details,
                evidence=evidence,
                sensitive=bool(evidence),
            )
        )

    return findings
