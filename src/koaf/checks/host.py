"""Local host identity checks."""

import socket
from pathlib import Path

from koaf.models import Finding, Severity


def check_host() -> list[Finding]:
    """Inspect stable host identifiers without changing them."""
    hostname = socket.gethostname()
    unique_chars = len(set(hostname))
    machine_id_path = Path("/etc/machine-id")

    findings = [
        Finding(
            category="Host",
            title="Hostname entropy",
            status=hostname,
            severity=Severity.LOW if unique_chars >= 6 else Severity.MEDIUM,
            details=(
                f"Unique character count: {unique_chars}. Low entropy hostnames are easier "
                "to correlate."
            ),
            sensitive=True,
        )
    ]

    if machine_id_path.is_file():
        # Presence is sufficient; never read or retain any bytes of this stable identifier.
        findings.append(
            Finding(
                category="Host",
                title="Machine ID presence",
                status="Present",
                severity=Severity.INFO,
                details=(
                    "A Linux machine-id file exists. Its contents are not read or included "
                    "in audit reports."
                ),
            )
        )
    else:
        findings.append(
            Finding(
                category="Host",
                title="Machine ID presence",
                status="Not found",
                severity=Severity.LOW,
                details="No /etc/machine-id file was found.",
            )
        )

    return findings
