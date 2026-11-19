"""Firefox privacy preference checks."""

import re
from pathlib import Path

from koaf.models import CheckOutcome, Finding, Severity

_PREF_LINE = re.compile(
    r'^\s*user_pref\(\s*"([^"]+)"\s*,\s*([^)]*?)\s*\)\s*;',
    re.MULTILINE,
)


def _parse_prefs(text: str) -> dict[str, str]:
    """Extract active user_pref assignments; later values override earlier ones."""
    return {match.group(1): match.group(2).strip() for match in _PREF_LINE.finditer(text)}


def check_firefox() -> list[Finding]:
    """Inspect Firefox preferences without editing any profile files."""
    findings: list[Finding] = []
    base = Path.home() / ".mozilla" / "firefox"

    if not base.exists():
        return [
            Finding(
                category="Browser",
                title="Firefox profile",
                status="No Firefox profile directory found",
                severity=Severity.INFO,
                outcome=CheckOutcome.UNKNOWN,
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
                severity=Severity.INFO,
                outcome=CheckOutcome.UNKNOWN,
                details="Firefox profile appears incomplete or not initialized.",
            )
        ]

    profile = next((p for p in profiles if p.name.endswith(".default-release")), profiles[0])
    prefs_text = (profile / "prefs.js").read_text(errors="ignore")
    user_js = profile / "user.js"
    user_text = user_js.read_text(errors="ignore") if user_js.exists() else ""
    prefs = _parse_prefs(prefs_text)
    # user.js is reapplied on Firefox startup and takes precedence for these settings.
    prefs.update(_parse_prefs(user_text))

    findings.append(
        Finding(
            category="Browser",
            title="Firefox profile",
            status=profile.name,
            severity=Severity.INFO,
            outcome=CheckOutcome.INFO,
            details="Firefox profile selected for privacy preference audit.",
            sensitive=True,
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
            "Expected media.peerconnection.enabled = false to reduce WebRTC leak risk.",
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
            "Expected network.trr.mode = 5 to explicitly disable Firefox DoH override.",
        ),
        (
            "privacy.trackingprotection.enabled",
            "true",
            "Firefox tracking protection",
            "Expected privacy.trackingprotection.enabled = true.",
        ),
        (
            "dom.security.https_only_mode",
            "true",
            "Firefox HTTPS-Only mode",
            "Expected dom.security.https_only_mode = true.",
        ),
        (
            "webgl.disabled",
            "true",
            "Firefox WebGL exposure",
            "Expected webgl.disabled = true for stricter fingerprint reduction.",
        ),
        (
            "media.navigator.enabled",
            "false",
            "Firefox media device enumeration",
            "Expected media.navigator.enabled = false to reduce device enumeration.",
        ),
    ]

    for key, expected, title, details in checks:
        configured = prefs.get(key)
        if configured is None:
            status = "Not explicitly set"
            severity = Severity.INFO
            outcome = CheckOutcome.UNKNOWN
        elif configured == expected:
            status = "Configured as recommended"
            severity = Severity.LOW
            outcome = CheckOutcome.PASS
        else:
            status = "Present with different value"
            severity = Severity.MEDIUM
            outcome = CheckOutcome.REVIEW

        findings.append(
            Finding(
                category="Browser",
                title=title,
                status=status,
                severity=severity,
                outcome=outcome,
                details=details,
            )
        )

    return findings
