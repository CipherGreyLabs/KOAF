"""Firefox privacy preference checks."""

from pathlib import Path

from koaf.models import Finding, Severity


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
