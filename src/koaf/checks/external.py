"""Explicitly opt-in external visibility checks."""

from __future__ import annotations

import ipaddress
import json
from http.client import HTTPResponse
from urllib.parse import urlsplit
from urllib.request import Request, urlopen

from koaf.models import Finding, Severity

_ALLOWED_EXTERNAL_HOSTS = frozenset({"api.ipify.org", "api6.ipify.org", "ipinfo.io"})
_MAX_RESPONSE_BYTES = 64 * 1024


def _classify_provider(org: str) -> str:
    """Classify provider text using intentionally cautious heuristics."""
    text = org.lower()
    vpn_terms = ["vpn", "nord", "mullvad", "proton", "surfshark", "expressvpn"]
    datacenter_terms = [
        "hosting",
        "cloud",
        "datacenter",
        "data center",
        "vps",
        "server",
        "digitalocean",
        "amazon",
        "aws",
        "google",
        "microsoft",
        "azure",
        "ovh",
        "hetzner",
        "leaseweb",
        "m247",
        "datacamp",
    ]
    isp_terms = [
        "telecom",
        "communications",
        "broadband",
        "cable",
        "fiber",
        "fibre",
        "proximus",
        "telenet",
        "orange",
        "vodafone",
        "ziggo",
        "kpn",
        "scarlet",
    ]

    if any(term in text for term in vpn_terms):
        return "VPN-like provider"
    if any(term in text for term in datacenter_terms):
        return "Datacenter or hosting-like provider"
    if any(term in text for term in isp_terms):
        return "Residential ISP-like provider"
    return "Unknown provider type"


def _validated_request(url: str) -> Request:
    parsed = urlsplit(url)
    if parsed.scheme != "https" or parsed.hostname not in _ALLOWED_EXTERNAL_HOSTS:
        raise ValueError("External lookup URL is not permitted")
    if parsed.username or parsed.password or parsed.port not in {None, 443}:
        raise ValueError("External lookup URL contains unsupported authority data")
    return Request(url, headers={"User-Agent": "KOAF/0.1.1"})


def _read_limited(response: HTTPResponse) -> bytes:
    # urllib may follow redirects, so validate the final destination as well.
    _validated_request(response.geturl())
    payload = response.read(_MAX_RESPONSE_BYTES + 1)
    if len(payload) > _MAX_RESPONSE_BYTES:
        raise ValueError("External lookup response exceeded the size limit")
    return payload


def _http_json(url: str, timeout: int = 5) -> dict:
    request = _validated_request(url)
    # URL scheme and hostname are constrained by _validated_request.
    with urlopen(request, timeout=timeout) as response:  # nosec B310
        content_type = response.headers.get_content_type()
        if content_type != "application/json":
            raise ValueError("External lookup returned an unexpected content type")
        return json.loads(_read_limited(response).decode())


def _http_text(url: str, timeout: int = 5) -> str:
    request = _validated_request(url)
    # URL scheme and hostname are constrained by _validated_request.
    with urlopen(request, timeout=timeout) as response:  # nosec B310
        return _read_limited(response).decode().strip()


def check_external(enabled: bool = False) -> list[Finding]:
    """Inspect public visibility only when external checks are explicitly enabled."""
    if not enabled:
        return [
            Finding(
                category="External",
                title="Public IPv4",
                status="Skipped by user",
                severity=Severity.INFO,
                details=(
                    "External IP lookup is disabled by default. Use --external to explicitly "
                    "enable third-party visibility checks."
                ),
            )
        ]

    findings: list[Finding] = []

    try:
        ip = _http_text("https://api.ipify.org", timeout=5)
        findings.append(
            Finding(
                category="External",
                title="Public IPv4",
                status=ip,
                severity=Severity.INFO,
                details=(
                    "Shows the IPv4 address observed by an external service. This helps compare "
                    "visible IP with expected VPN or ISP exit."
                ),
                sensitive=True,
            )
        )
    except Exception as exc:
        findings.append(
            Finding(
                category="External",
                title="Public IPv4",
                status="Unable to retrieve",
                severity=Severity.MEDIUM,
                details=(
                    "External IPv4 lookup failed. This may be due to no internet or "
                    "HTTPS blocking."
                ),
                evidence=str(exc),
                sensitive_evidence=True,
            )
        )
        return findings

    try:
        ipinfo = _http_json(f"https://ipinfo.io/{ip}/json", timeout=5)
        org = ipinfo.get("org", "Unknown")
        provider_type = _classify_provider(org)
        findings.append(
            Finding(
                category="External",
                title="External provider classification",
                status=provider_type,
                severity=Severity.INFO,
                details=(
                    "Classifies the visible external provider using public IP registration data. "
                    "This is a heuristic, not proof of VPN or ISP usage."
                ),
                evidence=org,
                sensitive_evidence=True,
            )
        )
    except Exception as exc:
        findings.append(
            Finding(
                category="External",
                title="External provider classification",
                status="Unable to classify",
                severity=Severity.INFO,
                details="Provider classification failed. Public IPv4 detection still completed.",
                evidence=str(exc),
                sensitive_evidence=True,
            )
        )

    try:
        ipv6 = _http_text("https://api6.ipify.org", timeout=5)
        if ipaddress.ip_address(ipv6).version == 6:
            findings.append(
                Finding(
                    category="External",
                    title="Public IPv6",
                    status=ipv6,
                    severity=Severity.MEDIUM,
                    details=(
                        "A public IPv6 address was visible externally. Compare this with IPv4 "
                        "to detect split routing or IPv6 leak surfaces."
                    ),
                    sensitive=True,
                )
            )
    except Exception:
        findings.append(
            Finding(
                category="External",
                title="Public IPv6",
                status="Not detected or unavailable",
                severity=Severity.LOW,
                details=(
                    "KOAF could not detect a public IPv6 address through the external lookup. "
                    "This usually means IPv6 egress is unavailable or blocked."
                ),
            )
        )

    return findings
