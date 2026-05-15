# Changelog

All notable changes to KOAF will be documented in this file.

## v0.1.0

Initial audit-first foundation.

### Added

- Beginner friendly Kali OPSEC and privacy audit workflow
- Read-only audit mode
- Local VPN interface visibility check inside Kali
- IPv4 default route inspection
- IPv6 exposure classification
- DNS resolver configuration check
- Local DNS stub resolver detection
- External public IPv4 visibility check
- Optional `--no-external` mode to skip external IP lookup
- Hostname entropy check
- Firefox privacy preference checks
- Beginner explanation mode with `--explain`
- Machine-readable JSON output with `--json`
- Structured Finding model
- Basic correlation alerts
- Development dependencies for pytest and ruff
- GitHub Actions CI workflow
- MIT license

### Notes

KOAF v0.1.0 is an audit-first release. It does not modify system settings and does not claim to guarantee anonymity.
