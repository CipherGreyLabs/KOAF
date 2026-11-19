# Changelog

All notable changes to KOAF will be documented in this file.

## Unreleased

_No new changes yet._

## v0.1.1 — integrated on 2026-11-19 (GitHub release pending)

### User experience

- Add optional `koaf --gui` local browser dashboard with responsive dark interface
- Add category navigation, severity filters, search, details, and JSON download
- Start with sensitive fields redacted; support explicit reveal or permanent `--redact` lock
- Serve bundled assets on loopback using a random port and unguessable session path
- Set strict browser security headers; do not log HTTP paths or upload reports
- Add integration tests for report redaction, local assets, and request isolation


### Security and reliability

- Validate third-party HTTP redirect destinations before following any redirect
- Validate externally returned IPv4 and provider metadata before further lookup
- Avoid reading or exposing machine-ID content, including identifier fragments
- Make on-disk log writing explicitly opt-in with `--log-file`
- Match VPN interface names instead of arbitrary text in network output
- Report unavailable network information as unknown rather than safe/absent
- Parse active Firefox preferences with user.js precedence to avoid false results
- Add regression coverage for these protections

### Security

- Redact exact external provider and ASN evidence from shareable reports
- Redact unexpected check failures that may contain local paths
- Restrict external lookups to an explicit HTTPS host allowlist
- Limit external response sizes and validate JSON response types
- Reject symbolic-link log targets and tighten POSIX log permissions
- Add automated dependency auditing and static security analysis to CI
- Pin GitHub Actions to immutable commit SHAs
- Make external checks opt-in by default at both the audit-engine and check-function layers
- Redact external lookup failure evidence that could expose sensitive request details

### Changed

- Refactor the monolithic checks module into focused network, DNS, external, host, and Firefox modules
- Make `--external` and `--no-external` mutually exclusive while retaining `--no-external` for backwards compatibility
- Replace remaining anonymity-focused package and CLI descriptions with privacy and exposure wording
- Test all supported Python versions from 3.10 through 3.13 in CI
- Expand Python package metadata for repository, issue tracker, license, classifiers, and project keywords

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
