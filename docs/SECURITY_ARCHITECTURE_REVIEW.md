# KOAF — Architecture, Privacy and Security Review

**Review date:** 2026-11-19  
**Scope:** KOAF CLI, audit engine, network/DNS/host/Firefox/external checks,
Finding model, redaction, logging, CI, packaging and the proposed local dashboard.  
**Baseline:** \`main\` v0.1.0 plus the unmerged maintenance work in PR #7.  
**Follow-up changes:** PR #8 (audit correctness) and PR #9 (local browser GUI).

This is a source-level engineering review with GitHub Actions smoke and regression
tests, **not** an independent penetration test, cross-distro compatibility
certification, anonymity audit or external DNS-leak validation. No claim is made
that a green CI run proves privacy or network isolation.

## 1. Architecture and trust boundaries

\`\`\`text
CLI flags
   |
   +--> AuditEngine (default: no external lookups)
            |
            +--> Local read-only checks
            |     network / DNS / host / Firefox
            |
            +--> Optional external lookups (--external required)
            |     api.ipify.org / api6.ipify.org / ipinfo.io
            |
            +--> Findings and correlation alerts
                        |
                        +--> Rich CLI and JSON (redact on request)
                        +--> Local browser dashboard (--gui)
                              127.0.0.1 / random port / session-token URL
                              redacted by default / no persistent report
\`\`\`

**Sensitive data:** public IP addresses, route details, resolvers, device
identifiers, profile identifiers, local paths, ASN/provider detail, and
unexpected error messages. Redaction must be enforced before any shareable
output. The dashboard has an explicit reveal action; \`--redact\` locks it.

**Relevant threat boundaries:**
- Local system inspection must not modify network/browser configuration.
- External calls must be explicitly opted into and limited to documented hosts.
- HTTP redirects must be checked **before** the next outbound request.
- A dashboard HTTP listener must never bind to LAN or public interfaces.
- Untrusted audit strings must be rendered as text, not executable HTML.
- A malicious local process with access to the user's session/browser is
  outside the dashboard's isolation guarantee.

## 2. Fixed or implemented in review branches

| Priority | Finding | Change | PR |
| --- | --- | --- | --- |
| High | Redirect destination was only validated *after* urllib followed it | Reject off-allowlist redirects before following | #8 |
| High | Machine-ID prefix needlessly read and shown | Inspect file presence only | #8 |
| High | VPN check scanned unrelated interface output text | Match actual interface headers instead | #8 |
| High | Missing \`ip\` command could be interpreted as absent VPN/IPv6 | Emit unknown/unavailable results | #8 |
| High | Firefox substring checks could match comments or stale values | Parse assignments, apply user.js precedence | #8 |
| Medium | External IP/provider responses assumed correct format | Validate IPv4, JSON shape and organization type | #8 |
| Medium | Default audit created disk logs | Require explicit \`--log-file\`; no default file writes | #8 |
| UX | Reports require reading long console tables | Optional interactive GUI with filters, contextual findings and export | #9 |
| Privacy | GUI could accidentally share raw data | Redacted first view, reveal interaction, hard lock via \`--redact\` | #9 |
| Security | Dashboard could expose audit data on local network | Loopback-only, session token, origin/host validation, CSP and no-store headers | #9 |

These changes are **not on main until the corresponding PRs are merged**.

## 3. Remaining technical risks and limitations

### P1 — Accuracy and trustworthiness

1. **Scoring conflates findings and correlation alerts.** The overall summary
   counts both, so one underlying observation may influence the score twice.
   Score unique primary controls, and report confidence separately.
2. **IPv6 classification is too broad.** Non-link-local addresses are treated
   as "global"; ULA, documentation, and other special-purpose address ranges
   should be separated from globally routable addresses. Test with \`ipaddress\`
   and structured \`ip -j\` output.
3. **VPN detection remains heuristic.** Prefixes such as \`tun\` and \`wg\`
   are not proof of an active VPN or correct routing. Support interface types
   and route validation; handle host-level VPN and VM NAT explicitly.
4. **Firefox settings are not an effective-policy audit.** Even after parser
   fixes, per-profile \`prefs.js\`/\`user.js\` do not capture enterprise policies,
   built-in defaults, add-ons, or the live runtime. DoH, WebRTC, telemetry, and
   fingerprint preferences have context-dependent trade-offs; avoid claiming
   every preferred value is universally secure.
5. **DNS checks are not a DNS leak test.** \`/etc/resolv.conf\` and
   \`resolvectl\` alone do not establish which upstream DNS servers are used
   for every domain/interface. Detect NetworkManager and systemd-resolved
   split-DNS; external leak tests require separate informed consent.
6. **Unavailable external IPv6 is not proof of safety.** A failed request to
   an IPv6 test service must be reported as unknown/unavailable, not a
   positive secure-state assertion.

### P2 — Security, quality and maintainability

7. **Explicit file logging still needs race-resistant opening.** Symlink
   pre-checks can have time-of-check/time-of-use races. Keep file logging off
   by default; for opted-in logs consider \`O_NOFOLLOW\` and restrictive
   secure-file opening/rotation.
8. **Redaction must be tested end to end.** Expand tests for route strings,
   Firefox profile names, DNS, server error text, HTML rendering, and exported
   JSON; prevent secrets in diagnostics, snapshots and logs.
9. **Reproducible packaging is limited.** Dependencies have ranges but no
   locked release resolution. Add wheel/sdist build-and-install validation,
   release artifact checksums, and update workflows with pinned provenance.
10. **The GUI has no manual Kali usability verification yet.** Test Firefox
    and Chromium at common desktop resolutions, keyboard navigation,
    reduced-motion preferences, and high contrast. The interface is a local
    browser UI, not a native GTK/Qt application.
11. **Test coverage is environment-heavy in places.** Add fixture-driven
    unit tests for Linux command failure modes, varying route formats and
    Firefox profile selection. External tests must never use live IP services
    in CI.
12. **Release versioning remains provisional.** PR #7 bumps the package to
    0.1.1; this is not a published GitHub release or PyPI publication.
    Align CHANGELOG dates with the actual release.
13. **Docs and governance need consistency.** Any roadmap suggesting
    automatic hardening must be reconciled with root \`AGENTS.md\`, which
    prohibits automatic system changes and stealth/anti-forensic functions.

## 4. Recommended delivery order

1. Merge #7 after final review of the maintenance changes and CI.
2. Merge #8 after verifying no security regressions and re-running CI.
3. Merge #9 after a manual Kali/Firefox dashboard smoke test and accessibility
   review. The branches are stacked in this order.
4. Release 0.1.1 with an accurate changelog date, GitHub tag, release notes,
   reproducible build artifacts and a clean post-merge CI run.
5. Create dedicated PRs for severity/confidence semantics, structured network
   inspection and IPv6 types, Firefox policy context, and DNS reliability.
6. Test on Kali VirtualBox NAT, host-level VPN, guest-side VPN, bare metal,
   offline networks, and systems without Firefox or \`resolvectl\`.

## 5. Release acceptance checks

- [ ] Source, PR diff and dependencies reviewed
- [ ] Python 3.10, 3.11, 3.12 and 3.13 CI green
- [ ] Ruff, pytest, pip-audit and Bandit green
- [ ] \`python -m koaf --audit\` makes no external network requests
- [ ] \`python -m koaf --audit --json --redact\` does not expose identifiers
- [ ] \`python -m koaf --gui --redact\` stays locked even with \`?redact=0\`
- [ ] Dashboard is only reachable on loopback; wrong Host/Origin/token rejected
- [ ] GUI can be opened in Kali and works without third-party assets
- [ ] No reports or logs written by default
- [ ] No misleading anonymity guarantees or false certainty in conclusions
- [ ] CHANGELOG, README, version, release tag and release artifacts aligned
