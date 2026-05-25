# AGENTS.md

## 1) Project Overview
KOAF (Kali OPSEC Automation Framework) is a **read-only Kali/Linux privacy and OPSEC surface audit tool**.

Core intent:
- Educational and transparent: findings should explain what was checked and why it matters.
- Privacy-conscious and safe: audits should minimize data exposure and avoid risky behavior.
- Defensive posture only: KOAF helps users understand local privacy/OPSEC posture; it does not provide offensive, evasive, or anti-forensic capability.

Non-goals:
- KOAF must **not** promise or imply guaranteed anonymity, invisibility, or complete protection.
- KOAF must **not** present results as legal, forensic, or professional security certification.

## 2) Safety Rules
- Keep KOAF read-only by default and in practice: avoid code paths that alter system configuration or state.
- **Do not add features that modify system settings**, including but not limited to:
  - disabling IPv6
  - changing DNS settings
  - editing Firefox profiles
  - deleting logs
  - spoofing MAC addresses
  - rotating machine IDs
- Prohibited behavior categories:
  - stealth/evasion
  - persistence
  - malware-like techniques
  - anti-forensics
- Do not add logic that attempts to hide KOAF execution or bypass host/network monitoring.
- Any new checks must be explainable, reversible in impact (preferably no impact), and auditable in source.

## 3) Privacy Rules
- Default audit mode must remain **local-first**.
- External lookup checks may only run when the user explicitly provides `--external`.
- Never silently exfiltrate, upload, or transmit audit artifacts.
- Data minimization first: collect only what is required for a stated check.
- Redaction support must be preserved for machine-readable output paths.
- Avoid embedding secrets, tokens, host identifiers, or personally identifying data in logs, fixtures, snapshots, and test artifacts.

## 4) Code Style Rules
- Prefer small, composable checks with clear function boundaries and explicit inputs/outputs.
- Keep behavior deterministic and side-effect free where feasible.
- Use explicit error handling and user-facing messages that describe limitations without overstating certainty.
- Preserve CLI backwards compatibility unless intentionally changed and documented.
- Keep modules focused: separate data collection, normalization, scoring/risk labeling, and rendering/output.
- Add or update type hints and docstrings where relevant for new/changed code.

## 5) Required Test Commands
Run the following commands before merging changes:

```bash
python -m compileall src/koaf
ruff check .
python -m pytest
python -m koaf --audit
python -m koaf --audit --json --redact
python -m koaf --audit --external --redact
```

If behavior changes, update `README.md`, `CHANGELOG.md`, and tests where relevant.

## 6) Documentation Rules
- Keep user-facing docs aligned with actual CLI behavior and defaults.
- Document safety/privacy constraints for any new check or output mode.
- If behavior changes, update:
  - `README.md`
  - `CHANGELOG.md`
  - tests and test fixtures (where relevant)
- Avoid marketing language that implies KOAF guarantees anonymity.
- Include clear notes when a check requires network access, and gate that behavior behind explicit user intent (`--external`).
