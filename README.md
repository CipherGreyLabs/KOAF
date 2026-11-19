# KOAF

**Kali OPSEC Automation Framework**

KOAF is a beginner friendly Kali Linux privacy and OPSEC audit tool. It helps new Linux and Kali users understand what their system may expose online, such as VPN visibility, DNS settings, IPv6 exposure, hostname identity, public IP routing, and Firefox privacy settings.

The goal is simple: make privacy related system exposure easier to see and understand.

KOAF is currently **read only**. It checks and explains. It does not change your system.

## Who this is for

KOAF is designed for:

* New Kali Linux users
* Linux beginners who are learning networking and privacy basics
* Privacy conscious users who want to understand what their VM exposes
* Students and lab users who want a simple OPSEC visibility tool

It is not meant to be a magic anonymity solution. It is an educational audit tool that helps you understand your current exposure posture.

## What KOAF currently checks

KOAF v0.1.1 performs read only checks for:

* Local VPN interface visibility inside Kali
* IPv4 and IPv6 exposure
* Default route inspection
* DNS resolver configuration
* Local DNS stub resolver detection
* Optional external public IPv4 visibility with `--external`
* Optional external provider classification with `--external`
* Optional public IPv6 visibility check with `--external`
* Privacy safe output redaction with `--redact`
* Hostname entropy
* Linux machine ID presence
* Firefox privacy preference posture
* Overall privacy surface summary

Firefox checks currently include:

* Fingerprinting resistance
* WebRTC exposure
* Telemetry setting
* DNS over HTTPS mode
* Tracking protection
* HTTPS Only mode
* WebGL exposure
* Media device enumeration

## Why this matters

Many beginners assume that using a VPN or running Kali in a virtual machine automatically means their setup is private. In reality, privacy depends on multiple layers working together.

KOAF helps show common exposure points, for example:

* A VPN may run on the host, but not inside the Kali guest
* IPv6 can create a separate network identity surface
* DNS may be handled by a local stub resolver that forwards upstream
* Firefox settings can affect browser privacy posture
* Hostnames and machine IDs can make systems easier to recognize or correlate
* A public IP may look like a residential ISP, VPN, datacenter, or unknown provider type

## Safety

Audit mode does not modify the system.

KOAF does not:

* Change network settings
* Disable IPv6
* Modify Firefox settings
* Change DNS settings
* Delete logs
* Spoof identifiers
* Claim to guarantee anonymity

By default, KOAF stays local and does not contact external lookup services. This privacy-first default is enforced both by the CLI and by KOAF's internal audit/check APIs. To check public IPv4, public IPv6 availability, and basic provider classification, explicitly use:

```bash
koaf --audit --external
```

External mode contacts `api.ipify.org`, `api6.ipify.org`, and `ipinfo.io`. KOAF only permits HTTPS requests to these hosts, validates redirect destinations, limits response sizes, and does not send local audit reports.

If you want to share output safely, use redaction:

```bash
koaf --audit --redact
koaf --audit --json --redact
koaf --audit --external --json --redact
```

Redaction hides public IPs, routes, hostnames, profile identifiers, machine identifiers, exact provider/ASN evidence, and sensitive failure details.

Future hardening features should be controlled, explainable, and reversible.

## Installation

Clone the repository:

```bash
git clone https://github.com/CipherGreyLabs/KOAF.git
cd KOAF
```

Create and activate a virtual environment:

```bash
python3 -m venv .venv
source .venv/bin/activate
```

Install KOAF in editable mode:

```bash
pip install -e .
```

For development and tests:

```bash
pip install -e .[dev]
```

## Usage

Run the standard local-only audit:

```bash
python3 -m koaf --audit
```

Or, after editable install:

```bash
koaf --audit
```

Run audit with external lookup checks:

```bash
koaf --audit --external
```

For beginner friendly explanations of each finding, add `--explain`:

```bash
koaf --audit --explain
```

To explicitly keep external lookup services disabled:

```bash
koaf --audit --no-external
```

`--no-external` is retained for backwards compatibility. External checks are already disabled by default, and it cannot be combined with `--external`.

To redact sensitive values such as IPs, routes, hostnames, and profile names:

```bash
koaf --audit --redact
```

To print machine readable JSON:

```bash
koaf --audit --json
```

You can combine options:

```bash
koaf --audit --external --json --redact
```

## Example output

KOAF displays findings in tables, grouped by category:

```text
Network   Local VPN interface inside Kali     Not detected inside Kali      MEDIUM
Network   IPv6 exposure                       Only link-local IPv6 present  LOW
DNS       Configured resolvers                127.0.0.53                    LOW
External  Public IPv4                         Skipped by user               INFO
Browser   Firefox WebRTC exposure             Configured securely           LOW
Summary   Overall privacy surface             Some exposure indicators      MEDIUM
```

When `--external` is used, additional external findings may appear:

```text
External  Public IPv4                         198.51.100.10                 INFO
External  External provider classification    Residential ISP-like provider INFO
External  Public IPv6                         Not detected or unavailable   LOW
```

It also shows correlation alerts when a finding needs interpretation, for example:

```text
No guest-side VPN interface detected
DNS stub resolver requires interpretation
External route check skipped
Public IPv6 visible externally
```

With `--explain`, KOAF also prints plain language explanations for each finding and correlation alert.

Example JSON shape:

```json
{
  "tool": "KOAF",
  "version": "0.1.1",
  "mode": "audit",
  "redacted": true,
  "findings": [],
  "correlation_alerts": []
}
```

## Development checks

Run syntax checks:

```bash
python -m compileall src/koaf
```

Run linting:

```bash
ruff check .
```

Run tests:

```bash
python -m pytest
```

## Important limitations

KOAF does not prove that you are anonymous.

Current limitations:

* External provider classification is heuristic and may be wrong
* DNS leak testing is not fully implemented yet
* Browser fingerprinting is limited to selected Firefox preferences
* Host VPN detection is inferred indirectly and not proven from inside Kali
* Hardening mode is not implemented yet

## Roadmap

Planned improvements:

* Better DNS upstream detection
* DNS versus external route correlation
* More beginner friendly explanations
* Optional controlled hardening with rollback support
* Stronger test coverage around CLI behavior

## Project status

Current version: **v0.1.1**

KOAF is currently an audit first foundation. The focus is visibility, explanation, and safe learning before adding automatic hardening.

## License

KOAF is released under the MIT License.

## Ethical use

KOAF is intended for personal learning, privacy awareness, lab use, and defensive OPSEC education. Use it only on systems you own or are authorized to assess.
