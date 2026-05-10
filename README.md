# KOAF

**Kali OPSEC Automation Framework**

KOAF is a beginner friendly Kali Linux privacy and OPSEC audit tool. It helps new Linux and Kali users understand what their system may expose online, such as VPN visibility, DNS settings, IPv6 exposure, hostname identity, and Firefox privacy settings.

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

KOAF v0.1.0 performs read only checks for:

* Local VPN interface visibility inside Kali
* IPv4 and IPv6 exposure
* Default route inspection
* DNS resolver configuration
* Local DNS stub resolver detection
* External public IPv4 visibility
* Hostname entropy
* Firefox privacy preference posture

Firefox checks currently include:

* Fingerprinting resistance
* WebRTC exposure
* Telemetry setting
* DNS over HTTPS mode
* Tracking protection
* HTTPS Only mode

## Why this matters

Many beginners assume that using a VPN or running Kali in a virtual machine automatically means their setup is private. In reality, privacy depends on multiple layers working together.

KOAF helps show common exposure points, for example:

* A VPN may run on the host, but not inside the Kali guest
* IPv6 can create a separate network identity surface
* DNS may be handled by a local stub resolver that forwards upstream
* Firefox settings can affect browser privacy posture
* Hostnames can make systems easier to recognize or correlate

## Safety

Audit mode does not modify the system.

KOAF does not:

* Change network settings
* Disable IPv6
* Modify Firefox settings
* Change DNS settings
* Delete logs
* Claim to guarantee anonymity

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

## Usage

Run the audit:

```bash
python3 -m koaf --audit
```

Or, after editable install:

```bash
koaf --audit
```

## Example output

KOAF displays findings in tables, grouped by category:

```text
Network   Local VPN interface inside Kali   Not detected inside Kali   MEDIUM
Network   IPv6 exposure                     Only link-local IPv6       LOW
DNS       Configured resolvers              127.0.0.53                 LOW
External  Public IPv4                       Detected                   INFO
Browser   Firefox WebRTC exposure           Configured securely        LOW
```

It also shows correlation alerts when a finding needs interpretation, for example:

```text
No guest-side VPN interface detected
DNS stub resolver requires interpretation
External IP available without guest VPN interface
```

## Important limitations

KOAF does not prove that you are anonymous.

Current limitations:

* External IP provider classification is not implemented yet
* DNS leak testing is not implemented yet
* ASN and ISP detection are not implemented yet
* Browser fingerprinting is limited to selected Firefox preferences
* Host VPN detection is inferred indirectly and not proven from inside Kali
* Hardening mode is not implemented yet

## Roadmap

Planned improvements:

* External IP provider and ASN classification
* Better DNS upstream detection
* DNS versus external route correlation
* More beginner friendly explanations with an explain mode
* Expanded Firefox privacy checks
* Optional controlled hardening with rollback support

## Project status

Current version: **v0.1.0**

KOAF is currently an audit first foundation. The focus is visibility, explanation, and safe learning before adding automatic hardening.

## Ethical use

KOAF is intended for personal learning, privacy awareness, lab use, and defensive OPSEC education. Use it only on systems you own or are authorized to assess.
