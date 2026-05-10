# KOAF - Kali OPSEC Automation Framework

KOAF is a Kali Linux OPSEC and anonymity surface audit tool.

It performs read-only checks for:

- Local VPN interface visibility
- IPv4 and IPv6 exposure
- Default route inspection
- DNS resolver configuration
- External public IPv4 visibility
- Hostname entropy
- Firefox privacy preference posture

Audit mode does not modify the system.

## Usage

Run without installation:

    python3 -m koaf --audit

Or after editable install:

    koaf --audit

## Status

Current version: v0.1.0

This is an audit-first foundation. Controlled hardening and rollback support are planned for later versions.
