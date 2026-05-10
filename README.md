# KOAF - Kali OPSEC Automation Framework

KOAF is a beginner friendly Kali Linux OPSEC and privacy audit tool that helps new Linux users understand what their system may expose online.

It is designed for people who are learning Kali, Linux networking, VPNs, DNS, IPv6, and browser privacy. Instead of silently changing system settings, KOAF explains what it finds so users can better understand their privacy and exposure posture.

## What KOAF checks

KOAF currently performs read-only checks for:

- Local VPN interface visibility
- IPv4 and IPv6 exposure
- Default route inspection
- DNS resolver configuration
- External public IPv4 visibility
- Hostname entropy
- Firefox privacy preference posture

## Safety

Audit mode does not modify the system. KOAF is currently focused on visibility, explanation, and learning rather than automatic hardening.

## Usage

Run without installation:

    python3 -m koaf --audit

Or after editable install:

    koaf --audit

## Status

Current version: v0.1.0

This is an audit-first foundation. Controlled hardening and rollback support are planned for later versions.
