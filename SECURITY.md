# Security Policy

## Supported versions

KOAF is currently in early development. Security fixes are applied to the latest version on the `main` branch.

## Reporting a vulnerability

Please report security issues privately. Do not open a public GitHub issue for vulnerabilities that could expose users, leak sensitive data, or enable abuse.

When reporting, include:

- A short description of the issue
- Steps to reproduce
- Expected and actual behavior
- Potential impact
- Suggested fix, if available

## Scope

Relevant issues include:

- Accidental exposure of sensitive local data
- Unsafe default behavior
- Incorrect privacy claims
- Command execution risks
- Dependency or packaging issues

## Project safety principles

KOAF is designed as a read-only audit tool. It should not silently modify system settings, delete logs, spoof identifiers, or claim to guarantee anonymity.
