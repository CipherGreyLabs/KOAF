# Contributing to KOAF

Thanks for your interest in contributing.

KOAF is a beginner-friendly Kali Linux OPSEC and privacy audit tool. Contributions should keep the project safe, educational, and transparent.

## Good contributions

Helpful contributions include:

- Clearer beginner explanations
- Safer audit checks
- Better tests
- Documentation improvements
- Bug fixes
- Privacy-preserving reporting improvements

## Avoid

Please avoid contributions that add:

- Silent system modifications
- Anti-forensics behavior
- Log deletion
- Credential collection
- Stealth or evasion features
- Claims that KOAF guarantees anonymity

## Development setup

```bash
git clone https://github.com/CipherGreyLabs/KOAF.git
cd KOAF
python3 -m venv .venv
source .venv/bin/activate
pip install -e .[dev]
```

## Checks before submitting

```bash
python -m compileall src/koaf
ruff check .
pytest
```

## Style

- Keep output beginner friendly
- Prefer read-only checks
- Explain limitations honestly
- Mark sensitive output as sensitive when it may include IPs, routes, hostnames, profile names, or machine identifiers
