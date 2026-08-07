import sys

import pytest

from koaf import cli
from koaf.checks import external as external_checks
from koaf.engine import AuditEngine


class DummyLogger:
    def info(self, *_args, **_kwargs):
        return None


def test_external_check_is_disabled_by_default(monkeypatch):
    def fail_if_called(*_args, **_kwargs):
        raise AssertionError("External network helper should not run by default")

    monkeypatch.setattr(external_checks, "_http_text", fail_if_called)
    monkeypatch.setattr(external_checks, "_http_json", fail_if_called)

    findings = external_checks.check_external()

    assert len(findings) == 1
    assert findings[0].title == "Public IPv4"
    assert findings[0].status == "Skipped by user"


def test_audit_engine_is_local_first_by_default():
    engine = AuditEngine(DummyLogger())

    assert engine.external_enabled is False


def test_external_cli_flags_are_mutually_exclusive(monkeypatch):
    monkeypatch.setattr(sys, "argv", ["koaf", "--audit", "--external", "--no-external"])

    with pytest.raises(SystemExit) as exc:
        cli.parse_args()

    assert exc.value.code == 2
