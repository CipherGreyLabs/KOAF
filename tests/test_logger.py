import logging
import os
import stat

import pytest

from koaf.logger import setup_logger


def _reset_koaf_logger() -> None:
    logger = logging.getLogger("koaf")
    for handler in logger.handlers[:]:
        handler.close()
        logger.removeHandler(handler)


@pytest.mark.skipif(os.name != "posix", reason="POSIX permission test")
def test_logger_uses_private_posix_permissions(tmp_path, monkeypatch):
    _reset_koaf_logger()
    monkeypatch.chdir(tmp_path)

    try:
        setup_logger(enable_console=False)

        assert stat.S_IMODE((tmp_path / "logs").stat().st_mode) == 0o700
        assert stat.S_IMODE((tmp_path / "logs" / "koaf.log").stat().st_mode) == 0o600
    finally:
        _reset_koaf_logger()


@pytest.mark.skipif(os.name != "posix", reason="POSIX symbolic-link test")
def test_logger_rejects_symbolic_link_directory(tmp_path, monkeypatch):
    _reset_koaf_logger()
    target = tmp_path / "target"
    target.mkdir()
    (tmp_path / "logs").symlink_to(target, target_is_directory=True)
    monkeypatch.chdir(tmp_path)

    try:
        with pytest.raises(RuntimeError, match="symbolic links"):
            setup_logger(enable_console=False)
    finally:
        _reset_koaf_logger()
