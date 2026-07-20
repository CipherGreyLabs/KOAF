from __future__ import annotations

import logging
import os
from logging.handlers import RotatingFileHandler
from pathlib import Path


def setup_logger(verbose: bool = False, enable_console: bool = True) -> logging.Logger:
    logger = logging.getLogger("koaf")
    logger.setLevel(logging.DEBUG)

    if logger.handlers:
        return logger

    log_directory = Path("logs")
    log_path = log_directory / "koaf.log"
    if log_directory.is_symlink() or log_path.is_symlink():
        raise RuntimeError("KOAF refuses to write logs through symbolic links")

    log_directory.mkdir(mode=0o700, exist_ok=True)
    if os.name == "posix":
        log_directory.chmod(0o700)

    formatter = logging.Formatter("%(asctime)s | %(levelname)s | %(name)s | %(message)s")

    file_handler = RotatingFileHandler(log_path, maxBytes=500_000, backupCount=3)
    if os.name == "posix":
        log_path.chmod(0o600)
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)

    if enable_console:
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.DEBUG if verbose else logging.INFO)
        console_handler.setFormatter(formatter)
        logger.addHandler(console_handler)

    return logger
