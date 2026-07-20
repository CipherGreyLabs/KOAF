from __future__ import annotations

import subprocess  # nosec B404
from dataclasses import dataclass


@dataclass(frozen=True)
class CmdResult:
    returncode: int
    stdout: str
    stderr: str


def run_cmd(argv: list[str], timeout: int = 3) -> CmdResult:
    try:
        # Callers pass fixed argument lists; shell expansion is intentionally disabled.
        result = subprocess.run(  # nosec B603
            argv,
            text=True,
            capture_output=True,
            timeout=timeout,
            check=False,
        )
        return CmdResult(result.returncode, result.stdout.strip(), result.stderr.strip())
    except subprocess.TimeoutExpired:
        return CmdResult(124, "", "Command timed out")
    except FileNotFoundError as exc:
        return CmdResult(127, "", str(exc))
    except Exception as exc:
        return CmdResult(1, "", str(exc))
