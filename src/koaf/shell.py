from __future__ import annotations

import subprocess
from dataclasses import dataclass


@dataclass(frozen=True)
class CmdResult:
    returncode: int
    stdout: str
    stderr: str


def run_cmd(argv: list[str], timeout: int = 3) -> CmdResult:
    try:
        result = subprocess.run(
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
