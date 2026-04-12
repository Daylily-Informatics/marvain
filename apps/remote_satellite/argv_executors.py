from __future__ import annotations

import shlex
import subprocess
import time
from typing import Any

_DISALLOWED_SHELL_TOKENS = {"|", "||", "&", "&&", ";", ">", ">>", "<", "2>", "2>>"}


def parse_safe_command(command: str, *, allowed_commands: set[str]) -> tuple[list[str], str]:
    try:
        argv = shlex.split(str(command or "").strip(), posix=True)
    except ValueError as exc:
        raise ValueError(f"invalid_command: {exc}") from exc
    if not argv:
        raise ValueError("missing_command")

    base_cmd = argv[0].split("/")[-1]
    if base_cmd not in allowed_commands:
        raise ValueError(f"command_not_allowed: {base_cmd}")

    for token in argv[1:]:
        if token in _DISALLOWED_SHELL_TOKENS:
            raise ValueError(f"disallowed_shell_token: {token}")
    return argv, base_cmd


def run_argv_command(argv: list[str], *, timeout: int, working_dir: str | None) -> dict[str, Any]:
    start_time = time.time()
    result = subprocess.run(
        argv,
        shell=False,
        capture_output=True,
        text=True,
        timeout=timeout,
        cwd=working_dir,
    )
    execution_time = time.time() - start_time
    return {
        "status": "success",
        "exit_code": result.returncode,
        "stdout": result.stdout[:50000],
        "stderr": result.stderr[:10000],
        "execution_time_seconds": round(execution_time, 3),
        "truncated": len(result.stdout) > 50000 or len(result.stderr) > 10000,
    }
