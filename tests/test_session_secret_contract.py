from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]


def test_hub_api_import_fails_without_explicit_session_secret() -> None:
    env = os.environ.copy()
    env.pop("SESSION_SECRET_KEY", None)
    env.pop("SESSION_SECRET_ARN", None)
    env["ENVIRONMENT"] = "test"
    env["HTTPS_ENABLED"] = "false"
    env["DB_RESOURCE_ARN"] = "arn:aws:rds:us-east-1:111122223333:cluster:test"
    env["DB_SECRET_ARN"] = "arn:aws:secretsmanager:us-east-1:111122223333:secret:test"
    env["DB_NAME"] = "test"

    result = subprocess.run(
        [sys.executable, "-c", "import api_app"],
        cwd=REPO_ROOT / "functions" / "hub_api",
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )

    assert result.returncode != 0
    assert "SESSION_SECRET_KEY or SESSION_SECRET_ARN is required" in result.stderr
