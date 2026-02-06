#!/usr/bin/env python3
"""Local development runner for Hub API with environment loading.

DEPRECATED: Use `marvain gui start` or `marvain gui run` instead.
Those commands read configuration from marvain-config.yaml and don't require
a .env.local file.

This script is kept for backward compatibility and requires manual creation
of a .env.local file in this directory.
"""

import os
import sys
from pathlib import Path

# Load environment variables from .env.local BEFORE importing anything else
# DEPRECATED: New code should use marvain-config.yaml via CLI
from dotenv import load_dotenv

env_file = Path(__file__).parent / ".env.local"
if not env_file.exists():
    print("ERROR: .env.local not found.", file=sys.stderr)
    print("DEPRECATED: This script is deprecated.", file=sys.stderr)
    print("Use 'marvain gui start' instead (reads from marvain-config.yaml).", file=sys.stderr)
    sys.exit(1)
load_dotenv(env_file)

# Ensure AWS_REGION is set for boto3
if not os.getenv("AWS_REGION"):
    os.environ["AWS_REGION"] = "us-east-1"

# Now import and run uvicorn
import uvicorn  # noqa: E402

if __name__ == "__main__":
    uvicorn.run(
        "app:app",
        host="127.0.0.1",
        port=8000,
        reload=False,
        log_level="debug",
    )
