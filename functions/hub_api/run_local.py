#!/usr/bin/env python3
"""Local development runner for Hub API with environment loading."""

import os
import sys
from pathlib import Path

# Load environment variables from .env.local BEFORE importing anything else
from dotenv import load_dotenv

env_file = Path(__file__).parent / ".env.local"
load_dotenv(env_file)

# Ensure AWS_REGION is set for boto3
if not os.getenv("AWS_REGION"):
    os.environ["AWS_REGION"] = "us-east-1"

# Now import and run uvicorn
import uvicorn

if __name__ == "__main__":
    uvicorn.run(
        "app:app",
        host="127.0.0.1",
        port=8000,
        reload=False,
        log_level="debug",
    )

