#!/bin/bash
# Start the local FastAPI development server with proper environment setup

set -eu

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
REPO_ROOT=$(cd "$SCRIPT_DIR/../.." && pwd)

# Source activate to set up conda env
cd "$REPO_ROOT"
source ./activate

# Set up PYTHONPATH to include shared layer
export PYTHONPATH="$REPO_ROOT/layers/shared/python:${PYTHONPATH:-}"

# Change to hub_api directory and run the server
cd "$SCRIPT_DIR"
python run_local.py
