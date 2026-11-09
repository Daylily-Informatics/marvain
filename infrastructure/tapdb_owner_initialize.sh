#!/usr/bin/env bash
set -euo pipefail
# Run as ubuntu in an interactive named tmux session after Marvain activation.
# The package is the PostgreSQL client required by TapDB's owning CLI.
sudo apt-get update
sudo DEBIAN_FRONTEND=noninteractive apt-get install -y postgresql-client
exec marvain deployment initialize-canonical "$@"
