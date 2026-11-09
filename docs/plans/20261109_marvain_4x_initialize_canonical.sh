#!/usr/bin/env bash
# Schema setup after network completion and successful PostgreSQL client install.
set -euo pipefail
tmux set-option -t marvain-4-0-0-tapdb-init remain-on-exit on
cd /home/ubuntu/marvain-deployment-ops
export AWS_PROFILE=daylily
export AWS_REGION=us-east-1
export AWS_DEFAULT_REGION=us-east-1
source ./activate
export AWS_PROFILE=lsmc
export AWS_REGION=us-east-2
export AWS_DEFAULT_REGION=us-east-2
marvain deployment initialize-canonical \
  --target-profile lsmc --target-region us-east-2 \
  --builder-instance-id i-0325430bfec70e41e \
  --host marvain4-prod-auroracluster-580rtisq8dlb.cluster-c3kq6c2uwhf7.us-east-2.rds.amazonaws.com \
  --port 5432 --database agenthub \
  --secret-arn arn:aws:secretsmanager:us-east-2:108782052779:secret:marvain4-prod/db-credentials-vJMvNX \
  --registry-root /home/ubuntu/marvain-4.0.0/tapdb_templates
