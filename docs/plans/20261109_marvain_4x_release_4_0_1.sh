#!/usr/bin/env bash
# Run as ubuntu on the selected EC2 builder; preserve the existing TapDB schema.
set -euo pipefail
tmux set-option -t marvain-4-0-1-release remain-on-exit on
cd /home/ubuntu
tar -xzf /home/ubuntu/marvain-4.0.1.tar.gz
cd /home/ubuntu/marvain-4.0.1
export AWS_PROFILE=daylily
export AWS_REGION=us-east-1
export AWS_DEFAULT_REGION=us-east-1
export SETUPTOOLS_SCM_PRETEND_VERSION_FOR_MARVAIN=4.0.1
source ./activate
python -m pip install --editable . > /home/ubuntu/marvain-4.0.1-package-install.log 2>&1
export AWS_PROFILE=lsmc
export AWS_REGION=us-east-2
export AWS_DEFAULT_REGION=us-east-2

marvain deployment initialize-prefixes \
  --target-profile lsmc --target-region us-east-2 \
  --builder-instance-id i-0325430bfec70e41e \
  --host marvain4-prod-auroracluster-580rtisq8dlb.cluster-c3kq6c2uwhf7.us-east-2.rds.amazonaws.com \
  --port 5432 --database agenthub \
  --secret-arn arn:aws:secretsmanager:us-east-2:108782052779:secret:marvain4-prod/db-credentials-vJMvNX \
  --cluster-identifier marvain4-prod-auroracluster-580rtisq8dlb \
  --registry-root /home/ubuntu/marvain-4.0.1/tapdb_templates \
  > /home/ubuntu/marvain-4.0.1-prefix-init.log 2>&1

marvain deployment publish-image --target-profile lsmc --target-region us-east-2 \
  --builder-instance-id i-0325430bfec70e41e \
  --repository-uri 108782052779.dkr.ecr.us-east-2.amazonaws.com/marvain4-prod-release-prerequisites-workerrepository-fdisivyobf3k \
  --release-version 4.0.1 --source-dir /home/ubuntu/marvain-4.0.1 --image-kind worker \
  > /home/ubuntu/marvain-4.0.1-worker-build.log 2>&1

marvain deployment publish-image --target-profile lsmc --target-region us-east-2 \
  --builder-instance-id i-0325430bfec70e41e \
  --repository-uri 108782052779.dkr.ecr.us-east-2.amazonaws.com/marvain4-prod-release-prerequisites-dotrepository-etkhiob3bqsd \
  --release-version 4.0.1 --source-dir /home/ubuntu/marvain-4.0.1 --image-kind dot \
  > /home/ubuntu/marvain-4.0.1-dot-build.log 2>&1

marvain config init --write /home/ubuntu/marvain-4.0.1-build.yaml --env prod --region us-east-2 --stack marvain4-prod
marvain --config /home/ubuntu/marvain-4.0.1-build.yaml --env prod --profile lsmc --region us-east-2 build \
  > /home/ubuntu/marvain-4.0.1-sam-build.log 2>&1
tar -czf /home/ubuntu/marvain-4.0.1-sam-build.tar.gz .aws-sam/build layers/shared
