#!/usr/bin/env bash
# Execute only on the selected EC2 builder as ubuntu in the named tmux session.
set -euo pipefail
tmux set-option -t marvain-4-0-23-release remain-on-exit on
cd /home/ubuntu
tar -xzf /home/ubuntu/marvain-4.0.23.tar.gz
cd /home/ubuntu/marvain-4.0.23
export AWS_PROFILE=daylily
export AWS_REGION=us-east-1
export AWS_DEFAULT_REGION=us-east-1
export SETUPTOOLS_SCM_PRETEND_VERSION_FOR_MARVAIN=4.0.23
source ./activate
python -m pip install --editable . > /home/ubuntu/marvain-4.0.23-package-install.log 2>&1
export AWS_PROFILE=lsmc
export AWS_REGION=us-east-2
export AWS_DEFAULT_REGION=us-east-2
marvain deployment publish-image --target-profile lsmc --target-region us-east-2 \
  --builder-instance-id i-0325430bfec70e41e \
  --repository-uri 108782052779.dkr.ecr.us-east-2.amazonaws.com/marvain4-prod-release-prerequisites-workerrepository-fdisivyobf3k \
  --release-version 4.0.23 --source-dir /home/ubuntu/marvain-4.0.23 --image-kind worker \
  > /home/ubuntu/marvain-4.0.23-worker-build.log 2>&1
marvain config init --write /home/ubuntu/marvain-4.0.23-build.yaml --env prod --region us-east-2 --stack marvain4-prod
marvain --config /home/ubuntu/marvain-4.0.23-build.yaml --env prod --profile lsmc --region us-east-2 build \
  > /home/ubuntu/marvain-4.0.23-sam-build.log 2>&1
tar -czf /home/ubuntu/marvain-4.0.23-sam-build.tar.gz .aws-sam/build layers/shared
