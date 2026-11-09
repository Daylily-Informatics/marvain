#!/usr/bin/env bash
# Resume publication after the owning prerequisite IAM update returned complete.
set -euo pipefail
tmux set-option -t marvain-4-0-0-resume remain-on-exit on
cd /home/ubuntu/marvain-4.0.0
export AWS_PROFILE=daylily
export AWS_REGION=us-east-1
export AWS_DEFAULT_REGION=us-east-1
source ./activate
export AWS_PROFILE=lsmc
export AWS_REGION=us-east-2
export AWS_DEFAULT_REGION=us-east-2
git clone --branch codex/marvain-operational-100-closure /home/ubuntu/marvain-deployment-ops.bundle /home/ubuntu/marvain-deployment-ops
cd /home/ubuntu/marvain-deployment-ops
source ./activate
python -m pip install --no-deps --editable .

marvain deployment publish-built-image --target-profile lsmc --target-region us-east-2 \
  --builder-instance-id i-0325430bfec70e41e \
  --repository-uri 108782052779.dkr.ecr.us-east-2.amazonaws.com/marvain4-prod-release-prerequisites-workerrepository-fdisivyobf3k \
  --release-version 4.0.0 > /home/ubuntu/marvain-4.0.0-worker-publish.log 2>&1

marvain deployment publish-image --target-profile lsmc --target-region us-east-2 \
  --builder-instance-id i-0325430bfec70e41e \
  --repository-uri 108782052779.dkr.ecr.us-east-2.amazonaws.com/marvain4-prod-release-prerequisites-dotrepository-etkhiob3bqsd \
  --release-version 4.0.0 --source-dir /home/ubuntu/marvain-4.0.0 --image-kind dot \
  > /home/ubuntu/marvain-4.0.0-dot-build.log 2>&1

cd /home/ubuntu/marvain-4.0.0
source ./activate
marvain config init --write /home/ubuntu/marvain-4.0.0-build.yaml --env prod --region us-east-2 --stack marvain4-prod
marvain --config /home/ubuntu/marvain-4.0.0-build.yaml --env prod --profile lsmc --region us-east-2 build \
  > /home/ubuntu/marvain-4.0.0-sam-build.log 2>&1
# SAM leaves the unbuilt shared layer as ../../layers/shared in its template.
tar -czf /home/ubuntu/marvain-4.0.0-sam-build.tar.gz .aws-sam/build layers/shared
