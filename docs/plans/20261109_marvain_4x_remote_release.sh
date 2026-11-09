#!/usr/bin/env bash
# Run only as ubuntu on the selected us-east-2 Marvain builder.
set -euo pipefail
cd /home/ubuntu
sudo apt-get install -y build-essential
tar -xzf /home/ubuntu/marvain-4.0.0.tar.gz
cd /home/ubuntu/marvain-4.0.0
export AWS_PROFILE=daylily
export AWS_REGION=us-east-1
export AWS_DEFAULT_REGION=us-east-1
export SETUPTOOLS_SCM_PRETEND_VERSION_FOR_MARVAIN=4.0.0
source ./activate
export AWS_PROFILE=lsmc
export AWS_REGION=us-east-2
export AWS_DEFAULT_REGION=us-east-2

marvain deployment publish-image --target-profile lsmc --target-region us-east-2 \
  --builder-instance-id i-0325430bfec70e41e \
  --repository-uri 108782052779.dkr.ecr.us-east-2.amazonaws.com/marvain4-prod-release-prerequisites-workerrepository-fdisivyobf3k \
  --release-version 4.0.0 --source-dir /home/ubuntu/marvain-4.0.0 --image-kind worker \
  > /home/ubuntu/marvain-4.0.0-worker-build.log 2>&1

marvain deployment publish-image --target-profile lsmc --target-region us-east-2 \
  --builder-instance-id i-0325430bfec70e41e \
  --repository-uri 108782052779.dkr.ecr.us-east-2.amazonaws.com/marvain4-prod-release-prerequisites-dotrepository-etkhiob3bqsd \
  --release-version 4.0.0 --source-dir /home/ubuntu/marvain-4.0.0 --image-kind dot \
  > /home/ubuntu/marvain-4.0.0-dot-build.log 2>&1

marvain config init --write /home/ubuntu/marvain-4.0.0-build.yaml --env prod --region us-east-2 --stack marvain4-prod
marvain --config /home/ubuntu/marvain-4.0.0-build.yaml --env prod --profile lsmc --region us-east-2 build \
  > /home/ubuntu/marvain-4.0.0-sam-build.log 2>&1
tar -czf /home/ubuntu/marvain-4.0.0-sam-build.tar.gz .aws-sam/build
