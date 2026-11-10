#!/usr/bin/env bash
# Final tagged Hub/Lambda packaging only, on the selected EC2 builder.
set -euo pipefail
tmux set-option -t marvain-4-0-6-release remain-on-exit on
cd /home/ubuntu
tar -xzf /home/ubuntu/marvain-4.0.6.tar.gz
cd /home/ubuntu/marvain-4.0.6
export AWS_PROFILE=daylily
export AWS_REGION=us-east-1
export AWS_DEFAULT_REGION=us-east-1
export SETUPTOOLS_SCM_PRETEND_VERSION_FOR_MARVAIN=4.0.6
source ./activate
python -m pip install --editable . > /home/ubuntu/marvain-4.0.6-package-install.log 2>&1
export AWS_PROFILE=lsmc
export AWS_REGION=us-east-2
export AWS_DEFAULT_REGION=us-east-2
marvain config init --write /home/ubuntu/marvain-4.0.6-build.yaml --env prod --region us-east-2 --stack marvain4-prod
marvain --config /home/ubuntu/marvain-4.0.6-build.yaml --env prod --profile lsmc --region us-east-2 build > /home/ubuntu/marvain-4.0.6-sam-build.log 2>&1
tar -czf /home/ubuntu/marvain-4.0.6-sam-build.tar.gz .aws-sam/build layers/shared
