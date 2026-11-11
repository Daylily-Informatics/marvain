#!/usr/bin/env bash
set -euo pipefail
tmux set-option -t marvain-4-0-18-release remain-on-exit on
cd /home/ubuntu
tar -xzf /home/ubuntu/marvain-4.0.18.tar.gz
cd /home/ubuntu/marvain-4.0.18
export AWS_PROFILE=daylily
export AWS_REGION=us-east-1
export AWS_DEFAULT_REGION=us-east-1
export SETUPTOOLS_SCM_PRETEND_VERSION_FOR_MARVAIN=4.0.18
source ./activate
python -m pip install --editable . > /home/ubuntu/marvain-4.0.18-package-install.log 2>&1
export AWS_PROFILE=lsmc
export AWS_REGION=us-east-2
export AWS_DEFAULT_REGION=us-east-2
marvain config init --write /home/ubuntu/marvain-4.0.18-build.yaml --env prod --region us-east-2 --stack marvain4-prod
marvain --config /home/ubuntu/marvain-4.0.18-build.yaml --env prod --profile lsmc --region us-east-2 build > /home/ubuntu/marvain-4.0.18-sam-build.log 2>&1
tar -czf /home/ubuntu/marvain-4.0.18-sam-build.tar.gz .aws-sam/build layers/shared
