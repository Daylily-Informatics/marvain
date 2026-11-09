#!/bin/bash
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y docker.io git tmux curl ca-certificates unzip build-essential
systemctl enable --now docker
usermod -aG docker ubuntu
curl -fsSL https://github.com/conda-forge/miniforge/releases/download/26.9.4-2/Miniforge3-Linux-x86_64.sh -o /tmp/marvain-miniforge.sh
sudo -u ubuntu bash /tmp/marvain-miniforge.sh -b -p /home/ubuntu/miniforge3
rm /tmp/marvain-miniforge.sh
printf '\nexport PATH="/home/ubuntu/miniforge3/bin:$PATH"\n' >> /home/ubuntu/.bashrc
install -d -m 700 -o ubuntu -g ubuntu /home/ubuntu/.aws
printf '[profile lsmc]\nrole_arn = __BUILDER_ROLE_ARN__\ncredential_source = Ec2InstanceMetadata\nregion = us-east-2\n' > /home/ubuntu/.aws/config
chown ubuntu:ubuntu /home/ubuntu/.aws/config
chmod 600 /home/ubuntu/.aws/config
