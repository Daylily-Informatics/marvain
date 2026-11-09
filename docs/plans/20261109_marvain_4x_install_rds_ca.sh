#!/usr/bin/env bash
# TapDB 6.0.8's reported manual certificate provisioning path.
# Use the exact AWS truststore source and owner cache path; retain verify-full.
set -euo pipefail
install -d -m 700 /home/ubuntu/.config/tapdb
curl --fail --silent --show-error \
  https://truststore.pki.rds.amazonaws.com/global/global-bundle.pem \
  --output /home/ubuntu/.config/tapdb/rds-ca-bundle.pem
chmod 644 /home/ubuntu/.config/tapdb/rds-ca-bundle.pem
