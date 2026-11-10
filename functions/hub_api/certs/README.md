# AWS RDS trust bundle

Manually provisioned from https://truststore.pki.rds.amazonaws.com/global/global-bundle.pem on 2026-11-09 for the hosted TapDB native admin/DAG runtime. The deployment explicitly configures `/var/task/certs/rds-ca-bundle.pem`; PostgreSQL retains `sslmode=verify-full`. Certificate updates are release assets, not runtime downloads.
