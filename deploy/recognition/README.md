# Recognition Service Deployment

The recognition worker is an outbound-only Amazon Linux 2023 service.
Provisioning the host and its IAM/SSM role is owned by the clean-room
deployment workflow. This directory defines only the supervised host service
contract. Installation fails unless `/etc/os-release` identifies Amazon Linux
2023 and the explicitly selected Python 3.12 executable is present.

Installation must provide every value explicitly through
`RecognitionInstallSpec` in `marvain_cli.recognition_service`:

- a local, immutable wheelhouse and exact Marvain package version;
- the worker source and systemd unit paths;
- a mode `0600` environment file containing Hub, queue, bucket, worker, host,
  timing, and health-path settings;
- a `marvain.recognition.models.v1` manifest with exact voice/face model IDs,
  versions, asset paths, engines, and SHA-256 checksums.

The service has no inbound listener and requires no inbound security-group
rule. Status consists of both `systemctl show` state and the worker's
authenticated runtime heartbeat file. Startup fails if configuration, model assets, Hub
heartbeat persistence, or artifact provenance is unavailable.

The worker creates observations and proposed hypotheses only. An authenticated
Hub review must accept or reject each hypothesis before any biometric
projection or presence assertion is created. Source recognition artifacts are
retained under the configured retention policy and are never deleted by the
worker.
