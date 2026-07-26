# Marvain Clean-Room Deployment Preflight Pause Ledger

Timestamp: `2026-07-26T10:38:23Z`

## Approved Target

- Stack: `marvain-cleanroom-20260712T111914Z`
- Account/region identity: `lsmc` / `us-west-1`
- Approved image digest: `sha256:1d4367eb8d9e360eacf5f2dc14dd0534995d8293cc7dc57fc513b28f2ea7e4f9`
- Pinned selected-config image: `108782052779.dkr.ecr.us-west-1.amazonaws.com/marvain-cleanroom-20260712t111914z-agent-worker@sha256:1d4367eb8d9e360eacf5f2dc14dd0534995d8293cc7dc57fc513b28f2ea7e4f9`
- User approval includes the SAM update, audited `agent finalize-deployment` token rotation, ECS force-new deployment, and ECS stability wait after preflight succeeds.

## Preflight Result

| ID | Check | Status | Evidence | Required Unblock |
|---|---|---|---|---|
| DP-01 | Use the explicitly authorized selected-config `resources.LiveKitUrl` as the in-process `LIVEKIT_URL` deploy input. | SUCCESS | The URL was read only into the command environment, redacted from output, and not persisted to config. | - |
| DP-02 | Run `marvain --dry-run deploy` against the selected config with non-interactive flags. | BLOCKED | The CLI accepted the LiveKit input, then hard-failed: `ArtifactCorsAllowedOrigins` is absent from `sam.parameter_overrides`; `ARTIFACT_CORS_ALLOWED_ORIGINS` is also absent from the process environment. | Supply an explicit allowed-origin value for `ARTIFACT_CORS_ALLOWED_ORIGINS`, or explicitly authorize an exact selected-config parameter override. Do not infer it from a UI/resource URL or use a wildcard/fallback. |
| DP-03 | Verify remaining required SAM deployment overrides. | SUCCESS | OpenAI and LiveKit credential secret ARNs, pinned image URI/version, worker token secret ARN, and desired count are present. | - |
| DP-04 | Verify finalization prerequisites that do not require a secret. | SUCCESS | Configured bootstrap agent ID and device ID are present. | - |
| DP-05 | Obtain the authenticated Cognito access token required to rotate the worker device token. | BLOCKED | `MARVAIN_ACCESS_TOKEN` is absent; `marvain agent finalize-deployment` has no login flow and correctly refuses an absent token. | Make a current authorized owner Cognito access token available to the command without printing or persisting it, then run finalization after successful SAM deployment. |

## Boundary Preserved

- No SAM build/deploy, CloudFormation change set/application, Secrets Manager write, Hub device-token rotation, or ECS restart was run after the image publication.
- Existing `resources.LiveKitUrl` was used only because the user explicitly authorized that exact source; no fallback or config promotion was added.
- No physical-device or owner-session acceptance proof has been claimed.

## Resume Inputs

1. An exact non-wildcard `ARTIFACT_CORS_ALLOWED_ORIGINS` value authorized for this clean-room stack.
2. A current authorized Cognito access token made available as `MARVAIN_ACCESS_TOKEN` only for finalization, without printing or persisting it.

After those inputs are available, rerun the redacted dry-run deployment; only a valid receipt permits the already-approved live SAM update and finalization.
