# Marvain Clean-Room Authenticated Finalization Pause Ledger

Timestamp: `2026-07-26T10:51:58Z`

## Approved Deployment Boundary

- Stack: `marvain-cleanroom-20260712T111914Z`
- Account/region identity: `lsmc` / `us-west-1`
- Approved pinned image: `108782052779.dkr.ecr.us-west-1.amazonaws.com/marvain-cleanroom-20260712t111914z-agent-worker@sha256:1d4367eb8d9e360eacf5f2dc14dd0534995d8293cc7dc57fc513b28f2ea7e4f9`
- User explicitly authorized use of the selected config's `resources.LiveKitUrl` as the in-process `LIVEKIT_URL` value.
- User explicitly authorized temporary `ARTIFACT_CORS_ALLOWED_ORIGINS='*'` for this clean-room deployment. This is a recorded security exception, not an inferred default; replace it with the exact intended origin before any broader/non-clean-room deployment.

## Preflight Evidence

| ID | Check | Status | Evidence | Terminal Note |
|---|---|---|---|---|
| AF-01 | Non-mutating selected-config SAM deployment receipt. | SUCCESS | With the approved in-process LiveKit URL and temporary `ARTIFACT_CORS_ALLOWED_ORIGINS='*'`, `marvain --dry-run deploy --no-guided --no-confirm` generated the SAM build/deploy command for the approved stack and pinned digest. | No SAM build or deploy was run because this was dry run. |
| AF-02 | Non-mutating worker finalization contract. | SUCCESS | `marvain --dry-run agent finalize-deployment` validated the configured bootstrap agent/device, project-tagged worker secret, cluster, and service identities. | No token rotation, Secrets Manager write, or ECS restart was run because this was dry run. |
| AF-03 | Acquire a valid Cognito owner access token as `MARVAIN_ACCESS_TOKEN`. | BLOCKED | No access token is available in the environment. A Cognito access token must result from a real authorized owner authentication; it cannot be invented, extracted from browser/session storage, or replaced with a newly-created identity without an explicit separate authorization. | Obtain a current authorized owner token through the normal Cognito login path and make it available only for the finalization command without printing or persisting it. |
| AF-04 | Execute live SAM update followed by token rotation and ECS stability wait. | BLOCKED | The user provided the required named approval, but AF-03 prevents completing the approved deployment/finalization as one coherent operation. | Keep the stack unchanged until AF-03 is satisfied, then run the already-approved deploy and `agent finalize-deployment` sequence. |

## Boundary Preserved

- No CloudFormation/SAM update, Secrets Manager mutation, Hub token rotation, or ECS force-new deployment occurred in this phase.
- No browser cookies, local storage, password store, or session storage was inspected.
- No physical-device or owner-session acceptance proof has been claimed.

## Resume

After a valid owner Cognito access token is available as `MARVAIN_ACCESS_TOKEN`, run the approved live sequence using the exact stack/digest above, then record the deployment receipt, token-secret version ID, ECS rollout state, and follow-on fresh owner-session evidence.
