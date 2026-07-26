# Marvain Clean-Room Immutable Image Publication Receipt Ledger

Timestamp: `2026-07-26T10:32:47Z`

## Authority And Scope

- User authorized local Colima startup and publication of only source commit `968cac443e2f9c0127f6628035868d30fa1d6d3a` to the selected `lsmc` / `us-west-1` clean-room ECR repository.
- The selected stack remains `marvain-cleanroom-20260712T111914Z`.
- The failed predecessor `marvain-cleanroom-20260712T103857Z` remains untouched.
- CloudFormation/SAM deployment, worker-token rotation, and ECS restart were not authorized by this publication approval and were not run.

## Immutable Publication Receipt

| Field | Value |
|---|---|
| Source commit / immutable tag | `968cac443e2f9c0127f6628035868d30fa1d6d3a` |
| Repository | `108782052779.dkr.ecr.us-west-1.amazonaws.com/marvain-cleanroom-20260712t111914z-agent-worker` |
| Immutable digest | `sha256:1d4367eb8d9e360eacf5f2dc14dd0534995d8293cc7dc57fc513b28f2ea7e4f9` |
| Pinned image URI | `108782052779.dkr.ecr.us-west-1.amazonaws.com/marvain-cleanroom-20260712t111914z-agent-worker@sha256:1d4367eb8d9e360eacf5f2dc14dd0534995d8293cc7dc57fc513b28f2ea7e4f9` |
| Selected local config | `/Users/jmajor/.config/marvain/marvain-cleanroom-20260712T111914Z.yaml` |
| Selected config update | `AgentWorkerImageUri` and `AgentWorkerVersion` only |

## Execution Rows

| ID | Action | Status | Evidence | Terminal Note |
|---|---|---|---|---|
| IP-04 | Start the authorized local Colima Docker daemon. | SUCCESS | `docker info` returned Docker Engine `29.2.1`, `linux/aarch64`, context `colima`; the builder supports `linux/amd64`. | Local daemon was unavailable at the prior pause and is now running. |
| IP-05 | Build from a detached worktree at the exact source commit and push the unused immutable tag. | SUCCESS | `marvain agent publish-image --source-commit 968cac443e2f9c0127f6628035868d30fa1d6d3a`; ECR returned the digest recorded above. | The temporary detached worktree was removed after build; no alternate source or repository was used. |
| IP-06 | Resolve ECR digest and pin only the selected config image/version fields. | SUCCESS | CLI receipt and post-publication config read show the image URI/digest and `AgentWorkerVersion=968cac443e2f9c0127f6628035868d30fa1d6d3a`. | No CloudFormation, Secrets Manager, token, or ECS operation was performed. |
| IP-07 | Review a selected-config deployment dry run. | BLOCKED | `marvain --config /Users/jmajor/.config/marvain/marvain-cleanroom-20260712T111914Z.yaml --env cleanroom --dry-run deploy` reported that `LIVEKIT_URL` is absent and `sam.parameter_overrides.LiveKitUrl` is missing. The config has `resources.LiveKitUrl`, but that is not an explicit deploy input. | Do not infer/promote the resource value or add a fallback. Supply `LIVEKIT_URL` or explicitly authorize a selected-config `sam.parameter_overrides.LiveKitUrl` update, then rerun the dry run. |
| IP-08 | Deploy the selected stack, rotate the worker token through `agent finalize-deployment`, and restart/wait for ECS. | BLOCKED | Requires a valid dry-run receipt plus a fresh approval naming the stack, digest, SAM update, worker-token rotation, and ECS restart. | Not run. |

## Required Resume Inputs

1. Resolve the explicit LiveKit deploy input without a fallback: provide `LIVEKIT_URL` for the deployment command, or explicitly authorize a selected-config `sam.parameter_overrides.LiveKitUrl` update.
2. After a valid dry-run receipt, obtain fresh approval that names:
   - stack `marvain-cleanroom-20260712T111914Z`;
   - digest `sha256:1d4367eb8d9e360eacf5f2dc14dd0534995d8293cc7dc57fc513b28f2ea7e4f9`;
   - SAM/CloudFormation update;
   - worker-token rotation through `marvain agent finalize-deployment`; and
   - ECS force-new deployment/restart and stability wait.

No physical-device or owner-session acceptance proof has been claimed.
