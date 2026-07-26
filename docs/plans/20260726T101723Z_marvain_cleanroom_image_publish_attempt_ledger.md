# Marvain Clean-Room Image Publication Attempt Ledger

Timestamp: `2026-07-26T10:17:23Z`

## Authority And Scope

- User authorization: publish only the immutable worker image from source commit `968cac443e2f9c0127f6628035868d30fa1d6d3a` to the selected `lsmc` / `us-west-1` clean-room ECR repository.
- Explicitly excluded: CloudFormation/SAM deployment, worker-token rotation, and ECS restart. Each still requires the separate follow-up approval specified in the continuation ledger.
- Target stack: `marvain-cleanroom-20260712T111914Z`.
- Target repository: `108782052779.dkr.ecr.us-west-1.amazonaws.com/marvain-cleanroom-20260712t111914z-agent-worker`.
- Required immutable tag: `968cac443e2f9c0127f6628035868d30fa1d6d3a`.
- Controlling records remain:
  - `docs/plans/20260713T080928Z_marvain_cleanroom_pause_point_ledger.md` (preserved unchanged)
  - `docs/plans/20260726T095340Z_marvain_cleanroom_vertical_slice_continuation_ledger.md`

## Attempt Record

| ID | Action | Status | Evidence | Result / Unblock |
|---|---|---|---|---|
| IP-01 | Run the approved `marvain agent publish-image --source-commit 968cac443e2f9c0127f6628035868d30fa1d6d3a` command against the explicit clean-room config. | BLOCKED | The CLI validated the existing ECR repository/tag state, created a detached temporary worktree at the exact source commit, then `docker buildx build --platform linux/amd64 --load` failed before ECR authorization-token retrieval or push. Its cleanup removed that temporary worktree. | Docker context `colima` points to `unix:///Users/jmajor/.colima/default/docker.sock`, but the socket does not exist. Start the intended local Docker/Colima daemon, then rerun the same approved Marvain CLI command; do not use a fallback build path. |
| IP-02 | Confirm post-attempt local source and target resolution. | SUCCESS | `git worktree list` contains no temporary publish worktree; source checkout remains at `968cac4`. A fresh CLI dry run resolves profile `lsmc`, region `us-west-1`, stack `marvain-cleanroom-20260712T111914Z`, repository `marvain-cleanroom-20260712t111914z-agent-worker`, and required tag/source commit. | No repository source or selected local config mutation occurred. |
| IP-03 | Preserve deployment boundary. | SUCCESS | The failed command stopped at local Docker build; no digest was produced. | No ECR image was published, and no CloudFormation deployment, token rotation, or ECS restart was attempted. CV-09 and CV-10 remain blocked pending successful publication and the separately named approval. |

## Resume Contract

After the user starts the intended Docker/Colima daemon, rerun only:

```bash
marvain --config /Users/jmajor/.config/marvain/marvain-cleanroom-20260712T111914Z.yaml --env cleanroom agent publish-image --source-commit 968cac443e2f9c0127f6628035868d30fa1d6d3a
```

Then record the returned immutable digest and request a fresh explicit approval naming the stack, digest, SAM update, token rotation, and ECS restart. Do not deploy or finalize before that approval.
