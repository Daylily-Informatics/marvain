# Marvain Clean-Room Pause Point Ledger

Timestamp: `2026-07-13T08:09:28Z`

## Scope And Safety Boundary

- Repository: `/Users/jmajor/projects/marvain`
- Branch: `codex/marvain-operational-100-closure`
- HEAD: `92889df8df86` (`Fix isolated clean-room worker deployment`)
- AWS profile: `lsmc`
- AWS region: `us-west-1`
- Active stack: `marvain-cleanroom-20260712T111914Z`
- Packaging stack: `marvain-cleanroom-20260712T111914Z-packaging`
- Failed predecessor stack: `marvain-cleanroom-20260712T103857Z`
- Required tag: `project=marvain`
- No AWS resource was stopped or deleted while creating this pause point.
- Any stop, disable, delete, secret deletion, stack rollback continuation, or teardown requires the repository's delayed double-approval process.

## Pause Status

Marvain is paused after successful clean-room deployment and worker configuration, but before a fresh post-fix Live Session acceptance run. The infrastructure is not release-ready because the repository is dirty, the current worker image still identifies commit `92889df`, the latest task-definition configuration and Lambda packages were deployed from later uncommitted work, and the complete conversation/memory/TapDB/recognition/topology acceptance path has not passed.

| ID | Workstream | Status | Evidence | Terminal note |
|---|---|---|---|---|
| PAUSE-01 | Clean-room stack deployment | SUCCESS | Stack `marvain-cleanroom-20260712T111914Z` is `UPDATE_COMPLETE`; 113 CloudFormation-managed resources; stack tag `project=marvain`. | Fresh stack exists in `us-west-1`. |
| PAUSE-02 | Database and TapDB initialization | SUCCESS | Canonical 141-statement schema executed; TapDB templates seeded with `overwrite=True`. | Initialization completed only in the active clean-room stack. |
| PAUSE-03 | Bootstrap identity | SUCCESS | Agent `676a9e3d-22ff-45a6-a04f-f5ddd7a0971a`; space `e0d7ac83-f0f6-4a81-a7b5-2765186579a7`; device `5be1f9b1-a8e3-40ef-baca-1c14d9bbad25`. | Agent, default persona, `cleanroom-home`, and worker device exist. |
| PAUSE-04 | Cognito and ownership | SUCCESS | User `john@daylilyinformatics.com` is confirmed; owner claim succeeded; protected local smoke credential file remains mode `0600`. | Hosted UI login and owner-scoped dashboard were proven. |
| PAUSE-05 | Worker credential binding | SUCCESS | Device token rotated through audited API, written to the tagged worker secret, and verified against the agent persona endpoint. | No plaintext worker token remains in Marvain config. |
| PAUSE-06 | Fargate worker | SUCCESS | ECS service `ACTIVE`, desired/running `1/1`, task definition revision `3`, task healthy, LiveKit worker `AW_ZP8f2dJmWYkz` registered in `US West B`. | Worker remains running and cost-bearing. |
| PAUSE-07 | Memory classifier configuration | SUCCESS | Task environment has `MARVAIN_MEMORY_CLASSIFIER_PROVIDER=openai` and `MARVAIN_MEMORY_CLASSIFIER_MODEL=gpt-4.1-mini`. | The original `provider_not_configured` cause is closed. |
| PAUSE-08 | Realtime model configuration | SUCCESS | Clean-room OpenAI credential resolved `gpt-realtime`; task environment has `OPENAI_REALTIME_MODEL=gpt-realtime` and `OPENAI_VOICE=marin`. | The obsolete `gpt-4o-realtime-preview` deployment override is closed. |
| PAUSE-09 | Fresh conversation and memory proof | BLOCKED | Last active room failed before the realtime model correction and left persisted session state `active`; no fresh session was tested after task revision `3`. | Resume by leaving the old room, joining a new room, and proving text, speech, audio, classification, candidate, commit, and recall. |
| PAUSE-10 | Worker replacement recovery | BLOCKED | Replacement worker attempted `opening -> active` while the persisted session was already `active`, producing HTTP 409 transition conflicts. | Implement and test idempotent session rehydration/replacement behavior. |
| PAUSE-11 | TapDB GUI query | BLOCKED | Mounted TapDB static/graph assets load, but the local Mac cannot connect directly to private Aurora `10.20.x.x` networking. | Add an approved private network path or run the TapDB UI inside the VPC; do not make Aurora public. |
| PAUSE-12 | Recognition and deployed topology | BLOCKED | Recognition host, real two-device/two-location proof, and provider integrations have not been deployed or accepted. | Continue later acceptance gates only after explicit cost/resource approval. |
| PAUSE-13 | Usage budgets | BLOCKED | `aws budgets describe-budgets` returned no Marvain budget. No per-agent OpenAI, LiveKit, provider, or storage hard budget exists. | Requires explicit dollar, token, media-minute, provider, and notification thresholds before implementation/deployment. |
| PAUSE-14 | Source and deployment provenance | BLOCKED | HEAD is `92889df`; current worktree is dirty; ECS image version remains `92889df`; task configuration and refreshed Lambda packages include uncommitted changes. | Commit, rebuild the worker image, deploy the immutable digest, and rerun acceptance before release. |
| PAUSE-15 | Pause resource inventory | SUCCESS | Read-only CloudFormation, ECS, RDS, ECR, S3, Secrets Manager, EventBridge, Lambda, Logs, and Budgets inventory completed. | No stop/delete operation was performed. |

## Local Verification Recorded

- Focused GUI/operations/environment suite: `194 passed`.
- Classifier/deployment contract suite: `79 passed`.
- Worker/environment/session-focused suite: `47 passed`.
- Ruff and formatting checks for the touched Python files passed.
- Basic SAM template validation passed.
- `sam validate --lint` still reports the pre-existing conditional API deployment warning `W1001`.
- The earlier full suite reported `1130 passed`, `37 skipped`, and four failures because truthful design-objective completion was `89%`, below legacy assertions expecting `>=90%`.

## Dirty Worktree At Pause

Do not discard these changes. `AGENTS.md` is a user-owned change and must not be staged or altered without an explicit request.

- User-owned: `AGENTS.md`
- Generated/pre-existing: `docs/CAPABILITY_MATRIX.generated.md`
- Runtime/configuration work: `apps/agent_worker/.env.example`, `apps/agent_worker/worker.py`, `functions/hub_api/app.py`, `functions/hub_api/templates/live_session.html`, `marvain_cli/commands.py`, `marvain_cli/ops.py`, `template.yaml`
- Tests: `tests/test_environment_contract.py`, `tests/test_gui_app.py`, `tests/test_ops.py`
- Local browser state: `.playwright-cli/`

## AWS Resources That Can Be Stopped Or Disabled

These are reversible pause actions. None has been executed.

| Priority | Resource | Current state | Pause action | Effect |
|---|---|---|---|---|
| 1 | ECS service `marvain-cleanroom-20260712T111914Z-agent-worker` | `1/1` healthy on task definition revision `3` | Set CloudFormation parameter `AgentWorkerDesiredCount=0` and update the stack. | Stops Fargate compute and OpenAI/LiveKit worker activity. Live Sessions will have no agent. The running-task alarm must be adjusted or it will alarm. |
| 2 | Aurora cluster `marvain-cleanroom-20260712t111914z-auroracluster-zvttosvsa7o9` | Available; Aurora PostgreSQL `17.7`; Serverless v2 `0.5-2 ACU`; one `db.serverless` instance | Temporarily stop the DB cluster. | Stops DB instance-hour/ACU compute, but DB-backed APIs fail. Storage and backups continue billing, and [AWS automatically restarts a stopped Aurora cluster after seven days](https://docs.aws.amazon.com/AmazonRDS/latest/AuroraUserGuide/aurora-cluster-stop-start.html). |
| 3 | EventBridge schedule `...ActionTimeoutSweeper...` | Enabled every minute | Disable rule. | Stops action-timeout sweeps; stale actions will not be reconciled. |
| 4 | EventBridge schedule `...SemanticOutboxDispatcher...` | Enabled every minute | Disable rule. | Stops semantic outbox delivery to TapDB; pending records accumulate. |
| 5 | EventBridge schedule `...GmailPoll...` | Enabled every five minutes | Disable rule. | Stops Gmail polling. This is appropriate while the provider is not configured. |
| 6 | EventBridge schedule `...RetentionSweeper...` | Enabled daily | Disable rule. | Stops retention processing. |
| 7 | Four Lambda SQS event-source mappings | Enabled for transcript, integration, action, and TapDB-writer queues | Disable mappings. | Stops queue consumers; messages remain queued until retention expires or processing resumes. These mappings have no meaningful idle compute cost, so disabling is optional. |
| Local | Local GUI PID `10473` on `https://localhost:8084` | Running | `marvain gui stop --port 8084` | Stops only the local process; no AWS effect. |

## AWS Resources That Cannot Be Stopped

These are pay-per-use, storage-bearing, fixed-hourly, or control-plane resources. They can remain idle or be deleted, but do not have a meaningful stop state.

- Secrets Manager interface endpoint `vpce-0fe8be25066547cbb`: fixed-hourly network resource; delete only. Removing it breaks private Secrets Manager access used by the worker.
- Seven CloudWatch alarms and dashboard `marvain-cleanroom-20260712T111914Z-observability`: delete or disable actions; alarm resources still exist.
- Eleven Lambda functions, API Gateway REST/WebSocket APIs, seven SQS queues, and two DynamoDB pay-per-request tables: primarily pay for requests/storage; no stop operation is needed for idle compute.
- Seven active Secrets Manager secrets: four stack-owned plus external OpenAI, LiveKit, and worker-token secrets; delete only, with credential loss.
- Active ECR repository `marvain-cleanroom-20260712t111914z-agent-worker`: delete images/repository only. It contains the tagged worker image and supporting manifests, approximately 265 MB of principal image data.
- Packaging bucket `marvain-cleanroom-20260712t111914z-packagingbucket-bccev8bwblrl`: 18 object versions totaling 212,927,051 bytes; empty/delete only.
- Artifact bucket `marvain-cleanroom-20260712t111914z-artifactbucket-qkwenuto9bbo`: empty; retained by CloudFormation; empty/delete only.
- Audit bucket `marvain-cleanroom-20260712t111914z-auditbucket-wvcw5pjxz1kj`: 16 versions totaling 7,285 bytes; retained by CloudFormation with 10-year Governance Object Lock. Deletion is intentionally constrained.
- Worker log group `/aws/ecs/marvain-cleanroom-20260712T111914Z/agent-worker`: 116,412 stored bytes, 30-day retention, and CloudFormation `Retain`; delete only.
- Cognito pool `us-west-1_BecII637d`, app client, and domain: delete only; deletion removes login identity.
- VPC, subnets, route tables, internet gateway, security groups, IAM roles, Lambda layer, and task definitions: no useful stop state; remove through stack teardown rather than manual drift.

## Deletion Candidates

Deletion remains unapproved and has not been attempted.

### Lowest-Risk Cleanup: Failed Predecessor Attempt

Failed stack `marvain-cleanroom-20260712T103857Z` is `ROLLBACK_FAILED` and retains six stack-visible resources:

- VPC `vpc-0ab28f9eb56c36997`
- Security group `sg-03fd6beaa3b57a27d` (`DELETE_FAILED`)
- Empty retained artifact bucket `marvain-cleanroom-20260712t103857z-artifactbucket-mecojkek5eps`
- Empty retained audit bucket `marvain-cleanroom-20260712t103857z-auditbucket-yl3kufkgfdie`
- Retained log group `/aws/ecs/marvain-cleanroom-20260712T103857Z/agent-worker` with 626 stored bytes
- Retained Lambda layer `arn:aws:lambda:us-west-1:108782052779:layer:marvain-cleanroom-20260712T103857Z-shared:1`

Additional failed-attempt resources outside that stack:

- ECR repository `marvain-cleanroom-20260712t103857z-agent-worker`, approximately 264 MB of principal image data
- Secrets `marvain-cleanroom-20260712T103857Z/openai-qqVBg1`, `.../livekit-nhpWuD`, and `.../agent-worker-device-token-XfApfW`

Current read-only inspection found no network interfaces attached to `sg-03fd6beaa3b57a27d` and no security-group rules referencing it. Recommended cleanup order after delayed double approval: retry rollback/delete of the failed stack; if the security-group deletion fails again, stop and re-inspect rather than forcing deletion; then separately remove retained empty buckets/log/layer and external ECR/secrets.

### Active Clean-Room Teardown

Deleting `marvain-cleanroom-20260712T111914Z` removes most of its 113 managed resources and destroys the current Aurora data, Cognito identity, queues, APIs, worker service, networking, and projections. CloudFormation retains the artifact bucket, audit bucket, and worker log group. The external packaging stack, ECR repository, and OpenAI/LiveKit/worker secrets require separate deletion actions.

Do not tear down the active stack until a final acceptance/export decision is made. No complete agent backup/restore proof exists yet.

## Recommended Pause Choice

For a short pause, stop only the local GUI and leave AWS unchanged. For a pause longer than a few hours, the highest-value reversible savings are scaling the ECS worker to zero and temporarily stopping Aurora. Disable the recurring EventBridge schedules if no background processing should continue. The interface endpoint and Secrets Manager resources remain small fixed costs unless the entire active stack is torn down.

## Resume Checklist

1. Confirm whether AWS resources were left running, stopped, or disabled after this record.
2. Start Aurora if stopped and wait for `available`.
3. Set `AgentWorkerDesiredCount=1` if scaled down and wait for ECS `1/1 HEALTHY`.
4. Re-enable any paused schedules or event-source mappings.
5. Start the local GUI with the clean-room config.
6. Leave any stale LiveKit room and create a fresh session.
7. Prove typed chat, speech, speaker playback, classifier-backed memory candidates, commit, recall, and provenance.
8. Fix worker session replacement/rehydration before testing another rolling deployment.
9. Establish explicit AWS/OpenAI/LiveKit/provider budgets before extended runtime testing.
10. Commit the dirty work, rebuild and redeploy an immutable worker image, and rerun the full local/deployed gates before release.
