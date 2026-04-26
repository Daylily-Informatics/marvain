# MARVAIN_REFACTOR_PLAN_INPUT_FOR_CODEX.md

This is not an implementation plan. It is a design input for a later Codex planning phase.

## 1. Agreed target architecture summary

Marvain remains an AWS-backed hub-and-satellite system. The Hub owns identity, policy, lifecycle decisions, event intake, memory/recognition/action semantics, and audit. Satellites own local capture/output and device-local action execution. LiveKit remains the realtime media plane. API Gateway WebSocket/DynamoDB remain the control-plane connection store. SQS remains asynchronous execution transport. S3 remains artifact/audit byte storage. PostgreSQL typed tables remain operational projections. TapDB, if adopted, becomes the semantic object graph/provenance/lineage/lifecycle substrate behind a Marvain-owned adapter/service boundary.

## 2. Non-negotiable invariants

- Memory candidate is not committed memory.
- Recognition observation is not identity confirmation.
- Unknown person is not durable identity.
- Consent must be active at use time.
- Device command must be idempotent and auditable.
- Deleted memory must leave tombstone/projection invalidation.
- Tool action must have proposal/approval/execution/result lifecycle.
- TapDB cannot replace specialized vector, queue, media, artifact, or WebSocket stores.
- Any TapDB canonical role requires dual-write consistency tests before migration.

## 3. Files and subsystems likely to be touched, with repo-grounded paths

- Hub API memory/recognition/session endpoints: `functions/hub_api/api_app.py`.
- Local GUI memory/recognition/action pages: `functions/hub_api/app.py`, `functions/hub_api/templates/*`.
- SQL migrations: `sql/*.sql`.
- Memory tool: `layers/shared/python/agent_hub/tools/create_memory.py`.
- Planner memory/action candidate path: `functions/planner/handler.py`.
- Action lifecycle: `layers/shared/python/agent_hub/action_service.py`, `functions/tool_runner/handler.py`.
- Device command/control plane: `functions/ws_message/handler.py`, `functions/ws_connect/handler.py`, `layers/shared/python/agent_hub/tools/device_command.py`, `layers/shared/python/agent_hub/broadcast.py`.
- Remote satellite: `apps/remote_satellite/hub_client.py`, `location_node.py`, `daemon.py`.
- Recognition worker: `apps/recognition_worker/worker.py`.
- Agent worker context hydration: `apps/agent_worker/worker.py`.
- Shared auth/policy/audit/metrics: `layers/shared/python/agent_hub/auth.py`, `policy.py`, `audit.py`, `metrics.py`.
- Infrastructure: `template.yaml`, `config/marvain-example.yaml`.
- Tests: `tests/test_*`, especially action, planner, websockets, devices, remote satellite, LiveKit, route smoke.

## 4. Files and subsystems to avoid touching initially

- Do not replace `RdsData` or all SQL access in the first implementation round.
- Do not replace LiveKit token/media code in `layers/shared/python/agent_hub/livekit_tokens.py` or `apps/agent_worker/worker.py` beyond context/session interfaces.
- Do not replace SQS queues in `template.yaml`.
- Do not replace DynamoDB WebSocket tables in `template.yaml`.
- Do not change external integration providers unless required by audit/provenance interfaces.
- Do not perform a big-bang migration of `memories`, `events`, `actions`, `devices`, or biometrics.

## 5. Recommended migration seams

- Add explicit session objects/IDs to events and agent worker metadata.
- Add memory candidate/commit/tombstone APIs and projections while retaining existing memory rows during pilot.
- Add recognition observation/hypothesis/presence tables/projections before changing recognizer behavior.
- Add device WebSocket authentication with device token before relying on remote command routing.
- Add TapDB adapter with idempotent source-ID-to-EUID mapping.
- Add dual-write consistency checker.

## 6. Recommended pilot scope

Pilot TapDB on two flows only:

1. Memory provenance: transcript event -> memory candidate -> committed memory -> recall projection -> provenance query.
2. Recognition provenance: artifact event -> recognition observation -> identity hypothesis -> presence assertion.

Do not pilot TapDB on all devices/actions/integrations simultaneously.

## 7. Required test gates

- Existing unit and route smoke tests remain green.
- New memory candidate/commit/tombstone tests pass.
- New recognition observation/hypothesis/unknown tests pass.
- Device WebSocket auth and command routing tests pass.
- TapDB template seed and lineage golden tests pass.
- Dual-write consistency tests pass.
- Failure-injection tests pass for TapDB outage, model outage, duplicate SQS, and device disconnect.

## 8. Required documentation updates

- Add `docs/design/MARVAIN_GLOBAL_DESIGN_OBJECTIVES_AND_REQUIREMENTS.md`.
- Add `docs/design/MARVAIN_TAPDB_FIT_AND_INTEGRATION_SPEC.md`.
- Add `docs/design/MARVAIN_V1_ACCEPTANCE_TESTS.md`.
- Add `docs/design/MARVAIN_REFACTOR_PLAN_INPUT_FOR_CODEX.md`.
- Rewrite or mark historical docs that overstate implementation status.
- Update README to clearly distinguish implemented runtime, external workers, and aspirational plans.

## 9. Known unknowns to resolve before implementation

- TapDB deployment topology relative to Marvain Aurora/Data API.
- Marvain domain code, EUID prefixes, and template pack ownership.
- V1 biometric scope and default retention policy.
- Policy for semantic memory auto-commit vs human approval.
- Device-local buffering and replay rules.
- Required UI depth for provenance/debugging.

## 10. Explicit anti-goals for the first implementation round

- No Codex multi-agent implementation plan yet.
- No big-bang rewrite.
- No replacement of queues, media plane, S3 artifacts, or WebSocket connection store.
- No production biometric matching using dummy embeddings.
- No autonomous risky actions.
- No unverified claims that TapDB solves consent enforcement.
