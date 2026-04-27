# MARVAIN_V1_ACCEPTANCE_TESTS.md

## 1. Test strategy overview

V1 tests must prove behavior, not only route existence. Current Marvain tests cover many units and smoke paths (`tests/test_action_service.py`, `tests/test_ws_message_handler.py`, `tests/test_remote_satellite.py`, `tests/test_planner.py`, `tests/test_hub_api_livekit.py`), but V1 requires end-to-end acceptance tests for memory provenance, recognition consent, multi-device operation, TapDB lineage, and failure recovery.

## 2. Capability-to-test traceability matrix

| Capability | Required test classes |
|---|---|
| Durable memory | unit, integration, golden recall, TapDB lineage, delete/tombstone |
| Recognition | consent, enrollment, observation/hypothesis, unknown handling, false-positive |
| Multi-device | simulated satellites, heartbeat, WS auth, command ack/result/timeout |
| Multi-location | two-space routing, output device selection, event provenance |
| Action lifecycle | proposal/approval/execution/result, idempotency, policy auto-approve |
| TapDB | template pack seed, object/edge creation, provenance queries, projection consistency |
| Privacy/consent | disabled capture, recall filtering, biometric gate, audit evidence |
| Failure recovery | model outage, queue retry, device disconnect, TapDB write failure |
| Observability | metrics, health, audit chain, dead-letter visibility |

## 3. Memory acceptance tests

1. Candidate creation from transcript:
   - Given a transcript event, planner creates a `memory.candidate`, not a committed memory, unless policy allows auto-commit.
   - Candidate links to event, device, space, session, and person.
2. Commit/edit:
   - Human approves or edits candidate.
   - Committed memory preserves source candidate and edit trail.
3. Recall with explanation:
   - Query returns content plus distance/ranking, source event excerpt, device, space, and session.
4. Deletion/tombstone:
   - Delete creates tombstone, invalidates pgvector projection, and preserves audit lineage.
5. Contradiction/supersession:
   - New memory can supersede prior memory; recall prefers active memory and exposes conflict.

## 4. Recognition acceptance tests

1. Enrollment requires active consent.
2. Revoked/expired consent blocks enrollment and matching.
3. Recognition observation is persisted separately from identity hypothesis.
4. Unknown face/voice does not create a person row or durable embedding.
5. False-positive correction marks hypothesis rejected and updates presence.
6. Multiple known people in one room produce separate observations/hypotheses/presence assertions.
7. Recognition disabled for space/session suppresses capture/matching.

## 5. Multi-device/multi-location acceptance tests

1. Satellite WebSocket auth with device token succeeds; this covers the current mismatch between `apps/remote_satellite/hub_client.py` and `functions/ws_message/handler.py`.
2. Two satellites heartbeat independently and appear online in current-state projection.
3. Two satellites join separate LiveKit rooms/spaces and events are attributed to the correct device/space.
4. Device command to satellite A does not route to satellite B.
5. Offline satellite command produces awaiting/timeout/failure lifecycle without duplicate execution.
6. Reconnect does not duplicate device identity or lose pending status.

## 6. Tool/action approval/execution tests

- Proposed action remains unexecuted until approved unless policy auto-approves.
- Approval records approver, reason, timestamp, policy decision, and audit event.
- Idempotency key prevents duplicate action creation.
- Device command creates dispatch metadata, ack, result, or timeout.
- SQS retry does not execute a completed action twice.

## 7. TapDB lineage/provenance tests

- Seed Marvain template pack.
- Create session/event/artifact/memory objects and required edges.
- Query from memory to source event/device/space/person/session.
- Query from recognition hypothesis to artifact/observation/person/consent grant.
- Query from action result to proposal/approval/execution/device/outbox dispatch.

## 8. TapDB/projection consistency tests

- Every committed memory has one active recall projection row.
- Tombstoned memory has no active recall projection row.
- Every recognition embedding projection has active consent and TapDB reference.
- Every device current-state row links to one TapDB device object.
- Drift checker reports missing, duplicate, and stale projections.

## 9. Consent and privacy enforcement tests

- Privacy mode blocks event ingestion, planning, recognition, and memory creation for that space.
- Memory recall for a person uses active consent/disclosure policy.
- Cross-person memory disclosure requires explicit allowed context.
- Biometric artifacts are not retained beyond policy.
- Consent revocation blocks future use and marks dependent projections stale where required.

## 10. Failure-injection tests

- OpenAI embedding outage: event persists, candidate records embedding failure, no corrupt vector row.
- Planner LLM outage: event remains processable/retriable.
- TapDB write failure: operational event continues, retry/dead-letter created.
- SQS duplicate delivery: idempotent action/memory processing.
- WebSocket disconnect during command: action times out cleanly.
- S3 artifact missing: recognition observation records artifact_missing, no hypothesis.

## 11. Observability and audit tests

- Metrics emitted for memory write/recall, device heartbeat lag, command dispatch/result latency, recognition matched/unmatched, queue age, TapDB write failures.
- Audit events exist for consent changes, biometric enrollment/revocation, recognition hypotheses, memory commit/edit/delete, action decisions, and device registration/location changes.
- S3 audit hash chain verification detects missing/tampered entries.

## 12. Minimum passing bar for V1

- All critical-path tests above pass in CI against local/mocked infrastructure and at least one deployed-stack contract test.
- No production recognition path uses dummy embeddings.
- No semantic memory can be committed without source evidence.
- No device command can execute without authenticated device identity and action lifecycle record.
- No TapDB canonical object can drift from its required projection without detection.
