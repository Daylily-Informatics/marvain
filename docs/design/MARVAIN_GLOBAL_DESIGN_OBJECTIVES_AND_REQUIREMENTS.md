# MARVAIN_GLOBAL_DESIGN_OBJECTIVES_AND_REQUIREMENTS.md

## 1. Executive summary

Marvain should be refactored into a durable, consent-aware, multi-person, multi-location AI companion/colleague system. The current repository contains a real AWS-backed hub, device model, event store, memory table, action lifecycle, LiveKit agent worker, remote satellite code, and recognition worker, but several important capabilities are brittle or incomplete. The design objective is not a chatbot with side demos. It is a hub-and-satellite system where people, devices, spaces, sessions, memories, recognition observations, and actions are explicit domain objects with provenance, lifecycle state, policy enforcement, and auditability.

Repository evidence:

- Hub/API: `functions/hub_api/api_app.py`, `functions/hub_api/lambda_handler.py`.
- Durable relational schema: `sql/001_init.sql` through `sql/019_integration_sync_state.sql`.
- Shared service layer: `layers/shared/python/agent_hub/*`.
- Planner: `functions/planner/handler.py`.
- Tool runner/action lifecycle: `layers/shared/python/agent_hub/action_service.py`, `functions/tool_runner/handler.py`.
- WebSocket control plane: `functions/ws_connect/handler.py`, `functions/ws_message/handler.py`, `functions/ws_disconnect/handler.py`.
- Realtime agent worker: `apps/agent_worker/worker.py`.
- Remote satellite: `apps/remote_satellite/hub_client.py`, `apps/remote_satellite/location_node.py`, `apps/remote_satellite/daemon.py`.
- Recognition worker: `apps/recognition_worker/worker.py`.
- AWS resources: `template.yaml`.

TapDB is not currently wired into Marvain. Any TapDB use is a target integration, not current implementation.

## 2. Non-goals

- Do not treat TapDB as a universal database replacement.
- Do not move WebSocket connection state, LiveKit media transport, SQS dispatch, or S3 media blobs into TapDB.
- Do not store biometric observations or durable memories as implicit LLM side effects.
- Do not allow recognition to silently create durable identity.
- Do not implement autonomous execution of risky actions without explicit approval or a narrow auto-approval policy.
- Do not anthropomorphize the system as conscious; personality is operational behavior, not sentience.

## 3. System principles

1. Durable truth is explicit: memories, recognition observations, action proposals, approvals, executions, consent grants, devices, spaces, and sessions have durable records.
2. Hot-path operations use purpose-built stores: pgvector for nearest-neighbor recall and biometric vectors, DynamoDB for WebSocket connection lookup, SQS for execution transport, S3 for media/artifact bytes, LiveKit for realtime media.
3. Provenance is first class: a remembered fact must be traceable to event(s), person(s), device(s), location(s), session(s), model decisions, and approval state.
4. Consent is enforced at use time, not merely recorded.
5. Unknown people are handled safely: unknown recognition observations may be logged under policy, but unknown persons must not become durable identities without enrollment/consent.
6. Every action has an intent, proposer, approval decision, dispatch record, execution result, idempotency key when applicable, and audit event.
7. Failure modes must be observable and graceful: missing model, offline device, broken recognition, failed memory embedding, expired consent, or unavailable cloud service should degrade capability rather than corrupt state.

## 4. Actors and domain model

Human actors:

- Account user: authenticated by Cognito and represented in `users` and `agent_memberships` (`sql/002_users_and_memberships.sql`).
- Person: semantic human identity represented in `people`; may be linked to an account through `person_accounts` (`sql/013_person_accounts.sql`).
- Unknown person: a transient observation class, not a durable `people` row unless enrolled with consent.
- Administrator/owner/member/guest: role semantics enforced through `agent_memberships` and `layers/shared/python/agent_hub/memberships.py`.

Physical actors:

- Device/satellite: a token-authenticated node represented in `devices`, enhanced by `sql/006_devices_enhancement.sql` and `sql/011_device_location.sql`.
- Location node: remote satellite behavior in `apps/remote_satellite/location_node.py`; not currently a distinct database entity.
- Room/space: `spaces` in `sql/001_init.sql`, currently doing double duty as logical space and LiveKit room binding.

AI actors:

- Agent/persona: `agents` in `sql/001_init.sql`; current persona instructions in `apps/agent_worker/worker.py` are hard-coded as `BASE_INSTRUCTIONS`.
- Planner: asynchronous Lambda in `functions/planner/handler.py`.
- Realtime worker: LiveKit/OpenAI worker in `apps/agent_worker/worker.py`.
- Recognition worker: external SQS-polling worker in `apps/recognition_worker/worker.py`.

Core entities required for V1:

- Person, account, agent, device, location, space, session, event, conversation turn, memory candidate, committed memory, memory evidence, recognition observation, identity hypothesis, presence assertion, consent grant, action proposal, action approval, action execution, action result, artifact reference, audit event.

## 5. Core use cases

1. Single-user local conversation with durable memory.
2. Multi-session continuity over days/weeks.
3. Remote satellite joins as an independent input/output node.
4. Two satellites in different locations online simultaneously.
5. Known person enters a location and is recognized with active consent.
6. Unknown person enters a location and is handled without biometric persistence.
7. Two known people converse with Marvain in the same room.
8. Two people interact from different locations concurrently.
9. Marvain recalls a relevant memory and exposes source evidence.
10. Marvain proposes a tool/device action and waits for approval when required.
11. Device/network failure mid-conversation degrades gracefully.
12. User audits, edits, or deletes a memory.
13. User audits identity/recognition events.
14. User disables recognition or memory capture for a person/location/session.
15. User asks why Marvain remembered or inferred something.
16. User asks which device/location/session/person produced a fact.

## 6. Capability requirements

- Identity and access must remain role/scoped and auditable.
- A device must authenticate as a device on every transport it uses. The current remote satellite sends `device_token` on WebSocket hello in `apps/remote_satellite/hub_client.py`, while `functions/ws_message/handler.py` only authenticates `access_token`; this mismatch must be closed before device command routing can be considered reliable.
- A session must become an explicit object. Current events have no session column; the agent worker passes `room_session_id` only in memory/event metadata.
- Every event must be attributable to agent, space, device, optional person, and optional artifact.
- Memory creation must go through a candidate/commit lifecycle for anything semantically durable.
- Recognition must distinguish observation, identity hypothesis, confirmed identity, consent grant used, and presence assertion.
- Tool/action execution must preserve existing approval/idempotency semantics and extend provenance.
- GUI/API must expose memory and recognition audit trails.

## 7. Memory requirements

- Memory types: episodic, semantic, procedural, preference, relationship, location, device, policy/audit-supporting notes.
- A memory candidate is not a committed memory.
- Every candidate must retain source event(s), transcript excerpt(s), device, space/location, session, model output, confidence, and creator.
- Committed memory must retain candidate lineage and approval/edit state.
- Deletion must create a tombstone and invalidate projections instead of hard deleting canonical meaning.
- Recall results must include why they were returned: ranking features, embedding distance, keyword match, source evidence, and consent/person filters.
- pgvector remains the recall projection. TapDB may be canonical for memory meaning/provenance if integrated.

## 8. Recognition requirements

- Enrollment requires active consent and must record consent grant used.
- Observation capture, embedding generation, matching, hypothesis creation, identity confirmation, and presence assertion are separate states.
- Unknown observations must not create `people` rows or durable face/voice templates.
- Dummy embeddings in `apps/recognition_worker/worker.py` are acceptable only for dev wiring and must not be used in production recognition.
- Face/voice vectors stay in typed/vector tables or a dedicated recognizer projection. TapDB should not become the vector search engine.
- Recognition audit must be queryable by person, device, space, session, artifact, consent grant, and hypothesis status.

## 9. Multi-device/multi-location requirements

- Devices require stable identity, capabilities, scopes, heartbeat, health, current connection state, and location/space binding.
- Location and space should be separated: a location is a physical site; a space/room is a sub-area or interaction boundary within a location.
- WebSocket control plane and LiveKit media plane are separate.
- Device commands must be idempotent and must handle ack/result/timeout.
- Offline devices must not lose command provenance; local buffering is acceptable only with explicit replay semantics.
- Current topology should be represented canonically as objects/edges, with a fast current-state projection for routing.

## 10. Tool/action/autonomy requirements

- Action lifecycle states: proposed, approved, executing, awaiting_device_result, device_acknowledged, executed, failed, rejected, timed_out/canceled.
- Each action requires proposer, actor type/id, origin, idempotency key when applicable, target device(s), policy decision, approval source, execution result, and audit event.
- Autonomy in V1 means proposing actions and executing only approved or policy-auto-approved low-risk actions.
- Tool handlers remain in `layers/shared/python/agent_hub/tools/*`; the runner remains in `functions/tool_runner/handler.py`.

## 11. Consent, privacy, and audit requirements

- Consent grants must be active at enrollment, matching, memory creation, recall, cross-person disclosure, and action execution.
- Privacy mode must suppress capture, planning, recall, recognition, and action side effects consistently.
- Audit must cover memory candidate creation/commit/edit/delete, recognition observation/hypothesis/presence, biometric enrollment/revocation/matching, action lifecycle, device registration/location changes, consent changes, and cross-person disclosure.
- S3 hash-chain audit in `layers/shared/python/agent_hub/audit.py` can remain immutable artifact storage, but code must not claim Object Lock guarantees unless configured and verified by infrastructure.

## 12. Architecture requirements

- Hub owns API, policy, permissions, canonical lifecycle decisions, and durable state.
- Satellites own local capture/output and device-local actions, not global truth.
- Realtime worker owns LiveKit/OpenAI session behavior and transcript forwarding, not durable memory policy.
- Planner proposes memory/action candidates; it should not directly commit high-risk semantic truth.
- Recognition worker proposes identity hypotheses; it should not silently confirm durable identity.
- Memory service owns candidate/commit/recall/tombstone semantics.
- TapDB, if adopted, owns semantic object graph, provenance, lineage, lifecycle, and audit-style relationship history.
- Typed PostgreSQL tables/projections own fast operational queries and vectors.

## 13. Operational requirements

- Local and cloud setup should remain CLI-driven (`marvain_cli/*`, `config/marvain-example.yaml`).
- Tests must include unit, contract, integration, end-to-end, simulation, golden memory, golden recognition, TapDB lineage/projection consistency, failure injection, and deployed smoke tests.
- Observability must expose health, queue lag, memory write/recall rates, recognition outcomes, device heartbeat age, command latency, audit append status, and TapDB/projection consistency.

## 14. Acceptance criteria

V1 is acceptable only when:

- A multi-day single-user conversation can create, recall, explain, edit, and delete/tombstone memories.
- Two satellites can be online simultaneously, with independent heartbeat, media participation, event ingestion, and command routing.
- Recognition uses active consent and records observations/hypotheses/presence without silently persisting unknown people.
- Tool/device actions require approval unless covered by explicit policy and record proposal/approval/execution/result.
- A user can ask why a fact was remembered or inferred and receive event/device/person/session lineage.
- Failure of model, device, network, queue, recognition, or TapDB projection does not corrupt canonical state.

## 15. Refactor implications

- Keep Memory Service, Recognition Service, Device/Topology Service, Action Lifecycle Service, and the TapDB Adapter as current production boundaries.
- Use TapDB as canonical semantic object graph/provenance/lifecycle state for the V1 semantic domains, with typed SQL tables retained only as rebuildable projections or specialized operational stores.
- Keep existing SQS/DynamoDB/S3/LiveKit operational stores.
- Remove obsolete compatibility, stale planning, and duplicate semantic storage paths rather than preserving them.

## 16. Open questions

- What risk level should be allowed for policy-auto-approved actions?
- Which biometric modes are in scope for V1: voice, face, or both?
- Should TapDB run in the same Aurora cluster or as a separate Postgres/TapDB service?
- What is the V1 default for memory capture: candidate-only, auto-commit episodic, or user-approved semantic?
- How should location privacy defaults be configured?
