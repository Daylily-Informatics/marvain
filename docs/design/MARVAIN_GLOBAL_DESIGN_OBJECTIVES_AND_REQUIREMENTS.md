# MARVAIN_GLOBAL_DESIGN_OBJECTIVES_AND_REQUIREMENTS.md

## Current product direction — 2026-11-09

The user's 9 November 2026 clarification restores rich memory, individual actor identity, simultaneous presence across locations, and eventual physical interaction to the center of Marvain's purpose. The authoritative scope clarification is in section 17 below. The earlier sections retain their historical design and implementation statements; this update is not a fresh implementation or deployment assessment.

## 1. Executive summary

Marvain should be refactored into a durable, consent-aware, multi-person, multi-location AI companion/colleague system. The current repository contains a real AWS-backed hub, device model, event store, memory table, action lifecycle, LiveKit agent worker, remote satellite code, and recognition worker, but several important capabilities are brittle or incomplete. The design objective is not a chatbot with side demos. It is a hub-and-satellite system where people, devices, spaces, sessions, memories, recognition observations, and actions are explicit domain objects with provenance, lifecycle state, policy enforcement, and auditability.

Repository evidence:

- Hub/API: `functions/hub_api/api_app.py`, `functions/hub_api/lambda_handler.py`.
- Durable relational schema: the single canonical greenfield definition in `sql/schema.sql`.
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

- Account user: authenticated by Cognito and represented in `users` and `agent_memberships` (`sql/schema.sql`).
- Person: semantic human identity represented in `people`; may be linked to an account through `person_accounts` (`sql/schema.sql`).
- Unknown person: a transient observation class, not a durable `people` row unless enrolled with consent.
- Administrator/owner/member/guest: role semantics enforced through `agent_memberships` and `layers/shared/python/agent_hub/memberships.py`.

Physical actors:

- Device/satellite: a token-authenticated node represented in `devices` (`sql/schema.sql`).
- Location node: remote satellite behavior in `apps/remote_satellite/location_node.py`; not currently a distinct database entity.
- Room/space: `spaces` in `sql/schema.sql`, currently doing double duty as logical space and LiveKit room binding.

AI actors:

- Agent/persona: `agents` and `personas` in `sql/schema.sql`; worker behavior is implemented in `apps/agent_worker/worker.py`.
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

## 17. Expanded actor, memory, and physical interaction requirements — 2026-11-09

### Source and scope

Source: the user's 9 November 2026 clarification in the Marvain discussion following the public-alternatives assessment. The user accepted Linear's role as the authoritative record for commitments, then emphasized enhanced memory detail, interaction with actors besides the user, linking voice and appearance to actors, distinguishing individual people, animals, and agents, simultaneous awareness across places, and eventual interaction with real-world sensors and robotics.

This records product requirements and proposed design implications. It does not claim implementation, authorize a deployment, activate observation or tracking, select hardware, or start a test campaign. The proposed implementation structure and example milestone below remain planning inputs.

### User requirements

| ID | Required capability | Intended outcome |
|---|---|---|
| ACTOR-01 | Distinguish individual humans, animals, and software agents | Preserve the identity and history of each distinct participant, beyond identifying a class such as human, dog, or assistant. Individual animal identity and the explicit unified scope across these actor kinds are new requirements. |
| ACTOR-02 | Link voice and appearance observations to actors | Associate applicable sensory evidence with the same actor across interactions, retaining uncertainty and corrections. Software agents also require service-origin identity; their display names or synthesized voices alone do not establish identity. |
| ACTOR-03 | Participate in active multi-actor situations | Communicate with participants besides the primary user; attribute statements, requests, replies, actions, and interactions to the appropriate actors and audiences. Track distinct participating agents as well as people and animals. |
| MEM-DETAIL-01 | Retain enhanced memory detail | Preserve useful event detail, sensory context, actor relationships, and interaction history so later recall can recover more than a compressed conversational summary. |
| PRESENCE-01 | Maintain simultaneous awareness across places | Support concurrent local observations and interactions at multiple locations, connected by durable actor and event memory. |
| PHYSICAL-01 | Interact with real-world sensors and robotics | Ultimately connect perception and memory to physical sensing and action through appropriate device and robot interfaces. |

Physical presence and multi-actor interaction are core product objectives. Implementation may be staged, but completion of a work-tracking integration alone does not satisfy this expanded product direction.

### Proposed identity and observation model

The following are design interpretations for a later implementation plan, not prescribed database schemas or claims about current support.

- Distinguish actor identity, actor kind, current role, conversation/session, observation, local track, account principal, and physical embodiment. A robot can be an embodiment of a software actor; a sensor is a source of observations. Neither relationship should be inferred from a shared name.
- A human can participate through speech, camera observations, messages, or authenticated software. An animal can have its own observed behavior, location, vocalizations, appearance, and interaction history. Species/category recognition alone does not meet individual identification.
- For software agents, distinguish a persistent agent identity from individual runs, delegated instances, and the service/account through which messages arrive. Separate instances can share an intentional identity only through an explicit owning-service relationship; identical prompts, model names, or voices do not establish it.
- Preserve the difference between detecting an actor, following a local track, proposing an identity match, and establishing a durable identity. Unknown or ambiguous observations remain explicit. A mistaken association can be corrected while preserving the history of the earlier assertion.
- Record who was observed where and when, which source observed them, and the basis for the association. Last observed location and inferred presence remain distinguishable from a fresh observation; unseen movement is not fabricated.
- Retain the existing enrollment, consent, privacy, and audience boundaries. Exact animal enrollment and caretaker authority semantics remain an open design choice; human consent requirements must not be mechanically assigned to animals.
- Durable relationships use TapDB lineage and typed external-reference objects under the existing modeling contract. Persisted identities come from the owning service; examples and design labels must not impersonate real EUIDs.

### Proposed rich-memory contract

Memory should support multiple levels of detail connected to the same sources:

1. **Source observations:** selected audio/video or sensor artifacts, timestamps, device/location context, authenticated messages, and the owning controller's action results, where capture and retention are permitted.
2. **Attributed events:** who spoke, acted, addressed whom, or was observed; applicable transcript spans, visual observations, measurements, and uncertainty.
3. **Episodes:** sequences of related interactions across actors, sessions, and places, with important detail available for later retrieval.
4. **Durable knowledge:** relationships, preferences, learned routines, decisions, and corrections grounded in those episodes.
5. **Recall views:** concise answers that can expand into the underlying event and permitted source detail.

Separate observed facts, attributed claims, and Marvain's interpretations. Preserve temporal changes and corrections so a later summary cannot silently overwrite its evidence. Rich memory does not imply indefinite retention of every raw stream; capture, detail level, retention, and permitted audience require an explicit product policy. This amendment does not choose that policy.

### Proposed distributed interaction contract

- Maintain concurrent local scenes and conversations with their own participants, turn attribution, devices, and audiences. Shared identity and memory connect these scenes without merging all conversations into one context.
- Keep event time, receipt time, last observation, and device availability explicit so delayed or disconnected sources do not appear current.
- Attribute human and agent messages to their actual origins, including who asked, who responded, who delegated, and which actor acted. Ambient presence does not grant access to every conversation or memory.
- Treat observation, communication, and physical action as distinct capabilities. Being able to hear a room does not itself confer authority to broadcast into it or operate its devices.
- Route sensor and robot interactions through the owning device/controller's supported interface and existing operational controls. Record its documented command, acknowledgment, and result semantics; do not add redundant success checks, limits, or enforcement layers.
- The specific modalities, actor populations, spatial precision, hardware, controllers, latency needs, and autonomy scope remain unselected.

### Relationship to Kit and Daylily

Linear remains authoritative for the commitments intentionally managed in Daylily. Marvain's actor identities, observations, episodes, relationships, and sensory memory have a broader scope than those work records. A conversation or observed event does not automatically become a task.

Kit can be a participating software actor and an interface to Marvain when a supported connection is implemented. The expanded requirement does not make Kit the exclusive conversational interface or assume that Kit can be attached directly to Marvain's media runtime. Marvain may need its own situated interaction runtime; shared memory does not prove identical agent identity.

Daylily is one application of Marvain's capabilities. Its existing separation from LSMC and its information boundaries remain intact; this amendment does not authorize cross-workspace synchronization or pooling restricted context.

### Proposed first representative milestone

Select a bounded two-location scenario that exercises the distinctive product purpose: two consenting people, one individually identified animal, two distinct software agents, and a chosen sensor/device interface. Retain an attributed episode, retrieve its detail in a later interaction, correct a mistaken identity association, and maintain the separate local scenes during simultaneous activity. A later approved physical-action scope should use the owning controller's documented result.

This is an illustrative milestone for planning, not a hardware selection, active tracking program, test authorization, or prerequisite that forces every capability into the first release. The next planning task is to map this scope to existing source and identify the smallest useful end-to-end slice.
