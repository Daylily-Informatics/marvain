# MARVAIN_TAPDB_FIT_AND_INTEGRATION_SPEC.md

## 1. Executive summary

TapDB should be used, if adopted, as Marvain's durable semantic object graph, provenance, lineage, lifecycle, and relationship-audit substrate. It should not replace pgvector recall, biometric vector tables, SQS queues, DynamoDB WebSocket connection state, S3 media/artifact storage, or LiveKit media transport.

TapDB is not currently referenced in Marvain. Integration must be incremental, dual-written, and reversible.

## 2. TapDB model summary grounded in TapDB repo evidence

TapDB implements a PostgreSQL-backed templated object model:

- Templates: `generic_template` in `schema/tapdb_schema.sql`; ORM in `daylily_tapdb/models/template.py`.
- Instances: `generic_instance` in `schema/tapdb_schema.sql`; ORM in `daylily_tapdb/models/instance.py`.
- Lineage edges: `generic_instance_lineage` in `schema/tapdb_schema.sql`; ORM and traversal helpers in `daylily_tapdb/models/lineage.py` and `daylily_tapdb/lineage.py`.
- Audit: `audit_log` plus insert/update/delete triggers in `schema/tapdb_schema.sql`; audit query helper in `daylily_tapdb/audit.py`.
- Outbox/inbox: `outbox_event`, `outbox_event_attempt`, `inbox_message` in `schema/tapdb_schema.sql`; helpers in `daylily_tapdb/outbox/repository.py`, `daylily_tapdb/outbox/worker.py`, and `daylily_tapdb/outbox/inbox.py`.
- Scoping: `domain_code`, `issuer_app_code`, and `tenant_id` in schema, migrations, `schema/rls.sql`, and `daylily_tapdb/connection.py`.
- EUID behavior: Meridian-style EUID functions and triggers in `schema/tapdb_schema.sql`; Python support in `daylily_tapdb/euid.py`.
- Template authoring: JSON pack loading/validation in `daylily_tapdb/templates/loader.py`, `manager.py`, and `schema/template-pack.schema.json`.
- Runtime surfaces: SQLAlchemy/psycopg connection in `daylily_tapdb/connection.py`; optional Aurora direct connection in `daylily_tapdb/aurora/connection.py`; web DAG/admin surfaces in `admin/main.py`, `daylily_tapdb/web/dag.py`, and `daylily_tapdb/web/factory.py`; CLI in `daylily_tapdb/cli/db.py`.

TapDB is not a generic graph database. It is a small template/instance/lineage substrate with audit/outbox/inbox support and domain/app/tenant scoping.

## 3. Current Marvain persistence map

- Aurora/PostgreSQL via RDS Data API: `sql/*.sql`, read/write through `layers/shared/python/agent_hub/rds_data.py`.
- Memories and pgvector recall: `memories` table in `sql/001_init.sql`, enriched by `sql/012_rich_memories.sql`; endpoints in `functions/hub_api/api_app.py`; planner writes in `functions/planner/handler.py`.
- Events: `events` table; ingestion endpoint in `functions/hub_api/api_app.py`; planner consumes through `TranscriptQueue`.
- Identity/account/person/consent: `agents`, `users`, `agent_memberships`, `people`, `consent_grants`, `person_accounts`; code in `api_app.py`, `auth.py`, `memberships.py`.
- Devices/presence: `devices`, `presence`; code in `api_app.py`, `auth.py`, `apps/remote_satellite/*`.
- Biometrics: `voiceprints`, `faceprints` in `sql/014_biometrics.sql`; endpoints in `api_app.py`; worker in `apps/recognition_worker/worker.py`.
- Actions/tools: `actions`, `action_auto_approve_policies`, `action_policy_decisions`; code in `action_service.py`, `tool_runner/handler.py`, `tools/*`.
- Integration messages/accounts/sync state: `sql/017_*` through `sql/019_*`; code in `layers/shared/python/agent_hub/integrations/*`.
- DynamoDB: `WsConnectionsTable`, `WsSubscriptionsTable` in `template.yaml`; code in `functions/ws_*` and `broadcast.py`.
- SQS: `TranscriptQueue`, `ActionQueue`, `RecognitionQueue`, `IntegrationQueue` in `template.yaml`.
- S3: `ArtifactBucket`, `AuditBucket` in `template.yaml`; artifact upload endpoint and audit helper.
- LiveKit: token minting in `livekit_tokens.py`, worker in `apps/agent_worker/worker.py`, location node in `apps/remote_satellite/location_node.py`.

## 4. TapDB replacement/overlay/avoid matrix

| Marvain surface | TapDB role | Rationale |
|---|---:|---|
| Memory provenance/candidate/commit | canonical overlay | Naturally object/lineage/lifecycle-shaped. |
| Memory recall vector index | avoid as engine; cross-reference | pgvector table/projection is better for nearest-neighbor recall. |
| Events/transcript turns | cross-reference/canonical selected semantic events | Hot ingestion can stay typed; TapDB should link evidence. |
| Person/account identity graph | canonical overlay | Person/account/agent relationships are graph-shaped. |
| Consent grants | canonical overlay plus typed enforcement projection | TapDB records lifecycle; application must enforce policy. |
| Device/location/capability topology | canonical overlay | Durable topology and history are graph-shaped. |
| Presence/current state | projection/cross-reference | Current presence is hot/current-state; TapDB can store assertions/history. |
| Voice/face embeddings | avoid as vector store | Needs typed vector/projection or external recognizer. |
| Recognition observations/hypotheses | canonical overlay | Observations, hypotheses, consent-used, artifacts, and presence are lineage-shaped. |
| Action proposal/approval/execution/result | canonical overlay | Lifecycle and provenance fit TapDB; SQS remains transport. |
| SQS queues | avoid | Execution transport, not semantic truth. |
| DynamoDB WS connection state | avoid | Ephemeral routing cache. |
| S3 artifacts/audit blobs | cross-reference only | TapDB can hold references/lineage, not bytes. |
| LiveKit media plane | avoid | Realtime transport. |

## 5. Recommended TapDB role in Marvain

TapDB should be integrated behind a Marvain-owned adapter/service boundary. The adapter creates Marvain-domain TapDB instances and lineage edges for memory, recognition, identity, device topology, consent, artifacts, sessions, and action lifecycle. Existing Marvain operational tables remain in place until projections and acceptance tests prove consistency.

## 6. TapDB non-goals

- Not the vector recall engine.
- Not the biometric matching engine.
- Not the WebSocket connection registry.
- Not the SQS replacement.
- Not a media plane.
- Not a substitute for consent enforcement.
- Not a substitute for typed application invariants.

## 7. Runtime integration options and chosen recommendation

Current Marvain Lambda code uses Aurora Serverless RDS Data API through `RdsData` (`layers/shared/python/agent_hub/rds_data.py`). TapDB uses SQLAlchemy/psycopg direct connections (`daylily_tapdb/connection.py`) and optional Aurora direct SSL/IAM connection (`daylily_tapdb/aurora/connection.py`). Therefore direct in-Lambda TapDB use would require new VPC/RDS Proxy/direct-connection configuration or a Data API adapter that TapDB does not currently implement.

Chosen recommendation: start with a Marvain TapDB adapter/service boundary, not deep inline replacement. A module-first pilot is acceptable only for local/dev or VPC workers with direct DB connectivity. Production Lambda integration should either add a small internal TapDB writer service or a deliberate direct-connection/RDS Proxy architecture.

## 8. Marvain TapDB template pack specification

Initial templates:

- `agent.companion`
- `person.human`
- `account.user`
- `space.physical`
- `location.physical_site`
- `device.satellite`
- `device.capability`
- `session.conversation`
- `event.transcript`
- `event.sensor`
- `memory.candidate`
- `memory.committed`
- `recognition.observation`
- `recognition.identity_hypothesis`
- `presence.assertion`
- `policy.consent_grant`
- `artifact.reference`
- `action.proposal`
- `action.approval`
- `action.execution`
- `action.result`

Each template should define `json_addl_schema`, lifecycle state enum, external Marvain row references, and required lineage edges.

## 9. Required lineage edge types

- `device LOCATED_IN space`
- `device HAS_CAPABILITY capability`
- `event OBSERVED_BY device`
- `event OCCURRED_IN space`
- `event PART_OF session`
- `event INVOLVES_PERSON person`
- `artifact CAPTURED_BY device`
- `event DERIVED_FROM artifact`
- `memory DERIVED_FROM event`
- `memory ABOUT_PERSON person`
- `memory SUPERSEDES memory`
- `recognition_observation DERIVED_FROM artifact`
- `identity_hypothesis BASED_ON recognition_observation`
- `identity_hypothesis CANDIDATE_PERSON person`
- `identity_hypothesis USED_CONSENT_GRANT consent_grant`
- `presence_assertion BASED_ON identity_hypothesis`
- `action_proposal CAUSED_BY event`
- `action_proposal TARGETS_DEVICE device`
- `action_execution DISPATCHED_AS outbox_event`
- `action_result FULFILLS action_execution`

## 10. Required typed projections

- `memory_recall_projection` or existing `memories` with pgvector embeddings and TapDB EUID/reference.
- `recognition_embedding_projection` or existing `voiceprints`/`faceprints` with TapDB references.
- `device_current_state_projection` for heartbeat/current routing.
- `presence_current_projection` for current presence.
- `action_status_projection` for low-latency UI/tool runner state.
- `session_recent_context_projection` for prompt hydration.

## 11. Dual-write and backfill strategy constraints

- All dual-write objects must carry stable Marvain source IDs and TapDB EUIDs.
- Dual-write must be idempotent.
- TapDB failures must not block critical realtime ingestion during pilot; they must create observable retry/dead-letter state.
- Backfill must not fabricate consent or memory approval state; unknown historical gaps should be marked as legacy/unknown.
- Projection rebuilds must be repeatable from canonical TapDB plus immutable artifacts/events where possible.

## 12. Performance and operational risks

- TapDB direct SQLAlchemy connections do not match Marvain's current Data API Lambda model.
- Lineage graph queries may be too slow for prompt hot-path hydration without projections.
- Generic JSON payloads can hide invariants unless Marvain services validate states.
- Template/EUID prefix configuration must be solved for Marvain domain/app scoping before production use.
- Dual-write drift can create conflicting truth unless consistency tests are mandatory.

## 13. Security, consent, privacy, and audit implications

TapDB can record consent grants, policy decisions, and lineage, but enforcement must occur in Marvain code paths. Every biometric enrollment, match, memory write, recall, cross-person disclosure, and action execution must check policy at use time. Audit must distinguish TapDB audit triggers from Marvain S3 hash-chain audit; both can coexist, but neither automatically proves privacy compliance.

## 14. Acceptance tests

- Create event -> candidate memory -> committed memory -> recall projection -> provenance query returns event/device/space/session/person.
- Recognition artifact -> observation -> identity hypothesis -> consent edge -> presence assertion.
- Action proposal -> approval -> SQS dispatch -> execution -> result; TapDB graph links all steps.
- Dual-write failure creates retry/dead-letter without losing operational event.
- Deleting/tombstoning memory invalidates recall projection and preserves provenance.

## 15. Open questions

- Same Aurora cluster or separate TapDB database/service?
- What Marvain domain code and prefix registry entries will be used?
- Which entities become canonical in TapDB in the first pilot?
- Should TapDB outbox dispatch to SQS or only record dispatch intent while Marvain continues to enqueue SQS directly?
