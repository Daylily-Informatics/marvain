# Marvain SOL Ultra Repository Assessment And Completion Notes

Assessment date: 2026-07-10
Reviewed branch: `codex/marvain-tapdb-boundary-closure`
Reviewed commit: `a70eb1b`
Assessment ledger: `docs/plans/20260710T072637Z_sol_ultra_repo_assessment_ledger.md`

## Executive Verdict

Marvain has a substantial domain model, a broad GUI, mature-looking API inventory, and many useful local tests. It is not yet operationally "alive" in the sense implied by its design documents: a durable agent that can reliably perceive, converse, remember, recognize, act, move across spaces and devices, explain its provenance, and survive service failures in a clean deployment.

The principal problem is no longer page or schema inventory. It is that several acceptance and status paths count declarations, fabricated events, or test doubles as proof of real runtime behavior. The repository therefore looks much closer to complete than the real cross-service system is.

| Assessment dimension | Score | Classification | Meaning |
|---|---:|---|---|
| Design and static implementation breadth | 78% | well | Most intended concepts have schema, routes, templates, or implementation code. |
| Local backend workflow implementation | 61% | well | Important local paths work, but semantic persistence, recognition, consent enforcement, and lifecycle behavior have material holes. |
| GUI workflow operability | 49% | weakly | Page coverage is broad; many workflow proofs use fake services, generic forms, or disabled controls. |
| Deployed runtime proof | 18% | weakly | No current clean-room proof exists, and `smoke v1-dev` synthesizes several required success signals. |
| Full desired-product completion | **47%** | **weakly** | Marvain is an advanced prototype with a credible core, not yet a trustworthy always-on agent system. |

The generated score of `100%` is an evidence-presence score, not an operational completion score. The generated API, GUI, and Playwright coverage values of `100%` similarly establish route discovery and token presence, not that all workflows execute correctly against real dependencies.

The detailed ledger below contains 85 scored capabilities: 38 `well`, 44 `weakly`, 3 `not at all`, and 0 `excellent`. Its unweighted mean is 45.3%. The 47% headline gives modest additional weight to the already coherent conversation, memory taxonomy, action, auth, and topology foundations, while retaining the deployed-proof penalty required by the rubric. It is an engineering estimate, not a generated test-coverage statistic.

## Classification Rubric

| Classification | Percentage | Interpretation |
|---|---:|---|
| `not at all` | 0-14% | No material implementation, or only an objective in documentation. |
| `weakly` | 15-49% | Some schema, route, UI, or isolated logic exists, but the end-to-end capability is incomplete, unsafe, or unproven. |
| `well` | 50-84% | A coherent local implementation exists with meaningful tests, but deployed or cross-service proof may still be missing. |
| `excellent` | 85-100% | The real workflow is proven across its dependencies, including failure behavior, observability, documentation, and regression coverage. |

No capability is rated `excellent` in this assessment because no fresh deployed acceptance run proves the complete real-service workflow.

## Desired Product Model

The controlling design documents describe a consent-aware, durable, multimodal personal agent system with these properties:

1. Agents are durable first-class entities with identity, personality, persona, constitution, lifecycle, memberships, and auditable self-development.
2. People, locations, spaces, devices, sessions, events, artifacts, memories, recognition observations, actions, and audit records are explicit objects.
3. A user can converse through typed text and speech, hear the agent, and provide camera input without the agent claiming to see anything it has not actually observed.
4. Memory is evidence-backed, classified across eight kinds, recallable across devices and spaces, attributable to its situation and participants, and owned by the agent rather than editable by other actors.
5. Voice and face recognition are consent-bound, observation-first, uncertainty-preserving, correctable, revocable, and safe for unknown people.
6. Devices in multiple physical locations authenticate independently, report health, receive only intended actions, and preserve dispatch, acknowledgement, result, timeout, and provenance.
7. TapDB owns semantic identity, lifecycle, external references, provenance, and lineage; PostgreSQL, pgvector, DynamoDB, S3, and SQS serve explicit specialized operational roles.
8. Actions and integrations are policy-controlled, idempotent, attributable, auditable, and observable.
9. Missing configuration and broken dependencies fail clearly. No compatibility shim, legacy path, silent fallback, or fabricated success evidence is acceptable.
10. A fresh stack can be created from the repository and prove the whole workflow without manual database repair or hidden AWS changes.

Later work adds a stronger agent-agency objective: immutable agent-owned memories, user annotations rather than edits, agent-authored constitution sections, maturity-based stasis protection, deletion-request review, cross-agent memories, self-reflection, and complete backup/restore readiness.

## Source Conflicts And Assessment Precedence

The codebase contains historical documents that conflict with the current greenfield contract:

- `docs/design/MARVAIN_GLOBAL_DESIGN_OBJECTIVES_AND_REQUIREMENTS.md` still contains pre-integration TapDB statements.
- `docs/design/MARVAIN_TAPDB_FIT_AND_INTEGRATION_SPEC.md` retains incremental, dual-write, migration, and reversibility language that conflicts with the current no-shim direction.
- `README.md` documents "canonical + legacy fallbacks" during local reset.
- Some GUI text still promises permanent deletion even though the backend now soft-deletes or tombstones objects (`functions/hub_api/templates/devices.html:127`, `functions/hub_api/templates/devices.html:354`, `functions/hub_api/templates/memories.html:976`).

This assessment treats the current `AGENTS.md` greenfield, hard-failure, no-legacy, and TapDB modeling contract as controlling.

## Detailed Capability Assessment

### 1. Foundation, Architecture, And Identity

| ID | Capability | Score | Class | Evidence and assessment | Fastest completion path |
|---|---|---:|---|---|---|
| FND-01 | Product mission and domain model | 72% | well | The design corpus consistently describes agent, person, topology, memory, recognition, action, artifact, and audit objects. Historical plans conflict about migration and TapDB state, so there is no single clean current specification. | Consolidate the current contract into one living architecture document and mark historical plans as superseded. |
| FND-02 | No-fallback/no-legacy architecture | 46% | weakly | Static guards exist, but alternate-path template discovery, default regions/models, silent JSON coercion, worker error swallowing, README legacy fallback instructions, and raw-token auth fallback remain. | Enumerate every runtime default/fallback, retain only explicitly designed optional behavior, and fail with durable operator-visible state. |
| FND-03 | Python and dependency contract | 38% | weakly | `pyproject.toml:10` requires Python 3.12 and pins the intended Daylily packages, while `template.yaml:68` and `template.yaml:393` deploy Python 3.11 functions/layers. This is a clean-deploy blocker. | Move all Lambda/layer/build contracts to Python 3.12 and prove SAM build/import in CI. |
| FND-04 | CLI and explicit configuration | 68% | well | The CLI follows `cli-core-yo`, root-owned JSON mode, explicit config support, and broad command tests. The full suite currently fails its dry-run build smoke because SAM CLI is absent. | Make the supported developer environment install/validate SAM and test every mutating CLI command against an isolated config. |
| FND-05 | Cognito browser and runtime auth | 62% | well | `daylily-auth-cognito` runtime/admin boundaries are used and Hosted UI scaffolding exists. Deployed login is skipped, default region logic remains (`auth.py:67`), and WebSocket/browser paths still accept alternate raw-token behavior. | Remove the raw-token browser fallback, require explicit region/config, and run the Hosted UI flow in clean-room acceptance. |
| FND-06 | Memberships and human roles | 70% | well | Owner/member roles, membership checks, GUI management, and API tests are substantial. Fine-grained object-level authorization is not consistently proven for mounted TapDB/admin or every operational record. | Add an authorization matrix test that uses two agents and two unrelated users across every mutable/read surface. |
| FND-07 | Agent-to-agent authentication | 43% | weakly | Agent tokens, scopes, expiry, and allowed spaces exist (`agent_hub/auth.py:215`). There is little runtime use, `target_agent_id` is not enforced during bearer authentication, and `None` or an explicitly empty space list can become unrestricted. | Define least-privilege defaults, enforce target identity and explicit spaces, and prove one cross-agent conversation and memory path. |
| FND-08 | Multi-tenant isolation | 35% | weakly | Main SQL routes generally scope by agent membership. Mounted TapDB users are elevated broadly and TapDB queries are domain-scoped rather than agent/tenant-scoped. | Add TapDB tenant filtering and adversarial tests proving one account cannot inspect another agent's graph or objects. |

### 2. Agent Identity, Personality, Lifecycle, And Agency

| ID | Capability | Score | Class | Evidence and assessment | Fastest completion path |
|---|---|---:|---|---|---|
| AGT-01 | Agent creation and durable identity | 72% | well | Create/list/detail/edit/disable paths, membership ownership, sessions, and default personas exist. TapDB identity is not reliably created on the production path. | Make agent creation transactionally enqueue an idempotent TapDB semantic write and expose sync state. |
| AGT-02 | Persona creation and selection | 55% | well | Personas and default selection exist and session contracts reference them. The GUI explicitly marks edit, disable, and revision APIs unavailable (`templates/personas.html:145-168`). | Implement persona revision/edit/disable APIs and prove active persona hydration in a real worker session. |
| AGT-03 | Personality and constitution model | 34% | weakly | Versioned founder, user, and agent sections have schema, APIs, and GUI. The worker does not hydrate the constitution, and a human request can label a revision as agent-authored. | Separate actor-authenticated endpoints, cryptographically/auditably establish authorship, and include the active revision in every session context. |
| AGT-04 | Agent self-update of constitution | 22% | weakly | The schema anticipates agent-owned revisions, but no authenticated agent reasoning workflow proposes, reviews, applies, or explains changes. | Add an agent-only proposal endpoint, conflict rules, human-visible diff, safety review, and rollback-by-new-revision. |
| AGT-05 | Maturity rubric | 64% | well | The documented age, memory, session, active-day, action, and constitution thresholds are implemented and tested. The rubric is additive and easy to satisfy without evidence of coherent agency. | Add weighted evidence quality, minimum diversity, anti-gaming rules, and explicit maturity transition audit records. |
| AGT-06 | Stasis and soft deletion | 42% | weakly | Mature agents are moved to stasis and others to `soft_deleted`; no SQL hard delete is used. Direct owner deletion still bypasses the intended review process, and the schema retains a `deleted` lifecycle value. | Make all terminal lifecycle changes review-request driven and remove unused terminal-delete states and misleading UI language. |
| AGT-07 | Agent-requested deletion review | 22% | weakly | Requests and list views exist, including a second-agent-review flag. No review, decision, appeal, or apply workflow was found. | Implement reviewer assignment, second-agent analysis, anti-pleasing evaluation, decision quorum, appeal, and stasis-only enforcement. |
| AGT-08 | Full agent backup/export | 38% | weakly | CLI export and backup manifests enumerate much state and exclude secret values. GUI backup creates a manifest/count/checksum record rather than a complete immutable bundle; TapDB graph/artifact bytes are not fully packaged. | Produce a signed bundle with SQL projections, TapDB subgraph, artifact manifest/versions, model/config references, and verification receipts. |
| AGT-09 | Restore and disaster recovery | 12% | not at all | Restore-readiness is asserted in metadata, but no restore command or clean-room restoration proof exists. | Define restore semantics and run export -> blank stack -> restore -> behavioral equivalence acceptance. |
| AGT-10 | Agent continuity across model/config upgrades | 10% | not at all | Versioned memory and constitution pieces exist, but no identity-continuity, model-change, or behavioral-drift contract is defined. | Add model/config revision objects, pre/post evaluations, continuity attestations, and rollback policy. |

### 3. Memory, Learning, And Recall

| ID | Capability | Score | Class | Evidence and assessment | Fastest completion path |
|---|---|---:|---|---|---|
| MEM-01 | Eight-kind memory taxonomy | 82% | well | Episodic, semantic, procedural, preference, relationship, location, device, and policy kinds share a canonical module and appear in API/GUI/tests. No deployed conversation proves natural capture across all kinds. | Run a real multi-turn conversation that generates evidence-backed candidates in every kind without direct fixture insertion. |
| MEM-02 | Provenance classes | 72% | well | External interaction, self-reflection, cross-agent interaction, and system observation are normalized and stored. Runtime producers seldom establish genuine self/cross-agent provenance. | Add actor-authenticated producers and provenance verification tests. |
| MEM-03 | Model-assisted classification | 52% | well | A strict provider interface and OpenAI classifier exist (`memory_classifier.py:92-176`); deterministic mode is test/smoke scoped. Output uses prompt-only JSON rather than schema-constrained responses, and live quality is untested. | Use structured output, validate rationale/evidence grounding, persist classifier failure state, and benchmark a labeled corpus. |
| MEM-04 | Source evidence and candidate lifecycle | 66% | well | Candidates, source event requirements, commit/reject/supersede/tombstone states, and review GUI exist. The device create endpoint immediately marks candidate and memory committed, bypassing an explicit policy decision; the GUI review commit does not create an embedding, so that reviewed memory cannot satisfy the current recall query. | Centralize capture policy so every commit records reviewer/policy/agent decision, source evidence, and a durable embedding state. |
| MEM-05 | Agent ownership and immutable content | 61% | well | Committed memories have no ordinary edit route; annotations and tombstones preserve history. UI language still says irreversible delete, and direct tool/device writes can create committed memories. | Enforce one immutable commit service and make every user interaction an annotation, dispute, or superseding memory. |
| MEM-06 | User annotation and disagreement | 55% | well | Comment, dispute, downweight, incorrect, and proposed-classification concepts are represented in schema/UI. They are not consumed by recall ranking, classification, contradiction handling, or learning. Memory-level lifecycle requests are explicitly disabled (`templates/memories.html:549-565`). | Make annotations influence a transparent derived ranking/policy layer without modifying canonical content, and complete the disabled request APIs. |
| MEM-07 | Embedding creation and durability | 34% | weakly | pgvector embedding/recall exists. Embedding failure logs and continues with a committed, unrecallable memory (`api_app.py:2918-2929`) without durable repair state. | Persist `embedding_pending/failed`, retry asynchronously with DLQ, and exclude no memory silently. |
| MEM-08 | Recall ranking and explanation | 58% | well | Results expose embedding distance, keyword match, rank, excerpt, source event, device, space, session, person, provenance, and TapDB EUID (`api_app.py:3210-3313`). Keyword and vector ranking are minimally combined. | Add hybrid ranking, recency/salience/confidence features, stable feature weights, and relevance evaluations. |
| MEM-09 | Consent/privacy-aware recall | 25% | weakly | The response claims `applied: true` and `privacy_mode_checked: true` (`api_app.py:3271-3279`), but the recall query does not check active consent or space privacy. This is false provenance. | Enforce consent and privacy before query execution and derive the explanation only from actual policy decisions. |
| MEM-10 | Cross-space/device/session/person recall | 56% | well | Agent-wide recall with space/person context and local cross-space tests exists. It is not proven through real workers/devices, and consent boundaries are incomplete. | Run one agent across two spaces/devices with situation-specific memories and assert both recall and non-disclosure. |
| MEM-11 | Cross-agent interaction memory | 28% | weakly | `interacting_agent_id`, token infrastructure, and provenance values anticipate the capability. No real two-agent interaction produces and recalls bilateral, permission-aware memories. | Add a real agent-to-agent session with separate viewpoints, consent/disclosure policy, and two TapDB-linked memory records. |
| MEM-12 | Self-inspired reflection and learning | 24% | weakly | `self_reflection` is a classification value, but there is no reflection scheduler, learning cycle, evidence synthesis, or clear separation between inference and observation. | Add an auditable reflection job that reads memories, creates clearly derived candidates, links sources, and cannot rewrite prior memories. |
| MEM-13 | Consolidation, forgetting, and contradiction | 18% | weakly | Supersede/tombstone mechanisms exist, but there is no operational consolidation, contradiction graph, confidence decay, forgetting budget, or re-evaluation loop. | Implement derived summaries, contradiction links, salience/decay policy, and source-preserving reversible consolidation. |

### 4. People, Consent, Recognition, And Presence

| ID | Capability | Score | Class | Evidence and assessment | Fastest completion path |
|---|---|---:|---|---|---|
| IDN-01 | People and account linkage | 65% | well | People CRUD, account linking, memberships, GUI, and SQL are substantial. Cross-agent identity and disclosure semantics are not deeply defined. | Add explicit identity-sharing policy and tests for one person represented across multiple agents. |
| IDN-02 | Consent grant/revoke lifecycle | 58% | well | Active consent checks protect voice/face enrollment and matching. Consent use is inconsistent outside recognition, and dependent projection staleness is not comprehensively handled. | Create one central use-time consent service and invoke it for memory, media, recognition, integrations, and export. |
| IDN-03 | Voice/face enrollment | 50% | well | GUI/API paths can create consent-linked artifact, observation, hypothesis, and projection records. The actual recognition worker instead posts projections directly, creating two different lifecycle paths. | Make the worker call the same observation-first service used by the GUI and remove direct projection creation. |
| IDN-04 | Production recognition worker | 28% | weakly | Real Resemblyzer/InsightFace dependencies hard-fail correctly. The worker bypasses `recognition_observations` and `recognition_hypotheses`, and unknown/no-match outcomes are mainly logs. The GUI reports recognition readiness as hard-coded `ready` without worker/model heartbeat (`app.py:6854-6860`). | Refactor every sample through artifact -> observation -> hypothesis -> optional projection/presence with durable failure records and measured readiness. |
| IDN-05 | Unknown/no-match retention | 32% | weakly | Schema and operator GUI represent unknowns and no-match hypotheses. Real worker paths do not reliably create them. | Persist every no-match/low-confidence outcome with retention policy and review/correction workflow. |
| IDN-06 | Recognition correction and revocation | 35% | weakly | Review/retraction concepts and projection deletion/revocation routes exist. Queue absence or enqueue failure can be reduced to `queued=false` rather than a hard workflow failure (`app.py:4908-4932`), and there is no end-to-end proof that revoked consent prevents future model use and marks derived state stale. | Add a grant -> enroll -> identify -> correct -> revoke -> denied-use acceptance test and fail enrollment when required processing cannot be queued. |
| IDN-07 | Presence assertions | 38% | weakly | Presence table, routes, and events exist, but presence is often written after direct matching instead of derived from a durable hypothesis. Expiry and conflicting sensor reconciliation are immature. | Derive presence only from accepted hypotheses, add TTL/retraction, and reconcile conflicting devices. |
| IDN-08 | Recognition quality and bias evaluation | 15% | weakly | Dependency and threshold tests exist, but there is no real distinct-user accuracy, false-positive, environmental robustness, demographic, or calibration benchmark. | Create consented evaluation fixtures and publish FAR/FRR/unknown/calibration thresholds before enabling autonomous identity claims. |
| IDN-09 | Biometric artifact governance | 30% | weakly | S3 purposes and short retention exist. The worker deletes artifacts by default and does not consistently preserve SQL/TapDB provenance, integrity, or deletion evidence. | Make artifact lifecycle explicit, consent-linked, integrity-checked, auditable, and consistent with review requirements. |

### 5. Live Session, Media, And Embodiment

| ID | Capability | Score | Class | Evidence and assessment | Fastest completion path |
|---|---|---:|---|---|---|
| LIV-01 | LiveKit room/token/session join | 68% | well | Membership/config checks, unique room/session creation, token metadata, GUI join, and worker code are coherent. No real deployed worker join is currently proven. | Deploy/supervise the worker and assert LiveKit participant identity from the LiveKit API. |
| LIV-02 | Typed chat loop | 62% | well | GUI persists chat then publishes LiveKit data; worker response/transcript code exists. The dual REST plus LiveKit ingestion path risks duplicate events and candidates. | Choose one canonical ingestion path with idempotency keys and prove one durable user turn and one durable agent turn. |
| LIV-03 | Speech transcription | 52% | well | OpenAI Realtime transcript handlers exist. Current deployed smoke posts a fake `speech_transcript` REST event rather than transmitting audio (`smoke.py:734-750`). | Browser-publish deterministic audio into LiveKit and assert STT output from the worker. |
| LIV-04 | Agent speech and speaker playback | 52% | well | Remote audio attachment, autoplay, `setSinkId`, and selector UI exist. No behavioral test proves a real agent audio track reaches a chosen output device. | Assert worker audio publication and browser remote-track playback, with unsupported-output behavior visible. |
| LIV-05 | Mic/speaker/camera controls | 70% | well | Enumeration, selectors, enable controls, selected-device publication, and switching are implemented. Join currently requires/publishes mic, preventing a clean typed-only path when permission is denied. | Support typed-only join, persist preferences, and test permission denial and hot unplug. |
| LIV-06 | Camera observation and visual truthfulness | 60% | well | Browser frame capture/upload, worker vision analysis, acknowledgement timeout, and no-vision response guard are strong local design. Camera state is snapshot-based; stale observations and spoken-turn vision context remain weak. | Revoke visual context on camera off, verify ACK sender/session, refresh before visual turns, and prove real S3/OpenAI vision. |
| LIV-07 | Session lifecycle and recovery | 25% | weakly | Sessions open during token minting but are not reliably closed/failed on disconnect. Reconnect, token refresh, duplicate participant, and crash recovery are not operationally handled. | Implement a session state machine and reconciliation job driven by LiveKit webhooks/participant state. |
| LIV-08 | Worker packaging and supervision | 28% | weakly | A local worker and Dockerfile exist; GUI controls are local-only. The worker is not a managed SAM/service deployment, and its package/runtime dependencies are not clean-room proven. | Build a reproducible worker image/service, health endpoint, restart policy, deployment command, and version identity. |
| LIV-09 | Media telemetry | 22% | weakly | UI status and logs exist, but no correlated metrics cover room join, STT latency, audio publication/playback, frame analysis, stale vision, or worker failures. | Emit session/run IDs and CloudWatch/Kahlo metrics for every media stage and alert on stalled transitions. |

### 6. Topology, Devices, Actions, And Integrations

| ID | Capability | Score | Class | Evidence and assessment | Fastest completion path |
|---|---|---:|---|---|---|
| TOP-01 | Locations, spaces, devices, sessions | 66% | well | Explicit schema, GUI, routes, and associations exist. Physical containment and semantic lineage are still SQL-authoritative in practice. | Create topology through one service that writes SQL projection plus idempotent TapDB lineage. |
| TOP-02 | Device token auth and scopes | 69% | well | Hashed bearer tokens, scope checks, rotation/revocation, and WS hello paths exist. Malformed scope/capability JSON silently becomes empty, and wildcard scope remains available. | Fail malformed persisted auth state, eliminate broad defaults, and test compromised/revoked tokens across REST/WS. |
| TOP-03 | Heartbeat and online state | 58% | well | Heartbeat timestamps and GUI status exist. There is no strong deployed liveness reconciliation or alerting proof. | Add explicit stale/offline transitions, metrics, and a device disconnect acceptance test. |
| TOP-04 | Remote satellite/location node | 47% | weakly | WebSocket client, capture/playback, safe HTTP, executors, and local tests exist. Trigger monitoring is explicitly a no-op stub (`apps/remote_satellite/monitoring.py:1-18`). | Package and supervise one location node on a second host and prove AV, heartbeat, commands, and recovery. |
| TOP-05 | Two-device/two-location routing | 28% | weakly | Local simulation and contracts exist. Deployed smoke merely registers two devices and posts two REST events into the same space (`smoke.py:622-684`); it does not route commands over WS. | Connect two real clients in distinct locations/spaces, dispatch targeted actions, and assert only the target receives/acks each command. |
| ACT-01 | Action proposal and policy | 70% | well | Planner, action service, policy evaluator, approval UI, idempotency schema, and tests are substantive. Real model/tool policy behavior is not deployed-proven. | Run one model proposal through approve/deny and one auto-approval rule with audit/TapDB proof. |
| ACT-02 | Device command ack/result/timeout | 62% | well | Tool runner, WS callbacks, states, idempotency, and timeout sweeper exist. Deployed topology proof does not traverse them. | Use real devices for success, duplicate delivery, disconnect, and timeout cases. |
| ACT-03 | Local host executors | 45% | weakly | Allowlisted process/shell/HTTP/device tools and tests exist. Host trust, sandboxing, credential boundaries, and production supervision need stronger definition. | Define executor isolation and run adversarial command/payload tests on a disposable satellite. |
| INT-01 | Integration account and message model | 70% | well | Gmail/Slack/Twilio/GitHub accounts, messages, dedupe keys, retention fields, routes, and tests are comprehensive. | Prove live provider accounts in a development tenant with secret rotation and replay tests. |
| INT-02 | Provider ingress | 63% | well | Signature verification and normalization exist for Slack, Twilio, and GitHub; Gmail polling exists. Queue redrive and live webhook configuration proof are absent. | Add DLQs and provider-specific deployed fixtures that prove signature, dedupe, persistence, planner ingestion, and retry. |
| INT-03 | Provider outbound actions | 55% | well | Slack message, Twilio SMS, GitHub issue comment, and related tool modules preserve status/error records locally. No current live-provider acceptance proof exists. | Execute one approved action per provider against test resources and reconcile provider IDs/status. |
| INT-04 | Cross-channel conversation continuity | 25% | weakly | Integration thread/message fields anticipate it, but no proven identity-safe conversation joins LiveKit, email, chat, SMS, and GitHub into one coherent session/memory policy. | Define thread-link and disclosure rules, then test the same agent/person across two channels. |

### 7. TapDB, Persistence, Artifacts, And Audit

| ID | Capability | Score | Class | Evidence and assessment | Fastest completion path |
|---|---|---:|---|---|---|
| DAT-01 | TapDB boundary conformance | 76% | well | Approved `TAPDBConnection`, `TemplateManager`, `InstanceFactory`, ORM, lookup, and graph services are centralized in `semantic_tapdb.py`. No invented facade or copied schema is needed. | Keep the boundary and add a real package/database integration test rather than further abstraction. |
| DAT-02 | TapDB native query/graph/admin surfaces | 62% | well | `/tapdb/*` and `/api/dag/*` mounts exist and fail visibly when unconfigured. Tests install fake TapDB apps; tenant scoping and live graph behavior are not proven. | Run mounted services against a fresh initialized TapDB and test authorized/unauthorized EUID queries. |
| DAT-03 | TapDB canonical production writes | 25% | weakly | `MarvainSemanticLifecycle` is used only by tests; no producer was found for `TAPDB_WRITER_QUEUE_URL`. Operational routes write SQL directly. | Add an idempotent outbox/queue producer to every semantic transaction and make sync status visible and repairable. |
| DAT-04 | TapDB write idempotency and retries | 22% | weakly | The writer queue has a DLQ, but create/link retries lack source-object lookup/upsert and can duplicate objects/edges. | Use stable external-reference lookup plus lineage existence checks before create/link; test SQS redelivery. |
| DAT-05 | Typed external references and lineage | 38% | weakly | Templates and lifecycle helpers exist, but many relationships remain metadata IDs and several expected topology/evidence links are absent or directionally questionable. | Model authoritative relationships as typed external-reference objects plus `generic_instance_lineage`; keep copied IDs display-only. |
| DAT-06 | SQL projection consistency | 31% | weakly | PostgreSQL is comprehensive but semantic state is authoritative in practice. `semantic_sync_status` has no `agent_id` (`sql/020...:222-234`) while the observability page queries it (`app.py:6904-6914`). | Fix the schema/query contract and implement rebuild/drift reconciliation from TapDB. |
| DAT-07 | Artifact storage and references | 43% | weakly | S3 presign/upload, artifact tables, checksums, and GUI exist. Some upload paths create bytes without a durable artifact/lineage record, and `events.artifact_id` lacks strong relational integrity. | Make one artifact service atomically issue upload intent, verify completion/hash, persist reference, and enqueue semantic lineage. |
| DAT-08 | Audit chain and immutability | 58% | well | Hash-chain helpers and a 10-year Object Lock governance bucket exist. Full write coverage, verification scheduling, and deployed lock proof are incomplete. | Centralize audit emission, verify chain/versions continuously, and test tamper detection against the real bucket. |
| DAT-09 | Retention and erasure | 40% | weakly | Retention fields/sweeper and short recognition-object lifecycle exist. Policy is fragmented across SQL and S3, while agent-memory ownership, human privacy rights, stasis, and immutable audit have unresolved conflicts. | Define one data-class retention matrix and implement traceable tombstone/redaction/retention transitions per class. |

### 8. GUI, Observability, Testing, And Operations

| ID | Capability | Score | Class | Evidence and assessment | Fastest completion path |
|---|---|---:|---|---|---|
| OPS-01 | GUI page inventory | 80% | well | Dashboard, agents, people, topology, sessions, live media, memories, recognition, actions, TapDB, audit, observability, capabilities, artifacts, and profile pages exist. | Stop adding inventory and remove/complete partial controls. |
| OPS-02 | GUI workflow operability | 45% | weakly | Core forms and safe error parsing are present, but disabled "API needed" controls remain, delete language is false, and many workflows are only tested against fake DB/services. | Give every visible command a real state assertion and remove any control that cannot perform its stated operation. |
| OPS-03 | GUI accessibility/responsiveness | 28% | weakly | Responsive styling and semantic form elements exist. No axe, keyboard-only, screen-reader, focus-management, contrast, reduced-motion, or mobile workflow gate was found. | Add accessibility and mobile viewport Playwright suites and fix modal/focus/status announcement behavior. |
| OPS-04 | Kahlo discovery and health contracts | 52% | well | `/obs_services`, `/api_health`, `/endpoint_health`, `/db_health`, `/auth_health`, and `/my_health` exist with tests and graph metadata. They report broad health, not end-to-end run health. | Add dependency-specific health with correlation IDs and verify local Kahlo discovery plus graph federation. |
| OPS-05 | Operational observability | 36% | weakly | Metrics helpers, dashboards/pages, failure catalog, and CloudWatch resources exist. The observability SQL currently errors on `semantic_sync_status.agent_id`, and worker/media/recognition/device evidence is sparse. | Fix schema mismatch and emit state-transition metrics from every asynchronous stage. |
| OPS-06 | Queue failure handling | 34% | weakly | TapDB writer has a DLQ. Transcript, action, recognition, and integration queues have no redrive policy (`template.yaml:298-329`). | Give every asynchronous queue DLQ/redrive/age alarms and build replay tooling with idempotency tests. |
| OPS-07 | Static and unit regression suite | 78% | well | Ruff, docs, generated matrices, and 666 local tests pass except one environment-dependent CLI smoke; tests cover many contracts. Heavy mocking and text assertions limit runtime confidence. | Preserve the suite but add service-level integration tests and remove assertions that merely recognize source tokens. |
| OPS-08 | API/GUI route coverage measurement | 35% | weakly | The script reports 100% because any dynamic route smoke marks every route covered (`generate_route_coverage.py:174-225`), regardless of meaningful assertions. | Generate per-method behavioral coverage requiring auth, success, validation failure, authorization failure, and persistence assertions. |
| OPS-09 | Playwright workflow coverage | 40% | weakly | 25 local E2E tests pass, but LiveKit, TapDB, recognition, media, and DB are mostly faked. The coverage script searches for route/name tokens (`generate_route_coverage.py:256-274`). | Define workflow manifests and count only executed steps with persisted postconditions against real local/deployed services. |
| OPS-10 | GUI smoke guide | 34% | weakly | Screenshot/report generation exists. It generally fills the first visible form and clicks the first submit rather than executing page-specific acceptance workflows. | Encode explicit steps, IDs, expected state, before/submit/after screenshots, and blocker semantics for each page. |
| OPS-11 | Deployed `v1-dev` smoke | 20% | weakly | It mutates a real REST API, but Cognito uses password auth rather than Hosted UI; worker join is inferred; speech and recognition are fabricated REST events; device proof is two event posts; graph can use a memory UUID (`smoke.py:687-883`). | Replace every synthetic proof with evidence from the owning service and fail unless that evidence is correlated to the smoke run. |
| OPS-12 | Fresh clean-room deployment | 10% | not at all | No current config or fresh-stack receipt proves current code initializes and runs without prior database/AWS state. The Python 3.11/3.12 contradiction is an immediate blocker. | Build a uniquely named stack/config from zero, initialize DB/TapDB, deploy workers, run acceptance, and retain receipts. |
| OPS-13 | Worker/service supervision | 27% | weakly | Lambda workers cover planner/tool queues, but agent and recognition workers are external local processes without a complete deployment/supervision contract. | Add deployable services with version, health, restart, log, metric, and upgrade behavior. |
| OPS-14 | Failure injection and recovery | 32% | weakly | Failure catalogs and many unit tests exist. Real queue failure, worker crash, OpenAI outage, expired consent, duplicate delivery, missing artifact, and reconnect recovery are not proven together. | Run deterministic failure scenarios in the clean-room stack and assert no canonical corruption plus visible recovery state. |
| OPS-15 | Cost, quota, and capacity controls | 24% | weakly | Serverless/Aurora choices and some limits exist. There are no explicit per-agent budgets, OpenAI/LiveKit quota handling, queue backpressure policy, or cost dashboards. | Add request/token/media budgets, rate/backpressure limits, quota alarms, and per-agent/run cost attribution. |

## Test And Verification Results

Commands were run non-destructively from the required activated environment.

| Check | Result | Interpretation |
|---|---|---|
| `ruff check functions/ layers/ apps/ marvain_cli/ tests/` | PASS | Static lint is clean. |
| `ruff format --check ...` | PASS | 159 files are formatted. |
| `python scripts/verify_docs_contracts.py` | PASS | Five documented action examples validate. |
| `python scripts/generate_implementation_status.py --check` | PASS | Generated implementation inventory is current. |
| `python scripts/generate_capability_matrix.py --check` | PASS | Generated inventory is current. |
| `python scripts/generate_design_objective_status.py --check --min-score 90` | PASS, reports 100% | Evidence files exist; this does not prove runtime completion. |
| `python scripts/generate_route_coverage.py --check --min-api 75 --min-gui 75 --min-playwright 75` | PASS, reports 100%/100%/100% | The metric over-credits dynamic route probes and token references. |
| `python -m pytest tests/ -q --tb=short` | **FAIL: 1 failed, 666 passed, 36 skipped** | The failing CLI dry-run build requires SAM CLI, which is not on PATH. |
| `python -m pytest tests/e2e/ -q --tb=short -rs` | PASS: 25 passed, 2 skipped | Hosted UI and deployed stack tests skipped because `MARVAIN_E2E_ENABLED!=1`; executed browser tests primarily use fakes. |

No AWS, LiveKit, OpenAI, provider, or biometric deployment was mutated in this assessment. No absent deployed evidence is counted as a pass.

## Critical Findings That Block "Alive"

### P0: The deploy/runtime contract is internally inconsistent

Python 3.12 is required by the package and auth dependency, but SAM functions and the shared layer target Python 3.11. A fresh deployment cannot be trusted until this is aligned and imported in CI.

### P0: TapDB is architecturally present but operationally disconnected

The central adapter uses TapDB correctly. The problem is that production semantic transactions do not appear to enqueue the TapDB writer, `MarvainSemanticLifecycle` is test-only, retry idempotency is incomplete, and the sync-status projection has a schema/query mismatch. Marvain therefore continues to behave as a PostgreSQL application with optional TapDB surfaces instead of a TapDB-canonical semantic system.

### P0: The deployed smoke asserts evidence it did not observe

The smoke's speech proof is a REST-created fake-audio event, recognition is an arbitrary event, worker join is inferred from configuration and space events, and two-device routing does not dispatch a command. The `ok: true` shape is accepted without provenance validation. Until corrected, a passing smoke would be misleading.

### P0: Consent-aware recall reports checks it does not perform

Recall emits `consent_filters.applied` and `privacy_mode_checked` without querying consent or privacy state. This is more serious than a missing feature because the explanation overstates enforcement.

### P0: The real recognition worker bypasses the designed lifecycle

The GUI/test route can create artifact -> observation -> hypothesis -> projection records, but the worker creates/queries projections directly and mainly logs unknown outcomes. The operational path therefore does not satisfy the core recognition design.

### P0: The realtime agent worker is not a deployable, supervised service

The LiveKit/OpenAI worker is strong local code but lacks a verified packaging, deployment, health, restart, and versioning path. A serverless API stack alone does not make the agent present in rooms.

### P1: Memory can disappear from recall without repair state

Embedding failure commits a memory with no embedding and only logs a warning. Worker ingestion/classification/network errors are also often swallowed to keep realtime operation alive. Continuity is useful, but silent loss is incompatible with durable memory.

### P1: Lifecycle and constitution surfaces overstate agency

Constitution revisions do not affect worker context, users can label changes as agent-authored, direct owner delete bypasses review, deletion requests cannot be decided, and backup has no restore.

### P1: The local GUI and deployed API are different products

`functions/hub_api/lambda_handler.py:1-10` explicitly deploys only `api_app.py`; the GUI application in `app.py` runs locally. Constitution, maturity, lifecycle-request, backup-manifest, annotation/review, and several richer operator workflows therefore have no equivalent deployed API. This split also permits duplicate implementations with different semantics. The intended product boundary must be made explicit, and every required workflow must use one shared service layer regardless of presentation surface.

### P1: Async queues other than TapDB lack DLQs

Transcript, action, recognition, and integration processing can repeatedly fail or age without a uniform redrive and recovery contract.

### P1: GUI and generated status metrics over-credit inventory

Disabled controls, generic form submissions, fake LiveKit/TapDB/recognition apps, and source-token coverage can all count toward apparently complete GUI and route scores.

## Missing Aspects And Design Blind Spots

These are not merely unfinished current routes. They are requirements needed for a durable agent system that are weakly represented or absent.

| Missing aspect | Current anticipation | Work shape |
|---|---|---|
| Authenticated agent authorship of self-reflection and constitution changes | Partial schema and token support | Refactor and new policy workflow |
| Agent identity continuity across model, prompt, tool, and constitution upgrades | Barely represented | Novel design plus evaluation system |
| Memory consolidation, contradiction, confidence revision, decay, and reversible forgetting | Supersede/tombstone only | New memory reasoning services |
| Separation of observation, testimony, inference, belief, preference, and derived reflection | Provenance classes are too coarse | Taxonomy/model refactor |
| Bilateral cross-agent memories and disclosure boundaries | Fields/tokens anticipate it | New end-to-end workflow |
| Multi-agent disagreement, negotiation, and shared action ownership | Not materially represented | Novel capability |
| Ethical deletion-request review and agent appeal | Request records only | Complete governance workflow |
| Restore, disaster recovery, and behavioral equivalence verification | Export manifests only | New operational capability |
| Exactly-once semantic effects across SQL, SQS, TapDB, S3, and providers | Partial idempotency | Cross-store architecture refactor |
| Durable session reconciliation after browser/worker/network failure | Session rows only | Runtime state-machine work |
| Prompt-injection, tool-exfiltration, and untrusted memory defenses | General scopes/approval only | Security architecture and adversarial tests |
| Recognition quality, calibration, bias, and environmental robustness | Thresholds only | Evaluation datasets and release gates |
| Conversation and memory quality evaluation over time | No durable benchmark | Novel evaluation harness |
| Per-agent cost, quota, latency, and resource budgets | Weakly anticipated | Operations and product policy |
| Accessibility and non-visual/non-auditory interaction guarantees | Generic web semantics only | GUI quality program |
| Explicit user/agent rights model for privacy versus immutable agent memory | Policy conflict unresolved | Product/governance design |
| Provenance authenticity for uploaded media and external-provider messages | Hash/signature pieces exist | Cross-source trust model |
| Autonomous management or mentoring of other agents | Mentioned as aspiration only | Novel post-V1 capability |

## Shortest Path To An Operational Marvain

The fastest route is not another broad refactor. It is a truth-first vertical slice, then integrity closure.

### Gate 1: Make a fresh build possible

1. Align SAM, layer, local, and CI runtimes on Python 3.12.
2. Ensure `source ./activate` provides SAM CLI and all build/runtime dependencies.
3. Remove configuration fallback behavior needed only by old deployments.
4. Create one explicit clean-room config and uniquely named stack.

Exit: `sam build`, imports, DB schema initialization, TapDB template initialization, and bootstrap pass from a blank environment.

### Gate 2: Put TapDB on the real transaction path

1. Add an idempotent semantic outbox/enqueue step to agent, topology, event, memory, recognition, action, artifact, consent, and audit writes.
2. Use typed external-reference objects and lineage for authoritative relationships.
3. Fix `semantic_sync_status` ownership/scoping and implement retry/DLQ/reconciliation.
4. Prove create, lookup, query, and graph from one generated TapDB EUID.

Exit: every semantic object in the vertical slice has a TapDB identity/lineage and a rebuildable SQL projection.

### Gate 3: Prove one real conversation

1. Deploy and supervise the agent worker.
2. Log in through Cognito Hosted UI.
3. Create one agent, constitution revision, location, space, person, consent, and device.
4. Join LiveKit, type a turn, publish deterministic audio, receive text and audible agent response.
5. Enable camera and either receive an artifact-backed observation or a hard visible failure.
6. Close/rejoin the session and verify lifecycle/recovery.

Exit: evidence comes from LiveKit/OpenAI/worker/S3 records, not direct REST fixture events.

### Gate 4: Prove durable, policy-correct memory

1. Classify the real transcript through the model provider.
2. Persist source evidence, candidate, explicit commit decision, embedding state, memory, and TapDB lineage.
3. Recall in a second space/device with complete situation context.
4. Revoke consent or enable privacy mode and prove the memory is excluded.
5. Annotate/dispute without mutating canonical content.

Exit: recall explanations report only policy checks actually executed.

### Gate 5: Repair recognition and presence

1. Route real worker samples through artifact -> observation -> hypothesis -> review/projection -> presence.
2. Prove two distinct voice/video fixtures, unknown/no-match, correction, expiry, and consent revocation.
3. Retain the minimum evidence required for review with explicit lifecycle/audit state.

Exit: no recognition claim exists without a durable observation and hypothesis.

### Gate 6: Prove two-device action routing

1. Run two real satellite/device clients in two locations/spaces.
2. Propose and approve targeted commands.
3. Prove only the target receives each command and records ack/result/timeout.
4. Repeat with disconnect and duplicate delivery.

Exit: action and device lineage is present in SQL, TapDB, audit, and observability.

### Gate 7: Make failures observable and recoverable

1. Add DLQ/redrive/age alarms to every queue.
2. Correlate smoke run, session, worker, media, memory, recognition, device, action, integration, and TapDB states.
3. Fix the observability schema query and expose failure plus recovery state to Kahlo.
4. Run the explicit failure catalog against the clean-room stack.

Exit: no failed asynchronous operation disappears into logs or falsely reports success.

### Gate 8: Replace synthetic acceptance metrics

1. Make route coverage behavioral and per method.
2. Make Playwright coverage count executed workflow/postcondition pairs.
3. Make `v1-dev` obtain evidence from each owning service.
4. Generate the screenshot guide from explicit page-specific workflows.
5. Make the design-objective score include static, local, GUI, and deployed dimensions separately.

Exit: a green score means the system was observed doing what the score claims.

## Practical Definition Of "Alive"

Marvain can reasonably be called alive for V1 when a clean-room run proves all of the following without manual data repair:

- A human signs in and creates an agent with an active persona and constitution revision.
- A supervised worker joins the agent's LiveKit room.
- Typed and spoken user turns create durable transcripts; the user receives text and audible responses.
- Camera-on produces a current artifact-backed visual observation, or fails before any visual claim.
- The conversation creates evidence-backed, model-classified memory candidates and an explicit commit decision.
- The same agent recalls those memories from another space/device with source, person, session, situation, ranking, policy, and TapDB lineage.
- Consent revocation and privacy mode actually prevent use and are reflected truthfully in explanations.
- Recognition records observation, hypothesis, uncertainty/unknown state, correction, and presence from the real worker.
- Two devices in two locations receive only their intended commands and preserve ack/result/timeout.
- Native TapDB graph/query shows the generated objects and lineage.
- Kahlo/CloudWatch/operator GUI show correlated healthy and intentionally failed states.
- Export and restore into another blank environment preserve the agent's defining state and provenance.

Until that receipt exists, the most accurate description is: **Marvain is a broad, promising, locally testable agent platform prototype at approximately 47% of its full desired operational capability.**

## Recommended Immediate Work Order

1. Fix Python 3.12 deployment alignment and SAM environment.
2. Replace synthetic `v1-dev` evidence and deploy/supervise the agent worker.
3. Connect idempotent TapDB writes and repair semantic sync status.
4. Enforce real consent/privacy in recall and remove false explanation fields.
5. Unify recognition on the observation/hypothesis lifecycle.
6. Run one clean-room real conversation and memory recall.
7. Run real two-device action routing and failure injection.
8. Complete agent constitution authorship, lifecycle review, and restore only after the core loop is trustworthy.

This ordering gets Marvain operational sooner because it concentrates on the smallest real vertical slice and the integrity of its evidence. New page inventory, new schema-only features, or higher generated percentages should not precede these gates.
