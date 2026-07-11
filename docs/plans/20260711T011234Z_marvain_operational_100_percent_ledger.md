# Marvain Operational 100 Percent Execution Ledger

Created: 2026-07-11T01:12:34Z

## Objective

Raise Marvain from the evidence-backed 47% baseline in `docs/sol_ultra_repo_assessment_completion_notes.md` to an operating-well milestone at 85% and then to 100% across all 85 assessed capabilities. Scores advance only from implementation, local workflow, browser/API integration, fresh deployed proof, failure recovery, observability, documentation, and regression evidence.

## Gate 0 Baseline

- Branch: `codex/marvain-operational-100-closure`.
- Baseline commit before assessment artifacts: `a70eb1b`.
- Assessment artifact commit: `cfbd6a9`.
- Pre-existing dirty file excluded from all staging: `AGENTS.md`.
- Source report: `docs/sol_ultra_repo_assessment_completion_notes.md`.
- Source assessment ledger: `docs/plans/20260710T072637Z_sol_ultra_repo_assessment_ledger.md`.
- Baseline operational score: 47%.
- Baseline capability distribution: 38 well, 44 weakly, 3 not at all, 0 excellent.
- Baseline local suite: 666 passed, 36 skipped, 1 failed because SAM CLI was unavailable.
- Baseline browser suite: 25 passed, 2 deployed tests skipped.
- Baseline deployed proof: none accepted.
- Clean-room AWS, live providers, and recognition host are later cost-bearing acceptance gates. No existing stack will be modified or destroyed.

## Status And Scoring Contract

Working statuses are `OPEN`, `IN_PROGRESS`, and `ATTEMPTING_BUGFIX`. Terminal statuses are `SUCCESS`, `DUPLICATE`, `NO_LONGER_NEEDED`, `FAIL`, and `BLOCKED`.

| Evidence available | Maximum score |
|---|---:|
| Incomplete implementation | 49 |
| Complete implementation without real local workflow | 74 |
| Local workflow without meaningful browser/API integration | 84 |
| Integration proof without fresh deployed proof | 94 |
| Deployed proof without failure, observability, docs, and regression evidence | 99 |
| Every required evidence class | 100 |

No row becomes `SUCCESS` until its current score is 100. `FAIL` requires a recorded `ATTEMPTING_BUGFIX`. Live-only rows become `BLOCKED` with exact unblock conditions when credentials, services, approvals, or test tenants are unavailable.

## Agent Ownership

| Agent | Scope | Exclusive shared ownership |
|---|---|---|
| A1 Coordinator | Ledger, architecture, route integration, status scoring, final acceptance | `app.py`, `api_app.py`, generated status definitions |
| A2 Runtime | Python 3.12, SAM, CI, ECS, clean-room deploy, CLI, smoke | `template.yaml`, deployment workflows, deployment CLI |
| A3 Persistence | TapDB, outbox, SQL, artifacts, audit, projection rebuild | Canonical greenfield SQL and TapDB writer |
| A4 Policy | Cognito, auth, tenancy, consent, privacy, ownership | Auth and policy services |
| A5 Memory | Classification, candidates, commit, embedding, annotation, recall, reflection | Memory services and memory tests |
| A6 Agent lifecycle | Persona, constitution, maturity, stasis, review, backup, restore | Agent lifecycle services |
| A7 Live media | LiveKit, text, speech, camera, sessions, ECS worker runtime | Agent worker and live media tests |
| A8 Recognition | Linux worker, observations, hypotheses, presence, quality | Recognition worker/services/tests |
| A9 Topology/actions | Devices, satellites, actions, Gmail, Slack, Twilio, GitHub | Topology/action/integration services |
| A10 GUI/QA | GUI, native observability, accessibility, Playwright, coverage | Templates, static assets, GUI workflow manifests |

Agents implement business behavior in disjoint service modules. A1 serially integrates route entrypoints. A3 owns all schema changes. No two agents edit the same integration file concurrently.

## Capability Ledger

The compact evidence fields below are initialized from the assessment. Agents replace `pending` with exact file, command, receipt, and failure evidence as work progresses.

| ID | Capability | Baseline | Target | Current | Status | Owner | Gate | Dependencies | Implementation evidence | Local proof | Deployed proof | Failure proof | Root cause | Terminal note |
|---|---|---:|---:|---:|---|---|---|---|---|---|---|---|---|---|
| FND-01 | Product mission and domain model | 72 | 100 | 72 | OPEN | A1 | 1 | - | Assessment report | Baseline docs checks | none | pending | Conflicting historical contracts | |
| FND-02 | No-fallback/no-legacy architecture | 46 | 100 | 46 | IN_PROGRESS | A1 | 1 | FND-01 | Session secret now hard-fails; broader purge pending | Import-failure contract plus GUI suite | none | pending | Other runtime defaults and silent substitutions remain | |
| FND-03 | Python and dependency contract | 38 | 100 | 60 | IN_PROGRESS | A2 | 1 | FND-01 | SAM functions/layer, CI, container, and environment now use Python 3.12; SAM 1.147.1 declared | 75 focused tests and full 10-function SAM build pass | none | pending | CLI build hardcode and dependency resolver conflict remain | |
| FND-04 | CLI and explicit configuration | 68 | 100 | 68 | OPEN | A2 | 1 | FND-03 | CLI and config modules | CLI tests; one failure | none | pending | Build preflight unavailable | |
| FND-05 | Cognito browser and runtime auth | 62 | 100 | 62 | OPEN | A4 | 1 | FND-03 | Auth boundary present | Auth tests | none | pending | Raw-token/default behavior remains | |
| FND-06 | Memberships and human roles | 70 | 100 | 70 | OPEN | A4 | 1 | FND-05 | Membership services | Membership tests | none | pending | Object-level matrix incomplete | |
| FND-07 | Agent-to-agent authentication | 43 | 100 | 49 | IN_PROGRESS | A4 | 3 | FND-05,FND-06 | Tokens require explicit target, scopes, and spaces; empty spaces deny all; issuer-space ownership checked | Auth, permission, and API route tests pass | none | Malformed persisted auth state fails hard | Bearer possession does not yet cryptographically attest the target agent identity | |
| FND-08 | Multi-tenant isolation | 35 | 100 | 35 | OPEN | A4 | 2 | FND-05,DAT-02 | SQL membership filters | Partial route tests | none | pending | TapDB/admin scoping incomplete | |
| AGT-01 | Agent creation and durable identity | 72 | 100 | 72 | OPEN | A6 | 3 | DAT-03,FND-06 | SQL agent creation | Local API tests | none | pending | TapDB identity not on production path | |
| AGT-02 | Persona creation and selection | 55 | 100 | 55 | OPEN | A6 | 3 | AGT-01 | Persona create/default | Local GUI tests | none | pending | Edit, revision, disable incomplete | |
| AGT-03 | Personality and constitution model | 34 | 100 | 34 | OPEN | A6 | 3 | AGT-01,FND-07 | Constitution schema/routes | Local route tests | none | pending | No worker hydration; authorship spoofable | |
| AGT-04 | Agent self-update of constitution | 22 | 100 | 22 | OPEN | A6 | 7 | AGT-03,FND-07 | Schema anticipation | none accepted | none | pending | No authenticated proposal/review workflow | |
| AGT-05 | Maturity rubric | 64 | 100 | 64 | OPEN | A6 | 3 | AGT-01 | Heuristic implemented | Local maturity tests | none | pending | OR gate can overstate maturity | |
| AGT-06 | Stasis and soft deletion | 42 | 100 | 42 | OPEN | A6 | 3 | AGT-05 | Lifecycle fields/routes | Local route tests | none | pending | Direct mutation bypasses review | |
| AGT-07 | Agent-requested deletion review | 22 | 100 | 22 | OPEN | A6 | 3 | AGT-06,FND-07 | Request create/list | Local tests | none | pending | No decision, appeal, apply, or second-agent review | |
| AGT-08 | Full agent backup/export | 38 | 100 | 38 | OPEN | A6 | 3 | DAT-07,DAT-08 | CLI export and manifest | Export unit tests | none | pending | No complete signed bundle | |
| AGT-09 | Restore and disaster recovery | 12 | 100 | 12 | OPEN | A6 | 7 | AGT-08,DAT-06 | none | none | none | pending | No restore implementation | |
| AGT-10 | Agent continuity across upgrades | 10 | 100 | 10 | OPEN | A6 | 7 | AGT-03,AGT-09 | none | none | none | pending | No revision continuity contract | |
| MEM-01 | Eight-kind memory taxonomy | 82 | 100 | 82 | OPEN | A5 | 3 | DAT-03 | Canonical taxonomy | Taxonomy tests | none | pending | Natural deployed capture unproven | |
| MEM-02 | Provenance classes | 72 | 100 | 72 | OPEN | A5 | 3 | MEM-01,DAT-05 | Four classes stored | Unit tests | none | pending | Actor-authenticated production provenance incomplete | |
| MEM-03 | Model-assisted classification | 52 | 100 | 60 | IN_PROGRESS | A5 | 3 | MEM-01,FND-04 | Strict schema-constrained OpenAI classifier with grounded quote, provider/model ID, confidence, rationale, and typed failures | 39 memory service/classifier tests pass | none | Invalid/ungrounded output and missing provider fail explicitly | Live model quality benchmark absent | |
| MEM-04 | Source evidence and candidate lifecycle | 66 | 100 | 66 | IN_PROGRESS | A5 | 3 | MEM-03,DAT-03 | Worker-only canonical commit requires existing scoped evidence, classifier metadata, embedding, candidate, memory, and transactional outbox | Canonical API and service tests pass | none | Missing evidence/classification/embedding cannot commit | Delegated and local GUI mutation paths are not converged | |
| MEM-05 | Agent ownership and immutable content | 61 | 100 | 61 | OPEN | A5 | 3 | MEM-04,FND-07 | Tombstone/annotation paths | Local tests | none | pending | Multiple direct commit paths | |
| MEM-06 | User annotation and disagreement | 55 | 100 | 55 | OPEN | A5 | 3 | MEM-05 | Annotation storage/UI | Local tests | none | pending | Ranking and learning ignore annotations | |
| MEM-07 | Embedding creation and durability | 34 | 100 | 49 | IN_PROGRESS | A5 | 3 | MEM-04 | Canonical worker path requires explicit model and successful embedding before SQL commit; pure state machine records pending/failed/retry states | Embedding failure and commit-transition tests pass | none | Provider failure leaves no canonical memory write | Durable retry/dead-letter persistence is not wired | |
| MEM-08 | Recall ranking and explanation | 58 | 100 | 58 | OPEN | A5 | 3 | MEM-06,MEM-07 | pgvector explanation fields | Mocked recall tests | none | pending | Minimal hybrid ranking | |
| MEM-09 | Consent/privacy-aware recall | 25 | 100 | 49 | IN_PROGRESS | A4 | 3 | MEM-08,FND-06 | Canonical recall executes source-space privacy and source-person memory-consent checks and emits only performed evidence | Policy and recall exclusion tests pass | none | Private/denied memories are excluded; malformed policy state fails | Delegated read and all noncanonical recall paths are not converged | |
| MEM-10 | Cross-space/device/session/person recall | 56 | 100 | 56 | OPEN | A5 | 3 | MEM-08,MEM-09 | Agent-wide hydration | Mocked worker tests | none | pending | No real cross-context proof | |
| MEM-11 | Cross-agent interaction memory | 28 | 100 | 28 | OPEN | A5 | 7 | MEM-10,FND-07 | Fields only | Unit contracts | none | pending | No bilateral workflow or reciprocal lineage | |
| MEM-12 | Self-inspired reflection and learning | 24 | 100 | 24 | OPEN | A5 | 7 | MEM-11,AGT-04 | Provenance label only | none accepted | none | pending | No reflection scheduler or derived evidence workflow | |
| MEM-13 | Consolidation, forgetting, contradiction | 18 | 100 | 18 | OPEN | A5 | 7 | MEM-12 | Tombstone/supersede only | none accepted | none | pending | No consolidation or contradiction model | |
| IDN-01 | People and account linkage | 65 | 100 | 65 | OPEN | A4 | 3 | FND-06,DAT-03 | People/account routes | Local tests | none | pending | Cross-agent disclosure undefined | |
| IDN-02 | Consent grant/revoke lifecycle | 58 | 100 | 58 | OPEN | A4 | 3 | IDN-01 | Recognition consent checks | Local tests | none | pending | Use-time enforcement inconsistent | |
| IDN-03 | Voice/face enrollment | 50 | 100 | 50 | OPEN | A8 | 4 | IDN-02,DAT-07 | Two enrollment paths | Mocked GUI tests | none | pending | Worker bypasses observation lifecycle | |
| IDN-04 | Production recognition worker | 28 | 100 | 28 | OPEN | A8 | 4 | IDN-03,FND-03 | Real recognizer dependencies | Contract tests | none | pending | Direct projection/presence path | |
| IDN-05 | Unknown/no-match retention | 32 | 100 | 32 | OPEN | A8 | 4 | IDN-04 | Schema/UI | Local fake tests | none | pending | Worker logs instead of persists | |
| IDN-06 | Recognition correction and revocation | 35 | 100 | 35 | OPEN | A8 | 4 | IDN-05,IDN-02 | Review routes | Local tests | none | pending | Queue failure can be silent; no full revocation proof | |
| IDN-07 | Presence assertions | 38 | 100 | 38 | OPEN | A8 | 4 | IDN-04,IDN-06 | Presence schema/routes | Local tests | none | pending | Not consistently hypothesis-derived | |
| IDN-08 | Recognition quality and bias evaluation | 15 | 100 | 15 | OPEN | A8 | 7 | IDN-04 | Thresholds only | none accepted | none | pending | No quality/calibration benchmark | |
| IDN-09 | Biometric artifact governance | 30 | 100 | 30 | OPEN | A8 | 4 | IDN-02,DAT-07 | S3 lifecycle and deletion | Unit contracts | none | pending | Fragmented provenance and retention | |
| LIV-01 | LiveKit room/token/session join | 68 | 100 | 68 | OPEN | A7 | 4 | FND-03,FND-05 | Token/session implementation | Local tests | none | pending | No real deployed worker join | |
| LIV-02 | Typed chat loop | 62 | 100 | 62 | OPEN | A7 | 4 | LIV-01,MEM-04 | REST plus LiveKit ingestion | Local Playwright | none | pending | Duplicate ingestion risk | |
| LIV-03 | Speech transcription | 52 | 100 | 52 | OPEN | A7 | 4 | LIV-01 | Realtime handlers | Unit tests | synthetic only | pending | Smoke inserts fake event | |
| LIV-04 | Agent speech and speaker playback | 52 | 100 | 52 | OPEN | A7 | 4 | LIV-01 | Audio attachment/selectors | Template tests | none | pending | No real playback proof | |
| LIV-05 | Mic/speaker/camera controls | 70 | 100 | 70 | OPEN | A7 | 4 | LIV-01 | Device selectors/switching | Local Playwright | none | pending | Typed-only join and hot-unplug incomplete | |
| LIV-06 | Camera observation and visual truthfulness | 60 | 100 | 60 | OPEN | A7 | 4 | LIV-01,DAT-07 | Frame upload and guard | Local tests | none | pending | Stale/off and spoken vision gaps | |
| LIV-07 | Session lifecycle and recovery | 25 | 100 | 25 | OPEN | A7 | 4 | LIV-01 | Session rows | Partial tests | none | pending | No close/fail/reconcile state machine | |
| LIV-08 | Worker packaging and supervision | 28 | 100 | 28 | OPEN | A2 | 4 | FND-03 | Local Dockerfile | Import tests | none | pending | No deployed managed service | |
| LIV-09 | Media telemetry | 22 | 100 | 22 | OPEN | A7 | 6 | LIV-03,LIV-04,LIV-06 | Logs/UI state | none accepted | none | pending | No correlated stage metrics | |
| TOP-01 | Locations, spaces, devices, sessions | 66 | 100 | 66 | OPEN | A9 | 5 | DAT-03,DAT-05 | Schema/routes/GUI | Local tests | none | pending | SQL authoritative; semantic lineage incomplete | |
| TOP-02 | Device token auth and scopes | 69 | 100 | 69 | OPEN | A9 | 5 | FND-06 | Device auth/rotation | Local tests | none | pending | Malformed auth state and wildcard scope | |
| TOP-03 | Heartbeat and online state | 58 | 100 | 58 | OPEN | A9 | 5 | TOP-02 | Heartbeat route/UI | Unit tests | none | pending | No deployed liveness reconciliation | |
| TOP-04 | Remote satellite/location node | 47 | 100 | 47 | OPEN | A9 | 5 | TOP-02,FND-03 | Satellite daemon | Local tests | none | pending | Monitoring stub and no supervised proof | |
| TOP-05 | Two-device/two-location routing | 28 | 100 | 28 | OPEN | A9 | 5 | TOP-04,ACT-02 | REST-only simulation | Contract tests | synthetic only | pending | No real targeted WS routing | |
| ACT-01 | Action proposal and policy | 70 | 100 | 70 | OPEN | A9 | 5 | FND-06,DAT-03 | Planner/policy/action service | Unit tests | none | pending | Real model/policy path unproven | |
| ACT-02 | Device command ack/result/timeout | 62 | 100 | 62 | OPEN | A9 | 5 | ACT-01,TOP-02 | Tool runner/WS/sweeper | Unit tests | none | pending | No deployed client proof | |
| ACT-03 | Local host executors | 45 | 100 | 45 | OPEN | A9 | 5 | ACT-01 | Executor implementations | Unit tests | none | pending | Isolation and trust undefined | |
| INT-01 | Integration account and message model | 70 | 100 | 70 | OPEN | A9 | 5 | FND-06,DAT-03 | Account/message schema | Local tests | none | pending | Live credentials and OAuth UX unproven | |
| INT-02 | Provider ingress | 63 | 100 | 63 | OPEN | A9 | 5 | INT-01 | Signature/normalization/polling | Provider unit tests | none | pending | No DLQ or live webhook proof | |
| INT-03 | Provider outbound actions | 55 | 100 | 55 | OPEN | A9 | 5 | INT-01,ACT-01 | Slack/Twilio/GitHub tools | Mocked tests | none | pending | No live provider receipts | |
| INT-04 | Cross-channel conversation continuity | 25 | 100 | 25 | OPEN | A9 | 7 | INT-02,INT-03,MEM-10 | Thread fields only | none accepted | none | pending | No identity-safe channel joining | |
| DAT-01 | TapDB boundary conformance | 76 | 100 | 76 | OPEN | A3 | 2 | FND-02 | Central adapter | Static/package tests | none | pending | Real DB integration missing | |
| DAT-02 | TapDB native query/graph/admin surfaces | 62 | 100 | 62 | OPEN | A3 | 2 | DAT-01,FND-08 | Mounted routes | Fake-backed tests | none | pending | Live graph and tenant scope unproven | |
| DAT-03 | TapDB canonical production writes | 25 | 100 | 49 | IN_PROGRESS | A3 | 2 | DAT-01 | Transactional agent/persona/event/memory producers plus agent-scoped outbox and idempotent TapDB inbox writer | Outbox, redelivery, API transaction, and writer tests pass | none | Writer failure remains retryable and records sync failure | Dispatcher and remaining object producers are not wired | |
| DAT-04 | TapDB write idempotency and retries | 22 | 100 | 22 | OPEN | A3 | 2 | DAT-03 | Writer queue/DLQ | Partial tests | none | pending | Retries can duplicate objects/edges | |
| DAT-05 | Typed external references and lineage | 38 | 100 | 38 | OPEN | A3 | 2 | DAT-03 | Templates/helpers | Fake lifecycle tests | none | pending | Metadata IDs remain authoritative | |
| DAT-06 | SQL projection consistency | 31 | 100 | 31 | OPEN | A3 | 2 | DAT-03,DAT-04 | Sync schema | Schema text tests | none | pending | Invalid agent_id query; no rebuild | |
| DAT-07 | Artifact storage and references | 43 | 100 | 43 | OPEN | A3 | 2 | DAT-03 | Presign/S3/tables | Local tests | none | pending | Upload paths bypass durable reference | |
| DAT-08 | Audit chain and immutability | 58 | 100 | 58 | OPEN | A3 | 2 | DAT-03,DAT-07 | Hash chain/Object Lock | Unit tests | none | pending | Write coverage and deployed lock proof incomplete | |
| DAT-09 | Retention and erasure | 40 | 100 | 40 | OPEN | A3 | 7 | DAT-07,DAT-08,IDN-02 | Retention fields/sweeper | Unit tests | none | pending | Fragmented policy and rights conflict | |
| OPS-01 | GUI page inventory | 80 | 100 | 80 | OPEN | A10 | 6 | FND-01 | 23 templates | Route tests | none | pending | Inventory exceeds workflow depth | |
| OPS-02 | GUI workflow operability | 45 | 100 | 45 | OPEN | A10 | 6 | FND-04 | Forms and partial controls | Fake-backed Playwright | none | pending | Disabled controls and duplicate APIs | |
| OPS-03 | GUI accessibility/responsiveness | 28 | 100 | 28 | OPEN | A10 | 6 | OPS-02 | Responsive CSS partial | none accepted | none | pending | Navigation/accessibility gates absent | |
| OPS-04 | Marvain-native discovery and health | 52 | 100 | 52 | IN_PROGRESS | A10 | 6 | FND-04 | Marvain-native schema and debranded route functions | 135 GUI tests; honest unmeasured counters | none | pending | Real dependency/request metrics still required | |
| OPS-05 | Operational observability | 36 | 100 | 36 | OPEN | A10 | 6 | DAT-06,LIV-09 | Metrics/page/resources | Partial tests | none | pending | Invalid query and sparse worker evidence | |
| OPS-06 | Queue failure handling | 34 | 100 | 34 | OPEN | A2 | 5 | DAT-04 | TapDB DLQ only | Template tests | none | pending | Four queues lack redrive/replay | |
| OPS-07 | Static and unit regression suite | 78 | 100 | 78 | OPEN | A10 | 6 | FND-03 | Broad suite | 666 pass; one fail | none | pending | Heavy mocking and missing SAM | |
| OPS-08 | API/GUI route coverage measurement | 35 | 100 | 35 | OPEN | A1 | 6 | OPS-07 | Token-based generator | Generator tests | none | pending | Dynamic probe over-credits behavior | |
| OPS-09 | Playwright workflow coverage | 40 | 100 | 40 | OPEN | A10 | 6 | OPS-02,OPS-07 | Local Playwright | 25 passed | none | pending | Fakes and token scanning | |
| OPS-10 | GUI smoke guide | 34 | 100 | 34 | OPEN | A10 | 6 | OPS-02,OPS-09 | Screenshot generator | Shallow test | none | pending | Generic first-form behavior | |
| OPS-11 | Deployed v1-dev smoke | 20 | 100 | 20 | IN_PROGRESS | A2 | 8 | LIV-08,IDN-04,TOP-05 | Runtime receipt contracts now reject synthetic REST, fake-audio, arbitrary recognition, inferred worker, and registration-only topology proof | 11 focused smoke tests pass | none accepted | Runtime evidence validator rejects malformed and fixture receipts | Owning-service collectors and clean-room run remain absent | |
| OPS-12 | Fresh clean-room deployment | 10 | 100 | 10 | OPEN | A2 | 8 | FND-03,DAT-03,LIV-08 | none accepted | none | none | pending | No clean-room receipt | |
| OPS-13 | Worker/service supervision | 27 | 100 | 27 | OPEN | A2 | 4 | FND-03 | Local processes | Local status tests | none | pending | Agent/recognition workers unmanaged | |
| OPS-14 | Failure injection and recovery | 32 | 100 | 32 | OPEN | A10 | 8 | OPS-06,OPS-11 | Failure catalog | Unit tests | none | pending | Real failures not exercised | |
| OPS-15 | Cost, quota, and capacity controls | 24 | 100 | 24 | OPEN | A2 | 7 | OPS-05,OPS-12 | Serverless limits partial | none accepted | none | pending | No per-agent budgets/backpressure | |

## Cross-Cutting Acceptance Rows

| ID | Requirement | Status | Owner | Gate | Dependencies | Evidence | Root cause | Terminal note |
|---|---|---|---|---|---|---|---|---|
| XG-001 | Operational scorer consumes executed evidence and starts at 47% | SUCCESS | A1 | 0 | all capability rows | `scripts/generate_operational_completion_status.py`; evidence manifest; 5 focused tests | Existing scorers count tokens/files | Tracks all 85 rows, enforces evidence caps, and reports the assessed 47% baseline. |
| XG-002 | Python 3.12 build and CI contract is green | IN_PROGRESS | A2 | 1 | FND-03,FND-04 | Python 3.12 SAM validation/build and focused environment tests pass | CLI build hardcode and dependency resolver conflict remain | |
| XG-003 | Local and deployed APIs use one business service layer | OPEN | A1 | 1 | FND-02 | pending | Local/deployed split | |
| XG-004 | TapDB semantic transaction and projection rebuild pass | OPEN | A3 | 2 | DAT-01 through DAT-08 | pending | Production writer disconnected | |
| XG-005 | Policy-correct conversation/memory vertical slice passes | OPEN | A4,A5,A7 | 4 | MEM-01 through MEM-10,LIV-01 through LIV-07 | pending | Cross-service path incomplete | |
| XG-006 | Recognition lifecycle and quality proof passes | OPEN | A8 | 4 | IDN-02 through IDN-09 | pending | Worker bypasses lifecycle | |
| XG-007 | Two-device/two-location action proof passes | OPEN | A9 | 5 | TOP-01 through ACT-03 | pending | Existing proof is REST-only | |
| XG-008 | Four live provider tenants pass ingress/outbound proof | OPEN | A9 | 5 | INT-01 through INT-03 | pending | Live credentials not yet configured | |
| XG-009 | Marvain-native observability and accessibility pass | IN_PROGRESS | A10 | 6 | OPS-01 through OPS-10 | Debranded native health payloads; GUI accessibility work parallelized | Synthetic health and weak accessibility | |
| XG-010 | Agent export/restore behavioral equivalence passes | OPEN | A6,A3 | 7 | AGT-08,AGT-09,DAT-06 | pending | Restore absent | |
| XG-011 | Fresh clean-room acceptance receipt passes | OPEN | A2 | 8 | XG-002 through XG-010 | pending | No deployed receipt | |
| XG-012 | All 85 capabilities score 100 and all rows are terminal | OPEN | A1 | 8 | all rows | pending | Program incomplete | |

## Gate Progress

| Gate | Objective | Status | Exit evidence |
|---|---|---|---|
| 0 | Baseline and truthful scoring | SUCCESS | Ledger, evidence manifest, scorer baseline 47% |
| 1 | Build, configuration, and API convergence | OPEN | Python 3.12 build; unified service routes; purity guards |
| 2 | TapDB and durable persistence | OPEN | Real DB, idempotency, graph, projection rebuild |
| 3 | Memory and agent governance | OPEN | Policy-correct memory, constitution, lifecycle, restore |
| 4 | Real conversation and recognition | OPEN | ECS worker, Linux recognition, clean vertical slice |
| 5 | Devices, actions, and providers | OPEN | Two-device routing and four live provider receipts |
| 6 | Native observability and GUI quality | OPEN | Measured health, accessibility, behavioral Playwright |
| 7 | Remaining 85-capability closure | OPEN | Continuity, reflection, security, evaluation, cost, restore |
| 8 | Final 100% acceptance | OPEN | Clean-room receipt; all capability rows 100/SUCCESS |

## Reporting Cadence

At every gate transition record status counts, rows completed, bugfix attempts, blocked credentials/approvals, commands run, evidence paths, residual risks, and next owners. Raw test/screenshot output belongs under `output/acceptance/<run-id>/`; sanitized receipts and summaries belong under `docs/reports/`.

## Execution Update 2026-07-11T05:19:29Z

- Commits `3d07797`, `b4b61bb`, and `fab315b` converged measured observability, cold-start browser-session authentication, canonical space CRUD, GUI agent/space creation, and behavior-receipt infrastructure.
- Canonical space creation, update, and soft deletion now enforce user roles and enqueue TapDB semantic records in the source transaction.
- Canonical behavior proof now covers memory commit/recall provenance, user/device LiveKit session creation, event persistence, device heartbeat, verified artifacts, and recognition observation/hypothesis/review/worker heartbeat paths.
- Same-commit route receipt `route-behavior` at `fab315b`: API `53%`, GUI `22%`, Playwright `0%`; reachability remains `100%` for API and GUI but receives no behavioral credit.
- A strict real-service Playwright runner now requires the exact service Git SHA, all 22 workflows, owning-service postconditions, and before/before-submit/after-submit PNG evidence.
- External blockers were rechecked: AWS STS with `AWS_PROFILE=daylily` fails with `InvalidClientTokenId`; `marvain config show` reports no config. No AWS mutation or synthetic deployed evidence was attempted.
- Gate 1 remains `IN_PROGRESS`; Gate 6 remains `IN_PROGRESS`; clean-room Gates 4, 5, and 8 cannot execute until credentials and explicit config are restored.
