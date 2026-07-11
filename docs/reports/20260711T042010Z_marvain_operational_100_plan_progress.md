# Marvain Operational 100% Plan Progress Review

Reviewed: 2026-07-11 05:19 UTC
Branch: `codex/marvain-operational-100-closure`
Committed revision reviewed: `fab315b`
Controlling ledger: `docs/plans/20260711T011234Z_marvain_operational_100_percent_ledger.md`

## Executive Result

- Official generated operational score: **49%**. This remains internally consistent but is stale relative to the latest implementation commits.
- Evidence-adjusted operational estimate: **59%** weighted, approximately **58%** simple average across all 85 capabilities.
- Committed-only estimate: **59%**. Shared observability, cold-start browser auth, canonical space CRUD, and the expanded behavior suites are committed.
- Operating-well target: **85%**. Current gap: approximately **26 weighted points**, plus mandatory clean-room proof.
- 100% target: **0 of 85** capabilities currently qualify. No capability has all deployed, failure-recovery, observability, documentation, and regression evidence.
- Latest full local gate: **1126 passed, 37 skipped, 3 failed**. All three failures are the intentional design-score coverage gate at 89%; no functional test failed.
- Current same-commit behavioral receipt: **API 53%, GUI 22%, Playwright 0%** at `fab315b`; API proof improved from 32% during this closure pass.
- Deployed acceptance remains unproven. `AWS_PROFILE=daylily` currently returns `InvalidClientTokenId`, no Marvain config exists, and smoke Cognito credentials are not configured.

The current code is materially stronger than the original 47% assessment, especially in greenfield schema construction, auth boundaries, artifacts, recognition lifecycle, semantic outbox dispatch, and LiveKit session lifecycle. It is not yet operating well because the product workflows still split between canonical `/v1` services and local `/api` business logic, and no fresh real-runtime receipt exists.

## Scoring Rules

- `0-24`: not at all; documentation, anticipation, or isolated primitives only.
- `25-49`: weakly implemented; partial code or tests without a complete local workflow.
- `50-84`: well implemented locally; meaningful code and focused proof, but incomplete integration or no deployed proof.
- `85-94`: excellent local/integration implementation with fresh deployed proof still incomplete.
- `95-100`: deployed and recovery-proven. No capability currently qualifies.

No score exceeds 84 because no fresh clean-room deployed receipt exists. Ignored local receipts are accepted only when their source commit matches the tested code.

## Category Summary

| Category | Score | Assessment | Primary remaining blocker |
|---|---:|---|---|
| Foundations (`FND`) | 67% | well | remaining API convergence, tenancy, and deployed auth proof |
| Agent identity/lifecycle (`AGT`) | 52% | well | persistence/API wiring, complete export, real restore, upgrade continuity |
| Memory (`MEM`) | 63% | well | one canonical capture path, durable embedding retry, live cross-context proof |
| Identity/recognition (`IDN`) | 54% | well | deployed recognition service, canonical GUI enrollment, quality evaluation |
| Live session (`LIV`) | 60% | well | real ECS worker, speech/audio/camera receipt, media telemetry |
| Topology (`TOP`) | 59% | well | supervised satellites and deployed two-location WebSocket proof |
| Actions (`ACT`) | 60% | well | deployed policy/execution receipts and executor isolation |
| Integrations (`INT`) | 59% | well | four live test tenants, replay proof, cross-channel continuity |
| Data/TapDB (`DAT`) | 62% | well | real TapDB drain/idempotency, projection rebuild, GUI artifact convergence |
| Operations/GUI (`OPS`) | 52% | well | executed real-service Playwright receipt, clean-room smoke, recovery/cost controls |

## Capability Ledger Recalculation

| ID | Capability | % | Class | Current evidence and shortest remaining gate |
|---|---|---:|---|---|
| FND-01 | Product mission and domain model | 72 | well | Strong design corpus and 85-row ledger; remove remaining conflicting local/runtime contracts. |
| FND-02 | No-fallback/no-legacy architecture | 58 | well | Canonical schema and several defaults removed; local duplicate APIs and additional substitutions remain. |
| FND-03 | Python and dependency contract | 68 | well | Python 3.12/SAM/container contracts and builds exist; broad suite is not green. |
| FND-04 | CLI and explicit configuration | 72 | well | Strict config and deploy parameter checks improved; clean-room CLI execution is unproven. |
| FND-05 | Cognito browser and runtime auth | 82 | well | Strict signed-session/bearer mode selection and cold-start session registration pass locally; Hosted UI deployed proof absent. |
| FND-06 | Memberships and human roles | 70 | well | Core role services tested; full object-level authorization matrix remains incomplete. |
| FND-07 | Agent-to-agent authentication | 65 | well | Explicit targets/spaces/scopes and wildcard rejection; presenting agent identity is not cryptographically attested. |
| FND-08 | Multi-tenant isolation | 40 | weak | SQL filters exist; TapDB/admin/worker cross-agent boundaries are incomplete. |
| AGT-01 | Agent creation and durable identity | 72 | well | SQL/API creation and semantic outbox exist; production TapDB-created identity receipt absent. |
| AGT-02 | Persona creation and selection | 55 | well | Create/default works locally; revision, disable, and canonical GUI convergence remain. |
| AGT-03 | Personality and constitution model | 55 | well | Versioned ownership contracts exist; persistence, worker hydration, and GUI proof remain incomplete. |
| AGT-04 | Agent self-update of constitution | 45 | weak | Authenticated pure proposal rules exist; no complete persisted agent-authored workflow. |
| AGT-05 | Maturity rubric | 72 | well | Evidence-based rubric and focused tests exist; production evaluation/observability are absent. |
| AGT-06 | Stasis and soft deletion | 60 | well | Strict transitions exist in pure contracts; direct mutation paths and persistence convergence remain. |
| AGT-07 | Agent-requested deletion review | 58 | well | Second-agent, human review, appeal, and apply contracts exist; canonical APIs/storage are incomplete. |
| AGT-08 | Full agent backup/export | 55 | well | Signed manifest and component validation exist; bundle completeness and real export proof remain. |
| AGT-09 | Restore and disaster recovery | 35 | weak | Restore dry-run validation exists; no writing restore or blank-environment proof. |
| AGT-10 | Agent continuity across upgrades | 15 | not at all | Requirement is identified; no behavioral revision evaluation/rollback workflow. |
| MEM-01 | Eight-kind memory taxonomy | 82 | well | All eight kinds are canonical and tested; natural deployed capture across all kinds is absent. |
| MEM-02 | Provenance classes | 72 | well | Four provenance classes exist; production actor authentication is not complete on every path. |
| MEM-03 | Model-assisted classification | 68 | well | Strict schema-constrained classifier and failure behavior exist; live quality benchmark absent. |
| MEM-04 | Source evidence and candidate lifecycle | 72 | well | Canonical worker commit path is evidence-backed; local/delegated GUI mutation paths remain. |
| MEM-05 | Agent ownership and immutable content | 68 | well | Immutable/tombstone contracts are strong; all direct mutation paths are not yet removed. |
| MEM-06 | User annotation and disagreement | 62 | well | Non-mutating annotations exist; ranking/persistence integration remains incomplete. |
| MEM-07 | Embedding creation and durability | 60 | well | Commit requires embedding success; durable pending/retry/DLQ processing remains incomplete. |
| MEM-08 | Recall ranking and explanation | 68 | well | Missing ranks now fail and explanation fields exist; hybrid ranking benchmark/live proof absent. |
| MEM-09 | Consent/privacy-aware recall | 62 | well | Canonical policy checks and exclusions are tested; all recall paths are not converged. |
| MEM-10 | Cross-space/device/session/person recall | 65 | well | Worker hydration is agent-wide with context fields; real cross-context conversation proof absent. |
| MEM-11 | Cross-agent interaction memory | 40 | weak | Schema/provenance anticipation exists; no bilateral permission-aware workflow. |
| MEM-12 | Self-inspired reflection and learning | 48 | weak | Pure scheduled self-reflection candidate contracts exist; no persistence/scheduler/worker integration. |
| MEM-13 | Consolidation, forgetting, contradiction | 50 | well | Pure contradiction, confidence, consolidation, decay, and restoration contracts exist; not wired. |
| IDN-01 | People and account linkage | 65 | well | Local CRUD/linkage works; cross-agent disclosure and deployed proof remain. |
| IDN-02 | Consent grant/revoke lifecycle | 58 | well | Consent records/checks exist; use-time enforcement is not uniform. |
| IDN-03 | Voice/face enrollment | 52 | well | Browser flows and canonical artifact lifecycle exist separately; the GUI still uses the old upload path. |
| IDN-04 | Production recognition worker | 55 | well | Canonical observation/hypothesis/heartbeat APIs exist; no supervised EC2 runtime receipt. |
| IDN-05 | Unknown/no-match retention | 55 | well | Canonical lifecycle/storage contracts exist; deployed worker production is unproven. |
| IDN-06 | Recognition correction and revocation | 60 | well | Reviewed decision APIs and projections exist; full revocation/retraction proof remains. |
| IDN-07 | Presence assertions | 58 | well | Presence can derive from reviewed hypotheses; consistency and deployed proof remain incomplete. |
| IDN-08 | Recognition quality and bias evaluation | 28 | weak | Threshold/quality primitives exist; no FAR/FRR/calibration/bias benchmark. |
| IDN-09 | Biometric artifact governance | 55 | well | Verified artifact requirement and retention fields exist; GUI/provider lifecycle is not converged. |
| LIV-01 | LiveKit room/token/session join | 72 | well | Token/session contracts and durable states exist; no real ECS worker join receipt. |
| LIV-02 | Typed chat loop | 62 | well | Local typed interaction works; duplication and deployed persistence proof remain. |
| LIV-03 | Speech transcription | 52 | well | Worker handlers/tests exist; prior smoke evidence was synthetic. |
| LIV-04 | Agent speech and speaker playback | 52 | well | Browser attachment/device controls exist; no audible real-runtime proof. |
| LIV-05 | Mic/speaker/camera controls | 70 | well | Device selectors and switching exist; hot-unplug and deployed browser proof remain. |
| LIV-06 | Camera observation and visual truthfulness | 62 | well | Truthfulness guard and artifact checks exist; GUI verified-upload convergence and live vision proof remain. |
| LIV-07 | Session lifecycle and recovery | 72 | well | Six-state durable worker/API projection and 37 focused tests; owning reconciliation job/deployed proof absent. |
| LIV-08 | Worker packaging and supervision | 60 | well | Explicit egress-only Fargate service contract exists; image/service has not been deployed and observed. |
| LIV-09 | Media telemetry | 35 | weak | Some correlated lifecycle evidence exists; stage-level media measurements are incomplete. |
| TOP-01 | Locations, spaces, devices, sessions | 72 | well | Canonical space CRUD now uses role checks, soft deletion, and transactional semantic outbox writes; deployed topology proof remains. |
| TOP-02 | Device token auth and scopes | 76 | well | Explicit route scopes, malformed-state rejection, and wildcard removal are tested; deployed denial proof absent. |
| TOP-03 | Heartbeat and online state | 60 | well | Heartbeat/disconnect receipts exist; liveness reconciliation is not deployed. |
| TOP-04 | Remote satellite/location node | 47 | weak | Daemon and local tests exist; no supervised satellite service proof. |
| TOP-05 | Two-device/two-location routing | 38 | weak | Deterministic routing contracts exist; no real two-client WebSocket receipt. |
| ACT-01 | Action proposal and policy | 70 | well | Planner/policy service is strong locally; real model/policy acceptance absent. |
| ACT-02 | Device command ack/result/timeout | 62 | well | Dispatch/ack/result/timeout contracts exist; no deployed satellite proof. |
| ACT-03 | Local host executors | 48 | weak | Executors exist; isolation, trust receipts, and supervised deployment remain incomplete. |
| INT-01 | Integration account and message model | 70 | well | Canonical models/routes exist; live OAuth/credential UX unproven. |
| INT-02 | Provider ingress | 70 | well | Signature, normalization, deduplication, and receipt contracts exist; no live tenant ingress. |
| INT-03 | Provider outbound actions | 65 | well | Provider action contracts/receipts exist; no live provider reconciliation proof. |
| INT-04 | Cross-channel conversation continuity | 30 | weak | Thread fields exist; no identity-safe multi-channel joining workflow. |
| DAT-01 | TapDB boundary conformance | 82 | well | Central Bloom/TapDB-style adapter and guards exist; real database boundary test remains. |
| DAT-02 | TapDB native query/graph/admin surfaces | 65 | well | Native mounted surfaces are tested with fakes; deployed tenant-scoped graph proof absent. |
| DAT-03 | TapDB canonical production writes | 67 | well | Multiple producers and a deployed dispatcher definition exist; full object coverage/drain proof absent. |
| DAT-04 | TapDB write idempotency and retries | 58 | well | Inbox/outbox/redelivery contracts exist; real SQS/TapDB duplicate-delivery proof absent. |
| DAT-05 | Typed external references and lineage | 50 | well | Typed templates/helpers exist; metadata IDs still act authoritatively in some paths. |
| DAT-06 | SQL projection consistency | 52 | well | One fresh-only canonical schema exists; projection rebuild/drift comparison is absent. |
| DAT-07 | Artifact storage and references | 76 | well | Strict intent/S3 verification/outbox lifecycle has 49 focused tests; GUI still bypasses it. |
| DAT-08 | Audit chain and immutability | 62 | well | Hash/Object Lock contracts exist; complete write coverage and deployed lock proof absent. |
| DAT-09 | Retention and erasure | 45 | weak | Retention states exist; policy is fragmented and rights/lifecycle conflicts remain unresolved. |
| OPS-01 | GUI page inventory | 80 | well | Required pages exist; page presence still exceeds workflow depth. |
| OPS-02 | GUI workflow operability | 50 | well | Many controls work locally; duplicate APIs and old artifact/recognition paths remain. |
| OPS-03 | GUI accessibility/responsiveness | 28 | weak | Partial responsive CSS exists; no accessibility acceptance suite. |
| OPS-04 | Marvain-native discovery and health | 78 | well | Shared measured routes are committed for local and Lambda apps with request, database, and auth evidence. |
| OPS-05 | Operational observability | 50 | well | Request/database/auth measurements now exist in the worktree; worker/media/queue/provider metrics remain. |
| OPS-06 | Queue failure handling | 55 | well | Semantic dispatcher/DLQ/alarms exist; transcript/action/recognition/provider queues remain incomplete. |
| OPS-07 | Static and unit regression suite | 80 | well | More than 1000 tests pass, but seven failures and extensive mocks prevent a green gate. |
| OPS-08 | API/GUI route coverage measurement | 60 | well | Same-commit receipt framework reports 53% API and 22% GUI behavior without reachability credit. |
| OPS-09 | Playwright workflow coverage | 45 | weak | A same-commit real-service receipt runner now exists; execution remains 0% because no configured service can run it. |
| OPS-10 | GUI smoke guide | 60 | well | The guide now has strict screenshot, workflow, owning-service, and commit validation; no complete real-service receipt exists. |
| OPS-11 | Deployed v1-dev smoke | 38 | weak | Validator rejects synthetic evidence; owning-service collectors and real run are absent. |
| OPS-12 | Fresh clean-room deployment | 10 | not at all | Plan only; no accepted clean-room stack receipt. |
| OPS-13 | Worker/service supervision | 45 | weak | ECS/systemd contracts exist; neither service has supervised deployed evidence. |
| OPS-14 | Failure injection and recovery | 45 | weak | Trust/failure contracts and local tests exist; real outage/recovery suite has not run. |
| OPS-15 | Cost, quota, and capacity controls | 24 | not at all | Resource limits are partial; no per-agent budgets, backpressure, or degraded-service policy. |

## Plan Gate Review

| Gate | State | Evidence-based assessment |
|---|---|---|
| Gate 0: baseline/truth | complete | 85-row ledger and evidence caps exist; the row scores now need this recalculation applied. |
| Gate 1: build/config/API convergence | in progress | Python/schema/config/auth improved; local `/api` business logic still diverges from `/v1`. |
| Gate 2: TapDB/durable persistence | in progress | outbox dispatcher and strict artifacts exist; live drain, reconciliation, rebuild, and full producer coverage do not. |
| Gate 3: memory/agent governance | in progress | strong pure contracts; persistence/API/worker integration and restore are incomplete. |
| Gate 4: real conversation/recognition | in progress | infrastructure and lifecycle contracts exist; no ECS/EC2 deployed receipt. |
| Gate 5: devices/actions/providers | open | local contracts only; two satellites and four live provider tenants have not run. |
| Gate 6: observability/GUI quality | in progress | native measured route integration is in the worktree; accessibility and executed GUI proof are absent. |
| Gate 7: all 85 blind spots | open | continuity, quality, security integration, cost, overload, and behavioral restore remain. |
| Gate 8: final acceptance | open | no clean-room, provider, failure-injection, or second-environment restore receipt. |

## Fastest Path To Operating Well

1. Restore valid AWS credentials, explicit Cognito smoke credentials, and one clean-room Marvain config.
2. Continue the started GUI convergence: agent and space creation now use `/v1`; artifact, recognition, memory, and lifecycle workflows still need conversion and duplicate-route removal.
3. Raise same-commit behavior proof from API 53%, GUI 22%, and Playwright 0% to at least 75% on every surface.
4. Run the committed real-service Playwright receipt runner against the configured clean-room GUI.
5. Deploy the clean-room stack, ECS agent worker, and recognition host; run the real vertical slice.
6. Run two-device routing, four provider tenants, failure injection, and TapDB projection-rebuild checks.
7. Implement real agent restore into a second blank environment and compare behavior.

The shortest credible operating-well milestone is not more static feature code. It is canonical workflow convergence followed by a clean-room runtime receipt. Until that receipt exists, the repository should report approximately **59%**, not 85% or 100%.
