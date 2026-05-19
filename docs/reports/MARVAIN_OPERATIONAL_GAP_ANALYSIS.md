# Marvain Operational Gap Analysis

Date: 2026-05-19  
Reviewed branch: `codex/marvain-tapdb-boundary-closure`  
Reviewed commit: `fcba7d7`

## Executive Estimate

Marvain is broad and well-represented in code, schema, GUI, and tests, but the generated `100%` design-objective score is an evidence-presence score, not a deployed-operability score.

| Dimension | Estimate | Assessment |
|---|---:|---|
| Static implementation coverage | 90% | The major domain objects, routes, SQL projections, TapDB boundary, workers, and GUI pages exist. |
| Local API/backend workflow proof | 82% | Focused tests and local deterministic smoke cover many workflows, but several queues/workers/external services are represented by fixtures. |
| GUI route/workflow coverage | 84% | Route coverage reports 100%, and Playwright workflows exist, but many tests use fakes for LiveKit, TapDB, S3, media, and recognition. |
| Deployed runtime proof | 45% | Deployed smoke is implemented but not run here; real worker join, speech transcript, recognition, two-device routing, TapDB graph, and CloudWatch evidence remain unproven. |
| Core V1 operational readiness | 78% | The system is close to operable for a constrained clean-room workflow, but not yet proven as a live, durable V1 stack. |
| All desired/post-V1 capability average | 71% | Broader integration and clean-room validation items pull the total down because they are anticipated but not proven. |

Coverage gates currently report above threshold:

- API route coverage: `65/65` (`100%`)
- GUI route coverage: `114/114` (`100%`)
- Playwright workflow coverage: `22/22` (`100%`)
- Design objective evidence score: `86/86` (`100%`)

Those numbers should remain useful gates, but they should not be used as the final readiness claim until live deployed proof exists.

## Capability Ledger

| ID | Capability | Desired behavior | Existing evidence | Completion | Status | Work shape | Fastest path to operational | Acceptance proof needed |
|---|---|---|---|---:|---|---|---|---|
| CAP-001 | Requirements, architecture purity, no fallback | Greenfield TapDB-first architecture, no shims, no legacy paths, hard failure for missing config. | AGENTS guidance, architecture-purity tests, generated objective gate, Round 4/TapDB reports. | 88% | mostly-complete | Refactor guard maintenance | Keep static guards current and remove stale cleanup wording as encountered. | `generate_design_objective_status --check` plus static scans for fallback/legacy/copy-schema terms. |
| CAP-002 | Activation, CLI, config, auth foundation | `source ./activate`, `marvain` CLI, explicit config, Cognito/browser/admin boundaries. | CLI command tree, config-path tests, Hosted UI e2e scaffold, `daylily-auth-cognito` dependency contract. | 82% | mostly-complete | Anticipated by current code | Run hosted UI proof against a clean-room stack and keep root-owned JSON mode tests. | Live Hosted UI login plus CLI conformance tests. |
| CAP-003 | Deploy/bootstrap clean-room readiness | A new dev stack can deploy, initialize DB/TapDB, bootstrap an agent/space/device/user, and run without manual DB/AWS patches. | SAM template, deploy/config/init commands, clean-room plan, init SQL and TapDB templates. | 65% | partial | Anticipated by current code | Execute a fresh clean-room stack validation using explicit `--config`. | Fresh deploy, `init db`, `init tapdb`, bootstrap, health endpoints, GUI smoke guide. |
| CAP-004 | Agents, personas, constitution, lifecycle | Agents have personas, memberships, constitutions, maturity, stasis, soft deletion, backup/export. | Agent routes, persona routes, Round 7 SQL, backup endpoints, GUI controls, lifecycle tests. | 78% | mostly-complete | Anticipated by current code | Exercise one agent through create, constitution revision, memory growth, maturity, stasis, and backup. | API+GUI workflow with retained backup manifest and no hard-delete proof. |
| CAP-005 | Agent-owned memory and annotations | Agent memories are immutable once committed; users annotate, dispute, downweight, supersede, tombstone, but do not overwrite. | Memory tables, annotations, candidate review, supersede/tombstone routes, GUI page, tests. | 76% | mostly-complete | Anticipated by current code | Add a live conversation proof that creates memory, user annotation, dispute, and recall. | End-to-end memory ownership workflow plus TapDB lineage. |
| CAP-006 | People, consent, account links | People are first-class, consent gates recognition/memory use, accounts link to people, revocations are visible. | People/consent routes, GUI, consent SQL, biometric projection routes/tests. | 78% | mostly-complete | Anticipated by current code | Run consent grant/revoke through GUI and recognition/memory use-time checks. | Consent denied/allowed tests tied to memory/recognition outcomes. |
| CAP-007 | Locations, spaces, sessions, topology | Physical locations contain spaces/devices; sessions/events are linked to space/device/person/agent context. | Locations/spaces/sessions routes, SQL projections, templates, tests. | 76% | mostly-complete | Anticipated by current code | Prove two spaces in two locations with separate device/session/event histories. | GUI/API route plus deployed device/session provenance proof. |
| CAP-008 | Devices and remote satellites | Devices authenticate as devices, heartbeat, receive targeted commands, and record ack/result/timeout lineage. | Device routes, WS handler, remote satellite client, action lifecycle SQL/tests. | 72% | partial | Anticipated by current code | Run real two-device proof through deployed REST/WS/device-token paths. | Two connected devices, targeted command isolation, ack/result/timeout evidence. |
| CAP-009 | Live session, media, worker | Space agent joins LiveKit, typed chat and speech create transcripts, speaker playback works, camera creates current visual observations or fails hard. | Live Session GUI, media selectors, worker code, token routes, local Playwright/media stubs. | 68% | partial | Refactor and external proof | Run live worker with valid LiveKit/OpenAI config and capture real typed, speech, audio, camera evidence. | Worker join, transcript IDs, spoken response, speaker playback, visual observation ack/hard-fail evidence. |
| CAP-010 | Memory taxonomy and classification | Eight memory kinds and provenance classes are classified, stored as evidence-backed candidates, committed, recalled, and graph-linked. | `memory_taxonomy.py`, GUI memory controls, classifier tests, live-session candidate creation paths. | 80% | mostly-complete | Anticipated by current code | Replace fixture-only confidence with model-backed classifier proof in a live session. | Candidate metadata for all kinds, source evidence, commit, recall explanation, TapDB EUIDs. |
| CAP-011 | Recall ranking and cross-context memory | Same agent recalls across spaces/devices/sessions/people, with ranking, embedding distance, keyword match, excerpt, filters, and source context. | Recall API, worker hydration, recall explanation projections, tests. | 72% | partial | Refactor-required | Strengthen recall acceptance tests around cross-space/cross-agent memory and embedding quality. | One assertion covering ranking, distance, keyword, excerpt, device, space, session, person, consent filters. |
| CAP-012 | Recognition, biometrics, presence | Voice/face enrollment, unknown/no-match retention, hypotheses, correction, revocation, and presence assertions work with real recognizers. | Recognition GUI/API, worker hard-failure behavior, SQL lifecycle, mock Playwright tests. | 70% | partial | External-proof-needed | Run real or explicitly configured dev recognition worker and record observation/hypothesis outcomes. | Voice/video proof for distinct users plus no-match and revocation scenarios. |
| CAP-013 | Actions, policies, tools | Tool/action proposals preserve policy, approval, idempotency, dispatch, execution, result, timeout, and audit. | Action service, policies, tool runner, timeout sweeper, GUI actions page, tests. | 78% | mostly-complete | Anticipated by current code | Prove a real device command and one hosted/local executor action through full lifecycle. | Action proposal, approval/policy decision, dispatch, ack, result/timeout, TapDB/audit linkage. |
| CAP-014 | Integrations and messaging | Gmail/Slack/Twilio/GitHub integrations ingest/send messages with account ownership and audit. | Integration routes, SQL tables, Gmail poll function, outbound tools. | 60% | partial | Anticipated and external config | Configure one provider in dev and prove an inbound and outbound message loop. | Provider account setup, message ingest, tool send, audit, retention/redaction. |
| CAP-015 | TapDB semantic graph/query boundary | TapDB owns semantic objects, provenance, lifecycle, graph/DAG; Marvain keeps a central boundary and no copied schema/custom graph. | `semantic_tapdb.py`, TapDB writer, mounted `/tapdb/*`, `/api/dag/*`, template pack, static tests. | 84% | mostly-complete | Anticipated by current code | Run live TapDB create/link/query/graph on a generated EUID in a clean-room stack. | `/tapdb/graph`, `/tapdb/query`, `/api/dag/*`, write/query evidence with TapDB config. |
| CAP-016 | Audit, privacy, retention, artifacts | Audit and artifact state is visible, tamper checks exist, privacy mode gates use, retention/redaction works. | Audit helpers, artifact routes, S3 presign/upload paths, retention sweeper, observability page. | 78% | mostly-complete | Anticipated by current code | Prove S3 artifact upload, audit verification, privacy denial, and retention redaction against dev stack. | Artifact manifest, audit verify, privacy-mode denial, retention sweep evidence. |
| CAP-017 | Observability and Kahlo discovery | Health endpoints, failure scenarios, worker/media/memory/device/TapDB state, CloudWatch alarms, Kahlo discovery. | `/obs_services`, `/api_health`, `/db_health`, `/auth_health`, `/endpoint_health`, `/my_health`, metrics helper, dashboard resources. | 70% | partial | External-proof-needed | Wire smoke run evidence into observability and verify Kahlo discovers graph endpoints. | Health payloads, CloudWatch metric/alarm samples, Kahlo graph stitching proof. |
| CAP-018 | GUI operability and smoke guide | Every primary page renders and core workflows have browser tests and screenshot-backed guide. | Route coverage 100%, Playwright workflow coverage 100%, GUI smoke guide report generation. | 84% | mostly-complete | Anticipated by current code | Convert more GUI smoke steps from first-form checks to durable state assertions. | Screenshots plus created IDs and verified persisted state for each workflow. |
| CAP-019 | Test gates and generated evidence | Docs/status/capability/route gates are reproducible and fail on stale evidence. | Scripts and tests for design status, capability matrix, route coverage, TapDB boundary, architecture purity. | 86% | mostly-complete | Refactor guard maintenance | Add deployed-proof fields to generated status so evidence score cannot mask runtime blockers. | Generated status includes distinct static/local/deployed readiness sections. |
| CAP-020 | Deployed smoke and acceptance | `smoke v1-dev` proves Cognito, LiveKit worker, chat/speech, memory commit/recall, recognition, devices, TapDB graph, observability. | `marvain_cli/smoke.py` real endpoint path, blocker detection, two-device option, e2e scaffolds. | 55% | external-proof-needed | External-proof and implementation hardening | Run with real smoke credentials and replace fixture speech/recognition evidence where required. | Structured smoke report with no placeholder blockers and live IDs/EUIDs. |
| CAP-021 | Fresh clean-room validation | Current code can create a new Marvain stack from scratch without old DB/config/resource state. | Clean-room plan, deploy/init/bootstrap CLI surfaces, SAM template. | 25% | anticipated | Anticipated by current code | Execute the clean-room stack plan with explicit isolated config. | Fresh deploy and acceptance report, or exact code/credential/AWS blocker classification. |
| CAP-022 | Broader post-V1 integrations | Deferred provider breadth, generic outbound providers, richer automation, external messaging expansion. | Post-V1 plan and partial integration tables/tools. | 35% | anticipated | Partly novel | Keep out of V1 critical path until deployed V1 proof is green. | Separate post-V1 milestone with provider-specific acceptance tests. |

## High-Risk Gaps

1. **Deployed proof is the main gap.** Static code, GUI, and local smoke are strong, but they do not prove a live Cognito/LiveKit/OpenAI/TapDB/worker/device runtime.
2. **`smoke v1-dev` still needs live-evidence hardening.** It requires real credentials and currently includes deterministic fixture evidence for speech and recognition paths.
3. **Live media and worker behavior remain under-proven.** The code supports typed chat, media controls, and worker behavior, but a real worker join plus speech transcript, audio playback, and camera observation needs a deployed run.
4. **Recognition lifecycle is implemented; recognition quality is not proven.** The repo correctly hard-fails without recognizer dependencies, but live biometric model behavior remains external.
5. **Device/action topology needs a deployed two-device proof.** Local tests cover protocol and lifecycle contracts; they do not prove two real connected devices route independently.
6. **Memory/recall needs stronger live semantic quality proof.** Taxonomy and lifecycle are present, but embedding quality, source excerpts, cross-space/cross-agent recall, and consent filters need one consolidated acceptance test.
7. **GUI coverage can over-credit route rendering.** Generated route/workflow coverage is 100%, but some Playwright paths use fakes and first-visible-form smoke behavior.
8. **Observability needs real runtime samples.** Health endpoints and CloudWatch resources exist; real smoke-run evidence, queue health, worker logs, and Kahlo graph discovery are not proven here.
9. **TapDB boundary is mostly correct, but live graph/query proof is still needed.** Direct TapDB package API use inside `agent_hub.semantic_tapdb` is intentional; the remaining risk is runtime config and live EUID graph proof.

## Operational Soon Plan

Fastest path to a usable Marvain is not more page inventory. It is one clean-room, end-to-end proof.

1. Run the local gate and fix any drift in docs/status/route tests.
2. Create a clean-room config and deploy a new dev stack without touching existing resources.
3. Initialize DB and TapDB from repo code only.
4. Bootstrap one agent, one person, one space, one location, and two devices.
5. Start the GUI and the real agent worker against the clean-room config.
6. Run hosted UI login and verify `/api_health`, `/db_health`, `/auth_health`, `/endpoint_health`, `/my_health`, and `/obs_services`.
7. Run a live session:
   - typed chat persists transcript;
   - speech creates transcript or fails with exact capability blocker;
   - speaker playback is verified;
   - camera creates a visual observation or hard-fails before visual claims.
8. Commit one memory candidate, annotate it, recall it with ranking/source/device/space/session/person/consent evidence, and open its TapDB graph.
9. Run recognition readiness or an explicit dev recognition observation/hypothesis path.
10. Connect two dev devices in two locations/spaces and prove targeted routing plus ack/result/timeout lineage.
11. Capture observability evidence for the smoke run, worker state, media state, memory writes, recognition, device routing, TapDB graph/query, and failures.
12. Generate the screenshot-backed GUI guide and verify that screenshots include created IDs and persisted state.

If this succeeds, Marvain can reasonably be called operational for V1 clean-room use. If it fails, classify each failure as code defect, missing credential/secret/quota, missing external service, or AWS service issue.

## Residual Design Blindspots

- **Agent memory quality policy.** The repo has taxonomy and lifecycle, but needs a clearer product rule for when model-assisted classification is required versus deterministic/test-only classification.
- **Agent self-evolution governance.** Constitution/personality revisions exist, but the balance between founder-owned, user-owned, and agent-owned sections needs live workflow proof and review policy.
- **Deployed worker fleet operations.** The system has worker code and launch controls, but production supervision, restart policy, logs, and worker health should be made part of acceptance.
- **Recognition deployment shape.** Recognition worker is a home-server/app process rather than a SAM function; operational deployment, model dependencies, and artifact retention need a runbook-level proof.
- **Live media observability.** The GUI can show media state, but acceptance should include worker-side media telemetry and explicit user-facing failure state.
- **TapDB drift and projection rebuild.** TapDB is treated as canonical, but projection rebuild/drift repair should be exercised in a clean-room or fixture-backed operational test.
- **External integration blast radius.** Slack/Twilio/Gmail/GitHub surfaces exist, but provider-specific consent, rate limits, retries, and redaction need one provider at a time before broad enablement.
- **Long-running cost and cleanup.** Clean-room validation should report cost-bearing resources and retention settings, with cleanup performed only after separate destructive approval.

## Bottom Line

Marvain looks like a substantial V1 implementation that is roughly **78% operationally ready** for the core objective and **90% statically implemented**. The gap is not another broad refactor. The next useful work is a clean-room deployed validation that proves the actual runtime loop: login, worker, chat/speech, memory, recognition, devices, TapDB, and observability.

## Validation Results

The report artifacts were validated locally with the activated Marvain environment.

| Command | Result |
|---|---|
| `ruff check functions/ layers/ apps/ marvain_cli/ tests/` | PASS |
| `ruff format --check functions/ layers/ apps/ marvain_cli/ tests/` | PASS |
| `python scripts/verify_docs_contracts.py` | PASS |
| `python scripts/generate_capability_matrix.py --check` | PASS |
| `python scripts/generate_design_objective_status.py --check --min-score 90` | PASS |
| `python scripts/generate_route_coverage.py --check --min-api 75 --min-gui 75 --min-playwright 75` | PASS |
| `python -m json.tool docs/reports/marvain_operational_gap_analysis.json` | PASS |
| `git diff --check` | PASS |
| `python -m pytest tests/ -q --tb=short` | FAIL: 641 passed, 60 skipped, 2 failed due to missing local prerequisites, not report content. |

Full-suite blockers:

- Playwright Chromium executable is missing from `/Users/jmajor/Library/Caches/ms-playwright/...`; Playwright suggests `playwright install`.
- `sam` is not on PATH, so `tests/test_typer_smoke.py` fails the `marvain --dry-run build` runtime validation.
