# Marvain Operational Gap Analysis Ledger

Date: 2026-05-19

## Control Ledger

Controlling plan: user request, 2026-05-19, "Marvain Operational Gap Analysis Ledger Plan"
Ledger path: `docs/plans/20260519T071331Z_marvain_operational_gap_analysis_ledger.md`
Report paths:
- `docs/reports/MARVAIN_OPERATIONAL_GAP_ANALYSIS.md`
- `docs/reports/marvain_operational_gap_analysis.json`

## Gate 0: Inventory Freeze

- Repo: `/Users/jmajor/projects/marvain`
- Branch: `codex/marvain-tapdb-boundary-closure`
- Baseline HEAD: `fcba7d7`
- Baseline status: clean at start of review, branch tracking `origin/codex/marvain-tapdb-boundary-closure`
- Instruction sources read: `/Users/jmajor/.agents/AGENTS.md`, `/Users/jmajor/.codex/AGENTS.md`, `/Users/jmajor/.codex/docs/plan-ledger-workflow.md`, `AGENTS.md`
- Governing requirement sources reviewed: `docs/design/**`, `docs/plans/**`, `docs/reports/**`, `README.md`, generated status/matrix files, code, SQL, tests, and smoke tooling
- Generated evidence baseline:
  - `docs/DESIGN_OBJECTIVE_STATUS.generated.md`: 100% evidence score, 86/86 checks, PASS
  - `docs/CAPABILITY_MATRIX.generated.md`: no major capability page exposure gaps
  - `scripts/generate_route_coverage.py --min-api 75 --min-gui 75 --min-playwright 75`: API 65/65, GUI 114/114, Playwright workflows 22/22
- Live-system limits: deployed `smoke v1-dev`, hosted UI, LiveKit/OpenAI worker proof, recognition model proof, real two-device proof, CloudWatch evidence, and clean-room deploy were not run in this report pass.

## Scoring Contract

Generated evidence score is separate from operational readiness. Completion estimates use this rubric:

| Percent | Meaning |
|---:|---|
| 0 | Not present |
| 10 | Mentioned only in docs |
| 25 | Anticipated by schema/routes/tests, no usable workflow |
| 40 | Skeleton implementation exists |
| 60 | Local API/backend path works |
| 75 | GUI/API workflow plus focused tests |
| 85 | Local end-to-end or deterministic smoke proof |
| 95 | Deployed live proof across real services |
| 100 | Deployed proof, docs, gates, and regression tests all pass |

## Workstream Ledger

| ID | Area | Requirement | Status | Category | Approval Gate | Owner | Evidence | Root Cause | Terminal Note |
|---|---|---|---|---|---|---|---|---|---|
| GAP-001 | Coordination | Create durable ledger and reports | SUCCESS | plan_amendment | Gate 0 | Coordinator / Ledger Agent | This ledger; operational report; JSON report | - | Ledger and reports created as tracked repo artifacts. |
| GAP-002 | Requirements | Extract desired capabilities from docs and generated artifacts | SUCCESS | contract_test | Gate 0 | Design Requirements Agent | `docs/design/**`; `docs/plans/**`; generated status/matrix | - | Requirements normalized into capability rows. |
| GAP-003 | Backend/API | Inventory Hub API, Lambda handlers, CLI, SQL, and route tests | SUCCESS | contract_test | Gate 0 | Backend/API Agent | Capability matrix, route coverage, API/SQL/test review | - | API exposure is broad, but report separates route coverage from operability. |
| GAP-004 | TapDB | Assess TapDB boundary, graph/query, DAG routes, and static guards | SUCCESS | contract_test | Gate 0 | TapDB Agent | `semantic_tapdb.py`; TapDB writer; `/tapdb/*`; `/api/dag/*`; static tests | - | Direct TapDB package APIs are accepted inside the Marvain TapDB boundary. |
| GAP-005 | Memory | Score taxonomy, classification, lifecycle, recall, ownership, backup | SUCCESS | contract_test | Gate 0 | Memory / Agent Lifecycle Agent | SQL, GUI/API routes, worker paths, tests, smoke fixtures | - | Memory is mostly implemented locally; live provenance/recall proof remains incomplete. |
| GAP-006 | Live Session | Score LiveKit, typed chat, speech, speaker, camera, worker evidence | SUCCESS | contract_test | Gate 0 | Live Session / Worker Agent | Live session routes, worker code, Playwright tests, deployed smoke code | - | Local/faked proof exists; deployed worker/media proof remains unproven. |
| GAP-007 | Recognition | Score people, consent, biometric enrollment, recognition, presence | SUCCESS | contract_test | Gate 0 | Recognition / Presence Agent | Recognition API/GUI, worker, SQL, tests | - | Lifecycle and hard-failure contracts exist; model quality/live proof remains external. |
| GAP-008 | Devices | Score topology, device auth, WS, commands, actions, integrations | SUCCESS | contract_test | Gate 0 | Devices / Actions / Integrations Agent | Device/action SQL, WS handler, remote satellite, tools, tests | - | Local device/action contracts exist; deployed two-device proof is not available. |
| GAP-009 | GUI | Score GUI route/workflow coverage and Playwright depth | SUCCESS | contract_test | Gate 0 | GUI / Playwright Agent | Route coverage script, Playwright files, GUI smoke guide | - | Generated route/workflow coverage is 100%; operational depth is lower than exposure. |
| GAP-010 | Runtime | Score smoke, deployed evidence, observability, external blockers | SUCCESS | contract_test | Gate 0 | Runtime Proof / Observability Agent | `marvain_cli/smoke.py`, E2E tests, SAM template, health endpoints | - | Report marks deployed readiness as unproven rather than completed. |

## Terminal State

All ledger rows are terminal for the reporting objective. The reporting objective is complete. The Marvain product objective is not complete: the report identifies remaining live-runtime, deployed-smoke, recognition, device-topology, observability, and clean-room validation gaps.

## Validation Results

Commands run from `/Users/jmajor/projects/marvain` with `AWS_PROFILE=daylily`, `AWS_REGION=us-east-1`, `AWS_DEFAULT_REGION=us-east-1`, and `source ./activate`:

| Command | Result | Evidence |
|---|---|---|
| `ruff check functions/ layers/ apps/ marvain_cli/ tests/` | PASS | `All checks passed!` |
| `ruff format --check functions/ layers/ apps/ marvain_cli/ tests/` | PASS | `159 files already formatted` |
| `python scripts/verify_docs_contracts.py` | PASS | `OK: validated 5 action examples` |
| `python scripts/generate_capability_matrix.py --check` | PASS | `Capability matrix doc is up to date.` |
| `python scripts/generate_design_objective_status.py --check --min-score 90` | PASS | `Design objective status doc is up to date; score 100% >= 90%.` |
| `python scripts/generate_route_coverage.py --check --min-api 75 --min-gui 75 --min-playwright 75` | PASS | `API 100%, GUI 100%, Playwright 100%` |
| `python -m json.tool docs/reports/marvain_operational_gap_analysis.json` | PASS | JSON parsed successfully. |
| `git diff --check` | PASS | No whitespace errors. |
| `python -m pytest tests/ -q --tb=short` | FAIL | 641 passed, 60 skipped, 2 failed. Failures were local prerequisite blockers: missing Playwright Chromium executable and missing `sam` CLI on PATH for the build dry-run smoke test. |

