# Marvain Clean-Room Vertical-Slice Continuation Ledger

Timestamp: `2026-07-26T09:53:40Z`

## Control And Safety Boundary

- Repository: `/Users/jmajor/projects/marvain`
- Branch: `codex/marvain-operational-100-closure`
- Gate 0 ref: `92889df8df86acfc454473431d21aec24994f2a9`
- Upstream at Gate 0: `HEAD` is 70 commits ahead of freshly fetched `origin/main`, 0 behind.
- Controlling prior records:
  - `docs/plans/20260713T080928Z_marvain_cleanroom_pause_point_ledger.md`
  - `Marvain_Restart_Thread.md` (local handoff note; do not stage or alter)
  - `docs/plans/20260711T011234Z_marvain_operational_100_percent_ledger.md`
- Active target: `marvain-cleanroom-20260712T111914Z` in explicit config profile `lsmc`, region `us-west-1`.
- Active worker baseline: ECS desired/running `1/1`; stack is `UPDATE_COMPLETE`; deployed worker identity is `92889df8df86acfc454473431d21aec24994f2a9`.
- Failed predecessor `marvain-cleanroom-20260712T103857Z` is out of scope and must not be changed.
- Do not run `marvain agent rebuild`, stop/clear LiveKit rooms, publish an image, update CloudFormation, rotate a worker token, or make any AWS mutation until the applicable approval gate is satisfied.

## Gate 0 Inventory

`git fetch origin --prune` completed before recording branch state.

| Ownership | Paths | Handling |
|---|---|---|
| User-owned | `AGENTS.md` | Preserve and exclude from staging. |
| Local/browser state | `.playwright-cli/` | Preserve and exclude from staging. |
| Local handoff note | `Marvain_Restart_Thread.md` | Preserve and exclude from staging. |
| Prior durable record | `docs/plans/20260713T080928Z_marvain_cleanroom_pause_point_ledger.md` | Check in unchanged. |
| In-scope runtime, CLI, template, tests, generated docs | Eleven tracked files excluding `AGENTS.md` | Complete, validate, and commit only after all local rows are terminal. |

Baseline evidence:

- `git diff --check` passed.
- Focused touched-suite baseline: `195 passed`.
- Full baseline: `8 failed, 1129 passed, 37 skipped`; failures are explicit test fixture configuration, stale generated documents, and obsolete design-gate expectations.
- Current design status is truthfully `89%` with a canonical `90%` threshold; operational completion remains `49%` and is not claimed as complete.
- `sam validate --lint` has pre-existing `W1001` for the conditional API deployment; do not hide it in this slice.

## Execution Rows

| ID | Area | Requirement | Status | Category | Approval Gate | Owner | Evidence | Root Cause / Unblock | Terminal Note |
|---|---|---|---|---|---|---|---|---|---|
| CV-01 | Ledger | Record Gate 0 and preserve prior pause evidence. | SUCCESS | plan_amendment | Gate 0 | Codex | This ledger; fresh fetch and inventory above. | - | Gate 0 baseline is durable. |
| CV-02 | Session API | Add a device-only worker lifecycle read endpoint with strict scope and identity rules. | SUCCESS | feature_implementation | Gate 3 | Codex | `GET /v1/sessions/{session_id}/worker-lifecycle`; `tests/test_session_api.py`. | - | Requires `events:read`, validates device/agent access, and returns only the required identity/state fields. |
| CV-03 | Worker | Rehydrate durable session state before LiveKit start without duplicate transitions or greetings. | SUCCESS | feature_implementation | Gate 3 | Codex | `apps/agent_worker/worker.py`; `tests/test_agent_worker_reliability.py`; `tests/test_agent_rejoin.py`. | - | `opening`, `active`, and `reconnecting` are handled explicitly; terminal, missing-event, and identity mismatch paths fail before `ctx.connect()`. |
| CV-04 | Deployment CLI | Publish an immutable existing-stack worker image from an exact detached commit without deploying. | SUCCESS | feature_implementation | Gate 2 | Codex | `marvain agent publish-image`; `tests/test_ops.py`; clean-room dry-run receipt. | Live image push remains approval-gated. | Requires explicit 40-character commit, existing tagged immutable ECR repository, unused tag, detached worktree build, digest pinning, and selected-config update only. |
| CV-05 | Runtime config | Keep realtime model and voice explicit; retain audited finalization behavior. | SUCCESS | config_or_startup_contract | Gate 2 | Codex | Worker/template/env tests; `tests/test_environment_contract.py`; `tests/test_ops.py`. | - | Runtime model/voice are required; finalization retains audited token rotation, tag checks, stable-service wait, persona verification, and plaintext-token removal. |
| CV-06 | Generated status | Regenerate capability matrix and separate canonical 90% document from explicit score enforcement. | SUCCESS | contract_test | Gate 4 | Codex | Generated capability and design-status docs; `tests/test_design_objective_status.py`. | - | Canonical document records 90% threshold and truthful 89% failure; optional enforcement flags no longer rewrite it. |
| CV-07 | Local validation | Run focused and full tests, static checks, generated-doc checks, and record expected gates. | SUCCESS | contract_test | Gate 5 | Codex | `1160 passed, 37 skipped, 52 warnings, 4 subtests`; static checks below. | - | All local acceptance checks passed; explicit release gates and pre-existing lint warning are recorded rather than hidden. |
| CV-08 | Source provenance | Commit only validated in-scope source and durable ledgers. | SUCCESS | feature_implementation | Gate 5 | Codex | This commit contains all in-scope runtime, CLI, tests, generated docs, and both ledger files. | User-owned paths remain intentionally dirty. | A single clean source commit is created after staging only the listed in-scope paths. |
| CV-09 | Clean-room deployment | Publish exact image, review receipt/dry run, deploy, and finalize worker token. | BLOCKED | active_product_contract | Fresh explicit deployment approval | User + Codex | Requires post-commit digest and explicit follow-up authorization naming stack, digest, SAM update, token rotation, and ECS restart. | Not authorized in the current turn. | - |
| CV-10 | Live acceptance | Fresh owner-session vertical slice with AV, memory, TapDB, and observability evidence. | BLOCKED | active_product_contract | Fresh explicit deployment and live-test approval | User + Codex | Requires CV-09 plus real owner/device interaction. | No synthetic or stale-room proof is permitted. | - |

## Acceptance Evidence To Capture After Deployment

For a new, never-reused room, capture the session/room/event IDs, deployed image digest, worker version, typed and spoken transcript evidence, text/audio response evidence, actual camera state, candidate-to-reviewed-memory-to-embedding-to-explained-recall lineage, persisted TapDB graph evidence, and correlated worker/observability receipt. TapDB EUIDs may be recorded only when returned by the owning persisted service.

## Local Completion Evidence

- Focused recovery, session API, CLI, and design-status validation: `102 passed`.
- Full local suite: `python -m pytest tests/ -q --tb=short` -> `1160 passed, 37 skipped, 52 warnings, 4 subtests passed`.
- `ruff check functions/ layers/ apps/ marvain_cli/ tests/` and `ruff format --check functions/ layers/ apps/ marvain_cli/ tests/` passed.
- `python scripts/verify_docs_contracts.py`, implementation-status check, capability-matrix check, and canonical design-status check passed.
- `python scripts/generate_design_objective_status.py --check --min-score 90` correctly returned nonzero because score is `89%`; the independent `--min-operational-score 85` gate correctly returned nonzero because operational completion is `49%`.
- `sam validate` passed. `sam validate --lint` still reports pre-existing `W1001` at `HubApiStage` conditional deployment reference; this slice does not suppress or misclassify it.
- `marvain agent publish-image --help` and a dry-run against the selected clean-room config passed without publishing an image or updating config/AWS state.
- CV-09 and CV-10 remain terminal `BLOCKED` pending the fresh live deployment approval named in their rows.
