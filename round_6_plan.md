# Marvain Round 6 Review And Closure Plan

## Current Assessment

I inspected the current worktree, design docs/status generators, route surface, tests, Atlas patterns, and Kahlo discovery contract. No files were changed.

Generated status is currently optimistic: `scripts/generate_design_objective_status.py --check --min-score 90` reports `100%`, but `scripts/generate_capability_matrix.py --check` fails because the matrix is out of date. My code-grounded true-completion estimate is **~84% overall**.

| Area | Est. Complete | Notes |
|---|---:|---|
| Memory taxonomy/lifecycle | 86% | All 8 kinds now exist and GUI loops over shared taxonomy; production policy/capture proof still too shallow. |
| Live session mic/camera/agent loop | 78% | Media controls and camera hard-fail exist; worker visual proof and real speech evidence remain incomplete. |
| Deployed V1 smoke | 70% | Now mutates real REST dev endpoints, but worker join, speech, recognition, and observability are still reported as external prerequisites. |
| TapDB correctness | 78% | Mounted `/tapdb`/`/api/dag` exist; boundary still uses TapDB connection/session/factory APIs directly. |
| daylily-auth-cognito | 88% | Runtime/browser/admin boundaries mostly used; shared auth module still mixes runtime and admin imports. |
| cli-core-yo | 90% | Dependency and root `CliSpec` pattern are present; keep guarding against argparse/raw output drift. |
| Device/location/topology | 84% | Local and REST proof exists; deployed WS two-device/two-location proof still needs hard evidence. |
| Observability/Kahlo | 62% | Marvain lacks Kahlo `/obs_services` discovery contract; Kahlo has localhost polling already but not federated service graph stitching. |
| GUI operability | 74% | Pages exist, but Playwright workflow coverage is below the requested 75% threshold. |

## Coverage Findings

Static route-to-test coverage from current routes:

| Surface | Routes | Any Test Coverage | Playwright Coverage |
|---|---:|---:|---:|
| GUI pages | 30 | 26 / 30 = **86.7%** | 20 / 30 = **66.7%** |
| GUI/API routes | 68 | 62 / 68 = **91.2%** | 26 / 68 = **38.2%** |
| `/v1` API routes | 65 | 53 / 65 = **81.5%** | 35 / 65 = **53.8%** |

The API and GUI route unit coverage clears 75%. Playwright does not. Missing or weak Playwright coverage includes auth callback/logout, dashboard partials, tools, personas, action guide, and diagnostic LiveKit behavior.

Prior review finding status:
- Memory taxonomy GUI finding: **mostly stale** in current worktree.
- Live-session episodic-only finding: **mostly stale** in current worktree.
- Dev smoke placeholder finding: **partially fixed**, but not yet true full deployed proof.
- Custom `/lineage` route finding: **stale**, route was not found.
- TapDB low-level boundary finding: **still valid in part**.

## Critical Gaps

- Objective scoring is too easy to satisfy. It accepts evidence presence even when deployed proof is only a string or gated skip.
- Marvain is not Kahlo-discoverable because it does not expose `/obs_services`, `/api_health`, `/endpoint_health`, `/db_health`, and `/auth_health`.
- TapDB usage is better than before, but Marvain still owns a semantic wrapper over TapDB internals instead of relying only on clearly approved public package APIs.
- Deployed smoke must prove Hosted UI login, LiveKit worker join, speech/chat transcript, recognition, device routing, TapDB graph, and observability. It does not yet prove all of these.
- GUI workflow tests still lean on mocks for the hardest parts: all-memory capture, visual observation, biometric recognition, and two-device deployment.
- Residual planning/docs language still mentions migrations, fallback, compatibility, dummy, and pilot concepts in non-current docs. That conflicts with the greenfield objective unless explicitly archived or removed from active checks.

## Implementation Plan

1. Add a strict objective/coverage gate.
   - Extend the generated status script so true completion cannot exceed 90% unless deployed smoke, Playwright route/function coverage, capability matrix freshness, TapDB boundary, and Kahlo-discovery checks pass.
   - Add a route coverage report with thresholds: API routes >=75%, GUI routes >=75%, Playwright GUI workflow coverage >=75%.

2. Finish deployed proof.
   - Upgrade `marvain smoke v1-dev` from REST-only proof to full deployed proof: Hosted UI browser login, worker LiveKit join, chat and speech transcript, memory candidate/commit/recall, recognition readiness/path, two deployed devices, TapDB graph, and observability rollups.
   - Replace current string placeholders with pass/fail evidence fields and exact blocker reporting.

3. Make Marvain Kahlo-discoverable.
   - Add `/obs_services`, `/api_health`, `/endpoint_health`, `/db_health`, `/auth_health`, and `/my_health` using Kahlo’s documented shapes.
   - Advertise Marvain graph endpoints through `/obs_services`, including `/api/dag/data`, `/api/dag/object/{euid}`, and `/tapdb/graph`.

4. Add Kahlo federated graph stitching.
   - Do not add basic localhost discovery; Kahlo already has it.
   - Add a graph viewer/federator that polls discoverable services, reads advertised graph endpoints, expands to a user-specified neighbor depth, and stitches cross-service EUIDs through external-ID objects.
   - Add tests in Kahlo for Marvain-style graph endpoint discovery and merged graph output.

5. Tighten TapDB boundaries.
   - Compare Marvain’s `semantic_tapdb.py` against the current TapDB public API and Atlas patterns.
   - Move canonical create/link/query work to approved public TapDB APIs or upstream missing APIs to `daylily-tapdb`.
   - Keep raw SQL limited to Marvain operational projections and add static guards for TapDB-owned state.

6. Raise Playwright coverage above 75%.
   - Add real workflow tests for personas, dashboard partials, auth callback/logout, action guide, tools, Live Session speech/camera, memory taxonomy capture, recognition, topology, TapDB graph/query, and observability.
   - Update the GUI smoke guide to include before, just-before-submit, and after-submit screenshots for each primary workflow.

## Test Plan

Required checks after implementation:

```bash
export AWS_PROFILE=daylily
export AWS_REGION=us-east-1
export AWS_DEFAULT_REGION=us-east-1
source ./activate
ruff check functions/ layers/ apps/ marvain_cli/ tests/
ruff format --check functions/ layers/ apps/ marvain_cli/ tests/
python scripts/verify_docs_contracts.py
python scripts/generate_capability_matrix.py --check
python scripts/generate_design_objective_status.py --check --min-score 90
python scripts/generate_route_coverage.py --check --min-api 75 --min-gui 75 --min-playwright 75
python -m pytest tests/ -q --tb=short
```

Credential-gated:

```bash
set -a
source .livekit
set +a
marvain smoke v1-dev --stack marvain-greenfield-tapdb-dev --include-two-device-proof
```

Kahlo checks should include its normal test suite plus new federated graph viewer tests.

## Assumptions

- “Coverage >75%” means endpoint/route/workflow coverage, not Python line coverage. If line coverage is required, add `pytest-cov` thresholds separately.
- No fallback, shim, dummy production path, or compatibility layer is allowed.
- Kahlo localhost discovery already exists; the missing Kahlo work is graph endpoint federation and stitched cross-service EUID visualization.
