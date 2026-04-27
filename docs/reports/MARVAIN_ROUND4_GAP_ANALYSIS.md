# Marvain Round 4 Gap Analysis

This report separates repository evidence from true V1 completion. The prior generated score reached 100%, but the Round 4 codebase review found architecture-purity gaps that could make the score misleading.

## Completion Estimate

| Area | Estimated completion | Review result |
|---|---:|---|
| GUI surface coverage | 95% | Primary V1 pages and navigation are present. Round 4 adds a screenshot-backed GUI smoke guide so route presence is not mistaken for operability. |
| Runtime workflow operability | 86% | Live session, memory, recognition, device, action, and observability workflows have tests, but deployed LiveKit/OpenAI/biometric proof still depends on external credentials and services. |
| TapDB correctness | 90% | TapDB is mounted and used as the semantic boundary. Round 4 removes Marvain's copied TapDB schema and requires package-owned schema initialization. |
| No fallback/shim/legacy compliance | 93% | Round 4 removes the tracked archive, obsolete planning docs, legacy membership rewrite behavior, and production dummy recognition embeddings. |
| Test/proof quality | 91% | Unit, route, local smoke, architecture purity, and Playwright workflow tests are present. The new GUI guide creates before, just-before-submit, and after-submit screenshots for each major page. |

Overall reviewer estimate after Round 4 target work: **91%**. Remaining incompleteness is external-service proof, not intentional fallback or compatibility behavior.

## Remaining Gaps

- Deployed V1 smoke still requires working AWS, Cognito, LiveKit, OpenAI, and TapDB configuration.
- Production biometric model quality is external to this repository; repository tests can prove hard-failure and lifecycle handling, not recognition accuracy.
- TapDB direct SQLAlchemy use remains confined to the Marvain TapDB boundary because `daylily-tapdb==6.0.5` exposes factory/session APIs for instance creation and lineage linking. Raw TapDB table access outside that boundary is blocked by static tests.
- Typed PostgreSQL tables remain for operational projections, transport state, vectors, WebSocket state, and user-facing query latency. They are acceptable only where the design docs identify specialized stores or rebuildable projections.

## Architecture Purity Score

Status: **PASS** when `scripts/generate_design_objective_status.py --check --min-score 90` reports no architecture-purity issues.

The purity gate fails if tracked active code or current design docs reintroduce:

- copied TapDB schema under Marvain-owned paths;
- production dummy recognition embeddings or environment switches;
- obsolete membership rewrite behavior;
- stale TapDB pilot, dual-write, or backfill planning language;
- tracked archive implementation code.

## GUI Smoke Guide Artifact

Round 4 adds `marvain smoke gui-guide`. It writes `GUI_SMOKE_REPORT.md` plus screenshots under `output/playwright/round4-gui-smoke/<run-id>/`.

Each page section includes:

- the page path visited;
- steps performed;
- a before screenshot;
- a just-before-submit screenshot;
- an after-submit screenshot;
- failures from JavaScript console errors or HTTP 500 responses.
