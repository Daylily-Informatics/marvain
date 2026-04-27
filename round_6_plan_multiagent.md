# Marvain Round 6 Multi-Agent Closure Plan

## Summary

Replace `/Users/jmajor/projects/marvain/round_6_plan.md` with a 10-agent implementation plan. Round 6 closes the remaining design gaps, raises real endpoint/GUI workflow coverage above 75%, makes Marvain Kahlo-discoverable, and updates the dependency contract to:

- `cli-core-yo==2.1.1`
- `daylily-auth-cognito==2.1.4`
- `daylily-tapdb[admin]==6.0.7`

No fallback behavior, compatibility shims, dummy production paths, legacy graph routes, or local-only deployed-smoke substitutes are allowed.

## 10-Agent Split

1. **Coordinator / Gates Agent**
   - Owns branch hygiene, `round_6_plan.md`, status scoring, final verification, and blocker reporting.
   - Gate: generated objective status, capability matrix, and route coverage checks agree with true implementation state.

2. **Dependency / Environment Agent**
   - Updates `pyproject.toml`, Lambda requirements, tests, and docs references to the new pinned versions.
   - Keeps Python deps out of `environment.yaml`.
   - Gate: environment contract tests pass for `cli-core-yo==2.1.1`, `daylily-auth-cognito==2.1.4`, and `daylily-tapdb[admin]==6.0.7`.

3. **CLI Agent**
   - Verifies Marvain still follows the current `cli-core-yo` pattern: one root `CliSpec`, root-owned JSON mode, registry policy, `cli_core_yo.output`, and no argparse fallback.
   - Gate: CLI conformance tests and smoke commands pass under `cli-core-yo==2.1.1`.

4. **Auth Agent**
   - Updates and verifies Cognito flows against `daylily-auth-cognito==2.1.4`.
   - Enforces runtime/browser/admin boundaries, no raw OAuth-token browser sessions, and no service imports from `daylily_auth_cognito.cli`.
   - Gate: Hosted UI, browser session, WS user auth, device auth, and admin user tests pass.

5. **TapDB Agent**
   - Updates to `daylily-tapdb[admin]==6.0.7`.
   - Refactors Marvain TapDB code to approved public APIs for semantic instance/link/query/graph work, or stops with the exact missing TapDB API.
   - Gate: `/tapdb`, `/tapdb/query`, `/tapdb/graph`, and `/api/dag/*` pass with fixture EUIDs; static guards prevent TapDB-owned raw SQL outside the approved boundary.

6. **Memory / Recall Agent**
   - Verifies all memory kinds are end-to-end operable: `episodic`, `semantic`, `procedural`, `preference`, `relationship`, `location`, `device`, `policy`.
   - Strengthens capture and recall proof: source evidence, ranking, embedding distance, keyword match, excerpt, device, space, session, person, and consent filters.
   - Gate: no semantic memory exists without source evidence; recall proof assertions pass for all required fields.

7. **Live Media / Vision Agent**
   - Proves mic and camera access in the real Live Session workflow.
   - Enforces hard failure when camera is enabled but the agent lacks a current visual observation.
   - Gate: typed chat, speech transcript, agent response, audio playback, camera observation, and no-vision truthfulness tests pass.

8. **Deployed Smoke / Topology Agent**
   - Makes `marvain smoke v1-dev` true deployed-stack proof, not REST-only placeholder evidence.
   - Verifies Cognito login, worker LiveKit join, chat/speech transcript, memory, recognition, device routing, TapDB graph, observability, and two deployed devices in distinct locations/spaces.
   - Gate: deployed smoke passes or reports the exact missing credential, secret, quota, stack output, or service failure.

9. **Observability / Kahlo Agent**
   - Adds Marvain Kahlo discovery endpoints: `/obs_services`, `/api_health`, `/endpoint_health`, `/db_health`, `/auth_health`, and `/my_health`.
   - Advertises Marvain graph endpoints through `/obs_services`.
   - Adds Kahlo federated graph stitching for discoverable services, using advertised graph endpoints and cross-service external-ID EUID nodes.
   - Gate: Kahlo discovers Marvain locally and can stitch Marvain graph data into a unified graph to requested neighbor depth.

10. **Playwright / Coverage Agent**
   - Raises Playwright workflow coverage above 75%.
   - Adds browser tests for auth, dashboard partials, personas, tools, action guide, live media, memory taxonomy, recognition, topology, TapDB graph/query, observability, and GUI smoke guide screenshots.
   - Gate: route coverage script reports API >=75%, GUI route >=75%, and Playwright workflow >=75%.

## Key Implementation Changes

- Update dependency pins in:
  - `pyproject.toml`
  - `functions/hub_api/requirements.txt`
  - `functions/ws_message/requirements.txt`
  - `functions/tapdb_writer/requirements.txt`
  - dependency contract tests and active docs/status checks

- Replace optimistic evidence-only scoring with strict gates:
  - deployed smoke placeholders cannot count as pass
  - stale capability matrix is a failure
  - route and Playwright coverage must meet thresholds
  - TapDB boundary violations fail status generation
  - Kahlo discovery absence fails observability completion

- Keep `/tapdb/graph` and `/api/dag/*` as the graph surface.
  - Do not restore `/lineage`.
  - Do not add compatibility redirects for removed graph routes.

- Marvain observability must use Kahlo-compatible payload shapes.
  - Advertise only routes that return valid contract payloads.
  - Include graph endpoint metadata in `/obs_services`.

- Kahlo graph viewer should reuse existing localhost polling and dashboard graph code where possible.
  - Add only the missing federated graph endpoint/query UI and stitching behavior.

## Test Plan

Required Marvain local gate:

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

Credential-gated Marvain deployed gate:

```bash
set -a
source .livekit
set +a
marvain smoke v1-dev --stack marvain-greenfield-tapdb-dev --include-two-device-proof
```

Kahlo gate:

```bash
cd /Users/jmajor/projects/lsmc/kahlo
source ./activate
ruff check app tests
ruff format --check app tests
python -m pytest tests/ -q --tb=short
```

Focused tests to add or strengthen:

- Dependency contract tests for all new pins.
- Static tests for no legacy `/lineage`, no TapDB raw-state bypass, no auth CLI imports, no CLI fallback path.
- API/GUI route coverage generator test.
- Kahlo `/obs_services` compatibility tests against Marvain payloads.
- Kahlo federated graph stitching tests with cross-service external-ID EUIDs.
- Playwright smoke guide with before, just-before-submit, and after-submit screenshots for each primary workflow.

## Assumptions

- In the implementation run, editing `/Users/jmajor/projects/marvain/round_6_plan.md` is in scope.
- `daylily-tapdb[admin]==6.0.7`, `daylily-auth-cognito==2.1.4`, and `cli-core-yo==2.1.1` are available to the active resolver; if not, stop and report the exact resolver failure.
- Coverage thresholds mean endpoint/route/workflow coverage, not Python line coverage.
- Kahlo already has localhost discovery; Round 6 adds Marvain conformance and federated graph stitching.
