## 1. Executive Recommendation

Title: Marvain Greenfield TapDB V1 Refactor Plan With Environment, CLI, And Auth Modernization

- Proposed feature branch: `codex/marvain-greenfield-tapdb-v1`.
- First implementation block: modernize local activation, dependency ownership, CLI, and Cognito auth before TapDB work.
- Adopt:
  - `source ./activate` from repo root.
  - root `environment.yaml` for Conda/system tools only.
  - `pyproject.toml` for Python/pip dependencies.
  - `cli-core-yo==2.1.0`.
  - `daylily-auth-cognito==2.1.1`.
  - `daylily-tapdb==6.0.5`.
- Then implement the TapDB-first greenfield refactor with no migration, no compatibility shims, and no fallback production behavior.
- Final deliverable: feature branch with env/CLI/auth refactor, TapDB V1 implementation, full local/e2e test report, dev deployment report, known limitations, and only truly blocking manual decisions.

## 2. Repository-Grounded Findings

- Marvain currently has `marvain_activate`, no root `activate`, and `config/marvain_conda.yaml`.
- `marvain_activate` currently does more than clean env activation: PATH mutation, app config discovery, legacy config fallback references, shell completion, and user guidance.
- Marvain currently uses `bin/marvain` with `PYTHONPATH` instead of relying cleanly on the installed console script.
- Marvain currently pins `cli-core-yo==2.0.0` and `daylily-auth-cognito==2.0.1` in `pyproject.toml`.
- Current Conda YAML still includes obsolete `daylily-cognito==0.1.24` and direct `python-jose[cryptography]`.
- `daylily-auth-cognito` tag `2.1.1` exists and its package contract exposes `runtime`, `browser`, `admin`, `cli`, and `policy` boundaries. Service runtime must not import `daylily_auth_cognito.cli`.
- Current Marvain auth has mixed behavior:
  - `agent_hub.auth` uses `daylily_auth_cognito.admin.client.CognitoAdminClient` but authenticates access tokens by calling Cognito `get_user`.
  - `agent_hub.cognito` still contains Marvain-local browser/JWT code with direct `jose` imports.
  - GUI routes store/expose raw Cognito access-token cookies for browser flows.
- Current memory and recognition behavior conflicts with the new design: direct memory writes, memory hard-delete, recall without provenance, production dummy recognition embeddings, and no durable unknown-observation model.
- TapDB uses SQLAlchemy/direct PostgreSQL access, not RDS Data API.

## 3. TapDB Boundary Decision

- Add a Marvain-owned TapDB writer/query boundary, not raw TapDB SQL scattered through Marvain.
- Allowed TapDB usage: one boundary module/service may use public `daylily_tapdb` APIs to seed templates, create instances, create lineage, query lineage/DAG data, and record lifecycle transitions.
- Forbidden outside the boundary: direct imports of `daylily_tapdb.models`, `daylily_tapdb.connection`, `daylily_tapdb.aurora`, SQLAlchemy sessions, psycopg connections, or raw SQL against TapDB-owned tables.
- Add static tests enforcing that rule.
- Use TapDB domain `MVN`, owner repo `marvain`, and a Marvain template pack stored in this repo.
- Resolve dependency alignment intentionally: Marvain should pin `cli-core-yo==2.1.0`, `daylily-auth-cognito==2.1.1`, and `daylily-tapdb==6.0.5`.

## 4. Target Runtime Architecture

- Replace `marvain_activate` with root `activate`:
  - must be sourced;
  - supports bash and zsh;
  - sets `MARVAIN_REPO_ROOT` and `MARVAIN_ACTIVE=1`;
  - creates Conda env `marvain` from `environment.yaml` if missing;
  - activates Conda env `marvain`;
  - installs Marvain editable from the repo;
  - does not inspect app config, set AWS profile/region, manage completions, add `./bin` to PATH, bootstrap resources, or hide activation failures.
- Replace `config/marvain_conda.yaml` with root `environment.yaml`.
- Keep Python/pip packages in `pyproject.toml`, including auth, CLI, TapDB, runtime, recognition, local-service, and dev/test dependencies.
- Refactor `marvain_cli` to the `daylily-ec` style with `EnvSpec`, `RuntimeSpec`, command policies, root-owned JSON/dry-run, and env/runtime command surfaces.
- Move Cognito runtime auth to `daylily_auth_cognito.runtime.CognitoTokenVerifier`.
- Move browser Hosted UI/session behavior to `daylily_auth_cognito.browser` and store only normalized session principals, not raw OAuth tokens.
- Keep Marvain CLI Cognito user/admin commands on `daylily_auth_cognito.admin.*` boundaries.
- Add a Marvain short-lived session/WS token path for browser WebSocket auth if browser flows no longer expose Cognito access tokens.
- Add `TapdbWriterFunction` in `template.yaml`, running in the private VPC with direct Aurora access and writer-specific dependencies.
- Keep Hub API, planner, tool runner, recognition worker, WebSocket handlers, GUI, and remote satellite as Marvain services.

## 5. Target Data/Domain Model

- TapDB canonical objects: agents, people, accounts, locations, spaces/rooms, devices, capabilities, sessions, events, memory candidates, committed memories, tombstones, recognition observations, hypotheses, unknown-person observations, presence assertions, consent/policy records, artifact references, action lifecycle records, personas, and semantic sync failures.
- Explicitly split `location` from `space`/`room`; retain LiveKit room bindings as operational metadata.
- Memory lifecycle: evidence event -> candidate -> scored/reviewed/committed -> recalled with provenance -> tombstoned if removed.
- Recognition lifecycle: artifact reference -> observation -> hypothesis -> match/no-match -> presence assertion only when confidence/consent rules pass.
- Persona model: configurable persona per agent/session; remove hardcoded-only Forge/base persona behavior as the sole production path.
- Auth identity model: default one authenticated Cognito account to one person, with explicit account/person links in TapDB and rebuildable SQL projections.
- Action model: keep SQS/tool-runner execution, but record proposal/approval/dispatch/ack/result lifecycle in TapDB.

## 6. Deletion and Replacement List

- Delete/replace `marvain_activate` with root `activate`.
- Delete/replace `config/marvain_conda.yaml` with root `environment.yaml`.
- Stop relying on `bin/marvain`; use installed console script `marvain = "marvain_cli.__main__:main"`.
- Remove active references to `. ./marvain_activate`, `source marvain_activate`, `config/marvain_conda.yaml`, and `./bin/marvain`.
- Replace `cli-core-yo==2.0.0` with `cli-core-yo==2.1.0`.
- Replace `daylily-auth-cognito==2.0.1` with `daylily-auth-cognito==2.1.1`.
- Remove obsolete `daylily-cognito==0.1.24`.
- Remove direct Marvain runtime reliance on `jose` where `daylily-auth-cognito` owns JWT verification.
- Remove imports of `daylily_auth_cognito.cli` from service/runtime code if any appear.
- Replace Marvain-local browser/JWT auth code with `daylily_auth_cognito.browser` and `daylily_auth_cognito.runtime` boundaries.
- Remove production dummy voice/face embedding fallback.
- Replace direct memory creation and hard-delete behavior with lifecycle services.
- Replace user-only WebSocket hello handling with explicit user/session/device authentication paths.

## 7. Multi-Agent Implementation Plan

- Agent 1, environment foundation: owns root `activate`, root `environment.yaml`, `pyproject.toml` dependency split, removal of old activation references, activation tests, and docs updates.
- Agent 2, CLI foundation: owns `cli-core-yo==2.1.0`, Marvain runtime/env CLI modernization, command policies, CLI tests, and CLI docs.
- Agent 3, Cognito auth foundation: owns `daylily-auth-cognito==2.1.1`, runtime token verifier adoption, browser session adoption, admin boundary updates, auth tests, and static import guards.
- Agent 4, TapDB boundary and templates: owns TapDB dependency, template pack, writer function, queue/DLQ, graph query contract, seed/init command, and static boundary tests.
- Agent 5, core domain and projections: owns SQL projection changes for locations/spaces/sessions/events/auth links/TapDB write status.
- Agent 6, memory lifecycle and recall: owns candidate/commit/tombstone services, planner/API/tool memory rewrites, recall provenance, and tests.
- Agent 7, recognition and biometrics: owns real recognizer gating, observation/hypothesis lifecycle, unknown observation retention, enrollment/match behavior, and failure-injection tests.
- Agent 8, device/satellite/WebSocket/location: owns device-token WS auth, browser session/WS token auth, remote satellite simulation, device capability/location modeling, and e2e contract repair.
- Agent 9, persona/session/action lifecycle: owns configurable persona storage, session model, prompt hydration, TapDB action lifecycle records, and SQS execution preservation.
- Agent 10, tests/docs/observability: owns acceptance suite, docs cleanup, generated status, CloudWatch metrics/alarms, deployment reports, and final full-test gate.

## 8. Phase-by-Phase Execution Plan

Phase 0, baseline and branch setup:
- Objective: create the feature branch later, confirm baseline, lock constraints.
- Tests/commands: `git fetch origin --prune`; create `codex/marvain-greenfield-tapdb-v1` from `origin/main`; use current setup for baseline; run Ruff, docs contract, generated status check, and full `pytest`.
- AWS commands: none.
- Gate: clean baseline or documented pre-existing failures.
- Stop: activation fails, `marvain` CLI unavailable, or baseline cannot be established.

Phase 1, clean activation and dependency split:
- Likely touched: `AGENTS.md`, `README.md`, `QUICKSTART.md`, `QUICKSTART_GUI.md`, `pyproject.toml`, `marvain_cli/ops.py`, `bin/init_setup.sh`, `functions/hub_api/start_server.sh`, `scripts/nuke_dev.sh`.
- New files: `activate`, `environment.yaml`, `tests/test_environment_contract.py`.
- Removed: `marvain_activate`, `config/marvain_conda.yaml`, obsolete activation references, likely `bin/marvain`.
- Tests: environment contract tests for `source ./activate`, no old activation references, Python deps in `pyproject.toml`, no `pip:` package block in `environment.yaml`, installed console script works.
- Commands: `python -m pytest tests/test_environment_contract.py -q`; re-source `./activate`; run `marvain version`.
- Gate: `source ./activate` creates/activates `marvain`, editable install provides `marvain`, and dependency ownership is clean.

Phase 2, CLI-core-yo 2.1.0 and daylily-ec CLI pattern:
- Likely touched: `pyproject.toml`, `marvain_cli/cli.py`, `marvain_cli/_registry_v2.py`, `marvain_cli/commands.py`, `marvain_cli/__main__.py`, CLI docs.
- New files: `tests/test_cli_registry_v2.py`, optional `tests/test_cli_runtime.py`.
- Tests: command tree/policies, help rendering, global JSON, env/runtime commands, dry-run contracts, version/info metadata.
- Commands: `python -m pytest tests/test_cli_registry_v2.py tests/test_cli_runtime.py tests/test_environment_contract.py -q`.
- Gate: `marvain --help`, `marvain --json version`, `marvain runtime status`, `marvain env status`, and existing commands render help on `cli-core-yo==2.1.0`.

Phase 3, daylily-auth-cognito 2.1.1:
- Likely touched: `pyproject.toml`, `layers/shared/python/agent_hub/auth.py`, `layers/shared/python/agent_hub/cognito.py`, `functions/hub_api/app.py`, `functions/ws_message/handler.py`, `marvain_cli/ops.py`, auth/GUI/WS tests.
- New files: `tests/test_auth_boundary.py`, `tests/test_cognito_browser_session.py`, static import guard tests.
- Removed: obsolete `daylily-cognito` dependency, direct Marvain JWT verification duplicated from `daylily-auth-cognito`, raw OAuth-token browser session storage, service imports from auth CLI modules.
- Tests: access token verification with `CognitoTokenVerifier`, browser callback/session principal storage, no raw OAuth tokens in session, admin user commands through `daylily_auth_cognito.admin`, WebSocket user/session/device auth, no direct `jose` imports in Marvain runtime.
- Commands: `python -m pytest tests/test_agent_tokens.py tests/test_gui_app.py tests/test_ws_message_handler.py tests/test_auth_boundary.py tests/test_cognito_browser_session.py -q`.
- AWS commands: none unless an auth-config smoke is explicitly scoped to dev.
- Gate: Marvain works with `daylily-auth-cognito==2.1.1`; service runtime uses runtime/browser/admin boundaries correctly; GUI no longer persists raw OAuth tokens.
- Stop: `2.1.1` is unavailable to the resolver or its public API cannot support current required Cognito flows.

Phase 4, TapDB dependency, templates, and writer boundary:
- Likely touched: `pyproject.toml`, `template.yaml`, `marvain_cli/commands.py`, `marvain_cli/ops.py`, shared TapDB client modules.
- New files: Marvain TapDB template pack, `functions/tapdb_writer/handler.py`, writer requirements if needed, TapDB boundary/static tests.
- Tests: dependency resolution, template validation/seed tests, static boundary tests.
- Commands: `pytest tests/test_tapdb_* -q` plus foundation tests.
- AWS commands: dry-run deploy/build only.
- Gate: template pack validates, writer can create/query objects in tests, CLI exposes `marvain init tapdb`.

Phase 5, core semantic model and projections:
- Likely touched: `sql/`, `layers/shared/python/agent_hub/`, Hub API bootstrap/config paths.
- New files: projection migrations for locations/spaces/sessions/account links/semantic write status and repository tests.
- Tests: location/space, session/event, auth account/person links, projection rebuild, idempotent semantic write status.
- AWS commands: `marvain --dry-run init db`.
- Gate: fresh DB schema applies from zero; no data migration/backfill code exists.

Phase 6, memory lifecycle and recall:
- Likely touched: Hub API, planner, memory tool, shared memory service, recall routes, agent worker.
- Removed: direct durable memory inserts, direct autosave memory writes, memory hard-delete.
- Tests: candidate creation, commit, tombstone, provenance recall, OpenAI embedding failure behavior, no silent fallback.
- Gate: planner and API cannot bypass candidate/commit flow.

Phase 7, recognition, biometrics, and presence:
- Likely touched: recognition worker, Hub API recognition endpoints, shared recognition service, consent/presence modules.
- Removed: dummy production embedding fallback and match-without-observation behavior.
- Tests: real dependency gating, unknown observation retained, no unknown person auto-created, consent enforcement, match-to-presence assertion, artifact ref provenance.
- Gate: production mode cannot use dummy embeddings.

Phase 8, device, satellite, WebSocket, and location:
- Likely touched: WebSocket handler, remote satellite, device heartbeat/API code, shared auth/location service.
- Tests: device token hello, browser session/WS token hello, rotated token invalidation, heartbeat capability projection, device command ack/result, location + room assertions.
- Gate: e2e contract shape is satisfied locally/mocked.

Phase 9, persona, sessions, action lifecycle, and docs cleanup:
- Likely touched: agent worker, shared prompt/context code, action service/tool runner, docs and generated status scripts.
- Removed: hardcoded-only persona production behavior and stale fallback/dual-write/pilot docs as current guidance.
- Tests: persona selection, context hydration provenance, action proposal/approval/dispatch/result lineage, timeout lifecycle.
- Gate: docs and implementation status match current behavior.

Phase 10, full integration, dev deploy, e2e, and report:
- Tests: full local suite, full e2e smoke against dev stack, failure-injection where practical.
- AWS commands: deploy dev stack, `init db`, `init tapdb`, bootstrap, run e2e.
- Gate: local checks green and deployed dev stack smoke green or exact missing AWS/secrets/quota reported.
- Stop: missing credentials/secrets/quota, non-dev resource deletion risk, prod/main impact, or 3 failed repair loops.

## 9. Test and Acceptance Gates

- Environment: `source ./activate` works, creates env from `environment.yaml`, activates `marvain`, installs editable package, exposes `marvain`, and has no app config/AWS/completion/PATH-wrapper side effects.
- Dependency split: Conda spec contains only Conda/system tools; Python/pip packages live in `pyproject.toml`.
- CLI: registry tree, policies, global JSON, env/runtime commands, dry-run behavior, help rendering, version/info metadata, config safety.
- Auth: `daylily-auth-cognito==2.1.1` installed; runtime auth uses `CognitoTokenVerifier`; browser flow uses token-free session principal; admin commands use `daylily_auth_cognito.admin`; no `daylily_cognito`; no service imports from `daylily_auth_cognito.cli`.
- Unit/integration: TapDB boundary, memory lifecycle, recognition lifecycle, persona/session, device auth, action lifecycle.
- AWS deployed smoke: bootstrap, owner claim, Cognito login/token verification, REST event ingest, WS user/session/device auth, TapDB semantic write, graph query, memory candidate/commit/recall, recognition queue smoke, action lifecycle smoke.

## 10. Operational/Deployment Changes

- Dev stack name: `marvain-greenfield-tapdb-dev`.
- Required shell setup after Phase 1:
  `export AWS_PROFILE=daylily`
  `export AWS_REGION=us-east-1`
  `export AWS_DEFAULT_REGION=us-east-1`
  `source ./activate`
- Required pinned Python packages:
  `cli-core-yo==2.1.0`
  `daylily-auth-cognito==2.1.1`
  `daylily-tapdb==6.0.5`
- Required TapDB env:
  `MERIDIAN_DOMAIN_CODE=MVN`
  `TAPDB_OWNER_REPO=marvain`
- Required secrets/config: admin API key, OpenAI key, Cognito pool/client/domain/session secret, Cognito test username/password, optional Google OAuth, LiveKit credentials when media tests are in scope, DB secret, generated TapDB config.
- Expected resources updated/created: TapDB writer Lambda, writer queue/DLQ, writer VPC access, writer IAM permissions, TapDB template seed path, optional graph query/proxy API, auth/session updates, metrics/alarms.
- Non-destructive deploy commands:
  `marvain --config ~/.config/marvain/marvain-config.yaml --env dev --stack marvain-greenfield-tapdb-dev deploy`
  `marvain --config ~/.config/marvain/marvain-config.yaml --env dev --stack marvain-greenfield-tapdb-dev init db`
  `marvain --config ~/.config/marvain/marvain-config.yaml --env dev --stack marvain-greenfield-tapdb-dev init tapdb`
- Teardown command, only after explicit destructive approval and only for the dev stack:
  `marvain --config ~/.config/marvain/marvain-config.yaml --env dev --stack marvain-greenfield-tapdb-dev teardown`

## 11. Risks and Mitigations

- Activation churn: make Phase 1 small and testable; re-source `./activate` before continuing.
- Dependency split mistakes: add environment contract tests.
- Auth package behavior change: isolate in Phase 3; pin `2.1.1`; test runtime, browser, admin, GUI, and WS auth seams before TapDB work.
- Browser token removal: replace raw Cognito token cookies with normalized session principal and Marvain short-lived WS/session token where browser WebSocket auth requires a bearer.
- CLI dependency conflict: resolve with `cli-core-yo==2.1.0` before TapDB and auth integration.
- TapDB direct PostgreSQL from Lambda: isolate to writer Lambda in VPC; keep existing Lambdas on RDS Data API.
- Recognition dependency weight: missing real recognizer is a readiness failure for recognition worker, not a dummy fallback.
- Existing docs conflict with greenfield design: rewrite or mark historical.

## 12. Stop Points and Review Gates

- Continue automatically from phase to phase when local gates pass.
- If tests fail, attempt up to 3 focused repair iterations before stopping with exact failing commands and logs.
- If AWS deploy fails from missing credentials, secrets, service quota, private networking, or account policy, stop and report the exact missing requirement.
- If any command would delete non-dev AWS resources, touch `main`/prod, or deploy to a non-dev stack, stop.
- If repo evidence conflicts with design docs, prefer design docs unless implementation is impossible; then document the conflict and choose the least-destructive path.
- Do not ask Major for rubber-stamp approvals between phases.

## 13. Open Questions That Truly Block Implementation

- None from current repository inspection. Implementation can proceed with the defaults above.
- Non-blocking values that may stop AWS/e2e only when absent: AWS credentials, Cognito test user/password, OpenAI secret, LiveKit credentials for media smoke, quota for Aurora/Lambda/VPC resources.

Exact first execution prompt for the later implementation run:

```text
You are in /Users/jmajor/projects/marvain. This is now an implementation run. Start from refreshed origin/main, create/switch to branch codex/marvain-greenfield-tapdb-v1, use the current setup for the initial baseline, and implement the approved Marvain Greenfield TapDB V1 Refactor Plan With Environment, CLI, And Auth Modernization. First replace marvain_activate/config/marvain_conda.yaml with the daylily-ephemeral-cluster-style source ./activate pattern and root environment.yaml, keeping Conda/system dependencies in environment.yaml and Python/pip dependencies in pyproject.toml. Then refactor Marvain CLI to cli-core-yo==2.1.0 using the daylily-ec patterns. Then update Marvain to daylily-auth-cognito==2.1.1, using runtime/browser/admin package boundaries and no raw OAuth-token browser sessions. Then continue through the TapDB-first V1 implementation using daylily-tapdb==6.0.5. Do not add migration, backward compatibility, shims, aliases, or fallback production behavior. Continue phase to phase automatically when gates pass. If tests fail, attempt up to 3 focused repairs. Stop only for missing AWS credentials/secrets/quota, non-dev/main/prod impact, destructive operations outside the dev stack, or impossible repo/design conflicts. Produce the final feature branch, full test report, dev deployment report if AWS allows it, and known limitations.
```
