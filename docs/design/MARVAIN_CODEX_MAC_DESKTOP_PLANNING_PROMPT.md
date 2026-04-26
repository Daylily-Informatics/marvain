# Codex Mac Desktop Planning Prompt: Marvain Greenfield TapDB Refactor

You are GPT-5.5 Codex Max in Codex Mac Desktop, operating in multi-agent planning mode.

You are working in an already-checked-out Marvain repository in this workspace. Use the current checked-out branch as the Marvain source of truth. You may also be given the `daylily-tapdb` repository/archive or a sibling checkout; inspect it directly before making TapDB API/boundary claims.

## Governing design documents

Before doing anything else, read these four documents fully. They are the source-of-truth design inputs:

1. `docs/design/MARVAIN_GLOBAL_DESIGN_OBJECTIVES_AND_REQUIREMENTS.md`
2. `docs/design/MARVAIN_TAPDB_FIT_AND_INTEGRATION_SPEC.md`
3. `docs/design/MARVAIN_V1_ACCEPTANCE_TESTS.md`
4. `docs/design/MARVAIN_REFACTOR_PLAN_INPUT_FOR_CODEX.md`

If these files are not already present in the repo, stop and report that they must be added before implementation planning proceeds.

## Current task

Produce a concrete multi-agent implementation plan only. Do not implement code. Do not modify files. Do not run destructive commands.

Your output must be suitable for the next Codex execution pass, where agents will implement the plan phase by phase.

## Binding architectural decisions

Treat these decisions as fixed unless direct repository evidence proves they are impossible:

1. Marvain is greenfield. There are no existing users, no production data, no migration requirement, no backward-compatibility requirement, and no shims/fallbacks to preserve.
2. Existing code is reusable material, not an architectural constraint.
3. TapDB is adopted as the canonical semantic object graph/provenance/lifecycle substrate for Marvain durable domain state where it has architectural advantage.
4. Marvain must use only TapDB-approved interfaces. Marvain code must not perform raw PostgreSQL/RDS Data API/SQLAlchemy/psycopg access to TapDB-owned tables or internals.
5. Prefer a TapDB service/API boundary for deployed Marvain if it is practical. If in-process TapDB package use is chosen, it must still go through public TapDB APIs only, with static tests preventing direct imports of TapDB connection internals and raw SQL against TapDB tables.
6. TapDB should own canonical semantic state for memory, recognition observations/hypotheses, unknown observations, presence assertions, person/account semantic links, locations, spaces/rooms, devices/capabilities, sessions/events, personas, artifact references, and action lifecycle.
7. TapDB should not replace LiveKit media, S3 artifact/media bytes, Cognito/daylily-auth-cognito auth, vector projections/search, or ephemeral WebSocket connection lookup merely for conceptual purity.
8. SQS versus TapDB outbox for dispatch is an implementation decision. Default to preserving SQS as operational transport while TapDB records semantic action lifecycle, unless TapDB outbox has a clearly superior already-supported path.
9. Memory should auto-capture and mostly auto-commit, but only through candidate→commit lifecycle with evidence, confidence, scope, and provenance. Autocommit is not direct-write.
10. Production V1 requires real face and/or voice recognition. Dummy embeddings/fake recognizers must be removed from production behavior.
11. Unknown recognition observations are retained by default, but they must not automatically create durable `person.human` identities or enrolled biometric profiles.
12. Default account model is one authenticated account to one person.
13. `location` and `space`/`room` are separate first-class concepts. Location supports lat/lon and annotation; spaces/rooms belong to locations.
14. Persona is configurable per agent. No hardcoded-only Forge/base persona path may remain as the sole production behavior.
15. Audit/provenance is for debugging, recoverability, trust, and introspection. Do not overbuild compliance machinery.
16. Aggressively remove obsolete code paths, duplicate semantic tables, dummy production behavior, old compatibility shims, and fallback paths that conflict with the target design.

## Required repository analysis before planning

Inspect the Marvain repo and produce a concise repository-grounded inventory of:

- current schema/migrations;
- memory write/recall paths;
- recognition/biometric paths;
- device/satellite/WebSocket paths;
- LiveKit/media paths;
- action/tool lifecycle paths;
- auth/Cognito/daylily-auth-cognito paths;
- tests;
- docs and historical planning files likely to be rewritten/archived;
- current direct database access patterns;
- code that appears to exist only for backward compatibility, migration, fallback, dummy/demo behavior, or stale assumptions.

Inspect daylily-tapdb and identify:

- public APIs that are safe/appropriate for Marvain to use;
- APIs that are internal and must not be used by Marvain;
- whether a TapDB service/API boundary already exists or must be added;
- template-pack loading/validation mechanisms;
- object/instance/lineage/audit/outbox APIs;
- deployment/runtime assumptions relevant to Marvain.

Ground claims in file paths. If something is not verified in repo, mark it `NOT VERIFIED IN REPO`.

## Required planning output

Produce exactly these top-level sections:

1. `Executive Recommendation`
2. `Repository-Grounded Findings`
3. `TapDB Boundary Decision`
4. `Target Runtime Architecture`
5. `Target Data/Domain Model`
6. `Deletion and Replacement List`
7. `Multi-Agent Implementation Plan`
8. `Phase-by-Phase Execution Plan`
9. `Test and Acceptance Gates`
10. `Operational/Deployment Changes`
11. `Risks and Mitigations`
12. `Stop Points and Review Gates`
13. `Open Questions That Truly Block Implementation`

## Multi-agent planning requirements

Use up to 8 agents. Assign each agent a clear domain, file scope, test scope, and dependencies.

Recommended agent domains, adjustable after repo inspection:

1. TapDB boundary/template-pack agent
2. Core domain/schema/projection agent
3. Memory lifecycle/recall agent
4. Recognition/biometrics agent
5. Device/satellite/WebSocket/location agent
6. Persona/session/prompt-hydration agent
7. Action/tool lifecycle agent
8. Tests/docs/cleanup/observability agent

For each agent, specify:

- objective;
- files likely touched;
- files forbidden or to avoid;
- implementation sequence;
- tests to add/update;
- deletion/cleanup responsibilities;
- acceptance criteria;
- dependencies on other agents.

## Phase requirements

The plan must be phased. Each phase must be independently reviewable and testable.

Recommended phase shape, adjustable after repo inspection:

### Phase 0: Source-of-truth docs and baseline inventory

- Place/verify the four design docs under `docs/design/`.
- Mark stale planning docs as historical.
- Run baseline tests and capture failures.
- Produce inventory of obsolete/fallback/dummy paths to remove.

### Phase 1: TapDB boundary and template pack

- Define `marvain.core` template pack.
- Define the Marvain TapDB approved interface boundary.
- Add static tests preventing raw TapDB SQL/direct internals access.
- Decide service/API vs in-process public API boundary from repo evidence.

### Phase 2: Core topology/person/persona/session domain

- Implement location + space/room topology.
- Implement device/capability semantic topology.
- Implement configurable persona.
- Implement session/conversation event canonical lineage.
- Implement account→person default linkage.

### Phase 3: Memory lifecycle and recall projection

- Replace direct memory writes with candidate→autocommit/commit lifecycle.
- Implement memory evidence/provenance/scope/confidence/supersession/tombstone.
- Implement rebuildable vector/keyword recall projection.
- Implement recall explanation.

### Phase 4: Recognition and presence

- Implement production face and/or voice recognition path.
- Remove dummy production embeddings/fallback recognizer behavior.
- Implement observation→hypothesis→presence lifecycle.
- Retain unknown observations without auto-person/profile creation.
- Implement correction/rejection path.

### Phase 5: Remote satellites and multi-location routing

- Fix device-token WebSocket auth.
- Prove two satellites in two locations operate independently.
- Implement targeted command/output routing.
- Preserve LiveKit as media plane and ephemeral connection state as operational store if justified.

### Phase 6: Action/tool lifecycle

- Move canonical action proposal/approval/auto-approval/execution/result lifecycle into TapDB semantic graph.
- Preserve or choose SQS/TapDB outbox operational dispatch explicitly.
- Implement idempotency and result/error/timeout semantics.

### Phase 7: Cleanup, observability, and acceptance

- Remove obsolete semantic SQL tables or reduce them to explicit projections.
- Remove stale fallback/compatibility/dummy production paths.
- Add observability/debug views for memory, recognition, topology, persona, and actions.
- Run full acceptance test suite.

## Testing requirements

The plan must include tests that prove:

- Marvain uses TapDB-approved interfaces only;
- no raw TapDB SQL/direct DB manipulation exists in Marvain code;
- memory autocommits through candidate→commit with evidence;
- recall includes provenance/explanation;
- production recognition does not use dummy embeddings;
- unknown observations are retained but not promoted;
- two satellites work independently across two locations;
- device WebSocket auth uses device credentials;
- location + space/room topology is first-class;
- persona is configurable;
- actions preserve proposal/approval/execution/result lineage;
- projections rebuild from TapDB canonical state;
- obsolete fallback/dummy/compatibility paths are absent or unreachable in production.

## Output constraints

- Do not implement.
- Do not modify files.
- Do not produce broad speculative architecture alternatives.
- Choose one recommended implementation path.
- Keep the plan concrete, file-path-grounded, and executable by Codex agents.
- Include exact files likely to be touched wherever the repo supports specificity.
- Mark unverified claims as `NOT VERIFIED IN REPO`.
- If a design doc conflicts with direct repository evidence, report the conflict and propose a correction.
- End with the exact first execution prompt to give Codex after this plan is approved.
