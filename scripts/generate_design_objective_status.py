#!/usr/bin/env python3
from __future__ import annotations

import argparse
import importlib.util
import sys
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT_FILE = ROOT / "docs" / "DESIGN_OBJECTIVE_STATUS.generated.md"
ARCHITECTURE_SCAN_ROOTS = ("apps", "functions", "layers", "marvain_cli", "scripts", "sql", "docs/design")
ARCHITECTURE_FORBIDDEN_TOKENS = (
    "RECOGNITION_ALLOW_DUMMY_EMBEDDINGS",
    "_dummy_embedding",
    "dummy-face",
    "dummy-voice",
    "legacy_memberships",
    "dual-write",
    "backfill",
    "during pilot",
    "Recommended pilot",
    "layers/shared/tapdb_schema",
)
ROUND5_MEMORY_KINDS = (
    "episodic",
    "semantic",
    "procedural",
    "preference",
    "relationship",
    "location",
    "device",
    "policy",
)
ROUND5_TAPDB_INTERNAL_TOKENS = (
    "daylily_tapdb.aurora",
    "engine.begin",
    "exec_driver_sql",
    "session.execute(",
    "text(",
    "tapdb_schema.sql",
)
ROUND6_MIN_API_ROUTE_COVERAGE = 100
ROUND6_MIN_GUI_ROUTE_COVERAGE = 100
ROUND6_MIN_PLAYWRIGHT_WORKFLOW_COVERAGE = 75
ROUND7_MEMORY_PROVENANCE_CLASSES = (
    "external_interaction",
    "self_reflection",
    "cross_agent_interaction",
    "system_observation",
)
ROUND7_BACKUP_SECTIONS = (
    "actions",
    "artifact_references",
    "audit_state",
    "events",
    "memory_annotations",
    "memory_candidates",
    "memory_opinions",
    "memories",
    "people",
    "presence_assertions",
    "recognition_hypotheses",
    "recognition_observations",
    "sessions",
)


@dataclass(frozen=True)
class EvidenceToken:
    kind: str
    label: str
    rel_path: str
    token: str


@dataclass(frozen=True)
class DesignObjective:
    objective_id: str
    title: str
    source: str
    requirement: str
    evidence: tuple[EvidenceToken, ...]
    known_limitations: tuple[str, ...] = ()


OBJECTIVES: tuple[DesignObjective, ...] = (
    DesignObjective(
        objective_id="OBJ-01",
        title="Source-of-truth design docs stay checked in",
        source="docs/design/MARVAIN_CODEX_MAC_DESKTOP_PLANNING_PROMPT.md",
        requirement="The four governing design documents exist under docs/design and drive implementation.",
        evidence=(
            EvidenceToken(
                "docs",
                "Global objectives doc",
                "docs/design/MARVAIN_GLOBAL_DESIGN_OBJECTIVES_AND_REQUIREMENTS.md",
                "## 6. Capability requirements",
            ),
            EvidenceToken(
                "docs",
                "TapDB fit spec",
                "docs/design/MARVAIN_TAPDB_FIT_AND_INTEGRATION_SPEC.md",
                "## 4. TapDB replacement/overlay/avoid matrix",
            ),
            EvidenceToken(
                "docs",
                "V1 acceptance tests",
                "docs/design/MARVAIN_V1_ACCEPTANCE_TESTS.md",
                "## 2. Capability-to-test traceability matrix",
            ),
            EvidenceToken(
                "docs",
                "Refactor input",
                "docs/design/MARVAIN_REFACTOR_PLAN_INPUT_FOR_CODEX.md",
                "MARVAIN_GLOBAL_DESIGN_OBJECTIVES_AND_REQUIREMENTS.md",
            ),
            EvidenceToken("test", "Docs contract check", "scripts/verify_docs_contracts.py", "validate_tool_payload"),
        ),
    ),
    DesignObjective(
        objective_id="OBJ-02",
        title="TapDB semantic boundary and template pack",
        source="docs/design/MARVAIN_TAPDB_FIT_AND_INTEGRATION_SPEC.md",
        requirement="TapDB acts as a semantic object, lineage, lifecycle, and provenance boundary rather than a hot-path store replacement.",
        evidence=(
            EvidenceToken(
                "code",
                "Semantic TapDB boundary",
                "layers/shared/python/agent_hub/semantic_tapdb.py",
                "class DaylilyTapdbSemanticStore",
            ),
            EvidenceToken(
                "code", "TapDB writer function", "functions/tapdb_writer/handler.py", "DaylilyTapdbSemanticStore"
            ),
            EvidenceToken(
                "code", "Template code map", "layers/shared/python/agent_hub/semantic_tapdb.py", "TEMPLATE_CODES"
            ),
            EvidenceToken("code", "Template pack", "tapdb_templates/MVN/marvain.json", '"templates"'),
            EvidenceToken(
                "test",
                "Template tests",
                "tests/test_tapdb_templates.py",
                "test_marvain_template_codes_cover_required_semantic_objects",
            ),
            EvidenceToken("test", "Boundary static test", "tests/test_tapdb_boundary_static.py", "daylily_tapdb"),
            EvidenceToken(
                "docs",
                "TapDB boundary pattern report",
                "docs/reports/MARVAIN_TAPDB_BOUNDARY_PATTERN.md",
                "does not introduce a new `daylily_tapdb.semantic.SemanticTapDBClient`",
            ),
            EvidenceToken("deployed", "Stack declares TapDB writer", "template.yaml", "TapdbWriterFunction"),
        ),
        known_limitations=(
            "Live TapDB write/query validation depends on a deployed dev stack and credentials; repo evidence only proves the boundary, templates, and stack contract.",
        ),
    ),
    DesignObjective(
        objective_id="OBJ-03",
        title="Explicit location, space, and session model",
        source="docs/design/MARVAIN_GLOBAL_DESIGN_OBJECTIVES_AND_REQUIREMENTS.md",
        requirement="Locations, spaces/rooms, sessions, events, devices, and personas are explicit and linkable domain objects.",
        evidence=(
            EvidenceToken(
                "code",
                "Locations table",
                "sql/020_greenfield_semantic_lifecycle.sql",
                "CREATE TABLE IF NOT EXISTS locations",
            ),
            EvidenceToken(
                "code",
                "Sessions table",
                "sql/020_greenfield_semantic_lifecycle.sql",
                "CREATE TABLE IF NOT EXISTS sessions",
            ),
            EvidenceToken(
                "code",
                "Events session link",
                "sql/020_greenfield_semantic_lifecycle.sql",
                "ALTER TABLE events ADD COLUMN IF NOT EXISTS session_id",
            ),
            EvidenceToken(
                "code",
                "Devices current space",
                "sql/020_greenfield_semantic_lifecycle.sql",
                "ALTER TABLE devices ADD COLUMN IF NOT EXISTS current_space_id",
            ),
            EvidenceToken("gui", "Locations page", "functions/hub_api/app.py", '@app.get("/locations"'),
            EvidenceToken("gui", "Sessions page", "functions/hub_api/app.py", '@app.get("/sessions"'),
            EvidenceToken(
                "test",
                "Greenfield schema test",
                "tests/test_greenfield_schema.py",
                "test_greenfield_semantic_lifecycle_schema_declares_required_projections",
            ),
        ),
    ),
    DesignObjective(
        objective_id="OBJ-04",
        title="Memory candidate, commit, recall, and tombstone lifecycle",
        source="docs/design/MARVAIN_GLOBAL_DESIGN_OBJECTIVES_AND_REQUIREMENTS.md",
        requirement="Semantic memory has source evidence, candidate/commit state, recall explanation, and tombstone deletion semantics.",
        evidence=(
            EvidenceToken(
                "code",
                "Memory candidates table",
                "sql/020_greenfield_semantic_lifecycle.sql",
                "CREATE TABLE IF NOT EXISTS memory_candidates",
            ),
            EvidenceToken(
                "code",
                "Memory tombstones table",
                "sql/020_greenfield_semantic_lifecycle.sql",
                "CREATE TABLE IF NOT EXISTS memory_tombstones",
            ),
            EvidenceToken(
                "code",
                "Recall explanation projection",
                "sql/020_greenfield_semantic_lifecycle.sql",
                "recall_explanation",
            ),
            EvidenceToken(
                "code", "API tombstones memory", "functions/hub_api/api_app.py", "INSERT INTO memory_tombstones"
            ),
            EvidenceToken("gui", "GUI tombstones memory", "functions/hub_api/app.py", "INSERT INTO memory_tombstones"),
            EvidenceToken(
                "test",
                "Memory lifecycle test",
                "tests/test_semantic_lifecycles.py",
                "test_memory_lifecycle_records_evidence_candidate_commit_recall_and_tombstone",
            ),
            EvidenceToken(
                "test",
                "No hard-delete test",
                "tests/test_greenfield_schema.py",
                "test_memory_deletes_are_modeled_as_tombstones_not_projection_hard_delete",
            ),
        ),
    ),
    DesignObjective(
        objective_id="OBJ-05",
        title="Recognition observations, hypotheses, consent, and unknown handling",
        source="docs/design/MARVAIN_GLOBAL_DESIGN_OBJECTIVES_AND_REQUIREMENTS.md",
        requirement="Recognition separates observation, hypothesis, consent-used, presence, and unknown-person behavior.",
        evidence=(
            EvidenceToken(
                "code",
                "Recognition observations table",
                "sql/020_greenfield_semantic_lifecycle.sql",
                "CREATE TABLE IF NOT EXISTS recognition_observations",
            ),
            EvidenceToken(
                "code",
                "Recognition hypotheses table",
                "sql/020_greenfield_semantic_lifecycle.sql",
                "CREATE TABLE IF NOT EXISTS recognition_hypotheses",
            ),
            EvidenceToken(
                "code",
                "Presence assertions table",
                "sql/020_greenfield_semantic_lifecycle.sql",
                "CREATE TABLE IF NOT EXISTS presence_assertions",
            ),
            EvidenceToken(
                "code",
                "Biometric consent projection",
                "sql/020_greenfield_semantic_lifecycle.sql",
                "ALTER TABLE voiceprints ADD COLUMN IF NOT EXISTS consent_id",
            ),
            EvidenceToken(
                "code",
                "Production recognizer hard failure",
                "apps/recognition_worker/worker.py",
                "recognizer_unavailable",
            ),
            EvidenceToken("gui", "Recognition audit page", "functions/hub_api/app.py", '@app.get("/recognition"'),
            EvidenceToken(
                "test",
                "Recognition unknown lifecycle test",
                "tests/test_semantic_lifecycles.py",
                "test_recognition_lifecycle_keeps_unknown_observation_without_presence_identity",
            ),
            EvidenceToken(
                "test",
                "Recognizer hard-failure test",
                "tests/test_recognition_worker_contract.py",
                "test_recognition_worker_requires_real_face_recognizer",
            ),
        ),
        known_limitations=(
            "Real face/voice recognizer dependencies are external; current repository evidence proves hard-failure behavior and lifecycle storage, not biometric model quality.",
        ),
    ),
    DesignObjective(
        objective_id="OBJ-06",
        title="Device auth, heartbeat, topology, and command provenance",
        source="docs/design/MARVAIN_GLOBAL_DESIGN_OBJECTIVES_AND_REQUIREMENTS.md",
        requirement="Devices authenticate as devices, report heartbeat/location state, and use the action lifecycle for command routing.",
        evidence=(
            EvidenceToken("code", "Device token WS hello", "functions/ws_message/handler.py", "authenticate_device"),
            EvidenceToken(
                "code", "Remote satellite sends device token", "apps/remote_satellite/hub_client.py", "device_token"
            ),
            EvidenceToken(
                "code", "Heartbeat endpoint", "functions/hub_api/api_app.py", '@api_app.post("/v1/devices/heartbeat"'
            ),
            EvidenceToken(
                "code",
                "Device location projection",
                "sql/020_greenfield_semantic_lifecycle.sql",
                "ALTER TABLE devices ADD COLUMN IF NOT EXISTS location_id",
            ),
            EvidenceToken("gui", "Locations device view", "functions/hub_api/templates/locations.html", "Devices"),
            EvidenceToken("test", "Remote satellite contract", "tests/test_remote_satellite.py", "device_token"),
            EvidenceToken("test", "WS message contract", "tests/test_ws_message_handler.py", "device_token"),
        ),
    ),
    DesignObjective(
        objective_id="OBJ-07",
        title="Action lifecycle preserves approval, idempotency, execution, and result",
        source="docs/design/MARVAIN_GLOBAL_DESIGN_OBJECTIVES_AND_REQUIREMENTS.md",
        requirement="Actions record proposal, approval/policy, dispatch/execution/result, idempotency, and audit evidence.",
        evidence=(
            EvidenceToken(
                "code", "Action service", "layers/shared/python/agent_hub/action_service.py", "create_action"
            ),
            EvidenceToken(
                "code",
                "Policy evaluator",
                "layers/shared/python/agent_hub/auto_approve_policy.py",
                "evaluate_auto_approve",
            ),
            EvidenceToken(
                "code",
                "Device execution lifecycle",
                "sql/009_action_device_execution_lifecycle.sql",
                "awaiting_result_until",
            ),
            EvidenceToken("code", "Action idempotency", "sql/016_action_idempotency.sql", "idempotency_key"),
            EvidenceToken("code", "Timeout sweeper", "functions/action_timeout_sweeper/handler.py", "timed_out"),
            EvidenceToken("gui", "Actions page", "functions/hub_api/app.py", '@app.get("/actions"'),
            EvidenceToken(
                "test",
                "Tool runner device lifecycle tests",
                "tests/test_tool_runner_handler_async.py",
                "test_device_command_moves_to_awaiting_device_result",
            ),
            EvidenceToken(
                "test",
                "Action lifecycle lineage test",
                "tests/test_semantic_lifecycles.py",
                "test_action_lifecycle_records_proposal_approval_execution_result_lineage",
            ),
        ),
    ),
    DesignObjective(
        objective_id="OBJ-08",
        title="Consent, privacy, and audit are enforced and observable",
        source="docs/design/MARVAIN_GLOBAL_DESIGN_OBJECTIVES_AND_REQUIREMENTS.md",
        requirement="Consent and privacy gates apply at use time, and audit/observability surfaces expose state and integrity checks.",
        evidence=(
            EvidenceToken("code", "Consent table", "sql/001_init.sql", "CREATE TABLE IF NOT EXISTS consent_grants"),
            EvidenceToken("code", "Privacy mode gate", "functions/hub_api/api_app.py", "is_privacy_mode"),
            EvidenceToken("code", "Audit helper", "layers/shared/python/agent_hub/audit.py", "append_audit_entry"),
            EvidenceToken("code", "Metrics helper", "layers/shared/python/agent_hub/metrics.py", "emit_metric"),
            EvidenceToken("gui", "Observability page", "functions/hub_api/app.py", '@app.get("/observability"'),
            EvidenceToken("gui", "Audit page", "functions/hub_api/app.py", '@app.get("/audit"'),
            EvidenceToken("test", "Audit tests", "tests/test_audit.py", "test_"),
            EvidenceToken("test", "Planner privacy test", "tests/test_planner_integration_events.py", "privacy_mode"),
        ),
        known_limitations=(
            "Object Lock or bucket-retention guarantees are infrastructure configuration concerns and are not claimed from code-only evidence.",
        ),
    ),
    DesignObjective(
        objective_id="OBJ-09",
        title="GUI exposes V1 audit and operational surfaces",
        source="docs/design/MARVAIN_GLOBAL_DESIGN_OBJECTIVES_AND_REQUIREMENTS.md",
        requirement="GUI/API expose major V1 surfaces for memory, recognition, lineage, locations, sessions, observability, persona, and capabilities.",
        evidence=(
            EvidenceToken(
                "gui", "Capability matrix generator", "scripts/generate_capability_matrix.py", "MAJOR_CAPABILITY_PAGES"
            ),
            EvidenceToken(
                "gui",
                "Generated capability matrix",
                "docs/CAPABILITY_MATRIX.generated.md",
                "Major capability page exposure gaps: none.",
            ),
            EvidenceToken("gui", "TapDB graph route", "functions/hub_api/templates/base.html", "/tapdb/graph"),
            EvidenceToken("gui", "Capabilities route", "functions/hub_api/app.py", '@app.get("/capabilities"'),
            EvidenceToken("gui", "Persona route", "functions/hub_api/app.py", '@app.get("/personas"'),
            EvidenceToken(
                "test",
                "Capability exposure tests",
                "tests/test_capability_exposure.py",
                "test_major_capability_pages_have_route_or_template_exposure",
            ),
            EvidenceToken("test", "Round 2 GUI functional tests", "tests/test_round2_gui_functional.py", "recognition"),
        ),
    ),
    DesignObjective(
        objective_id="OBJ-10",
        title="Persona and context are configurable domain state",
        source="docs/design/MARVAIN_IMPLEMENTATION_PLAN_n2.md",
        requirement="Persona is configurable per agent/session rather than a hardcoded-only production path.",
        evidence=(
            EvidenceToken(
                "code",
                "Personas table",
                "sql/020_greenfield_semantic_lifecycle.sql",
                "CREATE TABLE IF NOT EXISTS personas",
            ),
            EvidenceToken(
                "code",
                "Sessions link persona",
                "sql/020_greenfield_semantic_lifecycle.sql",
                "persona_id uuid REFERENCES personas",
            ),
            EvidenceToken("gui", "Persona page", "functions/hub_api/app.py", '@app.get("/personas"'),
            EvidenceToken("gui", "Persona template", "functions/hub_api/templates/personas.html", "persona"),
            EvidenceToken(
                "test", "Persona/session contracts", "tests/test_persona_session_action_contracts.py", "persona"
            ),
            EvidenceToken(
                "test",
                "Template coverage",
                "tests/test_capability_exposure.py",
                "test_capability_inventory_uses_required_sources",
            ),
        ),
    ),
    DesignObjective(
        objective_id="OBJ-11",
        title="Generated evidence matrix and objective score are reproducible",
        source="docs/design/MARVAIN_CODEX_MAC_DESKTOP_PLANNING_PROMPT.md",
        requirement="Generated status maps objectives to repository evidence and supports an objective completion threshold.",
        evidence=(
            EvidenceToken(
                "code", "Objective scorer", "scripts/generate_design_objective_status.py", "def build_status"
            ),
            EvidenceToken(
                "docs", "Generated objective status", "docs/DESIGN_OBJECTIVE_STATUS.generated.md", "Minimum score gate"
            ),
            EvidenceToken(
                "test", "Scorer tests", "tests/test_design_objective_status.py", "test_minimum_score_gate_passes_at_90"
            ),
            EvidenceToken(
                "test",
                "Doc current test",
                "tests/test_design_objective_status.py",
                "test_generated_design_objective_status_doc_is_current",
            ),
        ),
    ),
    DesignObjective(
        objective_id="OBJ-12",
        title="E2E and deployed acceptance surface is explicit",
        source="docs/design/MARVAIN_V1_ACCEPTANCE_TESTS.md",
        requirement="At least one real deployed-stack smoke path and local/browser workflow path are represented without substituting local-only proof for deployed acceptance.",
        evidence=(
            EvidenceToken(
                "deployed",
                "Deployed stack contracts",
                "tests/e2e/test_stack_contracts.py",
                "pytestmark = pytest.mark.e2e",
            ),
            EvidenceToken(
                "deployed",
                "Hosted UI Playwright e2e",
                "tests/e2e/test_hosted_ui_login_playwright.py",
                "sync_playwright",
            ),
            EvidenceToken("test", "Local smoke command", "marvain_cli/smoke.py", "run_local_smoke"),
            EvidenceToken("deployed", "Real deployed smoke runner", "marvain_cli/smoke.py", "run_deployed_smoke"),
            EvidenceToken(
                "deployed",
                "Deployed two-device proof option",
                "marvain_cli/smoke.py",
                "include_two_device_proof",
            ),
            EvidenceToken("test", "Local smoke tests", "tests/test_local_smoke.py", "test_"),
            EvidenceToken(
                "gui", "Live session smoke route", "functions/hub_api/app.py", '@app.post("/api/live-session/smoke"'
            ),
        ),
        known_limitations=(
            "E2E tests are intentionally opt-in behind MARVAIN_E2E_ENABLED and hosted UI credentials; absence of those environment variables is an external blocker, not a static pass.",
        ),
    ),
    DesignObjective(
        objective_id="OBJ-13",
        title="Architecture purity guards block obsolete behavior",
        source="docs/design/MARVAIN_CODEX_MAC_DESKTOP_PLANNING_PROMPT.md",
        requirement="Tracked code and current design docs contain no production dummy recognizer path, stale TapDB copy, compatibility shim, or obsolete planning path.",
        evidence=(
            EvidenceToken(
                "test",
                "Architecture purity tests",
                "tests/test_architecture_purity.py",
                "test_no_obsolete_architecture_paths_remain",
            ),
            EvidenceToken(
                "test",
                "TapDB package schema test",
                "tests/test_tapdb_templates.py",
                "test_tapdb_base_schema_is_not_copied_into_marvain",
            ),
            EvidenceToken(
                "test",
                "Recognizer hard-failure test",
                "tests/test_recognition_worker_contract.py",
                "test_recognition_worker_requires_real_face_recognizer",
            ),
            EvidenceToken(
                "docs",
                "Round 4 gap report",
                "docs/reports/MARVAIN_ROUND4_GAP_ANALYSIS.md",
                "Architecture Purity Score",
            ),
        ),
    ),
)


def _has(root: Path, rel_path: str, token: str) -> bool:
    path = root / rel_path
    if not path.exists():
        return False
    return token in path.read_text(encoding="utf-8")


def _load_peer_script(file_name: str, module_name: str):
    path = Path(__file__).with_name(file_name)
    spec = importlib.util.spec_from_file_location(module_name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Could not load {file_name}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def score_objective(
    objective: DesignObjective, root: Path = ROOT
) -> tuple[int, tuple[EvidenceToken, ...], tuple[EvidenceToken, ...]]:
    present = tuple(item for item in objective.evidence if _has(root, item.rel_path, item.token))
    missing = tuple(item for item in objective.evidence if item not in present)
    score = round((len(present) / len(objective.evidence)) * 100) if objective.evidence else 0
    return score, present, missing


def architecture_purity_issues(root: Path = ROOT) -> list[str]:
    issues: list[str] = []
    if (root / "archive").exists():
        issues.append("archive directory is still tracked or present")
    if (root / "layers" / "shared" / "tapdb_schema").exists():
        issues.append("Marvain still carries a copied TapDB schema directory")

    paths: list[Path] = []
    for name in ARCHITECTURE_SCAN_ROOTS:
        base = root / name
        if base.is_file():
            paths.append(base)
        elif base.exists():
            paths.extend(path for path in base.rglob("*") if path.is_file())

    for path in sorted(paths):
        if any(part == "__pycache__" for part in path.parts):
            continue
        rel = str(path.relative_to(root))
        if rel == "scripts/generate_design_objective_status.py":
            continue
        if path.suffix not in {".py", ".sql", ".md", ".txt", ".yaml", ".yml", ".json", ".html"}:
            continue
        text = path.read_text(encoding="utf-8", errors="ignore")
        for token in ARCHITECTURE_FORBIDDEN_TOKENS:
            if token in text:
                issues.append(f"{rel}: contains obsolete token {token!r}")
    issues.extend(round5_hard_gate_issues(root))
    issues.extend(round7_hard_gate_issues(root))
    issues.extend(round6_coverage_gate_issues(root))
    issues.extend(capability_matrix_stale_issues(root))
    return issues


def round5_hard_gate_issues(root: Path = ROOT) -> list[str]:
    issues: list[str] = []

    taxonomy = (root / "layers" / "shared" / "python" / "agent_hub" / "memory_taxonomy.py").read_text(
        encoding="utf-8", errors="ignore"
    )
    for kind in ROUND5_MEMORY_KINDS:
        if f'"{kind}"' not in taxonomy:
            issues.append(f"memory taxonomy is missing canonical kind {kind!r}")

    required_taxonomy_users = {
        "functions/hub_api/app.py": "normalize_memory_kind",
        "functions/hub_api/api_app.py": "normalize_memory_kind",
        "layers/shared/python/agent_hub/tools/create_memory.py": "MEMORY_KIND_VALUES",
        "marvain_cli/smoke.py": "MEMORY_KIND_VALUES",
        "apps/agent_worker/worker.py": "classify_memory_event",
    }
    for rel, token in required_taxonomy_users.items():
        if token not in (root / rel).read_text(encoding="utf-8", errors="ignore"):
            issues.append(f"{rel}: does not use shared memory taxonomy token {token!r}")

    smoke = (root / "marvain_cli" / "smoke.py").read_text(encoding="utf-8", errors="ignore")
    if "run_deployed_smoke" not in smoke:
        issues.append("marvain_cli/smoke.py: missing real deployed smoke runner")
    if "v1-dev-contract" in smoke or '"mutates_runtime": False' in smoke:
        issues.append("marvain_cli/smoke.py: v1-dev still contains local/non-mutating contract behavior")
    if "--include-two-device-proof" not in smoke:
        issues.append("marvain_cli/smoke.py: missing deployed two-device proof option")
    issues.extend(deployed_smoke_placeholder_issues(root))

    app = (root / "functions" / "hub_api" / "app.py").read_text(encoding="utf-8", errors="ignore")
    for token in ('@app.get("/lineage"', '@app.get("/api/lineage/', 'name="gui_lineage"'):
        if token in app:
            issues.append(f"functions/hub_api/app.py: custom lineage route remains ({token})")
    if (root / "functions" / "hub_api" / "templates" / "lineage.html").exists():
        issues.append("functions/hub_api/templates/lineage.html: custom lineage template remains")

    semantic_tapdb = (root / "layers" / "shared" / "python" / "agent_hub" / "semantic_tapdb.py").read_text(
        encoding="utf-8", errors="ignore"
    )
    for token in ROUND5_TAPDB_INTERNAL_TOKENS:
        if token in semantic_tapdb:
            issues.append(f"semantic_tapdb.py: raw TapDB workaround token remains {token!r}")
    for token in ("SemanticTapDBClient", "daylily_tapdb.semantic"):
        if token in semantic_tapdb:
            issues.append(f"semantic_tapdb.py: invented TapDB semantic facade token remains {token!r}")
    for token in ("TAPDBConnection", "TemplateManager", "InstanceFactory", "find_object_by_euid", "build_graph_payload"):
        if token not in semantic_tapdb:
            issues.append(f"semantic_tapdb.py: missing approved TapDB/Bloom boundary token {token!r}")
    if "InMemoryTapdbSemanticStore" in semantic_tapdb:
        issues.append("semantic_tapdb.py: production module still contains an in-memory TapDB store")
    report = root / "docs" / "reports" / "MARVAIN_TAPDB_BOUNDARY_PATTERN.md"
    if not report.exists():
        issues.append("docs/reports/MARVAIN_TAPDB_BOUNDARY_PATTERN.md: missing approved TapDB boundary report")
    elif "does not introduce a new `daylily_tapdb.semantic.SemanticTapDBClient`" not in report.read_text(
        encoding="utf-8", errors="ignore"
    ):
        issues.append("docs/reports/MARVAIN_TAPDB_BOUNDARY_PATTERN.md: missing corrected no-facade TapDB decision")

    live_session = (root / "functions" / "hub_api" / "templates" / "live_session.html").read_text(
        encoding="utf-8", errors="ignore"
    )
    worker = (root / "apps" / "agent_worker" / "worker.py").read_text(encoding="utf-8", errors="ignore")
    if "camera_enabled_but_visual_analysis_unavailable" not in live_session:
        issues.append("live_session.html: missing hard camera-unavailable failure")
    if "visual_observation_ack" not in worker:
        issues.append("apps/agent_worker/worker.py: missing worker visual observation acknowledgement")

    return issues


def _function_source(text: str, function_name: str) -> str:
    marker = f"def {function_name}("
    start = text.find(marker)
    if start < 0:
        return ""
    next_function = text.find("\ndef ", start + len(marker))
    if next_function < 0:
        return text[start:]
    return text[start:next_function]


def deployed_smoke_placeholder_issues(root: Path = ROOT) -> list[str]:
    smoke_path = root / "marvain_cli" / "smoke.py"
    if not smoke_path.exists():
        return ["marvain_cli/smoke.py: missing real deployed smoke runner"]

    smoke = smoke_path.read_text(encoding="utf-8", errors="ignore")
    body = _function_source(smoke, "run_deployed_smoke")
    if not body:
        return ["marvain_cli/smoke.py: missing real deployed smoke runner"]

    issues: list[str] = []
    placeholder_tokens = {
        "run_local_smoke(": "delegates deployed smoke to local smoke",
        '"mutates_runtime": False': "declares non-mutating deployed smoke evidence",
        "'mutates_runtime': False": "declares non-mutating deployed smoke evidence",
        '"mode": "v1-dev-contract"': "returns the old local contract mode",
        "'mode': 'v1-dev-contract'": "returns the old local contract mode",
        "NotImplementedError": "leaves deployed smoke unimplemented",
    }
    for token, reason in placeholder_tokens.items():
        if token in body:
            issues.append(f"marvain_cli/smoke.py: run_deployed_smoke {reason}")
    if '"mutates_runtime": True' not in body and "'mutates_runtime': True" not in body:
        issues.append("marvain_cli/smoke.py: run_deployed_smoke does not declare mutating deployed evidence")
    if "_http_json(" not in body:
        issues.append("marvain_cli/smoke.py: run_deployed_smoke does not exercise deployed HTTP endpoints")
    return issues


def round6_coverage_gate_issues(root: Path = ROOT) -> list[str]:
    route_coverage = _load_peer_script("generate_route_coverage.py", "generate_route_coverage_for_status")
    coverage = route_coverage.build_coverage(root)
    issues: list[str] = []
    if coverage.api.percent < ROUND6_MIN_API_ROUTE_COVERAGE:
        issues.append(
            "scripts/generate_route_coverage.py: "
            f"API route coverage {coverage.api.percent}% is below {ROUND6_MIN_API_ROUTE_COVERAGE}%"
        )
    if coverage.gui.percent < ROUND6_MIN_GUI_ROUTE_COVERAGE:
        issues.append(
            "scripts/generate_route_coverage.py: "
            f"GUI route coverage {coverage.gui.percent}% is below {ROUND6_MIN_GUI_ROUTE_COVERAGE}%"
        )
    if coverage.playwright.percent < ROUND6_MIN_PLAYWRIGHT_WORKFLOW_COVERAGE:
        issues.append(
            "scripts/generate_route_coverage.py: "
            f"Playwright workflow coverage {coverage.playwright.percent}% "
            f"is below {ROUND6_MIN_PLAYWRIGHT_WORKFLOW_COVERAGE}%"
        )
    return issues


def round7_hard_gate_issues(root: Path = ROOT) -> list[str]:
    issues: list[str] = []

    taxonomy = (root / "layers" / "shared" / "python" / "agent_hub" / "memory_taxonomy.py").read_text(
        encoding="utf-8", errors="ignore"
    )
    for provenance_class in ROUND7_MEMORY_PROVENANCE_CLASSES:
        if f'"{provenance_class}"' not in taxonomy:
            issues.append(f"memory taxonomy is missing provenance class {provenance_class!r}")

    app = (root / "functions" / "hub_api" / "app.py").read_text(encoding="utf-8", errors="ignore")
    required_app_tokens = {
        "GET memory annotations": '@app.get("/api/memories/{memory_id}/annotations"',
        "POST memory annotations": '@app.post("/api/memories/{memory_id}/annotations"',
        "candidate edit rejection": "Agent-owned memory candidates cannot be edited directly",
        "agent maturity endpoint": '@app.get("/api/agents/{agent_id}/maturity"',
        "agent lifecycle request list": '@app.get("/api/agents/{agent_id}/lifecycle-requests"',
        "constitution revision endpoint": '@app.post("/api/agents/{agent_id}/constitution/revisions"',
        "agent backup endpoint": '@app.post("/api/agents/{agent_id}/backup"',
        "backup download endpoint": '@app.get("/api/backups/{backup_id}/download"',
    }
    for label, token in required_app_tokens.items():
        if token not in app:
            issues.append(f"functions/hub_api/app.py: missing Round 7 {label}")

    delete_agent_source = _function_source(app, "api_delete_agent")
    if "DELETE FROM agents" in delete_agent_source or "DROP " in delete_agent_source:
        issues.append("functions/hub_api/app.py: agent lifecycle endpoint still hard-deletes agents")
    if "soft_deleted" not in delete_agent_source or "stasis" not in delete_agent_source:
        issues.append("functions/hub_api/app.py: agent lifecycle endpoint does not enforce soft-delete/stasis states")

    candidate_patch_source = _function_source(app, "api_update_memory_candidate")
    if "UPDATE memory_candidates" in candidate_patch_source:
        issues.append("functions/hub_api/app.py: users can still directly mutate agent-owned memory candidates")

    worker = (root / "apps" / "agent_worker" / "worker.py").read_text(encoding="utf-8", errors="ignore")
    if "_fetch_contextual_recall_memories" not in worker or "space_id=None" not in worker:
        issues.append("apps/agent_worker/worker.py: recall hydration still appears scoped to the current space")
    if "CURRENT_SPACE_MEMORY_WEIGHT" not in worker:
        issues.append("apps/agent_worker/worker.py: recall hydration does not weight current-space context")

    export_ops = (root / "marvain_cli" / "ops.py").read_text(encoding="utf-8", errors="ignore")
    for section in ROUND7_BACKUP_SECTIONS:
        if f'"{section}"' not in export_ops:
            issues.append(f"marvain_cli/ops.py: agent export is missing backup section {section!r}")
    for excluded_section in ("memories", "events", "actions", "recognition_records"):
        if f'"{excluded_section}",' in export_ops and "plaintext_secret_values" not in export_ops:
            issues.append(f"marvain_cli/ops.py: export appears to exclude required section {excluded_section!r}")

    round7_sql_path = root / "sql" / "030_agent_memory_lifecycle_round7.sql"
    if not round7_sql_path.exists():
        issues.append("sql/030_agent_memory_lifecycle_round7.sql: missing Round 7 lifecycle schema")
    else:
        round7_sql = round7_sql_path.read_text(encoding="utf-8", errors="ignore")
        for table in (
            "memory_annotations",
            "memory_opinions",
            "agent_constitutions",
            "agent_constitution_revisions",
            "agent_lifecycle_requests",
            "agent_maturity_evidence",
            "agent_backup_manifests",
        ):
            if table not in round7_sql:
                issues.append(f"sql/030_agent_memory_lifecycle_round7.sql: missing table {table!r}")
        if "DELETE FROM" in round7_sql or "ON DELETE CASCADE" in round7_sql:
            issues.append("sql/030_agent_memory_lifecycle_round7.sql: contains hard-delete or cascade-delete behavior")

    for sql_path in sorted((root / "sql").glob("*.sql")):
        sql_text = sql_path.read_text(encoding="utf-8", errors="ignore").upper()
        if " ON DELETE CASCADE" in sql_text:
            issues.append(f"{sql_path.relative_to(root)}: contains cascade-delete behavior")
        if "DELETE FROM " in sql_text:
            issues.append(f"{sql_path.relative_to(root)}: contains hard-delete behavior")

    required_tests = {
        "tests/test_greenfield_schema.py": "test_round7_schema_models_core_object_deletes_as_lifecycle_not_hard_delete",
        "tests/test_gui_app.py": "test_memory_annotation_creates_non_mutating_user_opinion",
        "tests/test_gui_app.py#lifecycle": "test_agent_lifecycle_request_api_creates_agent_review_record",
        "tests/test_gui_app.py#constitution": "test_agent_constitution_revision_api_appends_versioned_sections",
        "tests/test_gui_app.py#backup": "test_agent_backup_api_records_full_restore_manifest",
        "tests/test_agent_worker_memory_hydration.py": "test_contextual_recall_uses_current_space_as_query_context_not_filter",
        "tests/test_agent_export_cli.py": "test_agent_export_includes_defining_records_and_secret_references_only",
        "tests/test_memory_taxonomy.py": "test_memory_provenance_taxonomy_covers_required_classes",
    }
    for rel, token in required_tests.items():
        path_rel = rel.split("#", 1)[0]
        text = (root / path_rel).read_text(encoding="utf-8", errors="ignore") if (root / path_rel).exists() else ""
        if token not in text:
            issues.append(f"{path_rel}: missing Round 7 test token {token!r}")

    return issues


def capability_matrix_stale_issues(root: Path = ROOT) -> list[str]:
    matrix = _load_peer_script("generate_capability_matrix.py", "generate_capability_matrix_for_status")
    out_file = root / "docs" / "CAPABILITY_MATRIX.generated.md"
    existing = out_file.read_text(encoding="utf-8") if out_file.exists() else ""
    expected = matrix.build_doc(root)
    if existing != expected:
        return ["docs/CAPABILITY_MATRIX.generated.md: capability matrix is out of date"]
    return []


def build_status(root: Path = ROOT) -> dict[str, object]:
    rows = []
    total_evidence = 0
    present_evidence = 0
    for objective in OBJECTIVES:
        score, present, missing = score_objective(objective, root)
        total_evidence += len(objective.evidence)
        present_evidence += len(present)
        rows.append(
            {
                "objective": objective,
                "score": score,
                "present": present,
                "missing": missing,
            }
        )
    total_score = round((present_evidence / total_evidence) * 100) if total_evidence else 0
    architecture_issues = architecture_purity_issues(root)
    if architecture_issues and total_score >= 90:
        total_score = 89
    return {
        "score": total_score,
        "present_evidence": present_evidence,
        "total_evidence": total_evidence,
        "rows": rows,
        "architecture_purity_issues": architecture_issues,
    }


def _status_label(score: int) -> str:
    if score == 100:
        return "PASS"
    if score >= 90:
        return "LIMITED"
    return "FAIL"


def _format_items(items: tuple[EvidenceToken, ...]) -> str:
    if not items:
        return "-"
    return "<br>".join(f"`{item.kind}: {item.label}` ({item.rel_path})" for item in items)


def build_doc(root: Path = ROOT, *, min_score: int = 90) -> str:
    status = build_status(root)
    score = int(status["score"])
    rows = status["rows"]
    lines = [
        "# Design Objective Status (Generated)",
        "",
        "This file is generated by `scripts/generate_design_objective_status.py`.",
        "Scores are deterministic repository-evidence checks. External deployed-stack blockers are listed as limitations, not counted as false passes.",
        "",
        f"Overall score: **{score}%** ({status['present_evidence']}/{status['total_evidence']} evidence checks present).",
        f"Minimum score gate: **{min_score}%**.",
        f"Gate status: **{'PASS' if score >= min_score else 'FAIL'}**.",
        "",
        "## Architecture Purity Gate",
        "",
    ]
    architecture_issues = status["architecture_purity_issues"]
    assert isinstance(architecture_issues, list)
    if architecture_issues:
        lines.append("Status: **FAIL**.")
        lines.extend(f"- {issue}" for issue in architecture_issues)
    else:
        lines.append(
            "Status: **PASS**. No obsolete architecture tokens or copied TapDB schema paths were found in active scan roots."
        )
    lines.extend(
        [
            "",
            "## Objective Evidence",
            "",
            "| Objective | Score | Status | Source | Evidence present | Missing evidence | Known limitations |",
            "|---|---:|---|---|---|---|---|",
        ]
    )
    for row in rows:
        objective = row["objective"]
        assert isinstance(objective, DesignObjective)
        objective_score = int(row["score"])
        limitations = "<br>".join(objective.known_limitations) if objective.known_limitations else "-"
        lines.append(
            "| "
            + " | ".join(
                [
                    f"`{objective.objective_id}` {objective.title}",
                    f"{objective_score}%",
                    _status_label(objective_score),
                    f"`{objective.source}`",
                    _format_items(row["present"]),
                    _format_items(row["missing"]),
                    limitations,
                ]
            )
            + " |"
        )
    lines.append("")
    lines.append("## Objective Requirements")
    lines.append("")
    for objective in OBJECTIVES:
        lines.append(f"- `{objective.objective_id}`: {objective.requirement}")
    lines.append("")
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true", help="Fail if generated output differs")
    parser.add_argument("--min-score", type=int, default=90, help="Minimum overall score required to pass")
    args = parser.parse_args()

    generated = build_doc(ROOT, min_score=args.min_score)
    status = build_status(ROOT)
    score = int(status["score"])

    if args.check:
        existing = OUT_FILE.read_text(encoding="utf-8") if OUT_FILE.exists() else ""
        if existing != generated:
            print("Design objective status doc is out of date. Re-run generator.")
            return 1
        if score < args.min_score:
            print(f"Design objective score {score}% is below required minimum {args.min_score}%.")
            return 1
        print(f"Design objective status doc is up to date; score {score}% >= {args.min_score}%.")
        return 0

    OUT_FILE.write_text(generated, encoding="utf-8")
    print(f"Wrote {OUT_FILE}")
    print(f"Design objective score: {score}%")
    if score < args.min_score:
        print(f"Design objective score {score}% is below required minimum {args.min_score}%.")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
