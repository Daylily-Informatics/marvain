from __future__ import annotations

from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]


def test_agent_worker_resolves_configured_persona_and_includes_provenance_context() -> None:
    worker = (REPO_ROOT / "apps" / "agent_worker" / "worker.py").read_text(encoding="utf-8")

    assert "BASE_INSTRUCTIONS" not in worker
    assert "def _resolve_persona" in worker
    assert "MARVAIN_AGENT_PERSONA_INSTRUCTIONS" in worker
    assert "/v1/agents/{agent_id}/personas/default" in worker
    assert "source_event_id" in worker
    assert "session_id" in worker


def test_hub_persists_livekit_sessions_and_exposes_default_persona_endpoint() -> None:
    api = (REPO_ROOT / "functions" / "hub_api" / "api_app.py").read_text(encoding="utf-8")

    assert "INSERT INTO sessions" in api
    assert '"session_id": session_id' in api
    assert '@api_app.get("/v1/agents/{agent_id}/personas/default"' in api
    assert "Default persona not configured" in api


def test_memory_create_records_evidence_candidate_and_committed_projection() -> None:
    api = (REPO_ROOT / "functions" / "hub_api" / "api_app.py").read_text(encoding="utf-8")

    assert "space_id is required for memory evidence" in api
    assert "'memory.evidence'" in api
    assert "INSERT INTO memory_candidates" in api
    assert "memory_candidate_id" in api
    assert "source_event_id" in api


def test_bootstrap_seeds_default_persona_for_running_agent() -> None:
    ops = (REPO_ROOT / "marvain_cli" / "ops.py").read_text(encoding="utf-8")

    assert "DEFAULT_AGENT_PERSONA_INSTRUCTIONS" in ops
    assert "INSERT INTO personas" in ops
    assert "persona_id" in ops


def test_action_lifecycle_records_proposal_approval_execution_and_result() -> None:
    lifecycle = (REPO_ROOT / "layers" / "shared" / "python" / "agent_hub" / "semantic_lifecycle.py").read_text(
        encoding="utf-8"
    )

    for method in (
        "record_action_proposal",
        "record_action_approval",
        "record_action_execution",
        "record_action_result",
    ):
        assert method in lifecycle
