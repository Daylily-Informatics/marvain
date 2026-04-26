from __future__ import annotations

from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]


def test_greenfield_semantic_lifecycle_schema_declares_required_projections() -> None:
    sql = (REPO_ROOT / "sql/020_greenfield_semantic_lifecycle.sql").read_text(encoding="utf-8")

    for table in (
        "locations",
        "personas",
        "sessions",
        "artifact_references",
        "memory_candidates",
        "memory_tombstones",
        "recognition_observations",
        "recognition_hypotheses",
        "presence_assertions",
        "semantic_sync_status",
    ):
        assert f"CREATE TABLE IF NOT EXISTS {table}" in sql

    assert "ALTER TABLE spaces ADD COLUMN IF NOT EXISTS location_id" in sql
    assert "ALTER TABLE events ADD COLUMN IF NOT EXISTS session_id" in sql
    assert "ALTER TABLE memories ADD COLUMN IF NOT EXISTS lifecycle_state" in sql
    assert "ALTER TABLE memories ADD COLUMN IF NOT EXISTS tombstoned_at" in sql
    assert "ALTER TABLE actions ADD COLUMN IF NOT EXISTS session_id" in sql


def test_memory_deletes_are_modeled_as_tombstones_not_projection_hard_delete() -> None:
    api_text = (REPO_ROOT / "functions/hub_api/api_app.py").read_text(encoding="utf-8")
    gui_text = (REPO_ROOT / "functions/hub_api/app.py").read_text(encoding="utf-8")

    assert "INSERT INTO memory_tombstones" in api_text
    assert "INSERT INTO memory_tombstones" in gui_text
    assert "DELETE FROM memories WHERE memory_id" not in api_text
    assert "DELETE FROM memories WHERE memory_id" not in gui_text
