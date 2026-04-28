from __future__ import annotations

from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]


ROUND7_SQL = REPO_ROOT / "sql/030_agent_memory_lifecycle_round7.sql"


def _squash_sql(sql: str) -> str:
    return " ".join(sql.split())


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


def test_round7_schema_models_core_object_deletes_as_lifecycle_not_hard_delete() -> None:
    sql = ROUND7_SQL.read_text(encoding="utf-8")

    assert "lifecycle_state IN ('active', 'stasis', 'soft_deleted', 'deleted')" in sql
    assert "request_type IN ('stasis', 'resume', 'soft_delete', 'deletion')" in sql
    assert "DELETE FROM " not in sql
    assert " ON DELETE CASCADE" not in sql


def test_tracked_schema_files_do_not_define_hard_delete_cascades() -> None:
    for path in sorted((REPO_ROOT / "sql").glob("*.sql")):
        sql = path.read_text(encoding="utf-8").upper()
        assert " ON DELETE CASCADE" not in sql, path.name
        assert "DELETE FROM " not in sql, path.name


def test_round7_agent_memory_lifecycle_schema_declares_required_projections() -> None:
    sql = ROUND7_SQL.read_text(encoding="utf-8")

    for table in (
        "memory_annotations",
        "memory_opinions",
        "agent_constitutions",
        "agent_constitution_revisions",
        "agent_lifecycle_requests",
        "agent_maturity_evidence",
        "agent_backup_manifests",
    ):
        assert f"CREATE TABLE IF NOT EXISTS {table}" in sql

    for column in (
        "ALTER TABLE agents ADD COLUMN IF NOT EXISTS lifecycle_state",
        "ALTER TABLE agents ADD COLUMN IF NOT EXISTS stasis_at",
        "ALTER TABLE agents ADD COLUMN IF NOT EXISTS soft_deleted_at",
        "ALTER TABLE agents ADD COLUMN IF NOT EXISTS deleted_at",
        "ALTER TABLE agents ADD COLUMN IF NOT EXISTS maturity_state",
        "ALTER TABLE agents ADD COLUMN IF NOT EXISTS maturity_evidence",
        "ALTER TABLE agents ADD COLUMN IF NOT EXISTS maturity_summary",
        "ALTER TABLE memories ADD COLUMN IF NOT EXISTS provenance_class",
        "ALTER TABLE memory_candidates ADD COLUMN IF NOT EXISTS provenance_class",
    ):
        assert column in sql

    assert "request_type IN ('stasis', 'resume', 'soft_delete', 'deletion')" in sql
    assert "maturity_state IN ('immature', 'maturing', 'mature', 'regressed')" in sql
    assert "stance IN ('supports', 'disputes', 'refines', 'deprecates', 'neutral')" in sql
    assert "agent_constitutions_active_revision_id_fkey" in sql


def test_round7_schema_guards_agent_owned_product_rows_from_cascade_delete() -> None:
    sql = ROUND7_SQL.read_text(encoding="utf-8")
    squashed = _squash_sql(sql)

    for table in (
        "spaces",
        "agent_memberships",
        "devices",
        "people",
        "consent_grants",
        "person_accounts",
        "presence",
        "events",
        "memories",
        "actions",
        "action_auto_approve_policies",
        "audit_state",
        "locations",
        "personas",
        "sessions",
        "artifact_references",
        "memory_candidates",
        "memory_tombstones",
        "recognition_observations",
        "presence_assertions",
        "voiceprints",
        "faceprints",
        "integration_messages",
        "integration_accounts",
    ):
        constraint = f"{table}_agent_id_fkey"
        assert f"ALTER TABLE IF EXISTS {table} DROP CONSTRAINT IF EXISTS {constraint}" in sql
        assert (
            f"ADD CONSTRAINT {constraint} FOREIGN KEY (agent_id) REFERENCES agents(agent_id) ON DELETE RESTRICT"
        ) in squashed


def test_round7_schema_guards_product_evidence_child_rows_from_cascade_delete() -> None:
    sql = ROUND7_SQL.read_text(encoding="utf-8")
    squashed = _squash_sql(sql)

    for table, column, parent_table, parent_column in (
        ("agent_tokens", "issuer_agent_id", "agents", "agent_id"),
        ("agent_tokens", "target_agent_id", "agents", "agent_id"),
        ("consent_grants", "person_id", "people", "person_id"),
        ("person_accounts", "person_id", "people", "person_id"),
        ("presence", "space_id", "spaces", "space_id"),
        ("events", "space_id", "spaces", "space_id"),
        ("action_policy_decisions", "action_id", "actions", "action_id"),
        (
            "recognition_hypotheses",
            "recognition_observation_id",
            "recognition_observations",
            "recognition_observation_id",
        ),
        ("voiceprints", "person_id", "people", "person_id"),
        ("faceprints", "person_id", "people", "person_id"),
        (
            "integration_sync_state",
            "integration_account_id",
            "integration_accounts",
            "integration_account_id",
        ),
    ):
        constraint = f"{table}_{column}_fkey"
        assert f"ALTER TABLE IF EXISTS {table} DROP CONSTRAINT IF EXISTS {constraint}" in sql
        assert (f"FOREIGN KEY ({column}) REFERENCES {parent_table}({parent_column}) ON DELETE RESTRICT") in squashed


def test_round7_schema_does_not_introduce_hard_delete_or_compatibility_paths() -> None:
    sql = ROUND7_SQL.read_text(encoding="utf-8").upper()

    assert " ON DELETE CASCADE" not in sql
    assert "DELETE FROM " not in sql
    assert "DROP TABLE" not in sql
    assert "TRUNCATE " not in sql
