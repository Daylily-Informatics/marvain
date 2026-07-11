from __future__ import annotations

import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
SCHEMA_PATH = REPO_ROOT / "sql/schema.sql"

EXPECTED_TABLES = {
    "action_auto_approve_policies",
    "action_policy_decisions",
    "actions",
    "agent_backup_components",
    "agent_backup_manifests",
    "agent_constitution_revisions",
    "agent_constitutions",
    "agent_lifecycle_appeals",
    "agent_lifecycle_human_reviews",
    "agent_lifecycle_requests",
    "agent_lifecycle_second_agent_reviews",
    "agent_lifecycle_transitions",
    "agent_maturity_evidence",
    "agent_memberships",
    "agent_restore_attempts",
    "agent_tokens",
    "agents",
    "artifact_references",
    "audit_state",
    "biometric_projections",
    "consent_grants",
    "devices",
    "events",
    "faceprints",
    "integration_accounts",
    "integration_messages",
    "integration_sync_state",
    "locations",
    "memories",
    "memory_annotations",
    "memory_candidates",
    "memory_opinions",
    "memory_tombstones",
    "people",
    "person_accounts",
    "personas",
    "presence",
    "presence_assertions",
    "recognition_decisions",
    "recognition_hypotheses",
    "recognition_no_matches",
    "recognition_observations",
    "recognition_worker_heartbeats",
    "recognition_workers",
    "semantic_outbox",
    "semantic_outbox_dispatch_attempts",
    "semantic_outbox_reconciliations",
    "semantic_sync_status",
    "sessions",
    "spaces",
    "users",
    "voiceprints",
}

CYCLIC_FOREIGN_KEY_DDL = {
    (
        "ALTER TABLE public.agent_constitutions ADD CONSTRAINT "
        "agent_constitutions_active_revision_id_fkey FOREIGN KEY (active_revision_id) "
        "REFERENCES public.agent_constitution_revisions(revision_id) ON DELETE RESTRICT;"
    ),
    (
        "ALTER TABLE public.agent_lifecycle_requests ADD CONSTRAINT "
        "agent_lifecycle_requests_applied_transition_id_fkey FOREIGN KEY (applied_transition_id) "
        "REFERENCES public.agent_lifecycle_transitions(transition_id) ON DELETE RESTRICT;"
    ),
}


def _squash(sql: str) -> str:
    return " ".join(sql.split())


def _table_blocks(sql: str) -> dict[str, str]:
    return {
        match.group(1): match.group(2)
        for match in re.finditer(
            r"CREATE TABLE public\.([a-z0-9_]+) \((.*?)\n\);",
            sql,
            flags=re.DOTALL,
        )
    }


def test_schema_directory_contains_one_canonical_file() -> None:
    schema_files = sorted(path.relative_to(REPO_ROOT).as_posix() for path in (REPO_ROOT / "sql").glob("*.sql"))
    assert schema_files == ["sql/schema.sql"]
    assert not any(re.match(r"\d{3}[_-]", Path(path).name) for path in schema_files)


def test_schema_inventory_is_complete_and_explicit() -> None:
    sql = SCHEMA_PATH.read_text(encoding="utf-8")

    assert len(re.findall(r"^CREATE TABLE public\.", sql, flags=re.MULTILINE)) == 52
    assert len(re.findall(r"^CREATE (?:UNIQUE )?INDEX ", sql, flags=re.MULTILINE)) == 72
    assert len(re.findall(r"\bCONSTRAINT [a-z0-9_]+", sql)) == 323
    assert re.findall(r"^CREATE EXTENSION ([a-z0-9_]+) WITH SCHEMA public;", sql, flags=re.MULTILINE) == [
        "pgcrypto",
        "vector",
    ]
    assert "CREATE FUNCTION" not in sql
    assert "CREATE OR REPLACE FUNCTION" not in sql
    assert "CREATE TRIGGER" not in sql
    assert "CREATE CONSTRAINT TRIGGER" not in sql


def test_canonical_schema_contains_no_schema_history_or_destructive_ddl() -> None:
    sql = SCHEMA_PATH.read_text(encoding="utf-8")
    upper = sql.upper()
    lower = sql.lower()

    for forbidden in (
        "IF NOT EXISTS",
        "IF EXISTS",
        "ADD COLUMN",
        "DROP ",
        "DELETE FROM ",
        "TRUNCATE ",
        " ON DELETE CASCADE",
        "DO $$",
    ):
        assert forbidden not in upper

    for historical_term in ("migration", "backfill", "legacy", "compatibility"):
        assert re.search(rf"\b{historical_term}\b", lower) is None

    alter_statements = {
        _squash(match.group(0)) for match in re.finditer(r"ALTER TABLE public\..*?;", sql, flags=re.DOTALL)
    }
    assert alter_statements == CYCLIC_FOREIGN_KEY_DDL


def test_schema_table_order_satisfies_every_inline_foreign_key() -> None:
    sql = SCHEMA_PATH.read_text(encoding="utf-8")
    table_blocks = _table_blocks(sql)
    assert set(table_blocks) == EXPECTED_TABLES

    positions = {table: sql.index(f"CREATE TABLE public.{table} (") for table in table_blocks}
    for table, body in table_blocks.items():
        for referenced_table in re.findall(r"REFERENCES public\.([a-z0-9_]+)\(", body):
            if referenced_table != table:
                assert positions[referenced_table] < positions[table], (table, referenced_table)

    last_create = max(positions.values())
    for statement in CYCLIC_FOREIGN_KEY_DDL:
        assert sql.index(statement.split(" ADD CONSTRAINT", 1)[0]) > last_create


def test_core_semantic_projections_and_current_columns_are_declared_inline() -> None:
    sql = SCHEMA_PATH.read_text(encoding="utf-8")
    tables = _table_blocks(sql)

    for table in (
        "locations",
        "personas",
        "sessions",
        "artifact_references",
        "memory_candidates",
        "memory_tombstones",
        "recognition_observations",
        "recognition_hypotheses",
        "recognition_decisions",
        "recognition_no_matches",
        "biometric_projections",
        "presence_assertions",
        "semantic_sync_status",
        "semantic_outbox",
        "semantic_outbox_dispatch_attempts",
        "semantic_outbox_reconciliations",
    ):
        assert table in tables

    assert "location_id uuid" in tables["spaces"]
    assert "session_id uuid" in tables["events"]
    assert "lifecycle_state text" in tables["memories"]
    assert "tombstoned_at timestamp with time zone" in tables["memories"]
    assert "session_id uuid" in tables["actions"]


def test_sessions_use_only_canonical_runtime_states() -> None:
    sessions = _table_blocks(SCHEMA_PATH.read_text(encoding="utf-8"))["sessions"]

    assert "status text DEFAULT 'opening'::text NOT NULL" in sessions
    assert "status_event_id uuid" in sessions
    assert "status_changed_at timestamp with time zone" in sessions
    assert "sessions_status_event_id_fkey" not in sessions
    for state in ("opening", "active", "reconnecting", "closed", "failed", "reconciled"):
        assert f"'{state}'::text" in sessions
    assert "'open'::text" not in sessions
    assert "'paused'::text" not in sessions


def test_artifact_schema_requires_intent_and_verified_completion() -> None:
    sql = SCHEMA_PATH.read_text(encoding="utf-8")
    squashed = _squash(sql)
    artifact = _table_blocks(sql)["artifact_references"]

    for field in (
        "purpose text NOT NULL",
        "filename text NOT NULL",
        "device_id uuid NOT NULL",
        "source_event_id uuid",
        "expected_sha256 text NOT NULL",
        "actual_sha256 text",
        "expected_byte_count bigint NOT NULL",
        "actual_byte_count bigint",
        "lifecycle_state text DEFAULT 'pending_upload'::text NOT NULL",
        "upload_expires_at timestamp with time zone NOT NULL",
        "verification_observed_at timestamp with time zone",
        "completed_at timestamp with time zone",
        "s3_version_id text",
        "s3_etag text",
    ):
        assert field in artifact

    assert "purpose = ANY (ARRAY['general'::text, 'recognition'::text, 'visual'::text])" in artifact
    assert "actual_sha256 = expected_sha256" in artifact
    assert "actual_byte_count = expected_byte_count" in artifact
    assert "completed_at <= upload_expires_at" in artifact
    assert "artifact_references_device_id_fkey FOREIGN KEY (device_id) REFERENCES public.devices(device_id)" in squashed
    assert "artifact_references_source_event_id_fkey FOREIGN KEY (source_event_id)" in squashed
    assert "artifact_references_pending_upload_idx" in sql
    assert "artifact_references_retention_idx" in sql
    assert "artifact_references_source_event_idx" in sql
    assert "'deleted'" not in artifact


def test_agent_memory_lifecycle_and_backup_projections_are_current() -> None:
    sql = SCHEMA_PATH.read_text(encoding="utf-8")
    tables = _table_blocks(sql)

    for table in (
        "memory_annotations",
        "memory_opinions",
        "agent_constitutions",
        "agent_constitution_revisions",
        "agent_lifecycle_requests",
        "agent_lifecycle_second_agent_reviews",
        "agent_lifecycle_human_reviews",
        "agent_lifecycle_appeals",
        "agent_lifecycle_transitions",
        "agent_maturity_evidence",
        "agent_backup_manifests",
        "agent_backup_components",
        "agent_restore_attempts",
    ):
        assert table in tables

    for column in (
        "lifecycle_state text",
        "stasis_at timestamp with time zone",
        "soft_deleted_at timestamp with time zone",
        "maturity_state text",
        "maturity_evidence jsonb",
        "maturity_summary jsonb",
    ):
        assert column in tables["agents"]

    assert "provenance_class text" in tables["memories"]
    assert "provenance_class text" in tables["memory_candidates"]
    assert "soft_delete" in tables["agent_lifecycle_requests"]
    assert "soft_deleted" in tables["agents"]
    assert "mature" in tables["agents"]
    assert "author_authentication_id text NOT NULL" in tables["agent_constitution_revisions"]
    assert "change_source" not in sql
    for field in ("signature_algorithm", "signature_key_id", "signature_base64"):
        assert f"{field} text NOT NULL" in tables["agent_backup_manifests"]


def test_agent_owned_rows_use_restrictive_foreign_keys() -> None:
    squashed = _squash(SCHEMA_PATH.read_text(encoding="utf-8"))

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
        "integration_messages",
        "integration_accounts",
    ):
        assert (
            f"CONSTRAINT {table}_agent_id_fkey FOREIGN KEY (agent_id) "
            "REFERENCES public.agents(agent_id) ON DELETE RESTRICT"
        ) in squashed


def test_memory_deletes_are_modeled_as_tombstones_not_projection_hard_delete() -> None:
    api_text = (REPO_ROOT / "functions/hub_api/api_app.py").read_text(encoding="utf-8")
    gui_text = (REPO_ROOT / "functions/hub_api/app.py").read_text(encoding="utf-8")

    assert "INSERT INTO memory_tombstones" in api_text
    assert "INSERT INTO memory_tombstones" in gui_text
    assert "DELETE FROM memories WHERE memory_id" not in api_text
    assert "DELETE FROM memories WHERE memory_id" not in gui_text
