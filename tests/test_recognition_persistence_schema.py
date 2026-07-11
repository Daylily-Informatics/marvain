from __future__ import annotations

from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
SCHEMA_PATH = REPO_ROOT / "sql/schema.sql"


def test_recognition_schema_persists_reviewed_lifecycle_and_worker_health() -> None:
    sql = SCHEMA_PATH.read_text(encoding="utf-8")

    for table in (
        "recognition_observations",
        "recognition_hypotheses",
        "recognition_decisions",
        "recognition_no_matches",
        "biometric_projections",
        "presence_assertions",
        "recognition_workers",
        "recognition_worker_heartbeats",
    ):
        assert f"CREATE TABLE public.{table}" in sql

    for field in (
        "model_id text NOT NULL",
        "model_version text NOT NULL",
        "embedding_sha256 text NOT NULL",
        "reviewer_actor_type text NOT NULL",
        "reviewer_actor_id text NOT NULL",
        "reviewer_auth_subject text NOT NULL",
        "retention_until timestamp with time zone NOT NULL",
        "retraction_reason text",
        "retracted_by_decision_id uuid",
    ):
        assert field in sql

    assert "'ready'::text, 'degraded'::text, 'stopped'::text" in sql
    assert "recognition_decisions_hypothesis_uniq" in sql
    assert "recognition_no_matches_hypothesis_uniq" in sql
    assert "ON DELETE CASCADE" not in sql


def test_outbox_schema_persists_claim_attempt_and_reconciliation_history() -> None:
    sql = SCHEMA_PATH.read_text(encoding="utf-8")

    assert "CREATE TABLE public.semantic_outbox_dispatch_attempts" in sql
    assert "CREATE TABLE public.semantic_outbox_reconciliations" in sql
    assert "dispatch_cycle_attempt_count integer DEFAULT 0 NOT NULL" in sql
    assert "reconciliation_count integer DEFAULT 0 NOT NULL" in sql
    assert "'pending'::text, 'dispatching'::text, 'published'::text, 'failed'::text" in sql
    assert "semantic_outbox_dispatch_attempt_uniq" in sql
    assert "semantic_outbox_dispatch_attempts_message_idx" in sql


def test_recognition_artifacts_require_verified_upload_completion() -> None:
    sql = SCHEMA_PATH.read_text(encoding="utf-8")

    assert "'general'::text, 'recognition'::text, 'visual'::text" in sql
    assert "lifecycle_state text DEFAULT 'pending_upload'::text NOT NULL" in sql
    assert "verification_observed_at timestamp with time zone" in sql
    assert "actual_sha256 = expected_sha256" in sql
    assert "actual_byte_count = expected_byte_count" in sql
    assert "s3_version_id IS NOT NULL" in sql
    assert "s3_etag IS NOT NULL" in sql
