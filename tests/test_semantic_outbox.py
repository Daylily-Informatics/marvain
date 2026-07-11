from __future__ import annotations

import uuid
from pathlib import Path
from typing import Any, Mapping

import pytest
from agent_hub.semantic_outbox import (
    PersistedExternalReference,
    SemanticOutboxError,
    enqueue_semantic_record,
    semantic_idempotency_key,
    semantic_record_target,
)

REPO_ROOT = Path(__file__).resolve().parents[1]
AGENT_ID = "11111111-1111-4111-8111-111111111111"
SOURCE_ID = "22222222-2222-4222-8222-222222222222"
OUTBOX_ID = "33333333-3333-4333-8333-333333333333"
SYNC_ID = "44444444-4444-4444-8444-444444444444"


class FakeDatabase:
    def __init__(self, rows: list[dict[str, Any]]) -> None:
        self.rows = rows
        self.calls: list[tuple[str, Mapping[str, Any] | None, str | None]] = []

    def query(
        self,
        sql: str,
        params: Mapping[str, Any] | None = None,
        *,
        transaction_id: str | None = None,
    ) -> list[dict[str, Any]]:
        self.calls.append((sql, params, transaction_id))
        return self.rows


def _database_with_returned_row() -> FakeDatabase:
    reference = PersistedExternalReference.for_row(
        agent_id=AGENT_ID,
        source_table="events",
        source_id=SOURCE_ID,
    )
    key = semantic_idempotency_key(
        reference,
        operation="record",
        target=semantic_record_target("MVN/event/sensor/1.0/"),
    )
    return FakeDatabase(
        [
            {
                "semantic_outbox_id": OUTBOX_ID,
                "semantic_sync_id": SYNC_ID,
                "agent_id": AGENT_ID,
                "idempotency_key": key,
            }
        ]
    )


def test_idempotency_key_is_stable_uuid_derived_from_persisted_reference() -> None:
    reference = PersistedExternalReference.for_row(
        agent_id=AGENT_ID,
        source_table="events",
        source_id=SOURCE_ID,
    )

    first = semantic_idempotency_key(
        reference,
        operation="record",
        target=semantic_record_target("MVN/event/sensor/1.0/"),
    )
    second = semantic_idempotency_key(
        PersistedExternalReference.from_payload(reference.to_payload()),
        operation="record",
        target=semantic_record_target("MVN/event/sensor/1.0"),
    )
    other_target = semantic_idempotency_key(
        reference,
        operation="record",
        target=semantic_record_target("MVN/event/transcript/1.0/"),
    )

    assert first == second
    assert first != other_target
    assert uuid.UUID(first).version == 5
    assert reference.foreign_uid == f"agent/{AGENT_ID}/events/{SOURCE_ID}"


def test_persisted_reference_rejects_forged_foreign_uid() -> None:
    reference = PersistedExternalReference.for_row(
        agent_id=AGENT_ID,
        source_table="events",
        source_id=SOURCE_ID,
    ).to_payload()
    reference["foreign_uid"] = "events/not-the-persisted-row"

    with pytest.raises(SemanticOutboxError, match="does not match"):
        PersistedExternalReference.from_payload(reference)


def test_enqueue_semantic_record_uses_callers_transaction_and_agent_scope() -> None:
    db = _database_with_returned_row()

    record = enqueue_semantic_record(
        db,
        transaction_id="source-transaction",
        agent_id=AGENT_ID,
        source_table="events",
        source_id=SOURCE_ID,
        target_template_code="MVN/event/sensor/1.0/",
        name=f"event:{SOURCE_ID}",
        lifecycle_state="recorded",
        properties={"event_id": SOURCE_ID, "event_type": "sensor"},
    )

    assert record.semantic_outbox_id == OUTBOX_ID
    assert record.semantic_sync_id == SYNC_ID
    assert record.agent_id == AGENT_ID
    assert record.payload["properties"]["agent_id"] == AGENT_ID
    assert record.payload["external_reference"] == {
        "system": "marvain-postgres",
        "foreign_uid": f"agent/{AGENT_ID}/events/{SOURCE_ID}",
        "agent_id": AGENT_ID,
        "source_table": "events",
        "source_id": SOURCE_ID,
    }

    assert len(db.calls) == 1
    sql, params, transaction_id = db.calls[0]
    assert transaction_id == "source-transaction"
    assert "INSERT INTO semantic_sync_status" in sql
    assert "INSERT INTO semantic_outbox" in sql
    assert "ON CONFLICT (agent_id, source_system, source_table, source_id, target_template_code)" in sql
    assert params is not None
    assert params["agent_id"] == AGENT_ID
    assert params["idempotency_key"] == record.idempotency_key
    assert params["payload_sha256"] == record.payload_sha256


def test_enqueue_semantic_record_requires_existing_source_transaction() -> None:
    db = _database_with_returned_row()

    with pytest.raises(SemanticOutboxError, match="transaction_id is required"):
        enqueue_semantic_record(
            db,
            transaction_id="",
            agent_id=AGENT_ID,
            source_table="events",
            source_id=SOURCE_ID,
            target_template_code="MVN/event/sensor/1.0/",
            name="event",
            lifecycle_state="recorded",
            properties={},
        )

    assert db.calls == []


def test_enqueue_semantic_record_rejects_cross_agent_properties() -> None:
    db = _database_with_returned_row()

    with pytest.raises(SemanticOutboxError, match="properties.agent_id"):
        enqueue_semantic_record(
            db,
            transaction_id="source-transaction",
            agent_id=AGENT_ID,
            source_table="events",
            source_id=SOURCE_ID,
            target_template_code="MVN/event/sensor/1.0/",
            name="event",
            lifecycle_state="recorded",
            properties={"agent_id": "55555555-5555-4555-8555-555555555555"},
        )

    assert db.calls == []


def test_enqueue_semantic_record_rejects_payload_conflict() -> None:
    db = FakeDatabase([])

    with pytest.raises(SemanticOutboxError, match="different payload"):
        enqueue_semantic_record(
            db,
            transaction_id="source-transaction",
            agent_id=AGENT_ID,
            source_table="events",
            source_id=SOURCE_ID,
            target_template_code="MVN/event/sensor/1.0/",
            name="event",
            lifecycle_state="recorded",
            properties={},
        )


def test_canonical_schema_scopes_sync_and_outbox_rows_by_agent() -> None:
    sql = (REPO_ROOT / "sql" / "schema.sql").read_text(encoding="utf-8")
    squashed = " ".join(sql.split())

    assert "CREATE TABLE public.semantic_outbox" in sql
    assert "source_external_reference jsonb NOT NULL" in sql
    assert "idempotency_key uuid NOT NULL" in sql
    assert "semantic_sync_status_agent_state_idx" in sql
    assert "semantic_outbox_dispatch_idx" in sql
    assert (
        "CONSTRAINT semantic_sync_status_source_uniq UNIQUE (agent_id, source_system, source_table, source_id, "
        "target_template_code)"
    ) in squashed
    assert "CONSTRAINT semantic_sync_status_idempotency_uniq UNIQUE (agent_id, idempotency_key)" in squashed
    assert "CONSTRAINT semantic_outbox_idempotency_uniq UNIQUE (agent_id, idempotency_key)" in squashed
    assert "semantic_sync_status_source_idx" not in sql
