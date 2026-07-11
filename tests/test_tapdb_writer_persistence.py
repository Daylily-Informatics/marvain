from __future__ import annotations

import json
import uuid
from contextlib import contextmanager
from types import SimpleNamespace
from typing import Any

import pytest
from agent_hub.semantic_outbox import (
    PersistedExternalReference,
    semantic_idempotency_key,
    semantic_record_target,
)

from functions.tapdb_writer import handler as writer

AGENT_ID = "11111111-1111-4111-8111-111111111111"
SOURCE_ID = "22222222-2222-4222-8222-222222222222"
RECEIPT_ID = uuid.UUID("33333333-3333-4333-8333-333333333333")


class FakeResult:
    def __init__(self, row: object | None = None) -> None:
        self.row = object() if row is None else row

    def one_or_none(self) -> object:
        return self.row


class FakeSession:
    def __init__(self) -> None:
        self.flush_count = 0
        self.execute_calls: list[tuple[str, dict[str, Any]]] = []

    def flush(self) -> None:
        self.flush_count += 1

    def execute(self, statement: Any, params: dict[str, Any]) -> FakeResult:
        statement_text = str(statement)
        self.execute_calls.append((statement_text, params))
        if "SELECT tapdb_euid, status" in statement_text:
            return FakeResult(SimpleNamespace(tapdb_euid="persisted-object-1", status="written"))
        return FakeResult()


class FakeConnection:
    def __init__(self) -> None:
        self.session = FakeSession()
        self.commit_flags: list[bool] = []

    @contextmanager
    def session_scope(self, *, commit: bool = False):
        self.commit_flags.append(commit)
        yield self.session


class FakeFactory:
    def __init__(self) -> None:
        self.created: list[dict[str, Any]] = []
        self.linked: list[dict[str, Any]] = []

    def create_instance(
        self,
        session: FakeSession,
        *,
        template_code: str,
        name: str,
        properties: dict[str, Any],
        create_children: bool,
    ) -> SimpleNamespace:
        self.created.append(
            {
                "template_code": template_code,
                "name": name,
                "properties": properties,
                "create_children": create_children,
            }
        )
        return SimpleNamespace(
            euid=f"persisted-object-{len(self.created)}",
            name=name,
            bstatus="created",
            json_addl={"properties": properties},
        )

    def link_instances(
        self,
        session: FakeSession,
        parent: SimpleNamespace,
        child: SimpleNamespace,
        *,
        relationship_type: str,
    ) -> SimpleNamespace:
        self.linked.append(
            {
                "parent": parent.euid,
                "child": child.euid,
                "relationship_type": relationship_type,
            }
        )
        return SimpleNamespace(euid=f"persisted-lineage-{len(self.linked)}")


class FakeStore:
    domain_code = "V"
    owner_repo_name = "marvain"

    def __init__(self) -> None:
        self.connection = FakeConnection()
        self.factory = FakeFactory()


def _record_payload() -> dict[str, Any]:
    reference = PersistedExternalReference.for_row(
        agent_id=AGENT_ID,
        source_table="events",
        source_id=SOURCE_ID,
    )
    template_code = semantic_record_target("MVN/event/sensor/1.0/")
    key = semantic_idempotency_key(reference, operation="record", target=template_code)
    return {
        "action": "record",
        "agent_id": AGENT_ID,
        "external_reference": reference.to_payload(),
        "idempotency_key": key,
        "lifecycle_state": "recorded",
        "name": f"event:{SOURCE_ID}",
        "properties": {"agent_id": AGENT_ID, "event_id": SOURCE_ID},
        "template_code": template_code,
    }


def test_writer_retry_uses_native_inbox_and_does_not_duplicate_objects(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = FakeStore()
    receipt_statuses = iter(("received", "processed"))
    transitions: list[tuple[str, uuid.UUID]] = []
    received_payloads: list[dict[str, Any]] = []

    def fake_receive_message(session: FakeSession, **kwargs: Any) -> SimpleNamespace:
        received_payloads.append(kwargs)
        return SimpleNamespace(status=next(receipt_statuses), receipt_machine_uuid=RECEIPT_ID)

    monkeypatch.setattr(writer, "_store", lambda: store)
    monkeypatch.setattr(writer, "receive_message", fake_receive_message)
    monkeypatch.setattr(
        writer,
        "mark_inbox_processing",
        lambda session, key: transitions.append(("processing", key)),
    )
    monkeypatch.setattr(
        writer,
        "mark_inbox_processed",
        lambda session, key: transitions.append(("processed", key)),
    )
    payload = _record_payload()

    first = writer._dispatch_idempotent(payload)
    second = writer._dispatch_idempotent(payload)

    assert first["duplicate"] is False
    assert first["semantic_id"] == "persisted-object-1"
    assert second == {
        "ok": True,
        "duplicate": True,
        "idempotency_key": payload["idempotency_key"],
        "receipt_id": str(RECEIPT_ID),
        "semantic_id": "persisted-object-1",
    }
    assert len(store.factory.created) == 2
    assert store.factory.created[1]["template_code"] == writer.EXTERNAL_REFERENCE_TEMPLATE_CODE
    assert store.factory.created[1]["properties"]["foreign_uid"] == (f"agent/{AGENT_ID}/events/{SOURCE_ID}")
    assert store.factory.linked == [
        {
            "parent": "persisted-object-1",
            "child": "persisted-object-2",
            "relationship_type": "has_external_reference",
        }
    ]
    assert transitions == [
        ("processing", uuid.UUID(payload["idempotency_key"])),
        ("processed", uuid.UUID(payload["idempotency_key"])),
    ]
    assert received_payloads[0]["source_destination"] == "tapdb_writer"
    assert store.connection.commit_flags == [True, True]
    assert len(store.connection.session.execute_calls) == 2
    assert "status = 'written'" in store.connection.session.execute_calls[0][0]
    assert "SELECT tapdb_euid, status" in store.connection.session.execute_calls[1][0]


def test_writer_failure_is_retriable_and_records_sync_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    store = FakeStore()
    transitions: list[str] = []

    monkeypatch.setattr(writer, "_store", lambda: store)
    monkeypatch.setattr(
        writer,
        "receive_message",
        lambda session, **kwargs: SimpleNamespace(status="received", receipt_machine_uuid=RECEIPT_ID),
    )
    monkeypatch.setattr(writer, "mark_inbox_processing", lambda session, key: transitions.append("processing"))
    monkeypatch.setattr(writer, "mark_inbox_processed", lambda session, key: transitions.append("processed"))
    monkeypatch.setattr(
        writer,
        "_dispatch_in_session",
        lambda *args, **kwargs: (_ for _ in ()).throw(RuntimeError("temporary TapDB failure")),
    )

    with pytest.raises(RuntimeError, match="temporary TapDB failure"):
        writer._dispatch_idempotent(_record_payload())

    assert transitions == ["processing"]
    assert store.connection.commit_flags == [True, True]
    assert len(store.connection.session.execute_calls) == 1
    statement, params = store.connection.session.execute_calls[0]
    assert "status = 'failed'" in statement
    assert params["last_error"] == "temporary TapDB failure"


def test_writer_rejects_idempotency_key_not_derived_from_reference(monkeypatch: pytest.MonkeyPatch) -> None:
    payload = _record_payload()
    payload["idempotency_key"] = "55555555-5555-4555-8555-555555555555"
    monkeypatch.setattr(writer, "_store", lambda: pytest.fail("store must not be opened for an invalid envelope"))

    with pytest.raises(ValueError, match="does not match"):
        writer._dispatch_idempotent(payload)


def test_process_sqs_batch_reports_only_failed_message_ids() -> None:
    records = [
        {"messageId": "message-1", "body": json.dumps({"sequence": 1})},
        {"messageId": "message-2", "body": json.dumps({"sequence": 2})},
        {"messageId": "message-3", "body": json.dumps({"sequence": 3})},
    ]

    def dispatch(payload: dict[str, Any]) -> dict[str, Any]:
        if payload["sequence"] == 2:
            raise RuntimeError("retry this item")
        return {"ok": True}

    result = writer.process_sqs_batch(records, dispatch=dispatch)

    assert result == {
        "ok": False,
        "processed": 2,
        "batchItemFailures": [{"itemIdentifier": "message-2"}],
    }


def test_process_sqs_batch_retries_invalid_json_and_requires_message_id() -> None:
    invalid = writer.process_sqs_batch(
        [{"messageId": "message-1", "body": "not-json"}],
        dispatch=lambda payload: {"ok": True},
    )
    assert invalid["batchItemFailures"] == [{"itemIdentifier": "message-1"}]

    with pytest.raises(ValueError, match="messageId"):
        writer.process_sqs_batch([{"body": "{}"}], dispatch=lambda payload: {"ok": True})
