from __future__ import annotations

import sys
import unittest
from pathlib import Path

# Make the shared Lambda layer importable in local unit tests.
_SHARED = Path(__file__).resolve().parents[1] / "layers" / "shared" / "python"
if str(_SHARED) not in sys.path:
    sys.path.insert(0, str(_SHARED))

from agent_hub.integrations.models import IntegrationMessageCreate
from agent_hub.integrations.store import (
    get_integration_message,
    insert_integration_message,
    link_integration_message_event,
)


def _row(
    *,
    integration_message_id: str = "msg-1",
    agent_id: str = "agent-1",
    space_id: str | None = "space-1",
    event_id: str | None = None,
    provider: str = "slack",
    direction: str = "inbound",
    channel_type: str = "dm",
    object_type: str = "message",
    external_thread_id: str | None = "thread-1",
    external_message_id: str | None = "provider-msg-1",
    dedupe_key: str = "dedupe-1",
    sender_json: str = '{"id":"user-1"}',
    recipients_json: str = '[{"id":"user-2"}]',
    subject: str | None = None,
    body_text: str = "hello",
    body_html: str | None = None,
    payload_json: str = '{"raw":true}',
    status: str = "received",
    created_at: str = "2026-04-12T00:00:00+00:00",
    updated_at: str = "2026-04-12T00:00:00+00:00",
    inserted: bool | None = None,
) -> dict[str, object]:
    value = {
        "integration_message_id": integration_message_id,
        "agent_id": agent_id,
        "space_id": space_id,
        "event_id": event_id,
        "provider": provider,
        "direction": direction,
        "channel_type": channel_type,
        "object_type": object_type,
        "external_thread_id": external_thread_id,
        "external_message_id": external_message_id,
        "dedupe_key": dedupe_key,
        "sender_json": sender_json,
        "recipients_json": recipients_json,
        "subject": subject,
        "body_text": body_text,
        "body_html": body_html,
        "payload_json": payload_json,
        "status": status,
        "created_at": created_at,
        "updated_at": updated_at,
    }
    if inserted is not None:
        value["inserted"] = inserted
    return value


class _ScriptedDb:
    def __init__(self, responses: list[list[dict[str, object]]]):
        self.responses = list(responses)
        self.calls: list[tuple[str, dict[str, object], str | None]] = []

    def query(self, sql: str, params: dict[str, object] | None = None, *, transaction_id: str | None = None):
        self.calls.append((sql, params or {}, transaction_id))
        if not self.responses:
            return []
        return self.responses.pop(0)


class TestIntegrationMessagesMigration(unittest.TestCase):
    def test_migration_contains_expected_shape(self) -> None:
        path = Path(__file__).resolve().parents[1] / "sql" / "017_integration_messages.sql"
        text = path.read_text(encoding="utf-8")
        self.assertIn("CREATE TABLE IF NOT EXISTS integration_messages", text)
        self.assertIn("event_id uuid REFERENCES events(event_id) ON DELETE SET NULL", text)
        self.assertIn("CREATE UNIQUE INDEX IF NOT EXISTS integration_messages_agent_dedupe_idx", text)
        self.assertNotIn("integration_account_id", text)


class TestIntegrationMessageStore(unittest.TestCase):
    def test_insert_integration_message_returns_inserted_record(self) -> None:
        db = _ScriptedDb([[_row(inserted=True)]])
        message = IntegrationMessageCreate(
            agent_id="aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
            space_id="bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb",
            provider="slack",
            channel_type="dm",
            object_type="message",
            dedupe_key="slack:event:1",
            external_thread_id="thread-1",
            external_message_id="provider-msg-1",
            sender={"id": "user-1"},
            recipients=[{"id": "user-2"}],
            body_text="hello",
            payload={"raw": True},
        )

        result = insert_integration_message(db, message, transaction_id="tx-1")

        self.assertTrue(result.inserted)
        self.assertEqual(result.message.integration_message_id, "msg-1")
        self.assertEqual(result.message.provider, "slack")
        self.assertEqual(result.message.sender, {"id": "user-1"})
        self.assertEqual(result.message.recipients, [{"id": "user-2"}])
        self.assertEqual(result.message.payload, {"raw": True})
        sql, params, transaction_id = db.calls[0]
        self.assertIn("INSERT INTO integration_messages", sql)
        self.assertIn("ON CONFLICT (agent_id, dedupe_key) DO NOTHING", sql)
        self.assertEqual(transaction_id, "tx-1")
        self.assertEqual(params["dedupe_key"], "slack:event:1")
        self.assertEqual(params["sender"], '{"id": "user-1"}')
        self.assertEqual(params["recipients"], '[{"id": "user-2"}]')
        self.assertEqual(params["payload"], '{"raw": true}')

    def test_insert_integration_message_returns_existing_record_for_duplicate(self) -> None:
        db = _ScriptedDb([[_row(integration_message_id="msg-existing", inserted=False)]])
        message = IntegrationMessageCreate(
            agent_id="aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
            provider="github",
            channel_type="issue",
            object_type="comment",
            dedupe_key="github:event:1",
        )

        result = insert_integration_message(db, message)

        self.assertFalse(result.inserted)
        self.assertEqual(result.message.integration_message_id, "msg-existing")
        self.assertEqual(result.message.dedupe_key, "dedupe-1")

    def test_get_integration_message_returns_none_when_missing(self) -> None:
        db = _ScriptedDb([[]])
        result = get_integration_message(db, integration_message_id="msg-missing")
        self.assertIsNone(result)

    def test_link_integration_message_event_updates_row(self) -> None:
        db = _ScriptedDb([[_row(integration_message_id="msg-1", event_id="event-1")]])

        result = link_integration_message_event(
            db,
            integration_message_id="msg-1",
            event_id="event-1",
            transaction_id="tx-2",
        )

        self.assertEqual(result.event_id, "event-1")
        self.assertEqual(len(db.calls), 1)
        update_sql, update_params, transaction_id = db.calls[0]
        self.assertIn("UPDATE integration_messages", update_sql)
        self.assertIn("event_id IS NULL OR event_id = :event_id::uuid", update_sql)
        self.assertEqual(update_params["event_id"], "event-1")
        self.assertEqual(transaction_id, "tx-2")

    def test_link_integration_message_event_rejects_conflict_after_competing_update(self) -> None:
        db = _ScriptedDb(
            [
                [],
                [_row(integration_message_id="msg-1", event_id="event-existing")],
            ]
        )

        with self.assertRaisesRegex(RuntimeError, "already linked"):
            link_integration_message_event(
                db,
                integration_message_id="msg-1",
                event_id="event-new",
            )


if __name__ == "__main__":
    unittest.main()
