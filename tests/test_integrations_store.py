from __future__ import annotations

import sys
import unittest
from pathlib import Path

# Make the shared Lambda layer importable in local unit tests.
_SHARED = Path(__file__).resolve().parents[1] / "layers" / "shared" / "python"
if str(_SHARED) not in sys.path:
    sys.path.insert(0, str(_SHARED))

from agent_hub.integrations.models import IntegrationMessageCreate  # noqa: E402
from agent_hub.integrations.store import (  # noqa: E402
    create_integration_account,
    finalize_outbound_integration_message,
    get_integration_account,
    get_integration_message,
    get_integration_sync_state,
    insert_integration_message,
    link_integration_message_event,
    list_integration_accounts,
    list_integration_messages_for_thread,
    set_integration_message_status,
    update_integration_account,
    upsert_integration_sync_state,
)


def _row(
    *,
    integration_message_id: str = "msg-1",
    agent_id: str = "agent-1",
    space_id: str | None = "space-1",
    event_id: str | None = None,
    integration_account_id: str | None = None,
    action_id: str | None = None,
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
    contains_phi: bool = False,
    retention_until: str | None = None,
    processed_at: str | None = None,
    redacted_at: str | None = None,
    created_at: str = "2026-04-12T00:00:00+00:00",
    updated_at: str = "2026-04-12T00:00:00+00:00",
    inserted: bool | None = None,
) -> dict[str, object]:
    value = {
        "integration_message_id": integration_message_id,
        "agent_id": agent_id,
        "space_id": space_id,
        "event_id": event_id,
        "integration_account_id": integration_account_id,
        "action_id": action_id,
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
        "contains_phi": contains_phi,
        "retention_until": retention_until,
        "processed_at": processed_at,
        "redacted_at": redacted_at,
        "created_at": created_at,
        "updated_at": updated_at,
    }
    if inserted is not None:
        value["inserted"] = inserted
    return value


def _account_row(
    *,
    integration_account_id: str = "acct-1",
    agent_id: str = "agent-1",
    provider: str = "slack",
    display_name: str = "Primary Slack",
    external_account_id: str | None = "T123",
    default_space_id: str | None = "space-1",
    credentials_secret_arn: str = "arn:aws:secretsmanager:us-east-1:123:secret:stack/integrations/slack",
    scopes_json: str = '["chat:write"]',
    config_json: str = '{"channel_hint":"general"}',
    status: str = "active",
    created_at: str = "2026-04-12T00:00:00+00:00",
    updated_at: str = "2026-04-12T00:00:00+00:00",
) -> dict[str, object]:
    return {
        "integration_account_id": integration_account_id,
        "agent_id": agent_id,
        "provider": provider,
        "display_name": display_name,
        "external_account_id": external_account_id,
        "default_space_id": default_space_id,
        "credentials_secret_arn": credentials_secret_arn,
        "scopes_json": scopes_json,
        "config_json": config_json,
        "status": status,
        "created_at": created_at,
        "updated_at": updated_at,
    }


def _sync_state_row(
    *,
    integration_account_id: str = "acct-1",
    sync_key: str = "default",
    cursor: str | None = "cursor-1",
    state_json: str = '{"page_token":"x"}',
    updated_at: str = "2026-04-12T00:00:00+00:00",
) -> dict[str, object]:
    return {
        "integration_account_id": integration_account_id,
        "sync_key": sync_key,
        "cursor": cursor,
        "state_json": state_json,
        "updated_at": updated_at,
    }


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

    def test_follow_on_migrations_add_account_and_sync_state_tables(self) -> None:
        accounts_sql = (Path(__file__).resolve().parents[1] / "sql" / "018_integration_accounts.sql").read_text(
            encoding="utf-8"
        )
        sync_sql = (Path(__file__).resolve().parents[1] / "sql" / "019_integration_sync_state.sql").read_text(
            encoding="utf-8"
        )
        self.assertIn("CREATE TABLE IF NOT EXISTS integration_accounts", accounts_sql)
        self.assertIn("ADD COLUMN IF NOT EXISTS integration_account_id", accounts_sql)
        self.assertIn("ADD COLUMN IF NOT EXISTS action_id", accounts_sql)
        self.assertIn("ADD COLUMN IF NOT EXISTS contains_phi", accounts_sql)
        self.assertIn("CREATE TABLE IF NOT EXISTS integration_sync_state", sync_sql)
        self.assertIn("PRIMARY KEY (integration_account_id, sync_key)", sync_sql)


class TestIntegrationMessageStore(unittest.TestCase):
    # The repo does not currently expose a real Postgres fixture for the
    # integration store, so these tests lock the SQL compare-and-set contract.
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
        self.assertFalse(result.message.contains_phi)
        sql, params, transaction_id = db.calls[0]
        self.assertIn("INSERT INTO integration_messages", sql)
        self.assertIn("ON CONFLICT (agent_id, dedupe_key) DO NOTHING", sql)
        self.assertEqual(transaction_id, "tx-1")
        self.assertEqual(params["dedupe_key"], "slack:event:1")
        self.assertEqual(params["sender"], '{"id": "user-1"}')
        self.assertEqual(params["recipients"], '[{"id": "user-2"}]')
        self.assertEqual(params["payload"], '{"raw": true}')
        self.assertIsNone(params["integration_account_id"])
        self.assertIsNone(params["action_id"])

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
        normalized_update_sql = " ".join(update_sql.split())
        self.assertTrue(normalized_update_sql.startswith("UPDATE integration_messages"))
        self.assertIn(
            "SET event_id = CASE WHEN event_id IS NULL THEN :event_id::uuid ELSE event_id END",
            normalized_update_sql,
        )
        self.assertIn(
            "AND (event_id IS NULL OR event_id = :event_id::uuid)",
            normalized_update_sql,
        )
        self.assertEqual(update_params["event_id"], "event-1")
        self.assertEqual(transaction_id, "tx-2")

    def test_link_integration_message_event_is_idempotent_for_same_event_id(self) -> None:
        db = _ScriptedDb([[_row(integration_message_id="msg-1", event_id="event-1")]])

        result = link_integration_message_event(
            db,
            integration_message_id="msg-1",
            event_id="event-1",
        )

        self.assertEqual(result.event_id, "event-1")
        self.assertEqual(len(db.calls), 1)
        update_sql, update_params, _ = db.calls[0]
        normalized_update_sql = " ".join(update_sql.split())
        self.assertTrue(normalized_update_sql.startswith("UPDATE integration_messages"))
        self.assertIn(
            "AND (event_id IS NULL OR event_id = :event_id::uuid)",
            normalized_update_sql,
        )
        self.assertEqual(update_params["event_id"], "event-1")

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

        self.assertEqual(len(db.calls), 2)
        update_sql, update_params, _ = db.calls[0]
        self.assertIn("UPDATE integration_messages", update_sql)
        self.assertEqual(update_params["event_id"], "event-new")
        select_sql, select_params, _ = db.calls[1]
        self.assertIn("SELECT", select_sql)
        self.assertNotIn("UPDATE integration_messages", select_sql)
        self.assertEqual(select_params["integration_message_id"], "msg-1")

    def test_link_integration_message_event_raises_lookup_error_when_row_missing(self) -> None:
        db = _ScriptedDb([[], []])

        with self.assertRaisesRegex(LookupError, "not found"):
            link_integration_message_event(
                db,
                integration_message_id="missing",
                event_id="event-1",
            )

        self.assertEqual(len(db.calls), 2)
        update_sql, update_params, _ = db.calls[0]
        self.assertIn("UPDATE integration_messages", update_sql)
        self.assertEqual(update_params["integration_message_id"], "missing")
        select_sql, select_params, _ = db.calls[1]
        self.assertIn("SELECT", select_sql)
        self.assertEqual(select_params["integration_message_id"], "missing")

    def test_list_integration_messages_for_thread_returns_newest_first(self) -> None:
        db = _ScriptedDb(
            [
                [
                    _row(integration_message_id="msg-2", external_thread_id="thread-1"),
                    _row(integration_message_id="msg-1", external_thread_id="thread-1"),
                ]
            ]
        )

        result = list_integration_messages_for_thread(
            db,
            agent_id="aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
            provider="slack",
            external_thread_id="thread-1",
            exclude_integration_message_id="msg-current",
            limit=10,
        )

        self.assertEqual([item.integration_message_id for item in result], ["msg-2", "msg-1"])
        sql, params, _ = db.calls[0]
        self.assertIn("FROM integration_messages", sql)
        self.assertIn("external_thread_id = :external_thread_id", sql)
        self.assertIn("integration_message_id <>", sql)
        self.assertEqual(params["limit"], 10)

    def test_finalize_outbound_integration_message_updates_status_and_processed_at(self) -> None:
        db = _ScriptedDb(
            [
                [
                    _row(
                        integration_message_id="msg-1",
                        direction="outbound",
                        status="sent",
                        external_message_id="provider-msg-2",
                        action_id="action-1",
                        processed_at="2026-04-12T01:00:00+00:00",
                        payload_json='{"result":"ok"}',
                    )
                ]
            ]
        )

        result = finalize_outbound_integration_message(
            db,
            integration_message_id="msg-1",
            status="sent",
            payload={"result": "ok"},
            external_message_id="provider-msg-2",
            action_id="action-1",
        )

        self.assertEqual(result.status, "sent")
        self.assertEqual(result.action_id, "action-1")
        self.assertEqual(result.payload, {"result": "ok"})
        self.assertEqual(result.processed_at, "2026-04-12T01:00:00+00:00")
        sql, params, _ = db.calls[0]
        self.assertIn("processed_at = COALESCE(processed_at, now())", sql)
        self.assertEqual(params["status"], "sent")
        self.assertEqual(params["payload"], '{"result": "ok"}')

    def test_set_integration_message_status_updates_payload_metadata(self) -> None:
        db = _ScriptedDb(
            [
                [
                    _row(
                        integration_message_id="msg-1",
                        status="triaged",
                        processed_at="2026-04-12T01:30:00+00:00",
                        payload_json='{"existing":true,"status_update":{"status":"triaged","reason":"manual review"}}',
                    )
                ]
            ]
        )

        result = set_integration_message_status(
            db,
            integration_message_id="msg-1",
            status="triaged",
            reason="manual review",
        )

        self.assertEqual(result.status, "triaged")
        self.assertEqual(result.processed_at, "2026-04-12T01:30:00+00:00")
        self.assertEqual(result.payload["status_update"]["reason"], "manual review")
        sql, params, _ = db.calls[0]
        self.assertIn("jsonb_strip_nulls", sql)
        self.assertEqual(params["status"], "triaged")
        self.assertEqual(params["reason"], "manual review")


class TestIntegrationAccountStore(unittest.TestCase):
    def test_create_and_get_integration_account(self) -> None:
        db = _ScriptedDb([[_account_row()], [_account_row()]])

        created = create_integration_account(
            db,
            self._account_create(),
            transaction_id="tx-account",
        )
        fetched = get_integration_account(db, integration_account_id="acct-1")

        self.assertEqual(created.integration_account_id, "acct-1")
        self.assertEqual(created.scopes, ["chat:write"])
        self.assertEqual(created.config, {"channel_hint": "general"})
        self.assertEqual(fetched.integration_account_id, "acct-1")
        create_sql, create_params, tx = db.calls[0]
        self.assertIn("INSERT INTO integration_accounts", create_sql)
        self.assertEqual(create_params["scopes"], '["chat:write"]')
        self.assertEqual(tx, "tx-account")

    def test_list_integration_accounts_filters_by_provider_and_status(self) -> None:
        db = _ScriptedDb([[_account_row(), _account_row(integration_account_id="acct-2")]])

        result = list_integration_accounts(
            db,
            agent_id="aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
            provider="slack",
            status="active",
        )

        self.assertEqual(len(result), 2)
        sql, params, _ = db.calls[0]
        self.assertIn("FROM integration_accounts", sql)
        self.assertEqual(params["provider"], "slack")
        self.assertEqual(params["status"], "active")

    def test_update_integration_account_changes_requested_fields_only(self) -> None:
        from agent_hub.integrations.models import IntegrationAccountUpdate

        db = _ScriptedDb([[_account_row(display_name="Ops Slack", status="paused")]])

        result = update_integration_account(
            db,
            integration_account_id="acct-1",
            update=IntegrationAccountUpdate(display_name="Ops Slack", status="paused"),
        )

        self.assertEqual(result.display_name, "Ops Slack")
        self.assertEqual(result.status, "paused")
        sql, params, _ = db.calls[0]
        self.assertIn("UPDATE integration_accounts", sql)
        self.assertIn("display_name = :display_name", sql)
        self.assertEqual(params["display_name"], "Ops Slack")
        self.assertEqual(params["status"], "paused")

    @staticmethod
    def _account_create():
        from agent_hub.integrations.models import IntegrationAccountCreate

        return IntegrationAccountCreate(
            agent_id="aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
            provider="slack",
            display_name="Primary Slack",
            external_account_id="T123",
            default_space_id="bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb",
            credentials_secret_arn="arn:aws:secretsmanager:us-east-1:123:secret:stack/integrations/slack",
            scopes=["chat:write"],
            config={"channel_hint": "general"},
        )


class TestIntegrationSyncStateStore(unittest.TestCase):
    def test_get_and_upsert_integration_sync_state(self) -> None:
        db = _ScriptedDb([[_sync_state_row()], [_sync_state_row(cursor="cursor-2", state_json='{"cursor":"2"}')]])

        current = get_integration_sync_state(db, integration_account_id="acct-1")
        updated = upsert_integration_sync_state(
            db,
            integration_account_id="acct-1",
            cursor="cursor-2",
            state={"cursor": "2"},
        )

        self.assertEqual(current.cursor, "cursor-1")
        self.assertEqual(current.state, {"page_token": "x"})
        self.assertEqual(updated.cursor, "cursor-2")
        self.assertEqual(updated.state, {"cursor": "2"})
        upsert_sql, upsert_params, _ = db.calls[1]
        self.assertIn("ON CONFLICT (integration_account_id, sync_key)", upsert_sql)
        self.assertEqual(upsert_params["state"], '{"cursor": "2"}')


if __name__ == "__main__":
    unittest.main()
