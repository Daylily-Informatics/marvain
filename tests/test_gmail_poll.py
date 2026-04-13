from __future__ import annotations

import importlib
import os
import sys
import unittest
from pathlib import Path
from unittest import mock

_ROOT = Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))
_SHARED = _ROOT / "layers" / "shared" / "python"
if str(_SHARED) not in sys.path:
    sys.path.insert(0, str(_SHARED))

from agent_hub.integrations.models import IntegrationMessageCreate, IntegrationMessageRecord, IntegrationMessageWriteResult


class _FakeDb:
    def __init__(self) -> None:
        self.events: list[str] = []
        self.execute_calls: list[tuple[str, dict[str, object], str | None]] = []

    def begin(self) -> str:
        self.events.append("begin")
        return "tx-1"

    def execute(self, sql: str, params: dict[str, object], transaction_id: str | None = None) -> None:
        self.execute_calls.append((sql, params, transaction_id))
        self.events.append("event_insert")

    def commit(self, transaction_id: str) -> None:
        self.events.append("commit")

    def rollback(self, transaction_id: str) -> None:
        self.events.append("rollback")


class TestGmailPollHandler(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        env = {
            "DB_RESOURCE_ARN": "arn:aws:rds:us-east-1:123:cluster:test",
            "DB_SECRET_ARN": "arn:aws:secretsmanager:us-east-1:123:secret:db",
            "DB_NAME": "agenthub",
            "INTEGRATION_QUEUE_URL": "https://sqs.us-east-1.amazonaws.com/123/IntegrationQueue",
        }
        with mock.patch.dict(os.environ, env, clear=False):
            module = importlib.import_module("functions.gmail_poll.handler")
            cls.mod = importlib.reload(module)
        cls._orig_db = cls.mod._db

    def setUp(self) -> None:
        self.mod._db = _FakeDb()
        self.mod._cfg = mock.Mock(integration_queue_url="https://sqs.us-east-1.amazonaws.com/123/IntegrationQueue")
        self.mod._sqs = mock.Mock()

    def tearDown(self) -> None:
        self.mod._db = self._orig_db

    def test_handler_commits_then_enqueues_then_updates_cursor(self) -> None:
        sequence: list[str] = []

        normalized = mock.Mock(
            integration_message=IntegrationMessageCreate(
                agent_id="agent-1",
                space_id="space-1",
                integration_account_id="acct-1",
                provider="gmail",
                channel_type="email",
                object_type="message",
                dedupe_key="gmail:user@example.com:m1",
                external_thread_id="thread-1",
                external_message_id="m1",
                body_text="hello",
            ),
            event_payload={"provider": "gmail"},
        )
        pending_record = IntegrationMessageRecord(
            integration_message_id="msg-1",
            agent_id="agent-1",
            space_id="space-1",
            provider="gmail",
            direction="inbound",
            channel_type="email",
            object_type="message",
            dedupe_key="gmail:user@example.com:m1",
            created_at="2026-04-13T00:00:00+00:00",
            updated_at="2026-04-13T00:00:00+00:00",
            integration_account_id="acct-1",
        )
        linked_record = IntegrationMessageRecord(
            integration_message_id="msg-1",
            agent_id="agent-1",
            space_id="space-1",
            event_id="event-1",
            provider="gmail",
            direction="inbound",
            channel_type="email",
            object_type="message",
            dedupe_key="gmail:user@example.com:m1",
            created_at="2026-04-13T00:00:00+00:00",
            updated_at="2026-04-13T00:00:00+00:00",
            integration_account_id="acct-1",
        )

        with (
            mock.patch.object(
                self.mod,
                "_load_active_gmail_accounts",
                return_value=[
                    {
                        "integration_account_id": "acct-1",
                        "agent_id": "agent-1",
                        "default_space_id": "space-1",
                        "credentials_secret_arn": "secret-1",
                    }
                ],
            ),
            mock.patch.object(self.mod, "get_integration_sync_state", return_value=mock.Mock(cursor="100")),
            mock.patch.object(self.mod, "load_gmail_credentials", return_value=mock.Mock(user_email="user@example.com")),
            mock.patch.object(self.mod, "refresh_gmail_access_token", return_value="token"),
            mock.patch.object(self.mod, "list_gmail_message_refs", return_value=([mock.Mock(message_id="m1")], "200")),
            mock.patch.object(self.mod, "fetch_gmail_message", return_value={"id": "m1"}),
            mock.patch.object(self.mod, "normalize_gmail_message", return_value=normalized),
            mock.patch.object(
                self.mod,
                "insert_integration_message",
                side_effect=lambda *args, **kwargs: IntegrationMessageWriteResult(message=pending_record, inserted=True),
            ),
            mock.patch.object(
                self.mod,
                "link_integration_message_event",
                side_effect=lambda *args, **kwargs: linked_record,
            ),
            mock.patch.object(
                self.mod,
                "enqueue_integration_event",
                side_effect=lambda *args, **kwargs: sequence.append("enqueue"),
            ),
            mock.patch.object(
                self.mod,
                "upsert_integration_sync_state",
                side_effect=lambda *args, **kwargs: sequence.append("cursor"),
            ),
        ):
            result = self.mod.handler({}, None)

        self.assertEqual(result["accounts_processed"], 1)
        self.assertEqual(result["messages_enqueued"], 1)
        self.assertIn("commit", self.mod._db.events)
        self.assertEqual(sequence, ["enqueue", "cursor"])

    def test_handler_does_not_advance_cursor_when_enqueue_fails(self) -> None:
        normalized = mock.Mock(
            integration_message=IntegrationMessageCreate(
                agent_id="agent-1",
                space_id="space-1",
                integration_account_id="acct-1",
                provider="gmail",
                channel_type="email",
                object_type="message",
                dedupe_key="gmail:user@example.com:m1",
                body_text="hello",
            ),
            event_payload={"provider": "gmail"},
        )
        pending_record = IntegrationMessageRecord(
            integration_message_id="msg-1",
            agent_id="agent-1",
            space_id="space-1",
            provider="gmail",
            direction="inbound",
            channel_type="email",
            object_type="message",
            dedupe_key="gmail:user@example.com:m1",
            created_at="2026-04-13T00:00:00+00:00",
            updated_at="2026-04-13T00:00:00+00:00",
            integration_account_id="acct-1",
        )
        linked_record = IntegrationMessageRecord(
            integration_message_id="msg-1",
            agent_id="agent-1",
            space_id="space-1",
            event_id="event-1",
            provider="gmail",
            direction="inbound",
            channel_type="email",
            object_type="message",
            dedupe_key="gmail:user@example.com:m1",
            created_at="2026-04-13T00:00:00+00:00",
            updated_at="2026-04-13T00:00:00+00:00",
            integration_account_id="acct-1",
        )

        with (
            mock.patch.object(
                self.mod,
                "_load_active_gmail_accounts",
                return_value=[
                    {
                        "integration_account_id": "acct-1",
                        "agent_id": "agent-1",
                        "default_space_id": "space-1",
                        "credentials_secret_arn": "secret-1",
                    }
                ],
            ),
            mock.patch.object(self.mod, "get_integration_sync_state", return_value=mock.Mock(cursor="100")),
            mock.patch.object(self.mod, "load_gmail_credentials", return_value=mock.Mock(user_email="user@example.com")),
            mock.patch.object(self.mod, "refresh_gmail_access_token", return_value="token"),
            mock.patch.object(self.mod, "list_gmail_message_refs", return_value=([mock.Mock(message_id="m1")], "200")),
            mock.patch.object(self.mod, "fetch_gmail_message", return_value={"id": "m1"}),
            mock.patch.object(self.mod, "normalize_gmail_message", return_value=normalized),
            mock.patch.object(
                self.mod,
                "insert_integration_message",
                side_effect=lambda *args, **kwargs: IntegrationMessageWriteResult(message=pending_record, inserted=True),
            ),
            mock.patch.object(
                self.mod,
                "link_integration_message_event",
                side_effect=lambda *args, **kwargs: linked_record,
            ),
            mock.patch.object(self.mod, "enqueue_integration_event", side_effect=RuntimeError("queue down")),
            mock.patch.object(self.mod, "upsert_integration_sync_state") as mock_upsert,
        ):
            result = self.mod.handler({}, None)

        self.assertEqual(result["cursor_updates"], 0)
        mock_upsert.assert_not_called()
        self.assertIn("commit", self.mod._db.events)


if __name__ == "__main__":
    unittest.main()
