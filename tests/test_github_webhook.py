from __future__ import annotations

import dataclasses
import hashlib
import hmac
import importlib.util
import json
import os
import sys
import unittest
import uuid
from pathlib import Path
from unittest import mock


AGENT_ID = "11111111-1111-1111-1111-111111111111"
SPACE_ID = "22222222-2222-2222-2222-222222222222"
INTEGRATION_ACCOUNT_ID = "55555555-5555-5555-5555-555555555555"
INTEGRATION_MESSAGE_ID = "33333333-3333-3333-3333-333333333333"
EVENT_ID = "44444444-4444-4444-4444-444444444444"
GITHUB_WEBHOOK_SECRET = "github-webhook-secret"


def _load_hub_api_app_module():
    repo_root = Path(__file__).resolve().parents[1]
    shared = repo_root / "layers" / "shared" / "python"
    if str(shared) not in sys.path:
        sys.path.insert(0, str(shared))

    hub_api_dir = repo_root / "functions" / "hub_api"
    if str(hub_api_dir) not in sys.path:
        sys.path.insert(0, str(hub_api_dir))

    os.environ.setdefault("AWS_DEFAULT_REGION", "us-west-2")
    os.environ.setdefault("DB_RESOURCE_ARN", "arn:aws:rds:us-west-2:123:cluster:dummy")
    os.environ.setdefault("DB_SECRET_ARN", "arn:aws:secretsmanager:us-west-2:123:secret:dummy")
    os.environ.setdefault("DB_NAME", "dummy")
    os.environ.setdefault("STAGE", "test")
    os.environ.setdefault("ENVIRONMENT", "test")
    os.environ.setdefault("HTTPS_ENABLED", "false")
    os.environ.setdefault("SESSION_SECRET_KEY", "test-session-secret")

    api_app_py = repo_root / "functions" / "hub_api" / "api_app.py"
    spec = importlib.util.spec_from_file_location("hub_api_api_app_for_tests_github", api_app_py)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    with mock.patch("boto3.client", return_value=mock.Mock()):
        spec.loader.exec_module(mod)
    return mod


def _github_signature(body: str, webhook_secret: str = GITHUB_WEBHOOK_SECRET) -> str:
    digest = hmac.new(webhook_secret.encode("utf-8"), body.encode("utf-8"), hashlib.sha256).hexdigest()
    return f"sha256={digest}"


def _integration_row(
    *,
    integration_message_id: str = INTEGRATION_MESSAGE_ID,
    agent_id: str = AGENT_ID,
    space_id: str | None = SPACE_ID,
    event_id: str | None = None,
    provider: str = "github",
    direction: str = "inbound",
    channel_type: str = "issue",
    object_type: str = "issue_comment",
    external_thread_id: str | None = "octo/repo#issue:7",
    external_message_id: str | None = "9001",
    dedupe_key: str = "github:delivery-1",
    sender_json: str = '{"login":"octocat","id":"42"}',
    recipients_json: str = '[{"repository":"octo/repo"}]',
    subject: str | None = None,
    body_text: str = "hello from github",
    body_html: str | None = None,
    payload_json: str = '{"action":"created"}',
    status: str = "received",
    created_at: str = "2026-04-12T00:00:00+00:00",
    updated_at: str = "2026-04-12T00:00:00+00:00",
    inserted: bool | None = None,
) -> dict[str, object]:
    row = {
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
        row["inserted"] = inserted
    return row


def _account_row() -> dict[str, object]:
    return {
        "integration_account_id": INTEGRATION_ACCOUNT_ID,
        "agent_id": AGENT_ID,
        "provider": "github",
        "display_name": "Primary GitHub",
        "external_account_id": "octo-org",
        "default_space_id": SPACE_ID,
        "credentials_secret_arn": "arn:aws:secretsmanager:us-east-1:123:secret:github-account",
        "scopes_json": "[]",
        "config_json": "{}",
        "status": "active",
        "created_at": "2026-04-12T00:00:00+00:00",
        "updated_at": "2026-04-12T00:00:00+00:00",
    }


class _ScriptedDb:
    def __init__(self, query_responses: list[list[dict[str, object]]]):
        self.query_responses = list(query_responses)
        self.query_calls: list[tuple[str, dict[str, object], str | None]] = []
        self.execute_calls: list[tuple[str, dict[str, object], str | None]] = []
        self.begin_calls = 0
        self.commit_calls: list[str] = []
        self.rollback_calls: list[str] = []

    def begin(self) -> str:
        self.begin_calls += 1
        return f"tx-{self.begin_calls}"

    def commit(self, transaction_id: str) -> None:
        self.commit_calls.append(transaction_id)

    def rollback(self, transaction_id: str) -> None:
        self.rollback_calls.append(transaction_id)

    def query(self, sql: str, params: dict[str, object] | None = None, *, transaction_id: str | None = None):
        self.query_calls.append((sql, params or {}, transaction_id))
        if not self.query_responses:
            return []
        return self.query_responses.pop(0)

    def execute(self, sql: str, params: dict[str, object] | None = None, *, transaction_id: str | None = None):
        self.execute_calls.append((sql, params or {}, transaction_id))
        return {}


class TestGitHubWebhook(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.mod = _load_hub_api_app_module()
        from fastapi.testclient import TestClient

        cls._TestClient = TestClient
        cls._orig_cfg = cls.mod._cfg
        cls._orig_get_db = cls.mod._get_db
        cls._orig_get_sqs = cls.mod._get_sqs
        cls._orig_get_secret_json = cls.mod.get_secret_json
        cls._orig_append_audit_entry = cls.mod.append_audit_entry
        cls._orig_is_agent_disabled = cls.mod.is_agent_disabled
        cls._orig_uuid4 = cls.mod.uuid.uuid4

    def setUp(self) -> None:
        self.client = self.__class__._TestClient(self.mod.api_app, raise_server_exceptions=False)
        self.mod._cfg = dataclasses.replace(
            self.__class__._orig_cfg,
            audit_bucket=None,
            integration_queue_url="https://sqs.us-east-1.amazonaws.com/123/IntegrationQueue",
        )
        self.mod.get_secret_json = mock.Mock(return_value={"webhook_secret": GITHUB_WEBHOOK_SECRET})
        self.mod.append_audit_entry = mock.Mock()
        self.mod.is_agent_disabled = mock.Mock(return_value=False)
        self.mod.uuid.uuid4 = mock.Mock(return_value=uuid.UUID(EVENT_ID))
        self.mock_sqs = mock.Mock()
        self.mod._get_sqs = mock.Mock(return_value=self.mock_sqs)

    def tearDown(self) -> None:
        self.mod._cfg = self.__class__._orig_cfg
        self.mod._get_db = self.__class__._orig_get_db
        self.mod._get_sqs = self.__class__._orig_get_sqs
        self.mod.get_secret_json = self.__class__._orig_get_secret_json
        self.mod.append_audit_entry = self.__class__._orig_append_audit_entry
        self.mod.is_agent_disabled = self.__class__._orig_is_agent_disabled
        self.mod.uuid.uuid4 = self.__class__._orig_uuid4

    def _post(
        self,
        payload: dict[str, object],
        *,
        event_name: str = "issue_comment",
        delivery_id: str = "delivery-1",
        signature: str | None = None,
    ):
        body = json.dumps(payload, separators=(",", ":"))
        headers = {
            "content-type": "application/json",
            "x-github-event": event_name,
            "x-github-delivery": delivery_id,
            "x-hub-signature-256": signature or _github_signature(body),
        }
        return self.client.post(
            f"/v1/integrations/github/webhook/{INTEGRATION_ACCOUNT_ID}",
            content=body,
            headers=headers,
        )

    def test_invalid_signature_is_rejected(self) -> None:
        self.mod._get_db = mock.Mock(return_value=_ScriptedDb([[_account_row()]]))

        response = self._post(
            {
                "repository": {"full_name": "octo/repo"},
                "issue": {"number": 7},
                "comment": {"id": 9001, "body": "hello"},
            },
            signature="sha256=invalid",
        )

        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.json()["detail"], "invalid GitHub signature")

    def test_missing_github_secret_fails_closed(self) -> None:
        self.mod.get_secret_json = mock.Mock(return_value={})
        self.mod._get_db = mock.Mock(return_value=_ScriptedDb([[_account_row()]]))

        response = self._post(
            {
                "repository": {"full_name": "octo/repo"},
                "issue": {"number": 7},
                "comment": {"id": 9001, "body": "hello"},
            }
        )

        self.assertEqual(response.status_code, 500)
        self.assertEqual(response.json()["detail"], "GitHub webhook secret not configured")

    def test_ping_is_ignored_without_side_effects(self) -> None:
        db = _ScriptedDb([[_account_row()]])
        self.mod._get_db = mock.Mock(return_value=db)

        response = self._post({"zen": "keep it logically awesome"}, event_name="ping")

        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.json()["ignored"])
        self.assertEqual(response.json()["reason"], "ignored_ping")
        self.assertEqual(db.begin_calls, 0)
        self.assertEqual(db.commit_calls, [])
        self.mock_sqs.send_message.assert_not_called()

    def test_issue_comment_stores_event_and_enqueues(self) -> None:
        db = _ScriptedDb(
            [
                [_account_row()],
                [_integration_row(inserted=True)],
                [_integration_row(event_id=EVENT_ID)],
            ]
        )
        self.mod._get_db = mock.Mock(return_value=db)

        response = self._post(
            {
                "action": "created",
                "repository": {"full_name": "octo/repo"},
                "sender": {"login": "octocat", "id": 42},
                "issue": {"number": 7, "title": "Need help"},
                "comment": {"id": 9001, "body": "hello from github"},
            }
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["event_id"], EVENT_ID)
        self.assertTrue(response.json()["inserted"])
        self.assertEqual(db.begin_calls, 1)
        self.assertEqual(db.commit_calls, ["tx-1"])
        self.assertEqual(db.rollback_calls, [])
        self.assertEqual(len(db.execute_calls), 1)
        insert_sql, insert_params, txid = db.execute_calls[0]
        self.assertIn("INSERT INTO events", insert_sql)
        self.assertEqual(txid, "tx-1")
        event_payload = json.loads(str(insert_params["payload"]))
        self.assertEqual(event_payload["provider"], "github")
        self.assertEqual(event_payload["github_event"], "issue_comment")
        self.assertEqual(event_payload["repository"], "octo/repo")
        self.assertEqual(event_payload["text"], "hello from github")
        self.assertEqual(event_payload["integration_message_id"], INTEGRATION_MESSAGE_ID)
        self.mock_sqs.send_message.assert_called_once()
        sent_body = json.loads(self.mock_sqs.send_message.call_args.kwargs["MessageBody"])
        self.assertEqual(sent_body["event_id"], EVENT_ID)
        self.assertEqual(sent_body["integration_message_id"], INTEGRATION_MESSAGE_ID)

    def test_duplicate_delivery_reuses_existing_event(self) -> None:
        db = _ScriptedDb(
            [
                [_account_row()],
                [_integration_row(inserted=False, event_id=EVENT_ID)],
            ]
        )
        self.mod._get_db = mock.Mock(return_value=db)

        response = self._post(
            {
                "action": "created",
                "repository": {"full_name": "octo/repo"},
                "sender": {"login": "octocat", "id": 42},
                "issue": {"number": 7, "title": "Need help"},
                "comment": {"id": 9001, "body": "hello from github"},
            }
        )

        self.assertEqual(response.status_code, 200)
        self.assertFalse(response.json()["inserted"])
        self.assertEqual(response.json()["event_id"], EVENT_ID)
        self.assertEqual(db.begin_calls, 1)
        self.assertEqual(db.commit_calls, ["tx-1"])
        self.assertEqual(len(db.execute_calls), 0)
        self.mock_sqs.send_message.assert_called_once()


if __name__ == "__main__":
    unittest.main()
