from __future__ import annotations

import dataclasses
import hashlib
import hmac
import importlib.util
import json
import os
import sys
import time
import unittest
import uuid
from base64 import b64encode
from pathlib import Path
from urllib.parse import urlencode
from unittest import mock


AGENT_ID = "11111111-1111-1111-1111-111111111111"
SPACE_ID = "22222222-2222-2222-2222-222222222222"
INTEGRATION_MESSAGE_ID = "33333333-3333-3333-3333-333333333333"
EVENT_ID = "44444444-4444-4444-4444-444444444444"
TWILIO_ACCOUNT_SID = "AC123"
TWILIO_AUTH_TOKEN = "twilio-auth-token"


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
    spec = importlib.util.spec_from_file_location("hub_api_api_app_for_tests_twilio", api_app_py)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    with mock.patch("boto3.client", return_value=mock.Mock()):
        spec.loader.exec_module(mod)
    return mod


def _twilio_signature(url: str, payload: dict[str, str], auth_token: str = TWILIO_AUTH_TOKEN) -> str:
    base = url
    for key in sorted(set(payload)):
        base += f"{key}{payload[key]}"
    digest = hmac.new(auth_token.encode("utf-8"), base.encode("utf-8"), hashlib.sha1).digest()
    return b64encode(digest).decode("utf-8")


def _integration_row(
    *,
    integration_message_id: str = INTEGRATION_MESSAGE_ID,
    agent_id: str = AGENT_ID,
    space_id: str | None = SPACE_ID,
    event_id: str | None = None,
    provider: str = "twilio",
    direction: str = "inbound",
    channel_type: str = "sms",
    object_type: str = "sms",
    external_thread_id: str | None = "+15551230001:+15551239999",
    external_message_id: str | None = "SM123",
    dedupe_key: str = "twilio:AC123:SM123",
    sender_json: str = '{"account_sid":"AC123","phone_number":"+15551230001"}',
    recipients_json: str = '[{"phone_number":"+15551239999"}]',
    subject: str | None = None,
    body_text: str = "hello from twilio",
    body_html: str | None = None,
    payload_json: str = '{"Body":"hello from twilio"}',
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


class TestTwilioWebhook(unittest.TestCase):
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
            twilio_secret_arn="arn:aws:secretsmanager:us-east-1:123:secret:twilio",
        )
        self.mod.get_secret_json = mock.Mock(
            return_value={
                "account_sid": TWILIO_ACCOUNT_SID,
                "auth_token": TWILIO_AUTH_TOKEN,
                "from_number": "+15551239999",
            }
        )
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

    def _post(self, payload: dict[str, str], *, signature: str | None = None):
        body = urlencode(payload).encode("utf-8")
        url = f"http://testserver/v1/integrations/twilio/webhook/{AGENT_ID}/{SPACE_ID}"
        headers = {
            "content-type": "application/x-www-form-urlencoded",
            "x-twilio-signature": signature or _twilio_signature(url, payload),
        }
        return self.client.post(
            f"/v1/integrations/twilio/webhook/{AGENT_ID}/{SPACE_ID}",
            content=body,
            headers=headers,
        )

    def test_invalid_signature_is_rejected(self) -> None:
        self.mod._get_db = mock.Mock(return_value=_ScriptedDb([]))

        response = self._post(
            {
                "AccountSid": TWILIO_ACCOUNT_SID,
                "MessageSid": "SM123",
                "From": "+15551230001",
                "To": "+15551239999",
                "Body": "hello",
            },
            signature="invalid",
        )

        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.json()["detail"], "invalid Twilio signature")

    def test_missing_twilio_secret_fails_closed(self) -> None:
        self.mod._cfg = dataclasses.replace(self.mod._cfg, twilio_secret_arn=None)
        self.mod._get_db = mock.Mock(return_value=_ScriptedDb([]))

        response = self._post(
            {
                "AccountSid": TWILIO_ACCOUNT_SID,
                "MessageSid": "SM123",
                "From": "+15551230001",
                "To": "+15551239999",
                "Body": "hello",
            }
        )

        self.assertEqual(response.status_code, 500)
        self.assertEqual(response.json()["detail"], "TWILIO_SECRET_ARN not configured")

    def test_sms_stores_event_and_enqueues(self) -> None:
        db = _ScriptedDb(
            [
                [{"ok": True}],
                [_integration_row(inserted=True)],
                [_integration_row(event_id=EVENT_ID)],
            ]
        )
        self.mod._get_db = mock.Mock(return_value=db)

        response = self._post(
            {
                "AccountSid": TWILIO_ACCOUNT_SID,
                "MessageSid": "SM123",
                "SmsSid": "SM123",
                "From": "+15551230001",
                "To": "+15551239999",
                "Body": "hello from twilio",
                "NumMedia": "0",
            }
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.text, "")
        self.assertEqual(db.begin_calls, 1)
        self.assertEqual(db.commit_calls, ["tx-1"])
        self.assertEqual(db.rollback_calls, [])
        self.assertEqual(len(db.execute_calls), 1)
        insert_sql, insert_params, txid = db.execute_calls[0]
        self.assertIn("INSERT INTO events", insert_sql)
        self.assertEqual(txid, "tx-1")
        event_payload = json.loads(str(insert_params["payload"]))
        self.assertEqual(event_payload["integration_message_id"], INTEGRATION_MESSAGE_ID)
        self.assertEqual(event_payload["provider"], "twilio")
        self.assertEqual(event_payload["text"], "hello from twilio")

        self.mock_sqs.send_message.assert_called_once()
        queue_call = self.mock_sqs.send_message.call_args.kwargs
        self.assertEqual(queue_call["QueueUrl"], self.mod._cfg.integration_queue_url)
        message_body = json.loads(queue_call["MessageBody"])
        self.assertEqual(message_body["event_id"], EVENT_ID)
        self.assertEqual(message_body["agent_id"], AGENT_ID)
        self.assertEqual(message_body["space_id"], SPACE_ID)
        self.assertEqual(message_body["integration_message_id"], INTEGRATION_MESSAGE_ID)

    def test_duplicate_sms_returns_success_and_reenqueues(self) -> None:
        db = _ScriptedDb(
            [
                [{"ok": True}],
                [_integration_row(event_id=EVENT_ID, inserted=False)],
            ]
        )
        self.mod._get_db = mock.Mock(return_value=db)

        response = self._post(
            {
                "AccountSid": TWILIO_ACCOUNT_SID,
                "MessageSid": "SM123",
                "SmsSid": "SM123",
                "From": "+15551230001",
                "To": "+15551239999",
                "Body": "hello from twilio",
                "NumMedia": "0",
            }
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.text, "")
        self.assertEqual(db.execute_calls, [])
        self.assertEqual(db.commit_calls, ["tx-1"])
        self.mock_sqs.send_message.assert_called_once()

    def test_media_message_is_ignored_without_storage_or_enqueue(self) -> None:
        db = _ScriptedDb([[{"ok": True}]])
        self.mod._get_db = mock.Mock(return_value=db)

        response = self._post(
            {
                "AccountSid": TWILIO_ACCOUNT_SID,
                "MessageSid": "SM123",
                "SmsSid": "SM123",
                "From": "+15551230001",
                "To": "+15551239999",
                "Body": "hello from twilio",
                "NumMedia": "1",
            }
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.text, "")
        self.assertEqual(db.begin_calls, 0)
        self.assertEqual(db.execute_calls, [])
        self.assertEqual(db.commit_calls, [])
        self.mock_sqs.send_message.assert_not_called()


if __name__ == "__main__":
    unittest.main()
