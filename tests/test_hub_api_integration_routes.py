from __future__ import annotations

import dataclasses
import importlib.util
import json
import os
import sys
import unittest
from pathlib import Path
from unittest import mock

from agent_hub.auth import AuthenticatedUser


AGENT_ID = "11111111-1111-1111-1111-111111111111"
INTEGRATION_ACCOUNT_ID = "55555555-5555-5555-5555-555555555555"
INTEGRATION_MESSAGE_ID = "33333333-3333-3333-3333-333333333333"


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
    spec = importlib.util.spec_from_file_location("hub_api_api_app_for_tests_routes", api_app_py)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    with mock.patch("boto3.client", return_value=mock.Mock()):
        spec.loader.exec_module(mod)
    return mod


def _account_row(
    *,
    integration_account_id: str = INTEGRATION_ACCOUNT_ID,
    provider: str = "slack",
    display_name: str = "Primary Slack",
    status: str = "active",
) -> dict[str, object]:
    return {
        "integration_account_id": integration_account_id,
        "agent_id": AGENT_ID,
        "provider": provider,
        "display_name": display_name,
        "external_account_id": "external-1",
        "default_space_id": "22222222-2222-2222-2222-222222222222",
        "credentials_secret_arn": "arn:aws:secretsmanager:us-east-1:123:secret:stack/integration",
        "scopes_json": '["chat:write"]',
        "config_json": '{"workspace":"main"}',
        "status": status,
        "created_at": "2026-04-12T00:00:00+00:00",
        "updated_at": "2026-04-12T00:00:00+00:00",
    }


def _message_row(
    *,
    integration_message_id: str = INTEGRATION_MESSAGE_ID,
    provider: str = "slack",
    status: str = "received",
    external_thread_id: str | None = "thread-1",
) -> dict[str, object]:
    return {
        "integration_message_id": integration_message_id,
        "agent_id": AGENT_ID,
        "space_id": "22222222-2222-2222-2222-222222222222",
        "event_id": None,
        "integration_account_id": INTEGRATION_ACCOUNT_ID,
        "action_id": None,
        "provider": provider,
        "direction": "inbound",
        "channel_type": "dm",
        "object_type": "message",
        "external_thread_id": external_thread_id,
        "external_message_id": "provider-message-1",
        "dedupe_key": "dedupe-1",
        "sender_json": '{"id":"user-1"}',
        "recipients_json": '[{"id":"user-2"}]',
        "subject": None,
        "body_text": "hello",
        "body_html": None,
        "payload_json": '{"raw":true}',
        "status": status,
        "contains_phi": False,
        "retention_until": None,
        "processed_at": None,
        "redacted_at": None,
        "created_at": "2026-04-12T00:00:00+00:00",
        "updated_at": "2026-04-12T00:00:00+00:00",
    }


class _ScriptedDb:
    def __init__(self, query_responses: list[list[dict[str, object]]]):
        self.query_responses = list(query_responses)
        self.query_calls: list[tuple[str, dict[str, object], str | None]] = []
        self.execute_calls: list[tuple[str, dict[str, object], str | None]] = []

    def query(self, sql: str, params: dict[str, object] | None = None, *, transaction_id: str | None = None):
        self.query_calls.append((sql, params or {}, transaction_id))
        if not self.query_responses:
            return []
        return self.query_responses.pop(0)

    def execute(self, sql: str, params: dict[str, object] | None = None, *, transaction_id: str | None = None):
        self.execute_calls.append((sql, params or {}, transaction_id))
        return {}


class TestHubApiIntegrationRoutes(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.mod = _load_hub_api_app_module()
        from fastapi.testclient import TestClient

        cls._TestClient = TestClient
        cls._orig_cfg = cls.mod._cfg
        cls._orig_get_db = cls.mod._get_db
        cls._orig_authenticate_user_access_token = cls.mod.authenticate_user_access_token
        cls._orig_check_agent_permission = cls.mod.check_agent_permission

    def setUp(self) -> None:
        self.client = self.__class__._TestClient(self.mod.api_app, raise_server_exceptions=False)
        self.mod._cfg = dataclasses.replace(self.__class__._orig_cfg, audit_bucket=None)
        self.mod.authenticate_user_access_token = mock.Mock(
            return_value=AuthenticatedUser(
                user_id="user-1",
                cognito_sub="sub-1",
                email="user@example.com",
            )
        )
        self.mod.check_agent_permission = mock.Mock(return_value=True)

    def tearDown(self) -> None:
        self.mod._cfg = self.__class__._orig_cfg
        self.mod._get_db = self.__class__._orig_get_db
        self.mod.authenticate_user_access_token = self.__class__._orig_authenticate_user_access_token
        self.mod.check_agent_permission = self.__class__._orig_check_agent_permission

    def _headers(self) -> dict[str, str]:
        return {"Authorization": "Bearer user-token"}

    def test_integration_account_crud(self) -> None:
        db = _ScriptedDb(
            [
                [_account_row()],
                [_account_row()],
                [_account_row()],
                [_account_row(provider="slack", display_name="Updated Slack", status="paused")],
                [_account_row(provider="slack", display_name="Updated Slack", status="paused")],
                [{"integration_account_id": INTEGRATION_ACCOUNT_ID}],
            ]
        )
        self.mod._get_db = mock.Mock(return_value=db)

        create_response = self.client.post(
            f"/v1/agents/{AGENT_ID}/integration_accounts",
            headers=self._headers(),
            json={
                "provider": "slack",
                "display_name": "Primary Slack",
                "credentials_secret_arn": "arn:aws:secretsmanager:us-east-1:123:secret:stack/integration",
                "default_space_id": "22222222-2222-2222-2222-222222222222",
                "scopes": ["chat:write"],
                "config": {"workspace": "main"},
                "status": "active",
            },
        )
        self.assertEqual(create_response.status_code, 200)
        self.assertEqual(create_response.json()["integration_account"]["provider"], "slack")

        list_response = self.client.get(
            f"/v1/agents/{AGENT_ID}/integration_accounts?provider=slack&status=active",
            headers=self._headers(),
        )
        self.assertEqual(list_response.status_code, 200)
        self.assertEqual(len(list_response.json()["integration_accounts"]), 1)

        get_response = self.client.get(
            f"/v1/agents/{AGENT_ID}/integration_accounts/{INTEGRATION_ACCOUNT_ID}",
            headers=self._headers(),
        )
        self.assertEqual(get_response.status_code, 200)
        self.assertEqual(get_response.json()["integration_account"]["integration_account_id"], INTEGRATION_ACCOUNT_ID)

        patch_response = self.client.patch(
            f"/v1/agents/{AGENT_ID}/integration_accounts/{INTEGRATION_ACCOUNT_ID}",
            headers=self._headers(),
            json={"display_name": "Updated Slack", "status": "paused"},
        )
        self.assertEqual(patch_response.status_code, 200)
        self.assertEqual(patch_response.json()["integration_account"]["status"], "paused")

        delete_response = self.client.delete(
            f"/v1/agents/{AGENT_ID}/integration_accounts/{INTEGRATION_ACCOUNT_ID}",
            headers=self._headers(),
        )
        self.assertEqual(delete_response.status_code, 200)
        self.assertTrue(delete_response.json()["ok"])

    def test_message_read_routes_filter_and_return_newest_first(self) -> None:
        db = _ScriptedDb(
            [
                [
                    _message_row(integration_message_id="msg-2", status="triaged"),
                    _message_row(integration_message_id="msg-1", status="received"),
                ],
                [_message_row(integration_message_id=INTEGRATION_MESSAGE_ID, status="received")],
            ]
        )
        self.mod._get_db = mock.Mock(return_value=db)

        list_response = self.client.get(
            f"/v1/agents/{AGENT_ID}/messages?provider=slack&status=received&external_thread_id=thread-1&limit=250",
            headers=self._headers(),
        )
        self.assertEqual(list_response.status_code, 200)
        messages = list_response.json()["messages"]
        self.assertEqual([m["integration_message_id"] for m in messages], ["msg-2", "msg-1"])
        sql, params, _ = db.query_calls[0]
        self.assertIn("FROM integration_messages", sql)
        self.assertEqual(params["provider"], "slack")
        self.assertEqual(params["status"], "received")
        self.assertEqual(params["external_thread_id"], "thread-1")
        self.assertEqual(params["limit"], 200)

        detail_response = self.client.get(
            f"/v1/agents/{AGENT_ID}/messages/{INTEGRATION_MESSAGE_ID}",
            headers=self._headers(),
        )
        self.assertEqual(detail_response.status_code, 200)
        self.assertEqual(detail_response.json()["integration_message"]["integration_message_id"], INTEGRATION_MESSAGE_ID)


if __name__ == "__main__":
    unittest.main()
