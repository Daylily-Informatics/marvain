from __future__ import annotations

import importlib.util
import json
import os
import sys
import types
import unittest
from pathlib import Path
from unittest import mock


class _FakeTable:
    def __init__(self) -> None:
        self.update_calls: list[dict] = []

    def update_item(self, **kwargs):
        self.update_calls.append(kwargs)


class _FakeDynamo:
    def __init__(self, table: _FakeTable) -> None:
        self._table = table

    def Table(self, name: str) -> _FakeTable:
        # In prod this is the WS connections registry table.
        self.last_table_name = name
        return self._table


def _load_ws_message_module():
    """Load functions/ws_message/handler.py as a module without requiring it be a package."""

    # Make the shared Lambda layer importable in local unit tests.
    repo_root = Path(__file__).resolve().parents[1]
    shared = repo_root / "layers" / "shared" / "python"
    if str(shared) not in sys.path:
        sys.path.insert(0, str(shared))

    os.environ.setdefault("AWS_DEFAULT_REGION", "us-west-2")
    os.environ.setdefault("WS_TABLE", "ws-table")

    # Provide a tiny fake boto3 so this test does not depend on boto3 being installed.
    fake_table = _FakeTable()
    fake_dynamo = _FakeDynamo(fake_table)
    fake_apigw = types.SimpleNamespace(post_to_connection=lambda **kwargs: None)
    fake_boto3 = types.SimpleNamespace(
        resource=lambda service_name: fake_dynamo,
        client=lambda *args, **kwargs: fake_apigw,
    )

    handler_py = repo_root / "functions" / "ws_message" / "handler.py"
    spec = importlib.util.spec_from_file_location("ws_message_handler_for_tests", handler_py)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    with mock.patch.dict(sys.modules, {"boto3": fake_boto3}):
        spec.loader.exec_module(mod)

    # Expose the fake dynamo/table so tests can assert against it.
    mod._test_fake_table = fake_table
    mod._test_fake_dynamo = fake_dynamo
    return mod


class TestWsMessageHelloAuth(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.mod = _load_ws_message_module()

    def setUp(self) -> None:
        # Ensure per-test isolation for captured sends.
        self.sent: list[dict] = []
        self.mod._send = lambda event, connection_id, payload: self.sent.append(
            {"connection_id": connection_id, "payload": payload}
        )

        # Replace dynamo with fresh table per test.
        self.table = _FakeTable()
        self.mod._dynamo = _FakeDynamo(self.table)

        # Avoid depending on DB env vars; note args are evaluated before the auth stub is called.
        self.mod._get_db = lambda: object()

    def test_hello_access_token_success_updates_connection(self) -> None:
        self.mod.authenticate_user_access_token = mock.Mock(
            return_value=types.SimpleNamespace(user_id="u1", cognito_sub="sub-1", email="u1@example.com")
        )
        self.mod.list_agents_for_user = mock.Mock(
            return_value=[
                types.SimpleNamespace(
                    agent_id="a1",
                    name="Agent 1",
                    role="owner",
                    relationship_label="self",
                    disabled=False,
                )
            ]
        )

        event = {
            "requestContext": {"connectionId": "c1", "domainName": "example.com", "stage": "dev"},
            "body": json.dumps({"action": "hello", "access_token": "atok"}),
        }
        resp = self.mod.handler(event, context=None)
        self.assertEqual(resp["statusCode"], 200)

        self.assertEqual(len(self.table.update_calls), 1)
        call = self.table.update_calls[0]
        vals = call["ExpressionAttributeValues"]
        self.assertEqual(vals[":pt"], "user")
        self.assertEqual(vals[":uid"], "u1")
        self.assertEqual(vals[":cs"], "sub-1")
        self.assertEqual(vals[":em"], "u1@example.com")
        self.assertIsInstance(vals[":ag"], list)
        self.assertEqual(vals[":ag"][0]["agent_id"], "a1")

        self.assertEqual(self.sent[-1]["payload"]["type"], "hello")
        self.assertTrue(self.sent[-1]["payload"]["ok"])
        self.assertEqual(self.sent[-1]["payload"]["principal_type"], "user")
        self.assertEqual(self.sent[-1]["payload"]["user_id"], "u1")

    def test_hello_access_token_invalid_sends_error(self) -> None:
        self.mod.authenticate_user_access_token = mock.Mock(side_effect=PermissionError("bad token"))

        event = {
            "requestContext": {"connectionId": "c1"},
            "body": json.dumps({"action": "hello", "access_token": "bad"}),
        }
        resp = self.mod.handler(event, context=None)
        self.assertEqual(resp["statusCode"], 200)

        self.assertEqual(len(self.table.update_calls), 0)
        self.assertEqual(self.sent[-1]["payload"], {"type": "hello", "ok": False, "error": "invalid_access_token"})

    def test_hello_missing_tokens_sends_error(self) -> None:
        event = {
            "requestContext": {"connectionId": "c1"},
            "body": json.dumps({"action": "hello"}),
        }
        resp = self.mod.handler(event, context=None)
        self.assertEqual(resp["statusCode"], 200)

        self.assertEqual(
            self.sent[-1]["payload"],
            {"type": "hello", "ok": False, "error": "missing_access_token_or_device_token"},
        )
