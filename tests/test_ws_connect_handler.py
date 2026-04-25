from __future__ import annotations

import importlib.util
import os
import sys
import types
import unittest
from pathlib import Path
from unittest import mock


class _FakeTable:
    def __init__(self) -> None:
        self.put_calls: list[dict] = []

    def put_item(self, **kwargs):
        self.put_calls.append(kwargs)


class _FakeDynamo:
    def __init__(self, table: _FakeTable) -> None:
        self._table = table
        self.last_table_name: str | None = None

    def Table(self, name: str) -> _FakeTable:
        self.last_table_name = name
        return self._table


def _load_ws_connect_module(*, table_name: str | None = "ws-table", grace_seconds: str = "60"):
    repo_root = Path(__file__).resolve().parents[1]
    handler_py = repo_root / "functions" / "ws_connect" / "handler.py"

    if table_name is None:
        os.environ.pop("WS_TABLE", None)
    else:
        os.environ["WS_TABLE"] = table_name
    os.environ["WS_CONNECT_GRACE_SECONDS"] = grace_seconds

    fake_table = _FakeTable()
    fake_dynamo = _FakeDynamo(fake_table)
    fake_boto3 = types.SimpleNamespace(resource=lambda service_name: fake_dynamo)

    spec = importlib.util.spec_from_file_location("ws_connect_handler_for_tests", handler_py)
    assert spec and spec.loader
    sys.modules.pop(spec.name, None)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    with mock.patch.dict(sys.modules, {"boto3": fake_boto3}):
        spec.loader.exec_module(mod)

    mod._test_fake_table = fake_table
    mod._test_fake_dynamo = fake_dynamo
    return mod


class TestWsConnectHandler(unittest.TestCase):
    def test_returns_500_when_ws_table_missing(self) -> None:
        mod = _load_ws_connect_module(table_name=None)

        resp = mod.handler({"requestContext": {"connectionId": "conn-1"}}, context=None)

        self.assertEqual(resp, {"statusCode": 500, "body": "WS_TABLE not configured"})

    def test_returns_400_when_connection_id_missing(self) -> None:
        mod = _load_ws_connect_module()

        resp = mod.handler({"requestContext": {}}, context=None)

        self.assertEqual(resp, {"statusCode": 400, "body": "Missing connectionId"})
        self.assertEqual(mod._test_fake_table.put_calls, [])

    def test_persists_connection_with_grace_ttl(self) -> None:
        mod = _load_ws_connect_module(table_name="ws-table", grace_seconds="90")

        with mock.patch.object(mod.time, "time", return_value=1700000000):
            resp = mod.handler({"requestContext": {"connectionId": "conn-123"}}, context=None)

        self.assertEqual(resp, {"statusCode": 200, "body": "ok"})
        self.assertEqual(mod._test_fake_dynamo.last_table_name, "ws-table")
        self.assertEqual(len(mod._test_fake_table.put_calls), 1)

        item = mod._test_fake_table.put_calls[0]["Item"]
        self.assertEqual(item["connection_id"], "conn-123")
        self.assertEqual(item["status"], "connected")
        self.assertEqual(item["connected_at"], 1700000000)
        self.assertEqual(item["ttl"], 1700000090)
