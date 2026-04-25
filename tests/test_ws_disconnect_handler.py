from __future__ import annotations

import importlib.util
import os
import sys
import types
import unittest
from pathlib import Path
from unittest import mock


class _FakeConnectionsTable:
    def __init__(self) -> None:
        self.delete_calls: list[dict] = []

    def delete_item(self, **kwargs):
        self.delete_calls.append(kwargs)


class _FakeSubscriptionsTable:
    def __init__(self, *, pages: list[dict] | None = None, query_error: Exception | None = None) -> None:
        self.pages = list(pages or [])
        self.query_error = query_error
        self.query_calls: list[dict] = []
        self.delete_calls: list[dict] = []

    def query(self, **kwargs):
        self.query_calls.append(kwargs)
        if self.query_error is not None:
            raise self.query_error
        if self.pages:
            return self.pages.pop(0)
        return {"Items": []}

    def delete_item(self, **kwargs):
        self.delete_calls.append(kwargs)


class _FakeDynamo:
    def __init__(self, tables: dict[str, object]) -> None:
        self.tables = tables

    def Table(self, name: str):
        return self.tables[name]


def _load_ws_disconnect_module(
    *,
    table_name: str | None = "ws-table",
    subs_table_name: str | None = "subs-table",
    subs_pages: list[dict] | None = None,
    subs_query_error: Exception | None = None,
):
    repo_root = Path(__file__).resolve().parents[1]
    handler_py = repo_root / "functions" / "ws_disconnect" / "handler.py"

    if table_name is None:
        os.environ.pop("WS_TABLE", None)
    else:
        os.environ["WS_TABLE"] = table_name

    if subs_table_name is None:
        os.environ.pop("WS_SUBSCRIPTIONS_TABLE", None)
    else:
        os.environ["WS_SUBSCRIPTIONS_TABLE"] = subs_table_name

    connections = _FakeConnectionsTable()
    tables: dict[str, object] = {}
    if table_name is not None:
        tables[table_name] = connections

    subscriptions = _FakeSubscriptionsTable(pages=subs_pages, query_error=subs_query_error)
    if subs_table_name is not None:
        tables[subs_table_name] = subscriptions

    fake_dynamo = _FakeDynamo(tables)
    fake_boto3 = types.SimpleNamespace(resource=lambda service_name: fake_dynamo)

    spec = importlib.util.spec_from_file_location("ws_disconnect_handler_for_tests", handler_py)
    assert spec and spec.loader
    sys.modules.pop(spec.name, None)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    with mock.patch.dict(sys.modules, {"boto3": fake_boto3}):
        spec.loader.exec_module(mod)

    mod._test_connections = connections
    mod._test_subscriptions = subscriptions
    return mod


class TestWsDisconnectHandler(unittest.TestCase):
    def test_returns_500_when_ws_table_missing(self) -> None:
        mod = _load_ws_disconnect_module(table_name=None)

        resp = mod.handler({"requestContext": {"connectionId": "conn-1"}}, context=None)

        self.assertEqual(resp, {"statusCode": 500, "body": "WS_TABLE not configured"})

    def test_returns_400_when_connection_id_missing(self) -> None:
        mod = _load_ws_disconnect_module()

        resp = mod.handler({"requestContext": {}}, context=None)

        self.assertEqual(resp, {"statusCode": 400, "body": "Missing connectionId"})
        self.assertEqual(mod._test_connections.delete_calls, [])

    def test_deletes_connection_and_all_subscription_pages(self) -> None:
        mod = _load_ws_disconnect_module(
            subs_pages=[
                {
                    "Items": [{"topic_key": "topic/a", "connection_id": "conn-123"}],
                    "LastEvaluatedKey": {"topic_key": "topic/a", "connection_id": "conn-123"},
                },
                {
                    "Items": [
                        {"topic_key": "topic/b", "connection_id": "conn-123"},
                        {"topic_key": "", "connection_id": "conn-123"},
                    ]
                },
            ]
        )

        resp = mod.handler({"requestContext": {"connectionId": "conn-123"}}, context=None)

        self.assertEqual(resp, {"statusCode": 200, "body": "ok"})
        self.assertEqual(mod._test_connections.delete_calls, [{"Key": {"connection_id": "conn-123"}}])
        self.assertEqual(len(mod._test_subscriptions.query_calls), 2)
        self.assertEqual(mod._test_subscriptions.query_calls[0]["IndexName"], "connection_id_index")
        self.assertEqual(mod._test_subscriptions.query_calls[0]["ExpressionAttributeValues"], {":cid": "conn-123"})
        self.assertIn("ExclusiveStartKey", mod._test_subscriptions.query_calls[1])
        self.assertEqual(
            mod._test_subscriptions.delete_calls,
            [
                {"Key": {"topic_key": "topic/a", "connection_id": "conn-123"}},
                {"Key": {"topic_key": "topic/b", "connection_id": "conn-123"}},
            ],
        )

    def test_subscription_cleanup_is_best_effort(self) -> None:
        mod = _load_ws_disconnect_module(subs_query_error=RuntimeError("boom"))

        resp = mod.handler({"requestContext": {"connectionId": "conn-123"}}, context=None)

        self.assertEqual(resp, {"statusCode": 200, "body": "ok"})
        self.assertEqual(mod._test_connections.delete_calls, [{"Key": {"connection_id": "conn-123"}}])
        self.assertEqual(len(mod._test_subscriptions.query_calls), 1)
        self.assertEqual(mod._test_subscriptions.delete_calls, [])
