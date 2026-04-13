"""Tests for tool runner async device lifecycle behavior."""

from __future__ import annotations

import importlib.util
import json
import os
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from agent_hub.tools.registry import ToolResult


os.environ.setdefault("DB_RESOURCE_ARN", "arn:aws:rds:us-east-1:123:cluster:test")
os.environ.setdefault("DB_SECRET_ARN", "arn:aws:secretsmanager:us-east-1:123:secret:test")
os.environ.setdefault("DB_NAME", "testdb")
os.environ.setdefault("ACTION_QUEUE_URL", "https://sqs.us-east-1.amazonaws.com/123/action-queue")


def _load_module():
    module_name = "tool_runner_handler_module"
    if module_name in sys.modules:
        return sys.modules[module_name]

    root = Path(__file__).resolve().parents[1]
    module_path = root / "functions" / "tool_runner" / "handler.py"
    spec = importlib.util.spec_from_file_location(module_name, module_path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


def test_device_command_moves_to_awaiting_device_result():
    runner = _load_module()
    mock_db = MagicMock()

    action = {
        "action_id": "00000000-0000-0000-0000-000000000301",
        "agent_id": "00000000-0000-0000-0000-000000000001",
        "space_id": "00000000-0000-0000-0000-000000000002",
        "kind": "device_command",
        "payload": {
            "device_id": "00000000-0000-0000-0000-000000000111",
            "command": "run_action",
            "kind": "device_status",
            "payload": {},
        },
        "required_scopes": ["devices:write"],
        "status": "approved",
    }

    tool_result = ToolResult(
        ok=True,
        data={
            "dispatched": True,
            "device_id": "00000000-0000-0000-0000-000000000111",
            "correlation_id": "00000000-0000-0000-0000-000000000222",
            "timeout_seconds": 90,
            "command": "run_action",
            "connections_sent": 1,
        },
    )

    with (
        patch.object(runner, "_db", mock_db),
        patch.object(runner, "_cfg", SimpleNamespace(audit_bucket=None)),
        patch.object(runner, "_load_action", return_value=action),
        patch.object(
            runner,
            "begin_device_dispatch",
            return_value={
                "action_id": action["action_id"],
                "agent_id": action["agent_id"],
                "space_id": action["space_id"],
                "kind": "device_command",
                "status": "awaiting_device_result",
            },
        ) as mock_begin_dispatch,
        patch.object(runner, "execute_tool", return_value=tool_result),
        patch.object(runner, "is_agent_disabled", return_value=False),
        patch.object(runner, "broadcast_event") as mock_broadcast,
        patch.object(runner, "emit_count"),
        patch.object(runner, "emit_ms"),
    ):
        out = runner.handler(
            {
                "Records": [
                    {
                        "body": json.dumps(
                            {"action_id": "00000000-0000-0000-0000-000000000301", "agent_id": action["agent_id"]}
                        )
                    }
                ]
            },
            {},
        )

    assert out["processed"] == 1
    mock_begin_dispatch.assert_called_once()
    mock_broadcast.assert_called_once()
    assert mock_broadcast.call_args.kwargs["payload"]["status"] == "awaiting_device_result"


def test_non_device_tool_completes_immediately():
    runner = _load_module()
    mock_db = MagicMock()

    action = {
        "action_id": "00000000-0000-0000-0000-000000000302",
        "agent_id": "00000000-0000-0000-0000-000000000001",
        "space_id": None,
        "kind": "send_message",
        "payload": {
            "recipient_type": "space",
            "recipient_id": "00000000-0000-0000-0000-000000000002",
            "content": "hello",
        },
        "required_scopes": [],
        "status": "approved",
    }

    with (
        patch.object(runner, "_db", mock_db),
        patch.object(runner, "_cfg", SimpleNamespace(audit_bucket=None)),
        patch.object(runner, "_load_action", return_value=action),
        patch.object(runner, "execute_tool", return_value=ToolResult(ok=True, data={"delivered": True})),
        patch.object(runner, "is_agent_disabled", return_value=False),
        patch.object(runner, "broadcast_event") as mock_broadcast,
        patch.object(runner, "emit_count"),
    ):
        out = runner.handler(
            {
                "Records": [
                    {
                        "body": json.dumps(
                            {"action_id": "00000000-0000-0000-0000-000000000302", "agent_id": action["agent_id"]}
                        )
                    }
                ]
            },
            {},
        )

    assert out["processed"] == 1
    assert mock_db.execute.call_count == 1
    final_params = mock_db.execute.call_args.args[1]
    assert final_params["status"] == "executed"
    assert final_params["error"] is None
    mock_broadcast.assert_called_once()
    assert mock_broadcast.call_args.kwargs["payload"]["status"] == "executed"


class _SlackToolResponse:
    def __init__(self, payload: dict):
        self._payload = json.dumps(payload).encode("utf-8")
        self.status = 200

    def read(self) -> bytes:
        return self._payload

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False


class _TwilioToolResponse:
    def __init__(self, payload: dict):
        self._payload = json.dumps(payload).encode("utf-8")
        self.status = 201

    def read(self) -> bytes:
        return self._payload

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False


def test_slack_post_message_executes_through_runner():
    runner = _load_module()
    mock_db = MagicMock()

    action = {
        "action_id": "00000000-0000-0000-0000-000000000303",
        "agent_id": "00000000-0000-0000-0000-000000000001",
        "space_id": "00000000-0000-0000-0000-000000000002",
        "kind": "slack_post_message",
        "payload": {
            "channel_id": "C123",
            "text": "hello from runner",
        },
        "required_scopes": ["slack:message:write"],
        "status": "approved",
    }

    with (
        patch.object(runner, "_db", mock_db),
        patch.object(runner, "_cfg", SimpleNamespace(audit_bucket=None)),
        patch.object(runner, "_load_action", return_value=action),
        patch.object(runner, "is_agent_disabled", return_value=False),
        patch.object(runner, "broadcast_event") as mock_broadcast,
        patch.object(runner, "emit_count"),
        patch.dict(os.environ, {"SLACK_SECRET_ARN": "arn:aws:secretsmanager:us-east-1:123:secret:slack"}, clear=False),
        patch("agent_hub.tools.slack_post_message.get_secret_json", return_value={"bot_token": "xoxb-test"}),
        patch("agent_hub.tools.slack_post_message.insert_integration_message") as mock_insert,
        patch(
            "agent_hub.tools.slack_post_message.urllib.request.urlopen",
            return_value=_SlackToolResponse(
                {
                    "ok": True,
                    "channel": "C123",
                    "ts": "1712345678.000100",
                    "message": {"text": "hello from runner", "thread_ts": "1712345678.000100"},
                }
            ),
        ),
    ):
        out = runner.handler(
            {
                "Records": [
                    {
                        "body": json.dumps(
                            {"action_id": "00000000-0000-0000-0000-000000000303", "agent_id": action["agent_id"]}
                        )
                    }
                ]
            },
            {},
        )

    assert out["processed"] == 1
    assert mock_db.execute.call_count == 1
    final_params = mock_db.execute.call_args.args[1]
    assert final_params["status"] == "executed"
    assert final_params["error"] is None
    mock_broadcast.assert_called_once()
    assert mock_broadcast.call_args.kwargs["payload"]["status"] == "executed"
    inserted_message = mock_insert.call_args.args[1]
    assert inserted_message.dedupe_key == "action:00000000-0000-0000-0000-000000000303"


def test_twilio_send_sms_executes_through_runner():
    runner = _load_module()
    mock_db = MagicMock()

    action = {
        "action_id": "00000000-0000-0000-0000-000000000304",
        "agent_id": "00000000-0000-0000-0000-000000000001",
        "space_id": "00000000-0000-0000-0000-000000000002",
        "kind": "twilio_send_sms",
        "payload": {
            "to": "+15551230001",
            "body": "hello from runner",
        },
        "required_scopes": ["twilio:sms:send"],
        "status": "approved",
    }

    with (
        patch.object(runner, "_db", mock_db),
        patch.object(runner, "_cfg", SimpleNamespace(audit_bucket=None)),
        patch.object(runner, "_load_action", return_value=action),
        patch.object(runner, "is_agent_disabled", return_value=False),
        patch.object(runner, "broadcast_event") as mock_broadcast,
        patch.object(runner, "emit_count"),
        patch.dict(os.environ, {"TWILIO_SECRET_ARN": "arn:aws:secretsmanager:us-east-1:123:secret:twilio"}, clear=False),
        patch(
            "agent_hub.tools.twilio_send_sms.get_secret_json",
            return_value={
                "account_sid": "AC123",
                "auth_token": "auth-token",
                "from_number": "+15551239999",
            },
        ),
        patch("agent_hub.tools.twilio_send_sms.insert_integration_message") as mock_insert,
        patch(
            "agent_hub.tools.twilio_send_sms.urllib.request.urlopen",
            return_value=_TwilioToolResponse(
                {
                    "sid": "SM123",
                    "status": "queued",
                    "to": "+15551230001",
                    "from": "+15551239999",
                }
            ),
        ),
    ):
        out = runner.handler(
            {
                "Records": [
                    {
                        "body": json.dumps(
                            {"action_id": "00000000-0000-0000-0000-000000000304", "agent_id": action["agent_id"]}
                        )
                    }
                ]
            },
            {},
        )

    assert out["processed"] == 1
    assert mock_db.execute.call_count == 1
    final_params = mock_db.execute.call_args.args[1]
    assert final_params["status"] == "executed"
    assert final_params["error"] is None
    mock_broadcast.assert_called_once()
    assert mock_broadcast.call_args.kwargs["payload"]["status"] == "executed"
    inserted_message = mock_insert.call_args.args[1]
    assert inserted_message.dedupe_key == "action:00000000-0000-0000-0000-000000000304"
