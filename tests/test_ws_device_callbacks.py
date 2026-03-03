"""Tests for websocket device callback and subscription-index flows."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch


os.environ.setdefault("AWS_DEFAULT_REGION", "us-east-1")
os.environ.setdefault("DB_RESOURCE_ARN", "arn:aws:rds:us-east-1:123:cluster:test")
os.environ.setdefault("DB_SECRET_ARN", "arn:aws:secretsmanager:us-east-1:123:secret:test")
os.environ.setdefault("DB_NAME", "testdb")
os.environ.setdefault("WS_TABLE", "test-ws-connections")
os.environ.setdefault("WS_SUBSCRIPTIONS_TABLE", "test-ws-subscriptions")
os.environ.setdefault("ACTION_QUEUE_URL", "https://sqs.us-east-1.amazonaws.com/123/action-queue")

sys.path.insert(0, str(Path(__file__).parent.parent / "functions" / "ws_message"))


def _event(body: dict) -> dict:
    return {
        "requestContext": {
            "connectionId": "conn-123",
            "domainName": "test.execute-api.us-east-1.amazonaws.com",
            "stage": "prod",
        },
        "body": json.dumps(body),
    }


@patch("handler._dynamo")
@patch("handler._get_db")
@patch("handler._mgmt_api")
def test_device_action_ack_transitions_to_acknowledged(mock_mgmt, mock_db, mock_dynamo):
    from handler import handler

    mock_table = MagicMock()
    mock_table.get_item.return_value = {
        "Item": {
            "connection_id": "conn-123",
            "status": "authenticated",
            "principal_type": "device",
            "device_id": "device-1",
        }
    }
    mock_dynamo.Table.return_value = mock_table

    db = MagicMock()
    db.query.return_value = [
        {
            "action_id": "act-1",
            "agent_id": "agent-1",
            "space_id": None,
            "kind": "device_command",
            "status": "awaiting_device_result",
            "target_device_id": "device-1",
            "correlation_id": "corr-1",
            "age_ms": 1000,
        }
    ]
    mock_db.return_value = db

    mock_post = MagicMock()
    mock_mgmt.return_value.post_to_connection = mock_post

    result = handler(
        _event(
            {
                "action": "device_action_ack",
                "action_id": "act-1",
                "correlation_id": "corr-1",
                "device_id": "device-1",
                "received_at": 123,
            }
        ),
        {},
    )

    assert result["statusCode"] == 200
    db.execute.assert_called_once()
    assert "device_acknowledged" in db.execute.call_args.args[0]
    sent = json.loads(mock_post.call_args.kwargs["Data"].decode())
    assert sent["type"] == "device_action_ack"
    assert sent["ok"] is True


@patch("agent_hub.broadcast.broadcast_event")
@patch("handler._dynamo")
@patch("handler._get_db")
@patch("handler._mgmt_api")
def test_device_action_result_success_marks_executed(
    mock_mgmt,
    mock_db,
    mock_dynamo,
    mock_broadcast_event,
):
    from handler import handler

    mock_table = MagicMock()
    mock_table.get_item.return_value = {
        "Item": {
            "connection_id": "conn-123",
            "status": "authenticated",
            "principal_type": "device",
            "device_id": "device-1",
        }
    }
    mock_dynamo.Table.return_value = mock_table

    db = MagicMock()
    db.query.return_value = [
        {
            "action_id": "act-2",
            "agent_id": "agent-1",
            "space_id": "space-1",
            "kind": "device_command",
            "status": "device_acknowledged",
            "target_device_id": "device-1",
            "correlation_id": "corr-2",
            "age_ms": 2500,
        }
    ]
    mock_db.return_value = db

    mock_post = MagicMock()
    mock_mgmt.return_value.post_to_connection = mock_post

    result = handler(
        _event(
            {
                "action": "device_action_result",
                "action_id": "act-2",
                "correlation_id": "corr-2",
                "device_id": "device-1",
                "kind": "device_status",
                "status": "success",
                "result": {"online": True},
                "completed_at": 456,
            }
        ),
        {},
    )

    assert result["statusCode"] == 200
    db.execute.assert_called_once()
    assert db.execute.call_args.args[1]["status"] == "executed"
    mock_broadcast_event.assert_called_once()
    assert mock_broadcast_event.call_args.kwargs["event_type"] == "actions.updated"

    sent = json.loads(mock_post.call_args.kwargs["Data"].decode())
    assert sent["type"] == "device_action_result"
    assert sent["ok"] is True


@patch("handler._dynamo")
@patch("handler._get_db")
@patch("handler._mgmt_api")
def test_device_action_result_rejects_correlation_mismatch(mock_mgmt, mock_db, mock_dynamo):
    from handler import handler

    mock_table = MagicMock()
    mock_table.get_item.return_value = {
        "Item": {
            "connection_id": "conn-123",
            "status": "authenticated",
            "principal_type": "device",
            "device_id": "device-1",
        }
    }
    mock_dynamo.Table.return_value = mock_table

    db = MagicMock()
    db.query.return_value = [
        {
            "action_id": "act-3",
            "agent_id": "agent-1",
            "space_id": None,
            "kind": "device_command",
            "status": "awaiting_device_result",
            "target_device_id": "device-1",
            "correlation_id": "corr-expected",
            "age_ms": 2500,
        }
    ]
    mock_db.return_value = db

    mock_post = MagicMock()
    mock_mgmt.return_value.post_to_connection = mock_post

    result = handler(
        _event(
            {
                "action": "device_action_result",
                "action_id": "act-3",
                "correlation_id": "corr-actual",
                "device_id": "device-1",
                "kind": "device_status",
                "status": "success",
            }
        ),
        {},
    )

    assert result["statusCode"] == 200
    db.execute.assert_not_called()
    sent = json.loads(mock_post.call_args.kwargs["Data"].decode())
    assert sent["type"] == "device_action_result"
    assert sent["ok"] is False
    assert sent["error"] == "correlation_mismatch"


@patch("handler._upsert_subscription_index")
@patch("handler.check_agent_permission", return_value=True)
@patch("handler._dynamo")
@patch("handler._get_db")
@patch("handler._mgmt_api")
def test_subscribe_actions_dual_writes_subscription_index(
    mock_mgmt,
    mock_db,
    mock_dynamo,
    _mock_permission,
    mock_upsert_index,
):
    from handler import handler

    mock_table = MagicMock()
    mock_table.get_item.return_value = {
        "Item": {
            "connection_id": "conn-123",
            "status": "authenticated",
            "principal_type": "user",
            "user_id": "user-1",
            "subscriptions": [],
        }
    }
    mock_dynamo.Table.return_value = mock_table
    mock_db.return_value = MagicMock()

    mock_post = MagicMock()
    mock_mgmt.return_value.post_to_connection = mock_post

    result = handler(_event({"action": "subscribe_actions", "agent_id": "agent-1"}), {})

    assert result["statusCode"] == 200
    mock_upsert_index.assert_called_once_with("conn-123", "actions:agent-1", None)
    sent = json.loads(mock_post.call_args.kwargs["Data"].decode())
    assert sent["type"] == "subscribe_actions"
    assert sent["ok"] is True
