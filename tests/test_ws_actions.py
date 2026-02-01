"""Tests for WebSocket action handlers."""
from __future__ import annotations

import json
import os
import pytest
from unittest.mock import MagicMock, patch

# Set region before importing handler (boto3 needs it at import time)
os.environ.setdefault("AWS_DEFAULT_REGION", "us-east-1")
os.environ.setdefault("DB_RESOURCE_ARN", "arn:aws:rds:us-east-1:123:cluster:test")
os.environ.setdefault("DB_SECRET_ARN", "arn:aws:secretsmanager:us-east-1:123:secret:test")
os.environ.setdefault("DB_NAME", "testdb")
os.environ.setdefault("WS_TABLE", "test-ws-connections")
os.environ.setdefault("ACTION_QUEUE_URL", "https://sqs.us-east-1.amazonaws.com/123/action-queue")

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent / "functions" / "ws_message"))


class TestPingAction:
    """Tests for the ping action."""

    @patch("handler._dynamo")
    @patch("handler._get_db")
    @patch("handler._mgmt_api")
    @patch("handler.time")
    def test_ping_returns_pong_when_authenticated(self, mock_time, mock_mgmt, mock_db, mock_dynamo):
        """Authenticated connection should receive pong."""
        from handler import handler

        mock_time.time.return_value = 1700000000.123

        # Mock DynamoDB table
        mock_table = MagicMock()
        mock_table.get_item.return_value = {
            "Item": {"connection_id": "conn-123", "status": "authenticated", "principal_type": "user"}
        }
        mock_dynamo.Table.return_value = mock_table

        # Mock API Gateway management API
        mock_post = MagicMock()
        mock_mgmt.return_value.post_to_connection = mock_post

        event = {
            "requestContext": {"connectionId": "conn-123", "domainName": "test.execute-api.us-east-1.amazonaws.com", "stage": "prod"},
            "body": json.dumps({"action": "ping"})
        }

        result = handler(event, {})

        assert result["statusCode"] == 200
        # Verify pong was sent
        mock_post.assert_called_once()
        sent_data = json.loads(mock_post.call_args[1]["Data"].decode())
        assert sent_data["type"] == "pong"
        assert sent_data["timestamp"] == 1700000000123

    @patch("handler._dynamo")
    @patch("handler._get_db")
    @patch("handler._mgmt_api")
    def test_ping_requires_authentication(self, mock_mgmt, mock_db, mock_dynamo):
        """Unauthenticated connection should get error."""
        from handler import handler

        mock_table = MagicMock()
        mock_table.get_item.return_value = {
            "Item": {"connection_id": "conn-123", "status": "connected"}  # Not authenticated
        }
        mock_dynamo.Table.return_value = mock_table

        mock_post = MagicMock()
        mock_mgmt.return_value.post_to_connection = mock_post

        event = {
            "requestContext": {"connectionId": "conn-123", "domainName": "test.execute-api.us-east-1.amazonaws.com", "stage": "prod"},
            "body": json.dumps({"action": "ping"})
        }

        result = handler(event, {})

        assert result["statusCode"] == 200
        sent_data = json.loads(mock_post.call_args[1]["Data"].decode())
        assert sent_data["type"] == "error"
        assert sent_data["error"] == "not_authenticated"


class TestListActions:
    """Tests for the list_actions action."""

    @patch("handler._dynamo")
    @patch("handler._get_db")
    @patch("handler._mgmt_api")
    def test_list_actions_returns_actions_for_member(self, mock_mgmt, mock_db, mock_dynamo):
        """Member should be able to list actions."""
        from handler import handler

        mock_table = MagicMock()
        mock_table.get_item.return_value = {
            "Item": {
                "connection_id": "conn-123",
                "status": "authenticated",
                "principal_type": "user",
                "user_id": "user-abc",
            }
        }
        mock_dynamo.Table.return_value = mock_table

        # Mock DB
        mock_db_instance = MagicMock()
        mock_db_instance.query.return_value = [
            {
                "action_id": "act-1",
                "kind": "send_message",
                "payload": {"text": "hello"},
                "required_scopes": [],
                "status": "proposed",
                "created_at": "2025-01-01T00:00:00Z",
            }
        ]
        mock_db.return_value = mock_db_instance

        # Mock check_agent_permission
        with patch("handler.check_agent_permission", return_value=True):
            mock_post = MagicMock()
            mock_mgmt.return_value.post_to_connection = mock_post

            event = {
                "requestContext": {"connectionId": "conn-123", "domainName": "test.execute-api.us-east-1.amazonaws.com", "stage": "prod"},
                "body": json.dumps({"action": "list_actions", "agent_id": "agent-xyz"})
            }

            result = handler(event, {})

            assert result["statusCode"] == 200
            sent_data = json.loads(mock_post.call_args[1]["Data"].decode())
            assert sent_data["type"] == "list_actions"
            assert sent_data["ok"] is True
            assert len(sent_data["actions"]) == 1
            assert sent_data["actions"][0]["kind"] == "send_message"

    @patch("handler._dynamo")
    @patch("handler._get_db")
    @patch("handler._mgmt_api")
    def test_list_actions_requires_agent_id(self, mock_mgmt, mock_db, mock_dynamo):
        """Missing agent_id should return error."""
        from handler import handler

        mock_table = MagicMock()
        mock_table.get_item.return_value = {
            "Item": {"connection_id": "conn-123", "status": "authenticated", "principal_type": "user", "user_id": "u1"}
        }
        mock_dynamo.Table.return_value = mock_table

        mock_post = MagicMock()
        mock_mgmt.return_value.post_to_connection = mock_post

        event = {
            "requestContext": {"connectionId": "conn-123", "domainName": "test.execute-api.us-east-1.amazonaws.com", "stage": "prod"},
            "body": json.dumps({"action": "list_actions"})  # No agent_id
        }

        result = handler(event, {})

        sent_data = json.loads(mock_post.call_args[1]["Data"].decode())
        assert sent_data["type"] == "list_actions"
        assert sent_data["ok"] is False
        assert sent_data["error"] == "missing_agent_id"


class TestApproveAction:
    """Tests for the approve_action action."""

    @patch("handler._dynamo")
    @patch("handler._get_db")
    @patch("handler._mgmt_api")
    @patch("handler._sqs")
    @patch("handler._ACTION_QUEUE_URL", "https://sqs.us-east-1.amazonaws.com/123/action-queue")
    def test_approve_action_queues_for_execution(self, mock_sqs, mock_mgmt, mock_db, mock_dynamo):
        """Admin should be able to approve action and it gets queued."""
        from handler import handler

        mock_table = MagicMock()
        mock_table.get_item.return_value = {
            "Item": {"connection_id": "conn-123", "status": "authenticated", "principal_type": "user", "user_id": "user-abc"}
        }
        mock_dynamo.Table.return_value = mock_table

        mock_db_instance = MagicMock()
        mock_db_instance.query.return_value = [
            {"action_id": "act-1", "agent_id": "agent-xyz", "kind": "send_message", "status": "proposed"}
        ]
        mock_db.return_value = mock_db_instance

        with patch("handler.check_agent_permission", return_value=True):
            mock_post = MagicMock()
            mock_mgmt.return_value.post_to_connection = mock_post

            event = {
                "requestContext": {"connectionId": "conn-123", "domainName": "test.execute-api.us-east-1.amazonaws.com", "stage": "prod"},
                "body": json.dumps({"action": "approve_action", "action_id": "act-1"})
            }

            result = handler(event, {})

            assert result["statusCode"] == 200
            sent_data = json.loads(mock_post.call_args[1]["Data"].decode())
            assert sent_data["type"] == "approve_action"
            assert sent_data["ok"] is True
            assert sent_data["new_status"] == "approved"

    @patch("handler._dynamo")
    @patch("handler._get_db")
    @patch("handler._mgmt_api")
    def test_approve_requires_admin_permission(self, mock_mgmt, mock_db, mock_dynamo):
        """Non-admin should not be able to approve."""
        from handler import handler

        mock_table = MagicMock()
        mock_table.get_item.return_value = {
            "Item": {"connection_id": "conn-123", "status": "authenticated", "principal_type": "user", "user_id": "user-abc"}
        }
        mock_dynamo.Table.return_value = mock_table

        mock_db_instance = MagicMock()
        mock_db_instance.query.return_value = [
            {"action_id": "act-1", "agent_id": "agent-xyz", "kind": "send_message", "status": "proposed"}
        ]
        mock_db.return_value = mock_db_instance

        with patch("handler.check_agent_permission", return_value=False):
            mock_post = MagicMock()
            mock_mgmt.return_value.post_to_connection = mock_post

            event = {
                "requestContext": {"connectionId": "conn-123", "domainName": "test.execute-api.us-east-1.amazonaws.com", "stage": "prod"},
                "body": json.dumps({"action": "approve_action", "action_id": "act-1"})
            }

            result = handler(event, {})

            sent_data = json.loads(mock_post.call_args[1]["Data"].decode())
            assert sent_data["ok"] is False
            assert sent_data["error"] == "permission_denied"


class TestRejectAction:
    """Tests for the reject_action action."""

    @patch("handler._dynamo")
    @patch("handler._get_db")
    @patch("handler._mgmt_api")
    def test_reject_action_updates_status(self, mock_mgmt, mock_db, mock_dynamo):
        """Admin should be able to reject action."""
        from handler import handler

        mock_table = MagicMock()
        mock_table.get_item.return_value = {
            "Item": {"connection_id": "conn-123", "status": "authenticated", "principal_type": "user", "user_id": "user-abc"}
        }
        mock_dynamo.Table.return_value = mock_table

        mock_db_instance = MagicMock()
        mock_db_instance.query.return_value = [
            {"action_id": "act-1", "agent_id": "agent-xyz", "kind": "send_message", "status": "proposed"}
        ]
        mock_db.return_value = mock_db_instance

        with patch("handler.check_agent_permission", return_value=True):
            mock_post = MagicMock()
            mock_mgmt.return_value.post_to_connection = mock_post

            event = {
                "requestContext": {"connectionId": "conn-123", "domainName": "test.execute-api.us-east-1.amazonaws.com", "stage": "prod"},
                "body": json.dumps({"action": "reject_action", "action_id": "act-1", "reason": "Not needed"})
            }

            result = handler(event, {})

            assert result["statusCode"] == 200
            sent_data = json.loads(mock_post.call_args[1]["Data"].decode())
            assert sent_data["type"] == "reject_action"
            assert sent_data["ok"] is True
            assert sent_data["new_status"] == "rejected"


class TestSubscribePresence:
    """Tests for the subscribe_presence action."""

    @patch("handler._dynamo")
    @patch("handler._get_db")
    @patch("handler._mgmt_api")
    def test_subscribe_presence_stores_subscription(self, mock_mgmt, mock_db, mock_dynamo):
        """User should be able to subscribe to presence updates."""
        from handler import handler

        mock_table = MagicMock()
        mock_table.get_item.return_value = {
            "Item": {"connection_id": "conn-123", "status": "authenticated", "principal_type": "user", "user_id": "user-abc", "subscriptions": []}
        }
        mock_dynamo.Table.return_value = mock_table

        with patch("handler.check_agent_permission", return_value=True):
            mock_post = MagicMock()
            mock_mgmt.return_value.post_to_connection = mock_post

            event = {
                "requestContext": {"connectionId": "conn-123", "domainName": "test.execute-api.us-east-1.amazonaws.com", "stage": "prod"},
                "body": json.dumps({"action": "subscribe_presence", "agent_id": "agent-xyz", "space_id": "space-1"})
            }

            result = handler(event, {})

            assert result["statusCode"] == 200
            sent_data = json.loads(mock_post.call_args[1]["Data"].decode())
            assert sent_data["type"] == "subscribe_presence"
            assert sent_data["ok"] is True
            assert "presence:agent-xyz:space-1" in sent_data["subscription"]

            # Verify DynamoDB was updated
            mock_table.update_item.assert_called_once()

