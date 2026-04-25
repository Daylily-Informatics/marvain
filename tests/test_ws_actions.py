"""Tests for WebSocket action handlers."""

from __future__ import annotations

import json
import os
from unittest.mock import MagicMock, patch

# Set region before importing handler (boto3 needs it at import time)
os.environ.setdefault("AWS_DEFAULT_REGION", "us-east-1")
os.environ.setdefault("DB_RESOURCE_ARN", "arn:aws:rds:us-east-1:123:cluster:test")
os.environ.setdefault("DB_SECRET_ARN", "arn:aws:secretsmanager:us-east-1:123:secret:test")
os.environ.setdefault("DB_NAME", "testdb")
os.environ.setdefault("WS_TABLE", "test-ws-connections")
os.environ.setdefault("WS_SUBSCRIPTIONS_TABLE", "test-ws-subscriptions")
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
            "requestContext": {
                "connectionId": "conn-123",
                "domainName": "test.execute-api.us-east-1.amazonaws.com",
                "stage": "prod",
            },
            "body": json.dumps({"action": "ping"}),
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
            "requestContext": {
                "connectionId": "conn-123",
                "domainName": "test.execute-api.us-east-1.amazonaws.com",
                "stage": "prod",
            },
            "body": json.dumps({"action": "ping"}),
        }

        result = handler(event, {})

        assert result["statusCode"] == 200
        sent_data = json.loads(mock_post.call_args[1]["Data"].decode())
        assert sent_data["type"] == "error"
        assert sent_data["error"] == "not_authenticated"

    @patch("handler._dynamo")
    @patch("handler._get_db")
    @patch("handler._mgmt_api")
    def test_expired_auth_returns_auth_expired(self, mock_mgmt, mock_db, mock_dynamo):
        """Connection with expired authenticated_at should get auth_expired error."""
        import time as _time

        from handler import handler

        mock_table = MagicMock()
        # authenticated_at in the past, well beyond the default 3600s TTL
        expired_ts = int(_time.time()) - 7200
        mock_table.get_item.return_value = {
            "Item": {
                "connection_id": "conn-expired",
                "status": "authenticated",
                "principal_type": "user",
                "authenticated_at": expired_ts,
            }
        }
        mock_dynamo.Table.return_value = mock_table

        mock_post = MagicMock()
        mock_mgmt.return_value.post_to_connection = mock_post

        event = {
            "requestContext": {
                "connectionId": "conn-expired",
                "domainName": "test.execute-api.us-east-1.amazonaws.com",
                "stage": "prod",
            },
            "body": json.dumps({"action": "ping"}),
        }

        result = handler(event, {})

        assert result["statusCode"] == 200
        sent_data = json.loads(mock_post.call_args[1]["Data"].decode())
        assert sent_data["type"] == "error"
        assert sent_data["error"] == "auth_expired"
        # Connection status should be updated to expired
        mock_table.update_item.assert_called_once()

    @patch("handler._dynamo")
    @patch("handler._get_db")
    @patch("handler._mgmt_api")
    @patch("handler.time")
    def test_fresh_auth_not_expired(self, mock_time, mock_mgmt, mock_db, mock_dynamo):
        """Connection with recent authenticated_at should proceed normally."""
        import time as _time

        from handler import handler

        now = int(_time.time())
        mock_time.time.return_value = float(now)

        mock_table = MagicMock()
        # authenticated_at just a few seconds ago
        mock_table.get_item.return_value = {
            "Item": {
                "connection_id": "conn-fresh",
                "status": "authenticated",
                "principal_type": "user",
                "authenticated_at": now - 10,
            }
        }
        mock_dynamo.Table.return_value = mock_table

        mock_post = MagicMock()
        mock_mgmt.return_value.post_to_connection = mock_post

        event = {
            "requestContext": {
                "connectionId": "conn-fresh",
                "domainName": "test.execute-api.us-east-1.amazonaws.com",
                "stage": "prod",
            },
            "body": json.dumps({"action": "ping"}),
        }

        result = handler(event, {})

        assert result["statusCode"] == 200
        sent_data = json.loads(mock_post.call_args[1]["Data"].decode())
        assert sent_data["type"] == "pong"


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
                "requestContext": {
                    "connectionId": "conn-123",
                    "domainName": "test.execute-api.us-east-1.amazonaws.com",
                    "stage": "prod",
                },
                "body": json.dumps({"action": "list_actions", "agent_id": "agent-xyz"}),
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
            "requestContext": {
                "connectionId": "conn-123",
                "domainName": "test.execute-api.us-east-1.amazonaws.com",
                "stage": "prod",
            },
            "body": json.dumps({"action": "list_actions"}),  # No agent_id
        }

        handler(event, {})

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
    @patch("handler._get_cfg")
    @patch("handler._ACTION_QUEUE_URL", "https://sqs.us-east-1.amazonaws.com/123/action-queue")
    def test_approve_action_queues_for_execution(self, mock_cfg, mock_sqs, mock_mgmt, mock_db, mock_dynamo):
        """Admin should be able to approve action and it gets queued."""
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

        mock_db_instance = MagicMock()
        mock_db_instance.query.return_value = [
            {"action_id": "act-1", "agent_id": "agent-xyz", "kind": "send_message", "status": "proposed"}
        ]
        mock_db.return_value = mock_db_instance

        mock_cfg.return_value.audit_bucket = None

        with patch("handler.check_agent_permission", return_value=True):
            mock_post = MagicMock()
            mock_mgmt.return_value.post_to_connection = mock_post

            event = {
                "requestContext": {
                    "connectionId": "conn-123",
                    "domainName": "test.execute-api.us-east-1.amazonaws.com",
                    "stage": "prod",
                },
                "body": json.dumps({"action": "approve_action", "action_id": "act-1"}),
            }

            result = handler(event, {})

            assert result["statusCode"] == 200
            sent_data = json.loads(mock_post.call_args[1]["Data"].decode())
            assert sent_data["type"] == "approve_action"
            assert sent_data["ok"] is True
            assert sent_data["new_status"] == "approved"
            mock_sqs.send_message.assert_called_once()

    @patch("handler._dynamo")
    @patch("handler._get_db")
    @patch("handler._mgmt_api")
    def test_approve_requires_admin_permission(self, mock_mgmt, mock_db, mock_dynamo):
        """Non-admin should not be able to approve."""
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

        mock_db_instance = MagicMock()
        mock_db_instance.query.return_value = [
            {"action_id": "act-1", "agent_id": "agent-xyz", "kind": "send_message", "status": "proposed"}
        ]
        mock_db.return_value = mock_db_instance

        with patch("handler.check_agent_permission", return_value=False):
            mock_post = MagicMock()
            mock_mgmt.return_value.post_to_connection = mock_post

            event = {
                "requestContext": {
                    "connectionId": "conn-123",
                    "domainName": "test.execute-api.us-east-1.amazonaws.com",
                    "stage": "prod",
                },
                "body": json.dumps({"action": "approve_action", "action_id": "act-1"}),
            }

            handler(event, {})

            sent_data = json.loads(mock_post.call_args[1]["Data"].decode())
            assert sent_data["ok"] is False
            assert sent_data["error"] == "permission_denied"


class TestRejectAction:
    """Tests for the reject_action action."""

    @patch("handler._dynamo")
    @patch("handler._get_db")
    @patch("handler._mgmt_api")
    @patch("handler._get_cfg")
    def test_reject_action_updates_status(self, mock_cfg, mock_mgmt, mock_db, mock_dynamo):
        """Admin should be able to reject action."""
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

        mock_db_instance = MagicMock()
        mock_db_instance.query.return_value = [
            {"action_id": "act-1", "agent_id": "agent-xyz", "kind": "send_message", "status": "proposed"}
        ]
        mock_db.return_value = mock_db_instance

        mock_cfg.return_value.audit_bucket = None

        with patch("handler.check_agent_permission", return_value=True):
            mock_post = MagicMock()
            mock_mgmt.return_value.post_to_connection = mock_post

            event = {
                "requestContext": {
                    "connectionId": "conn-123",
                    "domainName": "test.execute-api.us-east-1.amazonaws.com",
                    "stage": "prod",
                },
                "body": json.dumps({"action": "reject_action", "action_id": "act-1", "reason": "Not needed"}),
            }

            result = handler(event, {})

            assert result["statusCode"] == 200
            sent_data = json.loads(mock_post.call_args[1]["Data"].decode())
            assert sent_data["type"] == "reject_action"
            assert sent_data["ok"] is True
            assert sent_data["new_status"] == "rejected"


class TestSubscribePresence:
    """Tests for the subscribe_presence action."""

    @patch("handler._upsert_subscription_index")
    @patch("handler._dynamo")
    @patch("handler._get_db")
    @patch("handler._mgmt_api")
    def test_subscribe_presence_stores_subscription(self, mock_mgmt, mock_db, mock_dynamo, mock_upsert_index):
        """User should be able to subscribe to presence updates."""
        from handler import handler

        mock_table = MagicMock()
        mock_table.get_item.return_value = {
            "Item": {
                "connection_id": "conn-123",
                "status": "authenticated",
                "principal_type": "user",
                "user_id": "user-abc",
                "subscriptions": [],
            }
        }
        mock_dynamo.Table.return_value = mock_table

        with patch("handler.check_agent_permission", return_value=True):
            mock_post = MagicMock()
            mock_mgmt.return_value.post_to_connection = mock_post

            event = {
                "requestContext": {
                    "connectionId": "conn-123",
                    "domainName": "test.execute-api.us-east-1.amazonaws.com",
                    "stage": "prod",
                },
                "body": json.dumps({"action": "subscribe_presence", "agent_id": "agent-xyz", "space_id": "space-1"}),
            }

            result = handler(event, {})

            assert result["statusCode"] == 200
            sent_data = json.loads(mock_post.call_args[1]["Data"].decode())
            assert sent_data["type"] == "subscribe_presence"
            assert sent_data["ok"] is True
            assert "presence:agent-xyz:space-1" in sent_data["subscription"]

            mock_upsert_index.assert_called_once_with("conn-123", "presence:agent-xyz:space-1", None)


class TestSubscribeEvents:
    """Tests for the subscribe_events action."""

    @patch("handler._upsert_subscription_index")
    @patch("handler._dynamo")
    @patch("handler._get_db")
    @patch("handler._mgmt_api")
    def test_subscribe_events_stores_subscription(self, mock_mgmt, mock_db, mock_dynamo, mock_upsert_index):
        """User should be able to subscribe to event stream."""
        from handler import handler

        mock_table = MagicMock()
        mock_table.get_item.return_value = {
            "Item": {
                "connection_id": "conn-123",
                "status": "authenticated",
                "principal_type": "user",
                "user_id": "user-abc",
                "subscriptions": [],
            }
        }
        mock_dynamo.Table.return_value = mock_table

        with patch("handler.check_agent_permission", return_value=True):
            mock_post = MagicMock()
            mock_mgmt.return_value.post_to_connection = mock_post

            event = {
                "requestContext": {
                    "connectionId": "conn-123",
                    "domainName": "test.execute-api.us-east-1.amazonaws.com",
                    "stage": "prod",
                },
                "body": json.dumps({"action": "subscribe_events", "agent_id": "agent-xyz"}),
            }

            result = handler(event, {})

            assert result["statusCode"] == 200
            sent_data = json.loads(mock_post.call_args[1]["Data"].decode())
            assert sent_data["type"] == "subscribe_events"
            assert sent_data["ok"] is True
            assert sent_data["subscription"] == "events:agent-xyz"
            assert sent_data["agent_id"] == "agent-xyz"

            mock_upsert_index.assert_called_once_with("conn-123", "events:agent-xyz", None)

    @patch("handler._dynamo")
    @patch("handler._get_db")
    @patch("handler._mgmt_api")
    def test_subscribe_events_with_space_filter(self, mock_mgmt, mock_db, mock_dynamo):
        """User should be able to subscribe to events for a specific space."""
        from handler import handler

        mock_table = MagicMock()
        mock_table.get_item.return_value = {
            "Item": {
                "connection_id": "conn-123",
                "status": "authenticated",
                "principal_type": "user",
                "user_id": "user-abc",
                "subscriptions": [],
            }
        }
        mock_dynamo.Table.return_value = mock_table

        with patch("handler.check_agent_permission", return_value=True):
            mock_post = MagicMock()
            mock_mgmt.return_value.post_to_connection = mock_post

            event = {
                "requestContext": {
                    "connectionId": "conn-123",
                    "domainName": "test.execute-api.us-east-1.amazonaws.com",
                    "stage": "prod",
                },
                "body": json.dumps({"action": "subscribe_events", "agent_id": "agent-xyz", "space_id": "space-1"}),
            }

            result = handler(event, {})

            assert result["statusCode"] == 200
            sent_data = json.loads(mock_post.call_args[1]["Data"].decode())
            assert sent_data["type"] == "subscribe_events"
            assert sent_data["ok"] is True
            assert sent_data["subscription"] == "events:agent-xyz:space-1"
            assert sent_data["space_id"] == "space-1"

    @patch("handler._dynamo")
    @patch("handler._get_db")
    @patch("handler._mgmt_api")
    def test_subscribe_events_requires_agent_id(self, mock_mgmt, mock_db, mock_dynamo):
        """subscribe_events should require agent_id."""
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

        mock_post = MagicMock()
        mock_mgmt.return_value.post_to_connection = mock_post

        event = {
            "requestContext": {
                "connectionId": "conn-123",
                "domainName": "test.execute-api.us-east-1.amazonaws.com",
                "stage": "prod",
            },
            "body": json.dumps({"action": "subscribe_events"}),  # Missing agent_id
        }

        result = handler(event, {})

        assert result["statusCode"] == 200
        sent_data = json.loads(mock_post.call_args[1]["Data"].decode())
        assert sent_data["type"] == "subscribe_events"
        assert sent_data["ok"] is False
        assert sent_data["error"] == "missing_agent_id"

    @patch("handler._dynamo")
    @patch("handler._get_db")
    @patch("handler._mgmt_api")
    def test_subscribe_events_requires_permission(self, mock_mgmt, mock_db, mock_dynamo):
        """subscribe_events should check agent permission."""
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

        with patch("handler.check_agent_permission", return_value=False):
            mock_post = MagicMock()
            mock_mgmt.return_value.post_to_connection = mock_post

            event = {
                "requestContext": {
                    "connectionId": "conn-123",
                    "domainName": "test.execute-api.us-east-1.amazonaws.com",
                    "stage": "prod",
                },
                "body": json.dumps({"action": "subscribe_events", "agent_id": "agent-xyz"}),
            }

            result = handler(event, {})

            assert result["statusCode"] == 200
            sent_data = json.loads(mock_post.call_args[1]["Data"].decode())
            assert sent_data["type"] == "subscribe_events"
            assert sent_data["ok"] is False
            assert sent_data["error"] == "permission_denied"


class TestAdditionalSubscriptions:
    """Tests for subscribe_actions and subscribe_memories actions."""

    @patch("handler._dynamo")
    @patch("handler._get_db")
    @patch("handler._mgmt_api")
    def test_subscribe_actions_stores_subscription(self, mock_mgmt, mock_db, mock_dynamo):
        from handler import handler

        mock_table = MagicMock()
        mock_table.get_item.return_value = {
            "Item": {
                "connection_id": "conn-123",
                "status": "authenticated",
                "principal_type": "user",
                "user_id": "user-abc",
                "subscriptions": [],
            }
        }
        mock_dynamo.Table.return_value = mock_table

        with patch("handler.check_agent_permission", return_value=True):
            mock_post = MagicMock()
            mock_mgmt.return_value.post_to_connection = mock_post
            event = {
                "requestContext": {
                    "connectionId": "conn-123",
                    "domainName": "test.execute-api.us-east-1.amazonaws.com",
                    "stage": "prod",
                },
                "body": json.dumps({"action": "subscribe_actions", "agent_id": "agent-xyz"}),
            }
            result = handler(event, {})

            assert result["statusCode"] == 200
            sent_data = json.loads(mock_post.call_args[1]["Data"].decode())
            assert sent_data["type"] == "subscribe_actions"
            assert sent_data["ok"] is True
            assert sent_data["subscription"] == "actions:agent-xyz"

    @patch("handler._dynamo")
    @patch("handler._get_db")
    @patch("handler._mgmt_api")
    def test_subscribe_memories_stores_subscription(self, mock_mgmt, mock_db, mock_dynamo):
        from handler import handler

        mock_table = MagicMock()
        mock_table.get_item.return_value = {
            "Item": {
                "connection_id": "conn-123",
                "status": "authenticated",
                "principal_type": "user",
                "user_id": "user-abc",
                "subscriptions": [],
            }
        }
        mock_dynamo.Table.return_value = mock_table

        with patch("handler.check_agent_permission", return_value=True):
            mock_post = MagicMock()
            mock_mgmt.return_value.post_to_connection = mock_post
            event = {
                "requestContext": {
                    "connectionId": "conn-123",
                    "domainName": "test.execute-api.us-east-1.amazonaws.com",
                    "stage": "prod",
                },
                "body": json.dumps({"action": "subscribe_memories", "agent_id": "agent-xyz", "space_id": "space-1"}),
            }
            result = handler(event, {})

            assert result["statusCode"] == 200
            sent_data = json.loads(mock_post.call_args[1]["Data"].decode())
            assert sent_data["type"] == "subscribe_memories"
            assert sent_data["ok"] is True
            assert sent_data["subscription"] == "memories:agent-xyz:space-1"


class TestCmdPingBroadcast:
    """Tests for cmd.ping device command broadcast."""

    @patch("handler._dynamo")
    @patch("handler._get_db")
    @patch("handler._mgmt_api")
    @patch("handler.time")
    def test_cmd_ping_broadcasts_to_device_connection(self, mock_time, mock_mgmt, mock_db, mock_dynamo):
        """cmd.ping should queue an auditable action."""
        from handler import handler

        mock_time.time.return_value = 1700000000.123

        # Mock DynamoDB table - user's connection
        mock_table = MagicMock()
        mock_table.get_item.return_value = {
            "Item": {
                "connection_id": "user-conn",
                "status": "authenticated",
                "principal_type": "user",
                "user_id": "user-abc",
            }
        }
        mock_dynamo.Table.return_value = mock_table

        mock_db_instance = MagicMock()
        mock_db_instance.query.return_value = [{"agent_id": "agent-xyz"}]
        mock_db.return_value = mock_db_instance

        with (
            patch("handler.check_agent_permission", return_value=True),
            patch(
                "handler.create_action",
                return_value={"action_id": "action-ping-1", "kind": "device_command", "status": "approved"},
            ) as mock_create_action,
        ):
            mock_post = MagicMock()
            mock_mgmt.return_value.post_to_connection = mock_post

            event = {
                "requestContext": {
                    "connectionId": "user-conn",
                    "domainName": "test.execute-api.us-east-1.amazonaws.com",
                    "stage": "prod",
                },
                "body": json.dumps(
                    {"action": "cmd.ping", "target_device_id": "device-xyz", "idempotency_key": "ping-req-1"}
                ),
            }

            result = handler(event, {})

            assert result["statusCode"] == 200
            assert mock_post.call_count == 1
            mock_create_action.assert_called_once()
            user_data = json.loads(mock_post.call_args[1]["Data"].decode())
            assert user_data["type"] == "cmd.ping"
            assert user_data["ok"] is True
            assert user_data["action_id"] == "action-ping-1"
            assert user_data["queued"] is True

    @patch("handler._dynamo")
    @patch("handler._get_db")
    @patch("handler._mgmt_api")
    @patch("handler.time")
    def test_cmd_ping_device_not_connected(self, mock_time, mock_mgmt, mock_db, mock_dynamo):
        """cmd.ping should still queue when connectivity is unknown."""
        from handler import handler

        mock_time.time.return_value = 1700000000.123

        mock_table = MagicMock()
        mock_table.get_item.return_value = {
            "Item": {
                "connection_id": "user-conn",
                "status": "authenticated",
                "principal_type": "user",
                "user_id": "user-abc",
            }
        }
        mock_dynamo.Table.return_value = mock_table

        mock_db_instance = MagicMock()
        mock_db_instance.query.return_value = [{"agent_id": "agent-xyz"}]
        mock_db.return_value = mock_db_instance

        with (
            patch("handler.check_agent_permission", return_value=True),
            patch(
                "handler.create_action",
                return_value={"action_id": "action-ping-2", "kind": "device_command", "status": "approved"},
            ),
        ):
            mock_post = MagicMock()
            mock_mgmt.return_value.post_to_connection = mock_post

            event = {
                "requestContext": {
                    "connectionId": "user-conn",
                    "domainName": "test.execute-api.us-east-1.amazonaws.com",
                    "stage": "prod",
                },
                "body": json.dumps(
                    {"action": "cmd.ping", "target_device_id": "device-xyz", "idempotency_key": "ping-req-2"}
                ),
            }

            result = handler(event, {})

            assert result["statusCode"] == 200
            sent_data = json.loads(mock_post.call_args[1]["Data"].decode())
            assert sent_data["type"] == "cmd.ping"
            assert sent_data["ok"] is True
            assert sent_data["status"] == "approved"
            assert sent_data["queued"] is True


class TestCmdRunActionBroadcast:
    """Tests for cmd.run_action device command broadcast."""

    @patch("handler._dynamo")
    @patch("handler._get_db")
    @patch("handler._mgmt_api")
    @patch("handler._sqs")
    @patch("handler.time")
    def test_cmd_run_action_broadcasts_to_device(self, mock_time, mock_sqs, mock_mgmt, mock_db, mock_dynamo):
        """cmd.run_action should create and queue an approved action."""
        from handler import handler

        mock_time.time.return_value = 1700000000.123

        mock_table = MagicMock()
        mock_table.get_item.return_value = {
            "Item": {
                "connection_id": "user-conn",
                "status": "authenticated",
                "principal_type": "user",
                "user_id": "user-abc",
            }
        }
        # Mock GSI query to find device connections
        mock_table.query.return_value = {
            "Items": [{"connection_id": "device-conn-1", "device_id": "device-xyz", "status": "authenticated"}]
        }
        mock_dynamo.Table.return_value = mock_table

        mock_db_instance = MagicMock()
        mock_db_instance.query.return_value = [{"agent_id": "agent-xyz"}]
        mock_db.return_value = mock_db_instance

        with (
            patch("handler.check_agent_permission", return_value=True),
            patch(
                "handler.create_action",
                return_value={"action_id": "action-run-1", "kind": "device_command", "status": "approved"},
            ) as mock_create_action,
        ):
            mock_post = MagicMock()
            mock_mgmt.return_value.post_to_connection = mock_post

            event = {
                "requestContext": {
                    "connectionId": "user-conn",
                    "domainName": "test.execute-api.us-east-1.amazonaws.com",
                    "stage": "prod",
                },
                "body": json.dumps(
                    {
                        "action": "cmd.run_action",
                        "target_device_id": "device-xyz",
                        "kind": "status",
                        "payload": {"include_disk": True},
                        "idempotency_key": "run-req-1",
                    }
                ),
            }

            result = handler(event, {})

            assert result["statusCode"] == 200
            assert mock_post.call_count == 1
            mock_create_action.assert_called_once()

            user_data = json.loads(mock_post.call_args[1]["Data"].decode())
            assert user_data["type"] == "cmd.run_action"
            assert user_data["ok"] is True
            assert user_data["status"] == "approved"
            assert user_data["queued"] is True
            assert user_data["kind"] == "status"
            assert user_data["target_device_id"] == "device-xyz"
            assert user_data["action_id"] == "action-run-1"

    @patch("handler._dynamo")
    @patch("handler._get_db")
    @patch("handler._mgmt_api")
    @patch("handler._sqs")
    def test_cmd_run_action_requires_connected_device(self, mock_sqs, mock_mgmt, mock_db, mock_dynamo):
        """cmd.run_action now queues the lifecycle action even if connectivity is unknown."""
        from handler import handler

        mock_table = MagicMock()
        mock_table.get_item.return_value = {
            "Item": {
                "connection_id": "user-conn",
                "status": "authenticated",
                "principal_type": "user",
                "user_id": "user-abc",
            }
        }
        mock_dynamo.Table.return_value = mock_table

        mock_db_instance = MagicMock()
        mock_db_instance.query.return_value = [{"agent_id": "agent-xyz"}]
        mock_db.return_value = mock_db_instance

        with (
            patch("handler.check_agent_permission", return_value=True),
            patch(
                "handler.create_action",
                return_value={"action_id": "action-run-2", "kind": "device_command", "status": "approved"},
            ),
        ):
            mock_post = MagicMock()
            mock_mgmt.return_value.post_to_connection = mock_post

            event = {
                "requestContext": {
                    "connectionId": "user-conn",
                    "domainName": "test.execute-api.us-east-1.amazonaws.com",
                    "stage": "prod",
                },
                "body": json.dumps(
                    {
                        "action": "cmd.run_action",
                        "target_device_id": "device-xyz",
                        "kind": "status",
                        "idempotency_key": "run-req-2",
                    }
                ),
            }

            handler(event, {})

            sent_data = json.loads(mock_post.call_args[1]["Data"].decode())
            assert sent_data["ok"] is True
            assert sent_data["status"] == "approved"
            assert sent_data["queued"] is True


class TestCmdConfigBroadcast:
    """Tests for cmd.config device command broadcast."""

    @patch("handler._dynamo")
    @patch("handler._get_db")
    @patch("handler._mgmt_api")
    @patch("handler._sqs")
    @patch("handler.time")
    def test_cmd_config_broadcasts_to_device(self, mock_time, mock_sqs, mock_mgmt, mock_db, mock_dynamo):
        """cmd.config should create and queue an approved action."""
        from handler import handler

        mock_time.time.return_value = 1700000000.123

        mock_table = MagicMock()
        mock_table.get_item.return_value = {
            "Item": {
                "connection_id": "user-conn",
                "status": "authenticated",
                "principal_type": "user",
                "user_id": "user-abc",
            }
        }
        # Mock GSI query to find device connections
        mock_table.query.return_value = {
            "Items": [{"connection_id": "device-conn-1", "device_id": "device-xyz", "status": "authenticated"}]
        }
        mock_dynamo.Table.return_value = mock_table

        mock_db_instance = MagicMock()
        mock_db_instance.query.return_value = [{"agent_id": "agent-xyz"}]
        mock_db.return_value = mock_db_instance

        with (
            patch("handler.check_agent_permission", return_value=True),
            patch(
                "handler.create_action",
                return_value={"action_id": "action-config-1", "kind": "device_command", "status": "approved"},
            ) as mock_create_action,
        ):
            mock_post = MagicMock()
            mock_mgmt.return_value.post_to_connection = mock_post

            event = {
                "requestContext": {
                    "connectionId": "user-conn",
                    "domainName": "test.execute-api.us-east-1.amazonaws.com",
                    "stage": "prod",
                },
                "body": json.dumps(
                    {
                        "action": "cmd.config",
                        "target_device_id": "device-xyz",
                        "config": {"log_level": "DEBUG", "heartbeat_interval": 30},
                        "idempotency_key": "config-req-1",
                    }
                ),
            }

            result = handler(event, {})

            assert result["statusCode"] == 200
            assert mock_post.call_count == 1
            mock_create_action.assert_called_once()

            user_data = json.loads(mock_post.call_args[1]["Data"].decode())
            assert user_data["type"] == "cmd.config"
            assert user_data["ok"] is True
            assert user_data["status"] == "approved"
            assert user_data["queued"] is True
            assert user_data["target_device_id"] == "device-xyz"
            assert user_data["action_id"] == "action-config-1"
