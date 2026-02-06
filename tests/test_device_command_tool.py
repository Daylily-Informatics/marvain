"""Tests for the device_command tool.

These tests verify the device command tool functionality including:
- Device ownership verification
- Connection lookup
- Command sending
- Error handling
"""
from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

# Add shared layer to path
repo_root = Path(__file__).resolve().parents[1]
shared = repo_root / "layers" / "shared" / "python"
if str(shared) not in sys.path:
    sys.path.insert(0, str(shared))

# Set required environment variables
os.environ.setdefault("AWS_DEFAULT_REGION", "us-east-1")
os.environ.setdefault("WS_CONNECTIONS_TABLE", "test-ws-connections")
os.environ.setdefault("WS_API_ENDPOINT", "https://test.execute-api.us-east-1.amazonaws.com/prod")


class MockToolContext:
    """Mock ToolContext for testing."""
    
    def __init__(
        self,
        agent_id: str = "agent-123",
        action_id: str = "action-456",
        device_scopes: list[str] | None = None,
    ):
        self.agent_id = agent_id
        self.action_id = action_id
        self.device_scopes = device_scopes or ["devices:write"]
        self.db = MagicMock()


class TestDeviceCommandHandler:
    """Tests for device_command_handler function."""

    def test_missing_device_id_returns_error(self):
        """Handler should return error if device_id is missing."""
        from agent_hub.tools.device_command import device_command_handler
        
        ctx = MockToolContext()
        result = device_command_handler({"command": "ping"}, ctx)
        
        assert result.ok is False
        assert result.error == "missing_device_id"

    def test_device_not_found_returns_error(self):
        """Handler should return error if device not found or not owned."""
        from agent_hub.tools.device_command import device_command_handler
        
        ctx = MockToolContext()
        ctx.db.query.return_value = []  # No device found
        
        result = device_command_handler(
            {"device_id": "device-xyz", "command": "ping"},
            ctx
        )
        
        assert result.ok is False
        assert result.error == "device_not_found_or_not_owned"

    @patch("agent_hub.tools.device_command._get_connections_for_device")
    def test_device_not_connected_returns_error(self, mock_get_connections):
        """Handler should return error if device has no WebSocket connections."""
        from agent_hub.tools.device_command import device_command_handler
        
        ctx = MockToolContext()
        ctx.db.query.return_value = [
            {"device_id": "device-xyz", "agent_id": "agent-123", "name": "Test Device"}
        ]
        mock_get_connections.return_value = []  # No connections
        
        result = device_command_handler(
            {"device_id": "device-xyz", "command": "ping"},
            ctx
        )
        
        assert result.ok is False
        assert result.error == "device_not_connected"

    @patch("agent_hub.tools.device_command._send_to_connection")
    @patch("agent_hub.tools.device_command._get_connections_for_device")
    def test_successful_command_send(self, mock_get_connections, mock_send):
        """Handler should successfully send command to connected device."""
        from agent_hub.tools.device_command import device_command_handler
        
        ctx = MockToolContext()
        ctx.db.query.return_value = [
            {"device_id": "device-xyz", "agent_id": "agent-123", "name": "Test Device"}
        ]
        mock_get_connections.return_value = ["conn-1", "conn-2"]
        mock_send.return_value = True  # Successful send
        
        result = device_command_handler(
            {"device_id": "device-xyz", "command": "ping", "data": {"test": True}},
            ctx
        )
        
        assert result.ok is True
        assert result.data["device_id"] == "device-xyz"
        assert result.data["device_name"] == "Test Device"
        assert result.data["command"] == "ping"
        assert result.data["connections_sent"] == 2

    @patch("agent_hub.tools.device_command._send_to_connection")
    @patch("agent_hub.tools.device_command._get_connections_for_device")
    def test_partial_send_failure(self, mock_get_connections, mock_send):
        """Handler should report partial success if some connections fail."""
        from agent_hub.tools.device_command import device_command_handler
        
        ctx = MockToolContext()
        ctx.db.query.return_value = [
            {"device_id": "device-xyz", "agent_id": "agent-123", "name": "Test Device"}
        ]
        mock_get_connections.return_value = ["conn-1", "conn-2", "conn-3"]
        # First two succeed, third fails
        mock_send.side_effect = [True, True, False]
        
        result = device_command_handler(
            {"device_id": "device-xyz", "command": "run_action"},
            ctx
        )
        
        assert result.ok is True
        assert result.data["connections_sent"] == 2

    @patch("agent_hub.tools.device_command._send_to_connection")
    @patch("agent_hub.tools.device_command._get_connections_for_device")
    def test_all_sends_fail_returns_error(self, mock_get_connections, mock_send):
        """Handler should return error if all connection sends fail."""
        from agent_hub.tools.device_command import device_command_handler
        
        ctx = MockToolContext()
        ctx.db.query.return_value = [
            {"device_id": "device-xyz", "agent_id": "agent-123", "name": "Test Device"}
        ]
        mock_get_connections.return_value = ["conn-1", "conn-2"]
        mock_send.return_value = False  # All sends fail
        
        result = device_command_handler(
            {"device_id": "device-xyz", "command": "config"},
            ctx
        )
        
        assert result.ok is False
        assert result.error == "failed_to_send_to_any_connection"

    def test_ws_endpoint_not_configured_returns_error(self):
        """Handler should return error if WS endpoint not configured."""
        from agent_hub.tools.device_command import device_command_handler
        
        # Temporarily unset the endpoint
        original = os.environ.get("WS_API_ENDPOINT")
        os.environ["WS_API_ENDPOINT"] = ""
        
        try:
            ctx = MockToolContext()
            ctx.db.query.return_value = [
                {"device_id": "device-xyz", "agent_id": "agent-123", "name": "Test"}
            ]
            
            with patch("agent_hub.tools.device_command._get_connections_for_device") as mock_conn:
                mock_conn.return_value = ["conn-1"]
                result = device_command_handler(
                    {"device_id": "device-xyz", "command": "ping"},
                    ctx
                )
        finally:
            if original:
                os.environ["WS_API_ENDPOINT"] = original
        
        assert result.ok is False
        assert result.error == "ws_endpoint_not_configured"


class TestToolRegistration:
    """Tests for device_command tool registration."""

    def test_tool_registers_with_correct_scopes(self):
        """Tool should register with devices:write scope."""
        from agent_hub.tools.registry import ToolRegistry
        from agent_hub.tools import device_command

        registry = ToolRegistry()
        device_command.register(registry)

        tool = registry.get("device_command")
        assert tool is not None
        assert "devices:write" in tool.required_scopes

    def test_tool_scope_check_passes_with_correct_scope(self):
        """Tool should pass scope check with devices:write."""
        from agent_hub.tools.registry import ToolRegistry
        from agent_hub.tools import device_command

        registry = ToolRegistry()
        device_command.register(registry)

        assert registry.check_scopes("device_command", ["devices:write"]) is True
        assert registry.check_scopes("device_command", ["devices:write", "events:read"]) is True

    def test_tool_scope_check_fails_without_scope(self):
        """Tool should fail scope check without devices:write."""
        from agent_hub.tools.registry import ToolRegistry
        from agent_hub.tools import device_command

        registry = ToolRegistry()
        device_command.register(registry)

        assert registry.check_scopes("device_command", []) is False
        assert registry.check_scopes("device_command", ["events:read"]) is False


class TestGetConnectionsForDevice:
    """Tests for _get_connections_for_device helper."""

    def test_returns_empty_list_when_no_table_configured(self):
        """Should return empty list if WS_CONNECTIONS_TABLE not set."""
        from agent_hub.tools import device_command

        # Temporarily unset table name
        original = device_command._WS_TABLE_NAME
        device_command._WS_TABLE_NAME = ""

        try:
            result = device_command._get_connections_for_device("device-123")
            assert result == []
        finally:
            device_command._WS_TABLE_NAME = original

    @patch("agent_hub.tools.device_command._get_dynamodb")
    def test_returns_connection_ids_from_dynamodb(self, mock_dynamo):
        """Should return connection IDs from DynamoDB query."""
        from agent_hub.tools import device_command

        mock_table = MagicMock()
        mock_table.query.return_value = {
            "Items": [
                {"connection_id": "conn-1"},
                {"connection_id": "conn-2"},
            ]
        }
        mock_dynamo.return_value.Table.return_value = mock_table

        result = device_command._get_connections_for_device("device-123")

        assert result == ["conn-1", "conn-2"]

    @patch("agent_hub.tools.device_command._get_dynamodb")
    def test_returns_empty_list_on_query_error(self, mock_dynamo):
        """Should return empty list if DynamoDB query fails."""
        from agent_hub.tools import device_command

        mock_table = MagicMock()
        mock_table.query.side_effect = Exception("DynamoDB error")
        mock_dynamo.return_value.Table.return_value = mock_table

        result = device_command._get_connections_for_device("device-123")

        assert result == []


class TestSendToConnection:
    """Tests for _send_to_connection helper."""

    @patch("boto3.client")
    def test_successful_send_returns_true(self, mock_boto_client):
        """Should return True on successful send."""
        from agent_hub.tools.device_command import _send_to_connection

        mock_client = MagicMock()
        mock_boto_client.return_value = mock_client

        result = _send_to_connection(
            "conn-123",
            {"type": "cmd.ping"},
            "https://test.execute-api.us-east-1.amazonaws.com/prod"
        )

        assert result is True
        mock_client.post_to_connection.assert_called_once()

    @patch("boto3.client")
    def test_failed_send_returns_false(self, mock_boto_client):
        """Should return False on send failure."""
        from agent_hub.tools.device_command import _send_to_connection

        mock_client = MagicMock()
        mock_client.post_to_connection.side_effect = Exception("Connection gone")
        mock_boto_client.return_value = mock_client

        result = _send_to_connection(
            "conn-123",
            {"type": "cmd.ping"},
            "https://test.execute-api.us-east-1.amazonaws.com/prod"
        )

        assert result is False

