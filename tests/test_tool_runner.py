"""Tests for tool registry and tool implementations."""
from __future__ import annotations

import json
import pytest
from unittest.mock import MagicMock, patch

from agent_hub.tools.registry import ToolRegistry, ToolResult, ToolContext


class TestToolRegistry:
    """Tests for the ToolRegistry class."""

    def test_register_and_get_tool(self):
        """Tools can be registered and retrieved."""
        registry = ToolRegistry()
        handler = MagicMock(return_value=ToolResult(ok=True))
        
        registry.register("test_tool", required_scopes=["scope:a"], handler=handler)
        
        tool = registry.get("test_tool")
        assert tool is not None
        assert tool.name == "test_tool"
        assert tool.required_scopes == ["scope:a"]

    def test_list_tools(self):
        """list_tools returns all registered tool names."""
        registry = ToolRegistry()
        registry.register("tool_a", required_scopes=[], handler=MagicMock())
        registry.register("tool_b", required_scopes=[], handler=MagicMock())
        
        tools = registry.list_tools()
        assert "tool_a" in tools
        assert "tool_b" in tools

    def test_check_scopes_passes_with_all_required(self):
        """check_scopes returns True when all required scopes are granted."""
        registry = ToolRegistry()
        registry.register("tool", required_scopes=["scope:a", "scope:b"], handler=MagicMock())
        
        assert registry.check_scopes("tool", ["scope:a", "scope:b", "scope:c"]) is True

    def test_check_scopes_fails_with_missing(self):
        """check_scopes returns False when required scopes are missing."""
        registry = ToolRegistry()
        registry.register("tool", required_scopes=["scope:a", "scope:b"], handler=MagicMock())
        
        assert registry.check_scopes("tool", ["scope:a"]) is False

    def test_execute_unknown_tool_returns_error(self):
        """Executing unknown tool returns error result."""
        registry = ToolRegistry()
        ctx = MagicMock(spec=ToolContext)
        ctx.device_scopes = []
        
        result = registry.execute("unknown", {}, ctx)
        
        assert result.ok is False
        assert "unknown_tool" in result.error

    def test_execute_with_missing_scopes_returns_error(self):
        """Executing with missing scopes returns error result."""
        registry = ToolRegistry()
        registry.register("tool", required_scopes=["scope:required"], handler=MagicMock())
        
        ctx = MagicMock(spec=ToolContext)
        ctx.device_scopes = []
        
        result = registry.execute("tool", {}, ctx)
        
        assert result.ok is False
        assert "missing_scopes" in result.error

    def test_execute_calls_handler(self):
        """Execute calls the registered handler."""
        registry = ToolRegistry()
        handler = MagicMock(return_value=ToolResult(ok=True, data={"result": "success"}))
        registry.register("tool", required_scopes=["scope:a"], handler=handler)
        
        ctx = MagicMock(spec=ToolContext)
        ctx.device_scopes = ["scope:a"]
        
        result = registry.execute("tool", {"key": "value"}, ctx)
        
        assert result.ok is True
        assert result.data == {"result": "success"}
        handler.assert_called_once_with({"key": "value"}, ctx)


class TestToolResult:
    """Tests for the ToolResult class."""

    def test_to_dict_success(self):
        """to_dict returns correct format for success."""
        result = ToolResult(ok=True, data={"key": "value"})
        d = result.to_dict()
        
        assert d["ok"] is True
        assert d["data"] == {"key": "value"}
        assert "error" not in d

    def test_to_dict_error(self):
        """to_dict returns correct format for error."""
        result = ToolResult(ok=False, error="something_failed")
        d = result.to_dict()
        
        assert d["ok"] is False
        assert d["error"] == "something_failed"
        assert "data" not in d


class TestCreateMemoryTool:
    """Tests for the create_memory tool."""

    def test_create_memory_success(self):
        """create_memory inserts memory and returns memory_id."""
        from agent_hub.tools.create_memory import _handler
        
        mock_db = MagicMock()
        mock_db.query.return_value = [{"memory_id": "mem-123"}]
        
        ctx = ToolContext(
            db=mock_db,
            agent_id="agent-1",
            space_id="space-1",
            action_id="action-1",
            device_scopes=["memory:write"],
        )
        
        result = _handler({"tier": "semantic", "content": "Test memory"}, ctx)
        
        assert result.ok is True
        assert result.data["memory_id"] == "mem-123"
        assert result.data["tier"] == "semantic"
        mock_db.query.assert_called_once()

    def test_create_memory_missing_content(self):
        """create_memory returns error for missing content."""
        from agent_hub.tools.create_memory import _handler
        
        ctx = MagicMock(spec=ToolContext)
        
        result = _handler({"tier": "semantic"}, ctx)
        
        assert result.ok is False
        assert "missing_content" in result.error

    def test_create_memory_invalid_tier(self):
        """create_memory returns error for invalid tier."""
        from agent_hub.tools.create_memory import _handler

        ctx = MagicMock(spec=ToolContext)

        result = _handler({"tier": "invalid", "content": "Test"}, ctx)

        assert result.ok is False
        assert "invalid_tier" in result.error


class TestSendMessageTool:
    """Tests for the send_message tool."""

    def test_send_message_success(self):
        """send_message broadcasts and records event."""
        from agent_hub.tools.send_message import _handler

        mock_db = MagicMock()
        mock_broadcast = MagicMock()

        ctx = ToolContext(
            db=mock_db,
            agent_id="agent-1",
            space_id="space-1",
            action_id="action-1",
            device_scopes=["message:send"],
            broadcast_fn=mock_broadcast,
        )

        result = _handler({
            "recipient_type": "space",
            "recipient_id": "space-1",
            "message_type": "notification",
            "content": "Hello!",
        }, ctx)

        assert result.ok is True
        assert result.data["delivered"] is True
        mock_broadcast.assert_called_once()
        mock_db.execute.assert_called_once()

    def test_send_message_missing_recipient(self):
        """send_message returns error for missing recipient."""
        from agent_hub.tools.send_message import _handler

        ctx = MagicMock(spec=ToolContext)

        result = _handler({"content": "Hello"}, ctx)

        assert result.ok is False
        assert "missing_recipient_type" in result.error

    def test_send_message_no_broadcast_fn(self):
        """send_message returns error when broadcast_fn not configured."""
        from agent_hub.tools.send_message import _handler

        ctx = ToolContext(
            db=MagicMock(),
            agent_id="agent-1",
            space_id=None,
            action_id="action-1",
            broadcast_fn=None,
        )

        result = _handler({
            "recipient_type": "space",
            "recipient_id": "space-1",
            "content": "Hello",
        }, ctx)

        assert result.ok is False
        assert "broadcast_not_configured" in result.error


class TestHttpRequestTool:
    """Tests for the http_request tool."""

    def test_http_request_host_not_allowed(self):
        """http_request returns error for disallowed hosts."""
        from agent_hub.tools.http_request import _handler

        ctx = ToolContext(
            db=MagicMock(),
            agent_id="agent-1",
            space_id=None,
            action_id="action-1",
            allowed_http_hosts=["allowed.com"],
        )

        result = _handler({
            "method": "GET",
            "url": "https://notallowed.com/api",
        }, ctx)

        assert result.ok is False
        assert "host_not_allowed" in result.error

    def test_http_request_invalid_method(self):
        """http_request returns error for invalid method."""
        from agent_hub.tools.http_request import _handler

        ctx = MagicMock(spec=ToolContext)
        ctx.allowed_http_hosts = []

        result = _handler({
            "method": "INVALID",
            "url": "https://example.com",
        }, ctx)

        assert result.ok is False
        assert "invalid_method" in result.error

    def test_http_request_missing_url(self):
        """http_request returns error for missing URL."""
        from agent_hub.tools.http_request import _handler

        ctx = MagicMock(spec=ToolContext)
        ctx.allowed_http_hosts = []

        result = _handler({"method": "GET"}, ctx)

        assert result.ok is False
        assert "missing_url" in result.error

    @patch("agent_hub.tools.http_request.urllib.request.urlopen")
    def test_http_request_success(self, mock_urlopen):
        """http_request returns response on success."""
        from agent_hub.tools.http_request import _handler

        mock_response = MagicMock()
        mock_response.status = 200
        mock_response.headers = {"Content-Type": "application/json"}
        mock_response.read.return_value = b'{"ok": true}'
        mock_response.__enter__ = MagicMock(return_value=mock_response)
        mock_response.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value = mock_response

        ctx = ToolContext(
            db=MagicMock(),
            agent_id="agent-1",
            space_id=None,
            action_id="action-1",
            allowed_http_hosts=[],  # Empty means all allowed
        )

        result = _handler({
            "method": "GET",
            "url": "https://example.com/api",
        }, ctx)

        assert result.ok is True
        assert result.data["status"] == 200
        assert '{"ok": true}' in result.data["body"]

