"""Tests for tool registry and tool implementations."""

from __future__ import annotations

import io
import base64
import json
import os
import urllib.error
from pathlib import Path
from unittest.mock import MagicMock, patch

from agent_hub.tools.registry import ToolContext, ToolRegistry, ToolResult


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
        """list_tools returns all registered ToolSpec objects."""
        registry = ToolRegistry()
        registry.register("tool_a", required_scopes=[], handler=MagicMock())
        registry.register("tool_b", required_scopes=[], handler=MagicMock())

        tools = registry.list_tools()
        names = [t.name for t in tools]
        assert "tool_a" in names
        assert "tool_b" in names

    def test_list_tool_names(self):
        """list_tool_names returns all registered tool names as strings."""
        registry = ToolRegistry()
        registry.register("tool_a", required_scopes=[], handler=MagicMock())
        registry.register("tool_b", required_scopes=[], handler=MagicMock())

        names = registry.list_tool_names()
        assert "tool_a" in names
        assert "tool_b" in names

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

        result = _handler(
            {
                "recipient_type": "space",
                "recipient_id": "space-1",
                "message_type": "notification",
                "content": "Hello!",
            },
            ctx,
        )

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

        result = _handler(
            {
                "recipient_type": "space",
                "recipient_id": "space-1",
                "content": "Hello",
            },
            ctx,
        )

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

        result = _handler(
            {
                "method": "GET",
                "url": "https://notallowed.com/api",
            },
            ctx,
        )

        assert result.ok is False
        assert "host_not_allowed" in result.error

    def test_http_request_blocks_metadata_endpoint(self):
        """http_request blocks AWS metadata endpoint (SSRF protection)."""
        from agent_hub.tools.http_request import _handler

        ctx = ToolContext(
            db=MagicMock(),
            agent_id="agent-1",
            space_id=None,
            action_id="action-1",
            allowed_http_hosts=[],  # Empty means all public allowed
        )

        result = _handler(
            {
                "method": "GET",
                "url": "http://169.254.169.254/latest/meta-data/",
            },
            ctx,
        )

        assert result.ok is False
        assert "host_not_allowed" in result.error

    def test_http_request_blocks_localhost(self):
        """http_request blocks localhost (SSRF protection)."""
        from agent_hub.tools.http_request import _handler

        ctx = ToolContext(
            db=MagicMock(),
            agent_id="agent-1",
            space_id=None,
            action_id="action-1",
            allowed_http_hosts=[],
        )

        result = _handler(
            {
                "method": "GET",
                "url": "http://localhost/secret",
            },
            ctx,
        )

        assert result.ok is False
        assert "host_not_allowed" in result.error

    def test_http_request_invalid_method(self):
        """http_request returns error for invalid method."""
        from agent_hub.tools.http_request import _handler

        ctx = MagicMock(spec=ToolContext)
        ctx.allowed_http_hosts = []

        result = _handler(
            {
                "method": "INVALID",
                "url": "https://example.com",
            },
            ctx,
        )

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

        result = _handler(
            {
                "method": "GET",
                "url": "https://example.com/api",
            },
            ctx,
        )

        assert result.ok is True
        assert result.data["status"] == 200
        assert '{"ok": true}' in result.data["body"]


class _FakeSlackResponse:
    def __init__(self, payload: dict):
        self._payload = json.dumps(payload).encode("utf-8")
        self.status = 200

    def read(self) -> bytes:
        return self._payload

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False


class _FakeTwilioResponse:
    def __init__(self, payload: dict):
        self._payload = json.dumps(payload).encode("utf-8")
        self.status = 201

    def read(self) -> bytes:
        return self._payload

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False


class TestSlackPostMessageTool:
    """Tests for the slack_post_message tool."""

    def test_slack_post_message_success(self):
        """slack_post_message calls Slack and returns response metadata."""
        from agent_hub.tools.slack_post_message import _handler

        ctx = ToolContext(
            db=MagicMock(),
            agent_id="agent-1",
            space_id="space-1",
            action_id="action-1",
            device_scopes=["slack:message:write"],
        )

        with (
            patch.dict(os.environ, {"SLACK_SECRET_ARN": "arn:aws:secretsmanager:us-east-1:123:secret:slack"}, clear=False),
            patch("agent_hub.tools.slack_post_message.get_secret_json", return_value={"bot_token": "xoxb-test"}),
            patch("agent_hub.tools.slack_post_message.insert_integration_message") as mock_insert,
            patch(
                "agent_hub.tools.slack_post_message.urllib.request.urlopen",
                return_value=_FakeSlackResponse(
                    {
                        "ok": True,
                        "channel": "C123",
                        "ts": "1712345678.000100",
                        "message": {"text": "hello", "thread_ts": "1712345678.000100"},
                    }
                ),
            ) as mock_urlopen,
        ):
            result = _handler({"channel_id": "C123", "text": "hello"}, ctx)

        assert result.ok is True
        assert result.data["channel_id"] == "C123"
        assert result.data["ts"] == "1712345678.000100"
        assert result.data["thread_ts"] == "1712345678.000100"
        req = mock_urlopen.call_args.args[0]
        assert req.full_url == "https://slack.com/api/chat.postMessage"
        assert req.get_header("Authorization") == "Bearer xoxb-test"
        inserted_message = mock_insert.call_args.args[1]
        assert inserted_message.provider == "slack"
        assert inserted_message.direction == "outbound"
        assert inserted_message.dedupe_key == "action:action-1"
        assert inserted_message.external_message_id == "1712345678.000100"

    def test_slack_post_message_handles_slack_api_error(self):
        """slack_post_message surfaces Slack application errors."""
        from agent_hub.tools.slack_post_message import _handler

        ctx = ToolContext(
            db=MagicMock(),
            agent_id="agent-1",
            space_id="space-1",
            action_id="action-1",
            device_scopes=["slack:message:write"],
        )

        with (
            patch.dict(os.environ, {"SLACK_SECRET_ARN": "arn:aws:secretsmanager:us-east-1:123:secret:slack"}, clear=False),
            patch("agent_hub.tools.slack_post_message.get_secret_json", return_value={"bot_token": "xoxb-test"}),
            patch("agent_hub.tools.slack_post_message.insert_integration_message") as mock_insert,
            patch(
                "agent_hub.tools.slack_post_message.urllib.request.urlopen",
                return_value=_FakeSlackResponse({"ok": False, "error": "channel_not_found"}),
            ),
        ):
            result = _handler({"channel_id": "C123", "text": "hello"}, ctx)

        assert result.ok is False
        assert result.error == "slack_api_error: channel_not_found"
        mock_insert.assert_not_called()

    def test_slack_post_message_handles_http_error(self):
        """slack_post_message returns HTTP-level failures."""
        from agent_hub.tools.slack_post_message import _handler

        ctx = ToolContext(
            db=MagicMock(),
            agent_id="agent-1",
            space_id="space-1",
            action_id="action-1",
            device_scopes=["slack:message:write"],
        )
        http_error = urllib.error.HTTPError(
            url="https://slack.com/api/chat.postMessage",
            code=429,
            msg="Too Many Requests",
            hdrs=None,
            fp=io.BytesIO(b'{"ok": false, "error": "rate_limited"}'),
        )

        with (
            patch.dict(os.environ, {"SLACK_SECRET_ARN": "arn:aws:secretsmanager:us-east-1:123:secret:slack"}, clear=False),
            patch("agent_hub.tools.slack_post_message.get_secret_json", return_value={"bot_token": "xoxb-test"}),
            patch("agent_hub.tools.slack_post_message.insert_integration_message") as mock_insert,
            patch("agent_hub.tools.slack_post_message.urllib.request.urlopen", side_effect=http_error),
        ):
            result = _handler({"channel_id": "C123", "text": "hello"}, ctx)

        assert result.ok is False
        assert result.error == "http_error_429"
        mock_insert.assert_not_called()


class TestTwilioSendSmsTool:
    """Tests for the twilio_send_sms tool."""

    def test_twilio_send_sms_success(self):
        """twilio_send_sms posts a form request and returns Twilio metadata."""
        from agent_hub.tools.twilio_send_sms import _handler

        ctx = ToolContext(
            db=MagicMock(),
            agent_id="agent-1",
            space_id="space-1",
            action_id="action-1",
            device_scopes=["twilio:sms:send"],
        )

        with (
            patch.dict(
                os.environ,
                {"TWILIO_SECRET_ARN": "arn:aws:secretsmanager:us-east-1:123:secret:twilio"},
                clear=False,
            ),
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
                return_value=_FakeTwilioResponse(
                    {
                        "sid": "SM123",
                        "status": "queued",
                        "to": "+15551230001",
                        "from": "+15551239999",
                    }
                ),
            ) as mock_urlopen,
        ):
            result = _handler({"to": "+15551230001", "body": "hello"}, ctx)

        assert result.ok is True
        assert result.data["sid"] == "SM123"
        assert result.data["status"] == "queued"
        req = mock_urlopen.call_args.args[0]
        assert req.full_url == "https://api.twilio.com/2010-04-01/Accounts/AC123/Messages.json"
        expected_auth = "Basic " + base64.b64encode(b"AC123:auth-token").decode("utf-8")
        assert req.get_header("Authorization") == expected_auth
        assert req.data.decode("utf-8") == "To=%2B15551230001&Body=hello&From=%2B15551239999"
        inserted_message = mock_insert.call_args.args[1]
        assert inserted_message.provider == "twilio"
        assert inserted_message.direction == "outbound"
        assert inserted_message.dedupe_key == "action:action-1"
        assert inserted_message.external_message_id == "SM123"

    def test_twilio_send_sms_handles_http_error(self):
        """twilio_send_sms returns HTTP-level failures."""
        from agent_hub.tools.twilio_send_sms import _handler

        ctx = ToolContext(
            db=MagicMock(),
            agent_id="agent-1",
            space_id="space-1",
            action_id="action-1",
            device_scopes=["twilio:sms:send"],
        )
        http_error = urllib.error.HTTPError(
            url="https://api.twilio.com/2010-04-01/Accounts/AC123/Messages.json",
            code=400,
            msg="Bad Request",
            hdrs=None,
            fp=io.BytesIO(b'{"message": "The To phone number is invalid."}'),
        )

        with (
            patch.dict(
                os.environ,
                {"TWILIO_SECRET_ARN": "arn:aws:secretsmanager:us-east-1:123:secret:twilio"},
                clear=False,
            ),
            patch(
                "agent_hub.tools.twilio_send_sms.get_secret_json",
                return_value={
                    "account_sid": "AC123",
                    "auth_token": "auth-token",
                    "from_number": "+15551239999",
                },
            ),
            patch("agent_hub.tools.twilio_send_sms.insert_integration_message") as mock_insert,
            patch("agent_hub.tools.twilio_send_sms.urllib.request.urlopen", side_effect=http_error),
        ):
            result = _handler({"to": "+15551230001", "body": "hello"}, ctx)

        assert result.ok is False
        assert result.error == "http_error_400"
        mock_insert.assert_not_called()


def test_tool_runner_template_wires_provider_secrets():
    template_text = (Path(__file__).resolve().parents[1] / "template.yaml").read_text(encoding="utf-8")
    assert "ToolRunnerFunction:" in template_text
    assert "SLACK_SECRET_ARN: !Ref SlackSecret" in template_text
    assert "- !Ref SlackSecret" in template_text
    assert "TWILIO_SECRET_ARN: !Ref TwilioSecret" in template_text
    assert "- !Ref TwilioSecret" in template_text


def test_hub_api_template_wires_github_secret():
    template_text = (Path(__file__).resolve().parents[1] / "template.yaml").read_text(encoding="utf-8")
    assert "HubApiFunction:" in template_text
    assert "GITHUB_SECRET_ARN: !Ref GitHubSecret" in template_text
    assert "- !Ref GitHubSecret" in template_text
