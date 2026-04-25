from __future__ import annotations

import json
import urllib.error
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from agent_hub.tools.registry import ToolContext


class _FakeResponse:
    def __init__(self, payload: dict):
        self._payload = json.dumps(payload).encode("utf-8")
        self.status = 200

    def read(self) -> bytes:
        return self._payload

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False


def _ctx() -> ToolContext:
    return ToolContext(
        db=MagicMock(),
        agent_id="agent-1",
        space_id="space-1",
        action_id="action-1",
        device_scopes=["github:issue:write", "linear:comment:write"],
    )


def test_github_issue_comment_uses_account_and_persists_comment_id():
    from agent_hub.tools.github_issue_comment import _handler

    ctx = _ctx()
    account = SimpleNamespace(integration_account_id="acct-1", status="active")
    pending = SimpleNamespace(inserted=True, message=SimpleNamespace(integration_message_id="msg-1"))

    with (
        patch(
            "agent_hub.tools.github_issue_comment.load_outbound_integration_account",
            return_value=(account, {"token": "gh-token"}),
        ),
        patch("agent_hub.tools.github_issue_comment.insert_integration_message", return_value=pending) as mock_insert,
        patch("agent_hub.tools.github_issue_comment.finalize_outbound_integration_message") as mock_finalize,
        patch(
            "agent_hub.tools.github_issue_comment.urllib.request.urlopen",
            return_value=_FakeResponse(
                {"id": 987654321, "html_url": "https://github.com/org/repo/issues/1#issuecomment-1"}
            ),
        ) as mock_urlopen,
    ):
        result = _handler(
            {
                "integration_account_id": "acct-1",
                "repository": "org/repo",
                "issue_number": 17,
                "body": "hello",
            },
            ctx,
        )

    assert result.ok is True
    assert result.data["comment_id"] == "987654321"
    req = mock_urlopen.call_args.args[0]
    assert req.full_url == "https://api.github.com/repos/org/repo/issues/17/comments"
    assert req.get_header("Authorization") == "Bearer gh-token"
    inserted = mock_insert.call_args.args[1]
    assert inserted.integration_account_id == "acct-1"
    assert inserted.action_id == "action-1"
    assert inserted.provider == "github"
    assert inserted.status == "pending"
    mock_finalize.assert_called_once()
    finalize_kwargs = mock_finalize.call_args.kwargs
    assert finalize_kwargs["external_message_id"] == "987654321"
    assert finalize_kwargs["status"] == "sent"
    assert finalize_kwargs["integration_message_id"] == "msg-1"


def test_github_issue_comment_finalizes_error_without_resend():
    from agent_hub.tools.github_issue_comment import _handler

    ctx = _ctx()
    account = SimpleNamespace(integration_account_id="acct-1", status="active")
    existing = SimpleNamespace(
        inserted=False,
        message=SimpleNamespace(
            status="error",
            payload={"error": "previous failure"},
            external_message_id=None,
        ),
    )

    with (
        patch(
            "agent_hub.tools.github_issue_comment.load_outbound_integration_account",
            return_value=(account, {"token": "gh-token"}),
        ),
        patch("agent_hub.tools.github_issue_comment.insert_integration_message", return_value=existing),
        patch("agent_hub.tools.github_issue_comment.finalize_outbound_integration_message") as mock_finalize,
        patch("agent_hub.tools.github_issue_comment.urllib.request.urlopen") as mock_urlopen,
    ):
        result = _handler(
            {
                "integration_account_id": "acct-1",
                "repository": "org/repo",
                "issue_number": 17,
                "body": "hello",
            },
            ctx,
        )

    assert result.ok is False
    assert result.error == "previous failure"
    mock_urlopen.assert_not_called()
    mock_finalize.assert_not_called()


def test_linear_comment_create_uses_account_and_persists_comment_id():
    from agent_hub.tools.linear_comment_create import _handler

    ctx = _ctx()
    account = SimpleNamespace(integration_account_id="acct-2", status="active")
    pending = SimpleNamespace(inserted=True, message=SimpleNamespace(integration_message_id="msg-2"))

    with (
        patch(
            "agent_hub.tools.linear_comment_create.load_outbound_integration_account",
            return_value=(account, {"api_key": "lin-token"}),
        ),
        patch("agent_hub.tools.linear_comment_create.insert_integration_message", return_value=pending) as mock_insert,
        patch("agent_hub.tools.linear_comment_create.finalize_outbound_integration_message") as mock_finalize,
        patch(
            "agent_hub.tools.linear_comment_create.urllib.request.urlopen",
            return_value=_FakeResponse(
                {
                    "data": {
                        "commentCreate": {
                            "success": True,
                            "comment": {"id": "comment-123", "body": "hello"},
                        }
                    }
                }
            ),
        ) as mock_urlopen,
    ):
        result = _handler(
            {
                "integration_account_id": "acct-2",
                "issue_id": "issue-1",
                "body": "hello",
            },
            ctx,
        )

    assert result.ok is True
    assert result.data["comment_id"] == "comment-123"
    req = mock_urlopen.call_args.args[0]
    assert req.full_url == "https://api.linear.app/graphql"
    assert req.get_header("Authorization") == "Bearer lin-token"
    inserted = mock_insert.call_args.args[1]
    assert inserted.integration_account_id == "acct-2"
    assert inserted.action_id == "action-1"
    assert inserted.provider == "linear"
    assert inserted.status == "pending"
    mock_finalize.assert_called_once()
    finalize_kwargs = mock_finalize.call_args.kwargs
    assert finalize_kwargs["external_message_id"] == "comment-123"
    assert finalize_kwargs["status"] == "sent"
    assert finalize_kwargs["integration_message_id"] == "msg-2"


def test_linear_comment_create_records_http_error():
    from agent_hub.tools.linear_comment_create import _handler

    ctx = _ctx()
    account = SimpleNamespace(integration_account_id="acct-2", status="active")
    pending = SimpleNamespace(inserted=True, message=SimpleNamespace(integration_message_id="msg-3"))
    http_error = urllib.error.HTTPError(
        url="https://api.linear.app/graphql",
        code=500,
        msg="Server Error",
        hdrs=None,
        fp=None,
    )

    with (
        patch(
            "agent_hub.tools.linear_comment_create.load_outbound_integration_account",
            return_value=(account, {"api_key": "lin-token"}),
        ),
        patch("agent_hub.tools.linear_comment_create.insert_integration_message", return_value=pending),
        patch("agent_hub.tools.linear_comment_create.finalize_outbound_integration_message") as mock_finalize,
        patch("agent_hub.tools.linear_comment_create.urllib.request.urlopen", side_effect=http_error),
    ):
        result = _handler(
            {
                "integration_account_id": "acct-2",
                "issue_id": "issue-1",
                "body": "hello",
            },
            ctx,
        )

    assert result.ok is False
    assert result.error == "http_error_500"
    mock_finalize.assert_called_once()
