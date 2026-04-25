"""linear_comment_create tool - Post a comment to a Linear issue."""

from __future__ import annotations

import json
import logging
import urllib.error
import urllib.request
from typing import Any

from agent_hub.integrations import (
    IntegrationMessageCreate,
    finalize_outbound_integration_message,
    insert_integration_message,
)
from agent_hub.tools._outbound import load_outbound_integration_account

from .registry import ToolContext, ToolRegistry, ToolResult

logger = logging.getLogger(__name__)

TOOL_NAME = "linear_comment_create"
REQUIRED_SCOPES = ["linear:comment:write"]
_LINEAR_API_URL = "https://api.linear.app/graphql"


def _require_text(value: Any, field_name: str) -> str:
    text = str(value or "").strip()
    if not text:
        raise ValueError(f"{field_name} is required")
    return text


def _response_json(resp: Any) -> dict[str, Any]:
    raw = resp.read()
    if not raw:
        return {}
    return json.loads(raw.decode("utf-8"))


def _linear_api_key(secret_data: dict[str, Any]) -> str:
    api_key = str(secret_data.get("api_key") or "").strip()
    if not api_key or api_key == "REPLACE_ME":
        raise RuntimeError("Linear API key not configured")
    return api_key


def _pending_message(
    ctx: ToolContext,
    *,
    integration_account_id: str,
    issue_id: str,
    body: str,
) -> tuple[str | None, ToolResult | None]:
    request_body = {
        "query": (
            "mutation CommentCreate($input: CommentCreateInput!) { "
            "commentCreate(input: $input) { success comment { id body } } "
            "}"
        ),
        "variables": {"input": {"issueId": issue_id, "body": body}},
    }
    result = insert_integration_message(
        ctx.db,
        IntegrationMessageCreate(
            agent_id=ctx.agent_id,
            space_id=ctx.space_id,
            integration_account_id=integration_account_id,
            action_id=ctx.action_id,
            provider="linear",
            direction="outbound",
            channel_type="issue",
            object_type="comment",
            dedupe_key=f"action:{ctx.action_id}",
            external_thread_id=issue_id,
            sender={"integration_account_id": integration_account_id, "provider": "linear"},
            recipients=[{"issue_id": issue_id}],
            body_text=body,
            payload={"request": request_body},
            status="pending",
        ),
    )
    if result.inserted:
        return result.message.integration_message_id, None

    existing = result.message
    if existing.status == "sent":
        response = existing.payload.get("response") if isinstance(existing.payload, dict) else {}
        data: dict[str, Any] = {
            "issue_id": issue_id,
            "comment_id": str(existing.external_message_id or ""),
        }
        if isinstance(response, dict):
            data.update(response)
        return None, ToolResult(ok=True, data=data)
    if existing.status == "error":
        error = existing.payload.get("error") if isinstance(existing.payload, dict) else None
        return None, ToolResult(ok=False, error=str(error or existing.status))
    return None, ToolResult(ok=False, error=f"outbound_message_pending:{ctx.action_id}")


def _finalize(
    ctx: ToolContext,
    *,
    integration_message_id: str,
    status: str,
    request_body: dict[str, Any],
    response_payload: dict[str, Any] | None = None,
    error: str | None = None,
    external_message_id: str | None = None,
) -> None:
    payload: dict[str, Any] = {"request": request_body}
    if response_payload is not None:
        payload["response"] = response_payload
    if error is not None:
        payload["error"] = error
    finalize_outbound_integration_message(
        ctx.db,
        integration_message_id=integration_message_id,
        status=status,
        payload=payload,
        external_message_id=external_message_id,
        action_id=ctx.action_id,
    )


def _handler(payload: dict[str, Any], ctx: ToolContext) -> ToolResult:
    integration_account_id = _require_text(payload.get("integration_account_id"), "integration_account_id")
    issue_id = _require_text(payload.get("issue_id"), "issue_id")
    body = _require_text(payload.get("body"), "body")
    action_id = _require_text(ctx.action_id, "action_id")
    _ = action_id

    account, secret_data = load_outbound_integration_account(
        ctx.db,
        integration_account_id=integration_account_id,
        provider="linear",
    )
    api_key = _linear_api_key(secret_data)

    pending_message_id, existing_result = _pending_message(
        ctx,
        integration_account_id=account.integration_account_id,
        issue_id=issue_id,
        body=body,
    )
    if pending_message_id is None:
        return existing_result or ToolResult(ok=False, error="outbound_message_not_inserted")

    request_body = {
        "query": (
            "mutation CommentCreate($input: CommentCreateInput!) { "
            "commentCreate(input: $input) { success comment { id body } } "
            "}"
        ),
        "variables": {"input": {"issueId": issue_id, "body": body}},
    }
    request = urllib.request.Request(
        _LINEAR_API_URL,
        data=json.dumps(request_body).encode("utf-8"),
        method="POST",
    )
    request.add_header("Authorization", f"Bearer {api_key}")
    request.add_header("Content-Type", "application/json; charset=utf-8")
    request.add_header("User-Agent", f"marvain-tool/{TOOL_NAME}")

    try:
        with urllib.request.urlopen(request, timeout=15) as resp:
            response_payload = _response_json(resp)
        data = response_payload.get("data") or {}
        if not isinstance(data, dict):
            raise RuntimeError("linear_api_error: invalid_response")
        comment_create = data.get("commentCreate", {})
        if not isinstance(comment_create, dict) or not comment_create.get("success"):
            raise RuntimeError("linear_api_error: commentCreate failed")
        comment = comment_create.get("comment")
        if not isinstance(comment, dict):
            raise RuntimeError("linear_api_error: missing_comment")
        comment_id = str(comment.get("id") or "").strip()
        if not comment_id:
            raise RuntimeError("linear_api_error: missing_comment_id")
        _finalize(
            ctx,
            integration_message_id=pending_message_id,
            status="sent",
            request_body=request_body,
            response_payload=response_payload,
            external_message_id=comment_id,
        )
        data = {
            "issue_id": issue_id,
            "comment_id": comment_id,
            "body": str(comment.get("body") or body),
        }
        return ToolResult(ok=True, data=data)
    except urllib.error.HTTPError as exc:
        try:
            error_body = exc.read().decode("utf-8", errors="replace")
        except Exception:
            error_body = ""
        error = f"http_error_{exc.code}"
        logger.warning("linear_comment_create http_error_%s: %s", exc.code, error_body[:500])
        _finalize(
            ctx,
            integration_message_id=pending_message_id,
            status="error",
            request_body=request_body,
            error=error,
        )
        return ToolResult(ok=False, error=error)
    except urllib.error.URLError as exc:
        error = f"url_error: {exc.reason}"
        logger.warning("linear_comment_create url_error: %s", exc.reason)
        _finalize(
            ctx,
            integration_message_id=pending_message_id,
            status="error",
            request_body=request_body,
            error=error,
        )
        return ToolResult(ok=False, error=error)
    except Exception as exc:
        error = str(exc)
        logger.exception("linear_comment_create failed")
        _finalize(
            ctx,
            integration_message_id=pending_message_id,
            status="error",
            request_body=request_body,
            error=error,
        )
        return ToolResult(ok=False, error=error)


def register(registry: ToolRegistry) -> None:
    registry.register(
        TOOL_NAME,
        required_scopes=REQUIRED_SCOPES,
        handler=_handler,
        description="Post a comment to a Linear issue using the configured integration account",
    )
