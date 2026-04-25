"""github_issue_comment tool - Post a comment on a GitHub issue."""

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

TOOL_NAME = "github_issue_comment"
REQUIRED_SCOPES = ["github:issue:write"]
_GITHUB_API_URL = "https://api.github.com"
_GITHUB_API_VERSION = "2022-11-28"


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


def _github_token(secret_data: dict[str, Any]) -> str:
    token = str(secret_data.get("token") or secret_data.get("access_token") or "").strip()
    if not token or token == "REPLACE_ME":
        raise RuntimeError("GitHub token not configured")
    return token


def _pending_message(
    ctx: ToolContext,
    *,
    integration_account_id: str,
    repository: str,
    issue_number: str,
    body: str,
) -> tuple[str | None, ToolResult | None]:
    request_body = {"body": body}
    result = insert_integration_message(
        ctx.db,
        IntegrationMessageCreate(
            agent_id=ctx.agent_id,
            space_id=ctx.space_id,
            integration_account_id=integration_account_id,
            action_id=ctx.action_id,
            provider="github",
            direction="outbound",
            channel_type="issue",
            object_type="issue_comment",
            dedupe_key=f"action:{ctx.action_id}",
            external_thread_id=f"{repository}#issue:{issue_number}",
            sender={"integration_account_id": integration_account_id, "provider": "github"},
            recipients=[{"repository": repository, "issue_number": issue_number}],
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
            "repository": repository,
            "issue_number": int(issue_number) if issue_number.isdigit() else issue_number,
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
    repository = _require_text(payload.get("repository"), "repository")
    issue_number = _require_text(payload.get("issue_number"), "issue_number")
    body = _require_text(payload.get("body"), "body")
    action_id = _require_text(ctx.action_id, "action_id")
    _ = action_id

    account, secret_data = load_outbound_integration_account(
        ctx.db,
        integration_account_id=integration_account_id,
        provider="github",
    )
    token = _github_token(secret_data)

    pending_message_id, existing_result = _pending_message(
        ctx,
        integration_account_id=account.integration_account_id,
        repository=repository,
        issue_number=issue_number,
        body=body,
    )
    if pending_message_id is None:
        return existing_result or ToolResult(ok=False, error="outbound_message_not_inserted")

    request_body = {"body": body}
    request = urllib.request.Request(
        f"{_GITHUB_API_URL}/repos/{repository}/issues/{issue_number}/comments",
        data=json.dumps(request_body).encode("utf-8"),
        method="POST",
    )
    request.add_header("Authorization", f"Bearer {token}")
    request.add_header("Accept", "application/vnd.github+json")
    request.add_header("X-GitHub-Api-Version", _GITHUB_API_VERSION)
    request.add_header("User-Agent", f"marvain-tool/{TOOL_NAME}")
    request.add_header("Content-Type", "application/json; charset=utf-8")

    try:
        with urllib.request.urlopen(request, timeout=15) as resp:
            response_payload = _response_json(resp)
        comment_id = str(response_payload.get("id") or "").strip()
        if not comment_id:
            raise RuntimeError("github_api_error: missing_comment_id")
        _finalize(
            ctx,
            integration_message_id=pending_message_id,
            status="sent",
            request_body=request_body,
            response_payload=response_payload,
            external_message_id=comment_id,
        )
        data = {
            "repository": repository,
            "issue_number": int(issue_number) if issue_number.isdigit() else issue_number,
            "comment_id": comment_id,
            "html_url": str(response_payload.get("html_url") or "").strip() or None,
        }
        return ToolResult(ok=True, data={k: v for k, v in data.items() if v is not None})
    except urllib.error.HTTPError as exc:
        try:
            error_body = exc.read().decode("utf-8", errors="replace")
        except Exception:
            error_body = ""
        error = f"http_error_{exc.code}"
        logger.warning("github_issue_comment http_error_%s: %s", exc.code, error_body[:500])
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
        logger.warning("github_issue_comment url_error: %s", exc.reason)
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
        logger.exception("github_issue_comment failed")
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
        description="Post a comment to a GitHub issue using the configured integration account",
    )
