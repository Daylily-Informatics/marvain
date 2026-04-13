"""slack_post_message tool - Post a message to Slack via chat.postMessage."""

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

from ._outbound import load_outbound_integration_account
from .registry import ToolContext, ToolRegistry, ToolResult

logger = logging.getLogger(__name__)

TOOL_NAME = "slack_post_message"
REQUIRED_SCOPES = ["slack:message:write"]
_SLACK_POST_MESSAGE_URL = "https://slack.com/api/chat.postMessage"


def _read_json_response(resp: Any) -> dict[str, Any]:
    raw = resp.read()
    if not raw:
        return {}
    return json.loads(raw.decode("utf-8"))


def _channel_type(channel_id: str) -> str:
    prefix = channel_id[:1].upper()
    if prefix == "D":
        return "dm"
    if prefix in {"C", "G"}:
        return "channel"
    return "slack"


def _message_data(message) -> dict[str, Any]:
    payload = message.payload if isinstance(message.payload, dict) else {}
    response = payload.get("response") if isinstance(payload.get("response"), dict) else {}
    response_message = response.get("message") if isinstance(response.get("message"), dict) else {}
    channel_id = str(response.get("channel") or "").strip()
    if not channel_id and getattr(message, "recipients", None):
        first_recipient = message.recipients[0] if message.recipients else {}
        if isinstance(first_recipient, dict):
            channel_id = str(first_recipient.get("channel_id") or "").strip()
    response_ts = str(response.get("ts") or message.external_message_id or "").strip()
    response_thread_ts = str(response_message.get("thread_ts") or message.external_thread_id or response_ts or "").strip() or None
    return {
        "channel_id": channel_id or None,
        "ts": response_ts or None,
        "thread_ts": response_thread_ts,
        "message": response_message,
    }


def _finalize_outbound(
    ctx: ToolContext,
    *,
    pending_message_id: str,
    request_body: dict[str, Any],
    response_payload: dict[str, Any],
    response_ts: str | None,
    response_thread_ts: str | None,
) -> None:
    finalize_outbound_integration_message(
        ctx.db,
        integration_message_id=pending_message_id,
        status="sent",
        payload={"request": request_body, "response": response_payload},
        external_thread_id=response_thread_ts,
        external_message_id=response_ts,
        transaction_id=None,
    )


def _finalize_failure(
    ctx: ToolContext,
    *,
    pending_message_id: str,
    request_body: dict[str, Any],
    error_message: str,
    response_payload: dict[str, Any] | None = None,
) -> None:
    try:
        finalize_outbound_integration_message(
            ctx.db,
            integration_message_id=pending_message_id,
            status="error",
            payload={
                "request": request_body,
                "error": error_message,
                "response": response_payload or {},
            },
            transaction_id=None,
        )
    except Exception:
        logger.exception("slack_post_message failed to finalize error status")


def _load_account_token(ctx: ToolContext, integration_account_id: str) -> str:
    _, secret_data = load_outbound_integration_account(
        ctx.db,
        integration_account_id=integration_account_id,
        provider="slack",
    )
    token = str(secret_data.get("bot_token") or "").strip()
    if not token or token == "REPLACE_ME":
        raise RuntimeError("Slack bot token not configured")
    return token


def _handler(payload: dict[str, Any], ctx: ToolContext) -> ToolResult:
    integration_account_id = str(payload.get("integration_account_id") or "").strip()
    channel_id = str(payload.get("channel_id") or "").strip()
    text = str(payload.get("text") or "")
    thread_ts = str(payload.get("thread_ts") or "").strip()

    if not integration_account_id:
        return ToolResult(ok=False, error="missing_integration_account_id")
    if not channel_id:
        return ToolResult(ok=False, error="missing_channel_id")
    if not text.strip():
        return ToolResult(ok=False, error="missing_text")

    request_body: dict[str, Any] = {"channel": channel_id, "text": text}
    if thread_ts:
        request_body["thread_ts"] = thread_ts

    pending = insert_integration_message(
        ctx.db,
        IntegrationMessageCreate(
            agent_id=ctx.agent_id,
            space_id=ctx.space_id,
            integration_account_id=integration_account_id,
            provider="slack",
            direction="outbound",
            channel_type=_channel_type(channel_id),
            object_type="message",
            dedupe_key=f"action:{ctx.action_id}",
            action_id=ctx.action_id,
            external_thread_id=thread_ts or None,
            sender={"type": "bot"},
            recipients=[{"channel_id": channel_id}],
            body_text=text,
            payload={"request": request_body, "state": "pending"},
            status="pending",
        ),
    )

    if not pending.inserted:
        if pending.message.status == "sent":
            return ToolResult(ok=True, data=_message_data(pending.message))
        if pending.message.status == "error":
            payload_data = pending.message.payload if isinstance(pending.message.payload, dict) else {}
            return ToolResult(ok=False, error=f"outbound_message_error: {payload_data.get('error') or pending.message.status}")
        return ToolResult(ok=False, error="outbound_message_pending")

    try:
        token = _load_account_token(ctx, integration_account_id)
        body = json.dumps(request_body).encode("utf-8")
        req = urllib.request.Request(_SLACK_POST_MESSAGE_URL, data=body, method="POST")
        req.add_header("Authorization", f"Bearer {token}")
        req.add_header("Content-Type", "application/json; charset=utf-8")
        req.add_header("User-Agent", f"marvain-tool/{TOOL_NAME}")
        with urllib.request.urlopen(req, timeout=15) as resp:
            response_payload = _read_json_response(resp)
    except urllib.error.HTTPError as exc:
        try:
            error_body = exc.read().decode("utf-8", errors="replace")
        except Exception:
            error_body = ""
        logger.warning("slack_post_message http_error_%s: %s", exc.code, error_body[:500])
        _finalize_failure(ctx, pending_message_id=pending.message.integration_message_id, request_body=request_body, error_message=f"http_error_{exc.code}")
        return ToolResult(ok=False, error=f"http_error_{exc.code}")
    except urllib.error.URLError as exc:
        logger.warning("slack_post_message url_error: %s", exc.reason)
        _finalize_failure(ctx, pending_message_id=pending.message.integration_message_id, request_body=request_body, error_message=f"url_error: {exc.reason}")
        return ToolResult(ok=False, error=f"url_error: {exc.reason}")
    except Exception as exc:
        logger.exception("slack_post_message failed")
        _finalize_failure(ctx, pending_message_id=pending.message.integration_message_id, request_body=request_body, error_message=str(exc))
        return ToolResult(ok=False, error=str(exc))

    if not bool(response_payload.get("ok")):
        error_message = f"slack_api_error: {response_payload.get('error') or 'unknown_error'}"
        _finalize_failure(
            ctx,
            pending_message_id=pending.message.integration_message_id,
            request_body=request_body,
            error_message=error_message,
            response_payload=response_payload,
        )
        return ToolResult(ok=False, error=error_message)

    message = response_payload.get("message")
    if not isinstance(message, dict):
        message = {}
    response_channel = str(response_payload.get("channel") or channel_id)
    response_ts = str(response_payload.get("ts") or message.get("ts") or "").strip() or None
    response_thread_ts = str(message.get("thread_ts") or request_body.get("thread_ts") or response_ts or "").strip() or None
    _finalize_outbound(
        ctx,
        pending_message_id=pending.message.integration_message_id,
        request_body=request_body,
        response_payload=response_payload,
        response_ts=response_ts,
        response_thread_ts=response_thread_ts,
    )

    return ToolResult(
        ok=True,
        data={
            "channel_id": response_channel,
            "ts": response_ts,
            "thread_ts": response_thread_ts,
            "message": message,
        },
    )


def register(registry: ToolRegistry) -> None:
    registry.register(
        TOOL_NAME,
        required_scopes=REQUIRED_SCOPES,
        handler=_handler,
        description="Post a message to a Slack channel or thread using the configured bot token",
    )
