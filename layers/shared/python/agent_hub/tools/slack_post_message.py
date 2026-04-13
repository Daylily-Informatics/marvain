"""slack_post_message tool - Post a message to Slack via chat.postMessage."""

from __future__ import annotations

import json
import logging
import os
import urllib.error
import urllib.request
from typing import Any

from agent_hub.integrations import IntegrationMessageCreate, insert_integration_message
from agent_hub.secrets import get_secret_json

from .registry import ToolContext, ToolRegistry, ToolResult

logger = logging.getLogger(__name__)

TOOL_NAME = "slack_post_message"
REQUIRED_SCOPES = ["slack:message:write"]
_SLACK_POST_MESSAGE_URL = "https://slack.com/api/chat.postMessage"


def _get_slack_bot_token() -> str:
    secret_arn = str(os.getenv("SLACK_SECRET_ARN") or "").strip()
    if not secret_arn:
        raise RuntimeError("SLACK_SECRET_ARN not configured")
    data = get_secret_json(secret_arn)
    token = str(data.get("bot_token") or "").strip()
    if not token or token == "REPLACE_ME":
        raise RuntimeError("Slack bot token not configured")
    return token


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


def _handler(payload: dict[str, Any], ctx: ToolContext) -> ToolResult:
    channel_id = str(payload.get("channel_id") or "").strip()
    text = str(payload.get("text") or "")
    thread_ts = str(payload.get("thread_ts") or "").strip()

    if not channel_id:
        return ToolResult(ok=False, error="missing_channel_id")
    if not text.strip():
        return ToolResult(ok=False, error="missing_text")

    request_body: dict[str, Any] = {
        "channel": channel_id,
        "text": text,
    }
    if thread_ts:
        request_body["thread_ts"] = thread_ts

    try:
        token = _get_slack_bot_token()
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
        return ToolResult(ok=False, error=f"http_error_{exc.code}")
    except urllib.error.URLError as exc:
        logger.warning("slack_post_message url_error: %s", exc.reason)
        return ToolResult(ok=False, error=f"url_error: {exc.reason}")
    except Exception as exc:
        logger.exception("slack_post_message failed")
        return ToolResult(ok=False, error=str(exc))

    if not bool(response_payload.get("ok")):
        return ToolResult(ok=False, error=f"slack_api_error: {response_payload.get('error') or 'unknown_error'}")

    message = response_payload.get("message")
    if not isinstance(message, dict):
        message = {}
    response_channel = str(response_payload.get("channel") or channel_id)
    response_ts = str(response_payload.get("ts") or message.get("ts") or "").strip()
    response_thread_ts = str(message.get("thread_ts") or request_body.get("thread_ts") or response_ts or "").strip() or None
    insert_integration_message(
        ctx.db,
        IntegrationMessageCreate(
            agent_id=ctx.agent_id,
            space_id=ctx.space_id,
            provider="slack",
            direction="outbound",
            channel_type=_channel_type(response_channel),
            object_type="message",
            dedupe_key=f"action:{ctx.action_id}",
            external_thread_id=response_thread_ts,
            external_message_id=response_ts or None,
            sender={"type": "bot"},
            recipients=[{"channel_id": response_channel}],
            body_text=text,
            payload={"request": request_body, "response": response_payload},
            status="sent",
        ),
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
