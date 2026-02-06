"""send_message tool - Posts messages to WebSocket connections.

This tool broadcasts a message to subscribed WebSocket connections
for real-time notification to connected clients.
"""

from __future__ import annotations

import logging
from typing import Any

from .registry import ToolContext, ToolRegistry, ToolResult

logger = logging.getLogger(__name__)

TOOL_NAME = "send_message"
REQUIRED_SCOPES = ["message:send"]


def _handler(payload: dict[str, Any], ctx: ToolContext) -> ToolResult:
    """Execute the send_message tool.

    Payload:
        recipient_type: "space" | "connection" | "user"
        recipient_id: The ID of the recipient (space_id, connection_id, or user_id)
        message_type: Type of message (e.g., "notification", "alert", "info")
        content: Message content (string or dict)
    """
    recipient_type = str(payload.get("recipient_type", "")).strip()
    recipient_id = str(payload.get("recipient_id", "")).strip()
    message_type = str(payload.get("message_type", "notification")).strip()
    content = payload.get("content")

    if not recipient_type:
        return ToolResult(ok=False, error="missing_recipient_type")
    if not recipient_id:
        return ToolResult(ok=False, error="missing_recipient_id")
    if content is None:
        return ToolResult(ok=False, error="missing_content")

    if recipient_type not in ("space", "connection", "user"):
        return ToolResult(ok=False, error=f"invalid_recipient_type: {recipient_type}")

    if ctx.broadcast_fn is None:
        logger.warning("send_message: no broadcast_fn configured")
        return ToolResult(ok=False, error="broadcast_not_configured")

    # Build the message payload
    message_payload = {
        "type": "message",
        "message_type": message_type,
        "agent_id": ctx.agent_id,
        "action_id": ctx.action_id,
        "content": content,
    }
    if ctx.space_id:
        message_payload["space_id"] = ctx.space_id

    try:
        # Broadcast to the recipient
        broadcast_key = f"{recipient_type}:{recipient_id}"
        ctx.broadcast_fn(broadcast_key, message_payload)

        # Also record in events table for persistence
        ctx.db.execute(
            """
            INSERT INTO events (agent_id, space_id, type, payload)
            VALUES (:agent_id::uuid, :space_id::uuid, :type, :payload::jsonb)
            """,
            {
                "agent_id": ctx.agent_id,
                "space_id": ctx.space_id,
                "type": f"tool.{TOOL_NAME}",
                "payload": {
                    "recipient_type": recipient_type,
                    "recipient_id": recipient_id,
                    "message_type": message_type,
                    "content": content if isinstance(content, str) else str(content)[:500],
                },
            },
        )

        return ToolResult(ok=True, data={"delivered": True, "recipient": broadcast_key})

    except Exception as e:
        logger.exception("send_message failed")
        return ToolResult(ok=False, error=f"broadcast_failed: {str(e)}")


def register(registry: ToolRegistry) -> None:
    """Register the send_message tool with the registry."""
    registry.register(
        TOOL_NAME,
        required_scopes=REQUIRED_SCOPES,
        handler=_handler,
        description="Send a message to WebSocket connections for real-time notifications",
    )
