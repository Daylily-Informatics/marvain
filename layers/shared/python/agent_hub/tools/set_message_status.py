"""set_message_status tool - mark an integration message with a triage status."""

from __future__ import annotations

from typing import Any

from agent_hub.integrations import set_integration_message_status

from .registry import ToolContext, ToolRegistry, ToolResult

TOOL_NAME = "set_message_status"
REQUIRED_SCOPES = ["message:triage"]


def _handler(payload: dict[str, Any], ctx: ToolContext) -> ToolResult:
    integration_message_id = str(payload.get("integration_message_id") or "").strip()
    status = str(payload.get("status") or "").strip()
    reason = str(payload.get("reason") or "").strip() or None

    if not integration_message_id:
        return ToolResult(ok=False, error="missing_integration_message_id")
    if not status:
        return ToolResult(ok=False, error="missing_status")

    try:
        message = set_integration_message_status(
            ctx.db,
            integration_message_id=integration_message_id,
            status=status,
            reason=reason,
        )
    except LookupError:
        return ToolResult(ok=False, error="integration_message_not_found")
    except Exception as exc:
        return ToolResult(ok=False, error=str(exc))

    return ToolResult(
        ok=True,
        data={
            "integration_message_id": message.integration_message_id,
            "status": message.status,
            "processed_at": message.processed_at,
        },
    )


def register(registry: ToolRegistry) -> None:
    registry.register(
        TOOL_NAME,
        required_scopes=REQUIRED_SCOPES,
        handler=_handler,
        description="Update an integration message status for triage and follow-up",
    )
