"""create_memory tool - Creates semantic memories for the agent.

This tool allows the agent to store semantic memories that can be
retrieved later for context and knowledge.
"""

from __future__ import annotations

import json
import logging
from typing import Any

from .registry import ToolContext, ToolRegistry, ToolResult

logger = logging.getLogger(__name__)

TOOL_NAME = "create_memory"
REQUIRED_SCOPES = ["memory:write"]

MAX_CONTENT_LENGTH = 8192


def _handler(payload: dict[str, Any], ctx: ToolContext) -> ToolResult:
    """Execute the create_memory tool.

    Payload:
        tier: "episodic" | "semantic" (default: "semantic")
        content: The memory content (string, required)
        participants: List of participant identifiers (optional)
        provenance: Dict with source info (optional)
        retention: Dict with retention policy (optional)
    """
    tier = str(payload.get("tier", "semantic")).strip().lower()
    content = payload.get("content")
    participants = payload.get("participants", [])
    provenance = payload.get("provenance", {})
    retention = payload.get("retention", {})

    # Validate tier
    if tier not in ("episodic", "semantic"):
        return ToolResult(ok=False, error=f"invalid_tier: {tier}")

    # Validate content
    if not content:
        return ToolResult(ok=False, error="missing_content")

    content_str = str(content).strip()
    if not content_str:
        return ToolResult(ok=False, error="empty_content")

    if len(content_str) > MAX_CONTENT_LENGTH:
        content_str = content_str[:MAX_CONTENT_LENGTH]
        logger.warning("create_memory: content truncated to %d chars", MAX_CONTENT_LENGTH)

    # Normalize participants to strings
    if not isinstance(participants, list):
        participants = []
    participants = [str(p) for p in participants if p]

    # Ensure provenance and retention are dicts
    if not isinstance(provenance, dict):
        provenance = {}
    if not isinstance(retention, dict):
        retention = {}

    # Add action provenance
    provenance["source_action_id"] = ctx.action_id
    provenance["source_tool"] = TOOL_NAME

    try:
        # Insert the memory
        rows = ctx.db.query(
            """
            INSERT INTO memories (agent_id, space_id, tier, content, participants, provenance, retention)
            VALUES (:agent_id::uuid, :space_id::uuid, :tier, :content, :participants::jsonb, :provenance::jsonb, :retention::jsonb)
            RETURNING memory_id::TEXT as memory_id
            """,
            {
                "agent_id": ctx.agent_id,
                "space_id": ctx.space_id,
                "tier": tier,
                "content": content_str,
                "participants": json.dumps(participants),
                "provenance": json.dumps(provenance),
                "retention": json.dumps(retention),
            },
        )

        memory_id = rows[0]["memory_id"] if rows else None

        return ToolResult(
            ok=True,
            data={
                "memory_id": memory_id,
                "tier": tier,
                "content_length": len(content_str),
            },
        )

    except Exception as e:
        logger.exception("create_memory failed")
        return ToolResult(ok=False, error=f"insert_failed: {str(e)}")


def register(registry: ToolRegistry) -> None:
    """Register the create_memory tool with the registry."""
    registry.register(
        TOOL_NAME,
        required_scopes=REQUIRED_SCOPES,
        handler=_handler,
        description="Create a semantic or episodic memory for the agent",
    )
