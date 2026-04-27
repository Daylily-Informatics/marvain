"""create_memory tool - Creates semantic memories for the agent.

This tool allows the agent to store semantic memories that can be
retrieved later for context and knowledge.
"""

from __future__ import annotations

import json
import logging
from typing import Any

from agent_hub.memory_taxonomy import MEMORY_KIND_VALUES, normalize_memory_kind

from .registry import ToolContext, ToolRegistry, ToolResult

logger = logging.getLogger(__name__)

TOOL_NAME = "create_memory"
REQUIRED_SCOPES = ["memory:write"]

MAX_CONTENT_LENGTH = 8192


def _handler(payload: dict[str, Any], ctx: ToolContext) -> ToolResult:
    """Execute the create_memory tool.

    Payload:
        tier: one of the canonical Marvain memory kinds (default: "semantic")
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
    subject_person_id = payload.get("subject_person_id")
    tags = payload.get("tags", [])
    scene_context = payload.get("scene_context")
    modality = str(payload.get("modality", "text")).strip().lower()
    confidence = float(payload.get("confidence", 1.0))
    related_memory_ids = payload.get("related_memory_ids", [])

    try:
        tier = normalize_memory_kind(tier, default="semantic")
    except ValueError:
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

    # Validate modality
    valid_modalities = ("text", "image", "audio", "video", "sensor")
    if modality not in valid_modalities:
        modality = "text"

    # Clamp confidence
    confidence = max(0.0, min(1.0, confidence))

    try:
        rows = ctx.db.query(
            """
            WITH candidate AS (
                INSERT INTO memory_candidates(
                    memory_candidate_id, agent_id, source_action_id, space_id, tier, content,
                    participants, subject_person_id, confidence, lifecycle_state
                )
                VALUES (
                    gen_random_uuid(),
                    :agent_id::uuid,
                    :source_action_id::uuid,
                    :space_id::uuid,
                    :tier,
                    :content,
                    :participants::jsonb,
                    CASE WHEN :subject_person_id IS NULL
                        THEN NULL ELSE :subject_person_id::uuid END,
                    :confidence,
                    'committed'
                )
                RETURNING memory_candidate_id
            )
            INSERT INTO memories (
                agent_id, space_id, tier, content, participants, provenance, retention,
                subject_person_id, tags, scene_context, modality, confidence, related_memory_ids,
                memory_candidate_id, source_action_id, lifecycle_state, recall_explanation
            )
            SELECT
                :agent_id::uuid, :space_id::uuid, :tier, :content,
                :participants::jsonb, :provenance::jsonb, :retention::jsonb,
                CASE WHEN :subject_person_id IS NULL THEN NULL ELSE :subject_person_id::uuid END,
                :tags::text[], :scene_context, :modality, :confidence,
                :related_memory_ids::uuid[],
                candidate.memory_candidate_id,
                :source_action_id::uuid,
                'committed',
                :recall_explanation::jsonb
            FROM candidate
            RETURNING memory_id::TEXT as memory_id
            """,
            {
                "agent_id": ctx.agent_id,
                "space_id": ctx.space_id,
                "source_action_id": ctx.action_id,
                "tier": tier,
                "content": content_str,
                "participants": json.dumps(participants),
                "provenance": json.dumps(provenance),
                "retention": json.dumps(retention),
                "subject_person_id": subject_person_id,
                "tags": "{" + ",".join(str(t) for t in tags) + "}" if tags else "{}",
                "scene_context": scene_context,
                "modality": modality,
                "confidence": confidence,
                "related_memory_ids": (
                    "{" + ",".join(str(r) for r in related_memory_ids) + "}" if related_memory_ids else "{}"
                ),
                "recall_explanation": json.dumps(
                    {
                        "source_action_id": ctx.action_id,
                        "source_tool": TOOL_NAME,
                        "commit_policy": "tool_action_commit_v1",
                    }
                ),
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
        description=f"Create a Marvain memory for the agent ({', '.join(MEMORY_KIND_VALUES)})",
    )
