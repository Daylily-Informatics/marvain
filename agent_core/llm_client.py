from __future__ import annotations

import json
from typing import Any, Dict, List, Optional
import logging

from .aws_model_client import AwsModelClient

logger = logging.getLogger(__name__)

try:
    from agent_config import BROKER_SYSTEM_PROMPT_BASE, HEARTBEAT_SYSTEM_PROMPT_BASE
except Exception:
    # Local fallback (e.g. if config layer isn't on PYTHONPATH)
    BROKER_SYSTEM_PROMPT_BASE = "You are a helpful agent. Return JSON with reply_text, actions, new_memories."
    HEARTBEAT_SYSTEM_PROMPT_BASE = "You are a scheduled agent heartbeat. Return JSON with reply_text, actions, new_memories."


def build_system_prompt(
    *,
    mode: str,
    agent_id: str,
    session_id: Optional[str] = None,
    speaker_name: Optional[str] = None,
    memories_json: Optional[str] = None,
    voice_instructions: Optional[str] = None,
    extra_personality_prompt: Optional[str] = None,
) -> str:
    """Build the system prompt string.

    REQ-42: supports optional per-request extra personality prompt text.
    """
    base = BROKER_SYSTEM_PROMPT_BASE if mode == "broker" else HEARTBEAT_SYSTEM_PROMPT_BASE

    parts: List[str] = [base.strip()]

    # Contextual header (harmless, helps debugging).
    hdr = {"agent_id": agent_id, "session_id": session_id, "speaker_name": speaker_name, "mode": mode}
    parts.append(f"Runtime context (do not repeat verbatim):\n{json.dumps(hdr, ensure_ascii=False)}")

    if voice_instructions:
        parts.append(f"Voice context instructions:\n{voice_instructions.strip()}")

    if extra_personality_prompt:
        parts.append(f"Extra per-request personality prompt:\n{extra_personality_prompt.strip()}")

    if memories_json:
        parts.append(f"Recent memories (JSON, newest first; may be truncated):\n{memories_json}")

    return "\n\n".join(parts).strip()


def chat_with_tools(
    model_client: AwsModelClient,
    messages: List[Dict[str, Any]],
    tools: Any,
) -> Dict[str, Any]:
    """Call the model with tools and return a normalized response."""
    resp = model_client.chat(messages=messages, tools=tools)
    # The downstream planner expects a dict; keep structure stable.
    return resp
