from __future__ import annotations

import json
import logging
import os
from pathlib import Path
from typing import Any, Dict, List, Optional

from agent_core.aws_model_client import AwsModelClient


def _load_prompt(name: str, default_text: str) -> str:
    """Load prompt text from config layer or local repo."""
    candidates: List[Path] = []

    # Lambda layer mount
    candidates.append(Path(f"/opt/prompts/{name}.txt"))

    # Explicit override
    prompts_dir = os.environ.get("PROMPTS_DIR")
    if prompts_dir:
        candidates.append(Path(prompts_dir) / f"{name}.txt")

    # Repo-relative search (local dev)
    here = Path(__file__).resolve()
    for parent in list(here.parents)[:10]:
        candidates.append(parent / "layers" / "config" / "prompts" / f"{name}.txt")

    for p in candidates:
        try:
            if p.exists():
                return p.read_text(encoding="utf-8").strip()
        except Exception as e:
            logging.debug("prompt load failed for %s: %s", p, e)

    return default_text.strip()


BASE_SYSTEM_PROMPT = _load_prompt(
    "system",
    default_text="""You are a helpful AI agent.

Return a single JSON object:
{
  "reply_text": "<string>",
  "actions": [],
  "new_memories": []
}

Do not wrap JSON in markdown fences.
""",
)

HEARTBEAT_PROMPT = _load_prompt(
    "heartbeat",
    default_text="""You are a system heartbeat for an AI agent.

Your job: review recent context and decide if any background actions or memories should be recorded.

Return a single JSON object:
{
  "reply_text": "<string or empty>",
  "actions": [],
  "new_memories": []
}

Do not wrap JSON in markdown fences.
""",
)


def build_system_prompt(
    *,
    memories: List[Dict[str, Any]],
    personality_extra: Optional[str] = None,
    voice_extra: Optional[str] = None,
    heartbeat_mode: bool = False,
    tools_spec: Optional[List[Dict[str, Any]]] = None,
) -> str:
    """Compose the system prompt from base instructions, context, and optional extras."""
    base = HEARTBEAT_PROMPT if heartbeat_mode else BASE_SYSTEM_PROMPT
    prompt = base.strip()

    if tools_spec:
        # Keep this short: the full schema can be huge
        tool_lines = []
        for t in tools_spec:
            try:
                tool_lines.append(f"- {t.get('name')}: {t.get('description')}")
            except Exception:
                pass
        if tool_lines:
            prompt += "\n\nAvailable tools:\n" + "\n".join(tool_lines)

    if memories:
        try:
            context_json = json.dumps(memories, default=str)
        except Exception as e:
            logging.debug("Could not JSON-encode memories: %s", e)
            context_json = str(memories)
        prompt += "\n\nRecent context (JSON):\n" + context_json

    if voice_extra:
        prompt += "\n\nVoice context:\n" + voice_extra.strip()

    if personality_extra:
        prompt += "\n\nExtra personality instructions:\n" + personality_extra.strip()

    return prompt.strip()


def chat_with_tools(
    model_client: AwsModelClient,
    messages: List[Dict[str, str]],
    tools: List[Dict[str, Any]],
) -> str:
    """Call the LLM and return raw assistant output.

    This uses Bedrock Converse for portability across supported models.
    """
    system_msg = next((m for m in messages if m.get("role") == "system"), None)
    user_msg = next((m for m in reversed(messages) if m.get("role") == "user"), None)

    system_text = system_msg.get("content", "") if system_msg else ""
    user_text = user_msg.get("content", "") if user_msg else ""

    # If tools were supplied, we reinforce the JSON output contract.
    if tools:
        system_text += (
            "\n\nIMPORTANT: Output MUST be a single JSON object with keys reply_text, actions, new_memories. "
            "Do not use markdown fences."
        )

    try:
        return model_client.converse(system_text=system_text, user_text=user_text)
    except Exception as e:
        logging.error("chat_with_tools: model call failed: %s", e)
        # fail soft
        return json.dumps(
            {
                "reply_text": "[ERROR] LLM invocation failed. Check Bedrock access, region, and MODEL_ID.",
                "actions": [],
                "new_memories": [{"kind": "META", "text": f"LLM error: {str(e)}"}],
            }
        )
