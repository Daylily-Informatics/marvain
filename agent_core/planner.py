from __future__ import annotations

import json
import logging
import re
from typing import Any, Dict, List, Tuple

from .schema import Action, Memory, memory_from_obj

logger = logging.getLogger(__name__)


_JSON_RE = re.compile(r"\{.*\}", re.DOTALL)


def _extract_json_obj(text: str) -> Dict[str, Any] | None:
    """Best-effort extraction of a JSON object from model text."""
    if not text:
        return None

    # If the whole thing is JSON, great.
    try:
        obj = json.loads(text)
        if isinstance(obj, dict):
            return obj
    except Exception:
        pass

    # Strip common markdown code fences
    cleaned = text.strip()
    if cleaned.startswith("```"):
        cleaned = re.sub(r"^```[a-zA-Z0-9_-]*", "", cleaned).strip()
        cleaned = cleaned.rstrip("`").strip()

    # Find a {...} blob.
    m = _JSON_RE.search(cleaned)
    if not m:
        return None

    blob = m.group(0)
    # Try parsing progressively (sometimes there's trailing garbage).
    for end in range(len(blob), 1, -1):
        candidate = blob[:end]
        try:
            obj = json.loads(candidate)
            if isinstance(obj, dict):
                return obj
        except Exception:
            continue
    return None


def _coerce_actions(actions_raw: Any) -> List[Action]:
    out: List[Action] = []
    if not actions_raw:
        return out
    if isinstance(actions_raw, dict):
        actions_raw = [actions_raw]
    if not isinstance(actions_raw, list):
        return out
    for a in actions_raw:
        if isinstance(a, Action):
            out.append(a)
            continue
        if not isinstance(a, dict):
            out.append(Action(kind="LOG", payload={"note": str(a)}))
            continue
        kind = str(a.get("kind") or "LOG")
        payload = a.get("payload") or {}
        if not isinstance(payload, dict):
            payload = {"value": payload}
        out.append(Action(kind=kind, payload=payload))
    return out


def handle_llm_result(llm_response: Dict[str, Any], agent_event) -> Tuple[List[Action], List[Memory], str]:
    """Interpret the model output into actions, new memories, and reply_text.

    REQ-40/41: planner step returns (actions, new_memories, reply_text).
    REQ-44: tool calling must be interpreted into persistent memories and actions.
    """
    text = (llm_response or {}).get("text") or ""
    tool_calls = (llm_response or {}).get("tool_calls") or []

    parsed = _extract_json_obj(text)

    reply_text = ""
    actions: List[Action] = []
    new_memories: List[Memory] = []

    if parsed:
        reply_text = str(parsed.get("reply_text") or parsed.get("reply") or "").strip()

        actions = _coerce_actions(parsed.get("actions"))

        memories_raw = parsed.get("new_memories") or parsed.get("memories") or []
        if isinstance(memories_raw, dict):
            memories_raw = [memories_raw]
        if isinstance(memories_raw, list):
            for m in memories_raw:
                try:
                    new_memories.append(
                        memory_from_obj(
                            agent_event.agent_id,
                            m,
                            session_id=agent_event.session_id,
                            source=agent_event.source,
                            speaker_name=(agent_event.payload or {}).get("speaker_name"),
                        )
                    )
                except Exception:
                    logger.exception("Failed to coerce memory: %s", m)
    else:
        # Not JSON: treat as plain reply text
        reply_text = str(text).strip()

    # Tool calls (if any) also become actions/memories.
    for tc in tool_calls:
        name = (tc or {}).get("name")
        inp = (tc or {}).get("input") or {}
        if name == "add_memory":
            try:
                new_memories.append(
                    memory_from_obj(
                        agent_event.agent_id,
                        inp,
                        session_id=agent_event.session_id,
                        source=agent_event.source,
                        speaker_name=(agent_event.payload or {}).get("speaker_name"),
                    )
                )
            except Exception:
                logger.exception("Failed to handle add_memory tool call: %s", tc)
        elif name == "create_action":
            try:
                actions.extend(_coerce_actions(inp))
            except Exception:
                logger.exception("Failed to handle create_action tool call: %s", tc)
        else:
            actions.append(Action(kind="LOG", payload={"unknown_tool_call": tc}))

    # Safety: ensure reply_text exists
    if not reply_text:
        reply_text = "OK."

    return actions, new_memories, reply_text
