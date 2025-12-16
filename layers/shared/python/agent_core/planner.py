from __future__ import annotations

import json
import logging
import re
from typing import Any, Dict, List, Tuple

from agent_core.schema import Event, MemoryItem, MemoryKind


_JSON_FENCE_RE = re.compile(r"```(?:json)?\s*(\{.*?\})\s*```", re.DOTALL)


def _try_parse_json(text: str) -> Any:
    text = text.strip()
    if not text:
        return None

    # If the model wrapped JSON in fences
    m = _JSON_FENCE_RE.search(text)
    if m:
        candidate = m.group(1).strip()
        try:
            return json.loads(candidate)
        except Exception:
            pass

    # Try full text
    try:
        return json.loads(text)
    except Exception:
        pass

    # Try extracting first {...} block
    start = text.find("{")
    end = text.rfind("}")
    if start != -1 and end != -1 and end > start:
        candidate = text[start : end + 1]
        try:
            return json.loads(candidate)
        except Exception:
            pass

    return None


def handle_llm_result(llm_response: Any, agent_event: Event) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], str]:
    """Interpret LLM output into actions, new memories, and reply_text.

    Contract:
      returns (actions, new_memories, reply_text)
    """
    # normalize to string
    if isinstance(llm_response, dict):
        parsed = llm_response
        raw_text = json.dumps(llm_response, default=str)
    else:
        raw_text = str(llm_response or "")
        parsed = _try_parse_json(raw_text)

    actions: List[Dict[str, Any]] = []
    new_memories: List[Dict[str, Any]] = []
    reply_text: str = ""

    if isinstance(parsed, dict) and ("reply_text" in parsed or "actions" in parsed or "new_memories" in parsed):
        reply_text = str(parsed.get("reply_text") or "")
        actions_raw = parsed.get("actions") or []
        mem_raw = parsed.get("new_memories") or []

        if isinstance(actions_raw, dict):
            actions = [actions_raw]
        elif isinstance(actions_raw, list):
            actions = [a for a in actions_raw if a is not None]
        else:
            actions = [{"action": str(actions_raw)}]

        if isinstance(mem_raw, dict) or isinstance(mem_raw, str):
            mem_items = [mem_raw]
        elif isinstance(mem_raw, list):
            mem_items = mem_raw
        else:
            mem_items = [str(mem_raw)]

        for m in mem_items:
            mem = MemoryItem.from_obj(m)
            # validate kind
            kind_str = mem.kind.value if isinstance(mem.kind, MemoryKind) else str(mem.kind)
            new_memories.append({"kind": kind_str, "text": mem.text, **({"ts": mem.ts} if mem.ts else {}), **({"meta": mem.meta} if mem.meta else {})})

    else:
        # unstructured: treat entire text as reply
        reply_text = raw_text.strip()
        actions = []
        new_memories = []

    logging.debug(
        "handle_llm_result: reply=%r actions=%d new_memories=%d", reply_text[:120], len(actions), len(new_memories)
    )

    return actions, new_memories, reply_text
