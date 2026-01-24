from __future__ import annotations

import json
import logging
import re
from typing import Any, Dict, List, Optional, Tuple

from agent_core.schema import Event, MemoryItem, MemoryKind, MemoryImportance


_JSON_FENCE_RE = re.compile(r"```(?:json)?\s*(\{.*?\})\s*```", re.DOTALL)


def _try_parse_json(text: str) -> Any:
    """Attempt to parse JSON from text, handling various formats."""
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


def _extract_speaker_from_event(event: Event) -> Optional[str]:
    """Extract speaker_id from an event."""
    if event.speaker_id:
        return event.speaker_id
    payload = event.payload or {}
    return payload.get("speaker_id") or payload.get("voice_id")


def _enrich_memory(
    mem: MemoryItem,
    event: Event,
    speaker_id: Optional[str] = None,
) -> Dict[str, Any]:
    """Enrich a memory item with event context."""
    kind_str = mem.kind.value if isinstance(mem.kind, MemoryKind) else str(mem.kind)
    importance_str = mem.importance.value if isinstance(mem.importance, MemoryImportance) else "MEDIUM"

    result: Dict[str, Any] = {
        "kind": kind_str,
        "text": mem.text,
        "importance": importance_str,
    }

    if mem.ts:
        result["ts"] = mem.ts

    # Build meta with speaker association
    meta = dict(mem.meta) if mem.meta else {}

    # Associate with speaker
    effective_speaker = speaker_id or mem.speaker_id or _extract_speaker_from_event(event)
    if effective_speaker:
        meta["speaker_id"] = effective_speaker
        result["speaker_id"] = effective_speaker

    # Add session context
    if event.session_id:
        meta["session_id"] = event.session_id

    if meta:
        result["meta"] = meta

    # Add tags if present
    if mem.tags:
        result["tags"] = mem.tags

    return result


def handle_llm_result(
    llm_response: Any,
    agent_event: Event,
    speaker_id: Optional[str] = None,
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], str]:
    """Interpret LLM output into actions, new memories, and reply_text.

    Args:
        llm_response: Raw LLM response (dict, string, or JSON)
        agent_event: The triggering event for context
        speaker_id: Optional speaker to associate with memories

    Returns:
        Tuple of (actions, new_memories, reply_text)
    """
    # Normalize to string or dict
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

        # Parse actions
        if isinstance(actions_raw, dict):
            actions = [actions_raw]
        elif isinstance(actions_raw, list):
            actions = [a for a in actions_raw if a is not None]
        else:
            actions = [{"action": str(actions_raw)}]

        # Parse memories
        if isinstance(mem_raw, dict) or isinstance(mem_raw, str):
            mem_items = [mem_raw]
        elif isinstance(mem_raw, list):
            mem_items = mem_raw
        else:
            mem_items = [str(mem_raw)]

        for m in mem_items:
            if not m:
                continue
            mem = MemoryItem.from_obj(m)
            if mem.text:  # Only store non-empty memories
                enriched = _enrich_memory(mem, agent_event, speaker_id)
                new_memories.append(enriched)

    else:
        # Unstructured response: treat entire text as reply
        reply_text = raw_text.strip()
        actions = []
        new_memories = []

    logging.debug(
        "handle_llm_result: reply=%r actions=%d new_memories=%d",
        reply_text[:120] if reply_text else "",
        len(actions),
        len(new_memories),
    )

    return actions, new_memories, reply_text


def extract_implicit_memories(
    transcript: str,
    speaker_id: Optional[str] = None,
    speaker_name: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Extract implicit memories from user transcript.

    This function looks for patterns like:
    - "My name is X" -> FACT about speaker name
    - "I like X" / "I prefer X" -> PREFERENCE
    - "I work at X" / "I'm a X" -> FACT about speaker

    Args:
        transcript: User's spoken text
        speaker_id: Speaker identifier
        speaker_name: Known speaker name

    Returns:
        List of memory dicts to store
    """
    memories: List[Dict[str, Any]] = []
    text = transcript.strip()

    if not text:
        return memories

    # Pattern: "My name is X"
    name_patterns = [
        r"(?i)my name is\s+([\w\-\s]{1,40})",
        r"(?i)i'?m\s+([\w\-\s]{1,40})\b",
        r"(?i)call me\s+([\w\-\s]{1,40})",
    ]
    for pattern in name_patterns:
        match = re.search(pattern, text)
        if match:
            name = match.group(1).strip().rstrip(".,!?")
            # Avoid grabbing phrases
            if len(name.split()) <= 3:
                memories.append({
                    "kind": "FACT",
                    "text": f"Speaker's name is {name}",
                    "importance": "HIGH",
                    "speaker_id": speaker_id,
                    "meta": {"extracted_from": "name_introduction"},
                })
                break

    # Pattern: "I like/love/prefer X"
    pref_patterns = [
        r"(?i)i (?:really )?(?:like|love|prefer|enjoy)\s+(.+?)(?:\.|$|,)",
        r"(?i)my favorite\s+(.+?)(?:is|are)\s+(.+?)(?:\.|$|,)",
    ]
    for pattern in pref_patterns:
        matches = re.findall(pattern, text)
        for match in matches[:2]:  # Limit to 2 preferences per message
            if isinstance(match, tuple):
                pref_text = " ".join(match).strip()
            else:
                pref_text = match.strip()
            if pref_text and len(pref_text) < 100:
                memories.append({
                    "kind": "PREFERENCE",
                    "text": f"Speaker preference: {pref_text}",
                    "importance": "MEDIUM",
                    "speaker_id": speaker_id,
                    "meta": {"extracted_from": "preference_statement"},
                })

    # Pattern: "I work at X" / "I'm a X (profession)"
    work_patterns = [
        r"(?i)i work (?:at|for)\s+(.+?)(?:\.|$|,| as)",
        r"(?i)i'?m (?:a|an)\s+([\w\s]+?)(?:\.|$|,)",
    ]
    for pattern in work_patterns:
        match = re.search(pattern, text)
        if match:
            info = match.group(1).strip().rstrip(".,!?")
            if info and len(info.split()) <= 5:
                memories.append({
                    "kind": "FACT",
                    "text": f"Speaker works/is: {info}",
                    "importance": "MEDIUM",
                    "speaker_id": speaker_id,
                    "meta": {"extracted_from": "work_statement"},
                })
                break

    return memories


def build_relationship_summary(memories: List[Dict[str, Any]]) -> str:
    """Build a summary of relationship with a speaker from their memories.

    Args:
        memories: List of memories associated with the speaker

    Returns:
        A brief summary string
    """
    if not memories:
        return "No prior relationship established."

    facts = [m for m in memories if m.get("kind") == "FACT"]
    preferences = [m for m in memories if m.get("kind") == "PREFERENCE"]
    insights = [m for m in memories if m.get("kind") == "AI_INSIGHT"]

    summary_parts = []

    # Add key facts
    if facts:
        fact_texts = [f["text"] for f in facts[:3]]
        summary_parts.append(f"Known facts: {'; '.join(fact_texts)}")

    # Add preferences
    if preferences:
        pref_texts = [p["text"] for p in preferences[:2]]
        summary_parts.append(f"Preferences: {'; '.join(pref_texts)}")

    # Add insights
    if insights:
        insight_texts = [i["text"] for i in insights[:2]]
        summary_parts.append(f"Observations: {'; '.join(insight_texts)}")

    return " | ".join(summary_parts) if summary_parts else "Limited information available."
