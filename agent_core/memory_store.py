from __future__ import annotations

import os
import json
import logging
from typing import Any, Dict, List, Optional, Union
from datetime import datetime, timezone
import uuid

import boto3
from boto3.dynamodb.conditions import Key

from .schema import Event, Memory, memory_from_obj, MemoryKind

logger = logging.getLogger(__name__)

_TABLE = None


def _table():
    global _TABLE
    if _TABLE is not None:
        return _TABLE
    table_name = os.environ.get("AGENT_STATE_TABLE")
    if not table_name:
        raise RuntimeError("AGENT_STATE_TABLE env var is required")
    dynamodb = boto3.resource("dynamodb")
    _TABLE = dynamodb.Table(table_name)
    return _TABLE


def _ts_ms_from_iso(ts_iso: str) -> int:
    try:
        dt = datetime.fromisoformat(ts_iso.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return int(dt.timestamp() * 1000)
    except Exception:
        return int(datetime.now(timezone.utc).timestamp() * 1000)


def _pad_ms(ms: int) -> str:
    return str(ms).zfill(13)


def _agent_pk(agent_id: str) -> str:
    return f"AGENT#{agent_id}"


def _safe_part(s: str) -> str:
    return s.replace("#", "_").replace("\n", " ").strip()


def put_event(event: Event) -> None:
    """Persist an Event into DynamoDB."""
    t = _table()
    ts_ms = _ts_ms_from_iso(event.ts)
    sk = f"EVENT#{_pad_ms(ts_ms)}#{_safe_part(event.session_id)}#{event.event_id}"
    item: Dict[str, Any] = {
        "pk": _agent_pk(event.agent_id),
        "sk": sk,
        "gsi1pk": f"SESSION#{event.agent_id}#{_safe_part(event.session_id)}",
        "gsi1sk": _pad_ms(ts_ms),
        "type": "EVENT",
        **event.to_dict(),
    }
    t.put_item(Item=item)
    logger.debug("put_event ok sk=%s", sk)


def put_memory(memory_obj: Union[Memory, Dict[str, Any]]) -> Memory:
    """Persist a Memory into DynamoDB. Returns the stored Memory."""
    t = _table()
    if isinstance(memory_obj, dict):
        agent_id = memory_obj.get("agent_id") or os.environ.get("AGENT_ID") or "agent-default"
        memory = memory_from_obj(agent_id, memory_obj)
    else:
        memory = memory_obj

    ts_ms = _ts_ms_from_iso(memory.ts)
    sk = f"MEMORY#{_pad_ms(ts_ms)}#{memory.memory_id}"
    item: Dict[str, Any] = {
        "pk": _agent_pk(memory.agent_id),
        "sk": sk,
        "gsi1pk": f"MEMORY_KIND#{memory.agent_id}#{memory.kind.value}",
        "gsi1sk": _pad_ms(ts_ms),
        "type": "MEMORY",
        **memory.to_dict(),
    }
    t.put_item(Item=item)
    logger.debug("put_memory ok sk=%s kind=%s", sk, memory.kind)
    return memory


def recent_memories(agent_id: str, limit: int = 40) -> List[Dict[str, Any]]:
    """Retrieve most recent memories for an agent (newest first)."""
    t = _table()
    resp = t.query(
        KeyConditionExpression=Key("pk").eq(_agent_pk(agent_id)) & Key("sk").begins_with("MEMORY#"),
        ScanIndexForward=False,
        Limit=limit,
    )
    items = resp.get("Items") or []
    # Normalize output (strip DynamoDB keys)
    out: List[Dict[str, Any]] = []
    for it in items:
        out.append(
            {
                "kind": it.get("kind"),
                "content": it.get("content"),
                "ts": it.get("ts"),
                "session_id": it.get("session_id"),
                "source": it.get("source"),
                "speaker_name": it.get("speaker_name"),
                "metadata": it.get("metadata") or {},
                "memory_id": it.get("memory_id"),
            }
        )
    return out


# --- Voice Registry (stored in same table) -----------------------------------

def _voice_pk(agent_id: str) -> str:
    return f"AGENT#{agent_id}#VOICE"


def _voice_sk(voice_id: str) -> str:
    return f"VOICE#{_safe_part(voice_id)}"


def get_voice_record(agent_id: str, voice_id: str) -> Optional[Dict[str, Any]]:
    t = _table()
    resp = t.get_item(Key={"pk": _voice_pk(agent_id), "sk": _voice_sk(voice_id)})
    return resp.get("Item")


def put_voice_record(agent_id: str, voice_id: str, record: Dict[str, Any]) -> None:
    t = _table()
    now_ms = int(datetime.now(timezone.utc).timestamp() * 1000)
    item = {
        "pk": _voice_pk(agent_id),
        "sk": _voice_sk(voice_id),
        "gsi1pk": f"VOICE#{agent_id}",
        "gsi1sk": _pad_ms(now_ms),
        "type": "VOICE",
        "agent_id": agent_id,
        "voice_id": voice_id,
        **record,
        "updated_at": datetime.now(timezone.utc).isoformat(),
    }
    t.put_item(Item=item)
