from __future__ import annotations

import json
import logging
import os
import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional

import boto3
from boto3.dynamodb.conditions import Attr, Key

from agent_core.schema import Event, MemoryItem, MemoryKind


_dynamodb = boto3.resource("dynamodb")
_cached_table = None
_cached_table_name: Optional[str] = None


def _get_table():
    global _cached_table, _cached_table_name
    table_name = os.environ.get("AGENT_STATE_TABLE")
    if not table_name:
        return None
    if _cached_table is None or _cached_table_name != table_name:
        _cached_table_name = table_name
        _cached_table = _dynamodb.Table(table_name)
    return _cached_table


def _now_iso() -> str:
    """UTC ISO8601 with microseconds and trailing Z."""
    return datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def put_event(event: Event) -> None:
    """Persist an Event into the unified DynamoDB table."""
    table = _get_table()
    if table is None:
        logging.error("put_event: DynamoDB table not configured (AGENT_STATE_TABLE missing).")
        return

    ts = event.ts or _now_iso()
    event.ts = ts

    pk = f"AGENT#{event.agent_id}"
    # make SK unique even within same microsecond
    sk = f"{ts}#EVENT#{uuid.uuid4().hex[:8]}"

    item: Dict[str, Any] = {
        "pk": pk,
        "sk": sk,
        "session_id": event.session_id,
        "source": event.source,
        "channel": event.channel,
        "ts": ts,
        "payload": event.payload,
        # helpful GSI for per-session queries
        "gsi1pk": f"SESSION#{event.session_id}",
        "gsi1sk": f"{ts}#EVENT",
    }

    try:
        table.put_item(Item=item)
        logging.debug("put_event: stored %s %s", pk, sk)
    except Exception as e:
        logging.error("put_event: failed: %s", e)


def put_memory(memory_obj: Any) -> None:
    """Persist a MemoryItem (or dict/str convertible) into DynamoDB."""
    table = _get_table()
    if table is None:
        logging.error("put_memory: DynamoDB table not configured (AGENT_STATE_TABLE missing).")
        return

    agent_id = os.environ.get("AGENT_ID", "agent1")
    mem = MemoryItem.from_obj(memory_obj)
    ts = mem.ts or _now_iso()
    mem.ts = ts

    kind_str = mem.kind.value if isinstance(mem.kind, MemoryKind) else str(mem.kind)

    pk = f"AGENT#{agent_id}"
    sk = f"{ts}#MEMORY#{kind_str}#{uuid.uuid4().hex[:8]}"

    item: Dict[str, Any] = {
        "pk": pk,
        "sk": sk,
        "kind": kind_str,
        "ts": ts,
        "text": mem.text,
        "gsi1pk": f"MEMORYKIND#{kind_str}",
        "gsi1sk": ts,
    }
    if mem.meta:
        item["meta"] = mem.meta

    try:
        table.put_item(Item=item)
        logging.debug("put_memory: stored %s %s", pk, sk)
    except Exception as e:
        logging.error("put_memory: failed: %s", e)


def recent_memories(
    agent_id: str, limit: int = 40, session_id: Optional[str] = None
) -> List[Dict[str, Any]]:
    """Retrieve most recent items for an agent (events + memories), truncated to ~6000 chars.

    When ``session_id`` is provided, events are filtered to the selected session but memories
    (which are global) are still included. Returns a chronological list (oldest->newest).
    """
    table = _get_table()
    if table is None:
        logging.error("recent_memories: DynamoDB table not configured (AGENT_STATE_TABLE missing).")
        return []

    pk = f"AGENT#{agent_id}"
    filter_expr = None
    query_limit = max(1, int(limit))

    if session_id:
        # Include items where the session matches OR where there is no session id (e.g., agent memories).
        filter_expr = Attr("session_id").eq(session_id) | Attr("session_id").not_exists()
        # Increase the raw limit because filter expressions are applied after fetching.
        query_limit = max(query_limit * 3, query_limit + 20)

    try:
        resp = table.query(
            KeyConditionExpression=Key("pk").eq(pk),
            ScanIndexForward=False,
            Limit=query_limit,
            **({"FilterExpression": filter_expr} if filter_expr is not None else {}),
        )
    except Exception as e:
        logging.error("recent_memories: query failed: %s", e)
        return []

    items: List[Dict[str, Any]] = resp.get("Items", []) or []
    items.reverse()

    # truncate serialized context to ~6000 chars by dropping oldest items
    try:
        context_json = json.dumps(items, default=str)
    except Exception:
        context_json = str(items)

    if len(context_json) > 6000:
        while items:
            items.pop(0)
            try:
                context_json = json.dumps(items, default=str)
            except Exception:
                context_json = str(items)
            if len(context_json) <= 6000:
                break
        logging.debug("recent_memories: truncated context to %d items", len(items))

    return items
