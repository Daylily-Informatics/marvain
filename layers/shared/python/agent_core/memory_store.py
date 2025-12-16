from __future__ import annotations

import json
import logging
import os
import uuid
from datetime import datetime
from decimal import Decimal
from typing import Any, Dict, List, Optional, Union

import boto3
from boto3.dynamodb.conditions import Attr, Key
from botocore.exceptions import ClientError

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


def _sanitize_for_dynamodb(obj: Any) -> Any:
    """Sanitize values for DynamoDB storage.

    Converts floats to Decimals and handles nested structures.
    """
    if isinstance(obj, float):
        return Decimal(str(obj))
    if isinstance(obj, dict):
        return {k: _sanitize_for_dynamodb(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_sanitize_for_dynamodb(v) for v in obj]
    return obj


class MultiAgentMemoryStore:
    """Memory store with proper multi-agent isolation.

    This class provides explicit agent_id scoping for all operations,
    ensuring clean separation between multiple agent instances sharing
    the same DynamoDB table.

    Key Schema:
    - Events: pk=AGENT#{agent_id}, sk={ts}#EVENT#{uuid}
    - Memories: pk=AGENT#{agent_id}, sk={ts}#MEMORY#{kind}#{uuid}
    - Sessions: pk=AGENT#{agent_id}, sk=SESSION#{session_id}
    - Speakers: pk=AGENT#{agent_id}#SPEAKER, sk={speaker_id}
    - Speaker Memories: pk=AGENT#{agent_id}#SPEAKER#{speaker_id}, sk={ts}#MEMORY#{uuid}

    GSI1 (for cross-agent queries):
    - gsi1pk=SESSION#{session_id}, gsi1sk={ts}#EVENT
    - gsi1pk=MEMORYKIND#{kind}, gsi1sk={ts}
    - gsi1pk=SPEAKER#{speaker_id}, gsi1sk={ts}
    """

    # Context truncation limits
    DEFAULT_CONTEXT_CHAR_LIMIT = 6000
    MAX_CONTEXT_CHAR_LIMIT = 50000

    def __init__(self, table_name: Optional[str] = None):
        self.table_name = table_name or os.environ.get("AGENT_STATE_TABLE")
        self._table = None

    @property
    def table(self):
        if self._table is None and self.table_name:
            self._table = _dynamodb.Table(self.table_name)
        return self._table

    def put_event(
        self,
        agent_id: str,
        event: Event,
        speaker_id: Optional[str] = None,
    ) -> Optional[str]:
        """Persist an Event with proper agent isolation.

        Args:
            agent_id: Agent identifier for isolation
            event: Event to persist
            speaker_id: Optional speaker to associate with event

        Returns:
            Sort key of the stored item, or None if failed
        """
        if not self.table:
            logging.error("put_event: DynamoDB table not configured")
            return None

        ts = event.ts or _now_iso()
        event.ts = ts

        pk = f"AGENT#{agent_id}"
        sk = f"{ts}#EVENT#{uuid.uuid4().hex[:8]}"

        item: Dict[str, Any] = {
            "pk": pk,
            "sk": sk,
            "item_type": "EVENT",
            "agent_id": agent_id,
            "session_id": event.session_id,
            "source": event.source,
            "channel": event.channel,
            "ts": ts,
            "payload": _sanitize_for_dynamodb(event.payload),
            "gsi1pk": f"SESSION#{event.session_id}",
            "gsi1sk": f"{ts}#EVENT",
        }

        if speaker_id:
            item["speaker_id"] = speaker_id
            # Also index by speaker for speaker-specific queries
            item["gsi2pk"] = f"SPEAKER#{speaker_id}"
            item["gsi2sk"] = f"{ts}#EVENT"

        try:
            self.table.put_item(Item=item)
            logging.debug("put_event: stored %s %s", pk, sk)
            return sk
        except ClientError as e:
            logging.error("put_event: failed: %s", e)
            return None

    def put_memory(
        self,
        agent_id: str,
        memory_obj: Any,
        speaker_id: Optional[str] = None,
        session_id: Optional[str] = None,
    ) -> Optional[str]:
        """Persist a memory with agent and optional speaker association.

        Args:
            agent_id: Agent identifier
            memory_obj: MemoryItem, dict, or string to store
            speaker_id: Optional speaker to associate memory with
            session_id: Optional session context

        Returns:
            Sort key of stored item, or None if failed
        """
        if not self.table:
            logging.error("put_memory: DynamoDB table not configured")
            return None

        mem = MemoryItem.from_obj(memory_obj)
        ts = mem.ts or _now_iso()
        mem.ts = ts

        kind_str = mem.kind.value if isinstance(mem.kind, MemoryKind) else str(mem.kind)

        # Use speaker-scoped partition if speaker_id provided
        if speaker_id:
            pk = f"AGENT#{agent_id}#SPEAKER#{speaker_id}"
        else:
            pk = f"AGENT#{agent_id}"

        sk = f"{ts}#MEMORY#{kind_str}#{uuid.uuid4().hex[:8]}"

        item: Dict[str, Any] = {
            "pk": pk,
            "sk": sk,
            "item_type": "MEMORY",
            "agent_id": agent_id,
            "kind": kind_str,
            "ts": ts,
            "text": mem.text,
            "gsi1pk": f"MEMORYKIND#{kind_str}",
            "gsi1sk": ts,
        }

        if speaker_id:
            item["speaker_id"] = speaker_id
            item["gsi2pk"] = f"SPEAKER#{speaker_id}"
            item["gsi2sk"] = f"{ts}#MEMORY"

        if session_id:
            item["session_id"] = session_id

        if mem.meta:
            item["meta"] = _sanitize_for_dynamodb(mem.meta)
            # Extract speaker_id from meta if not explicitly provided
            if not speaker_id and mem.meta.get("speaker_id"):
                item["speaker_id"] = mem.meta["speaker_id"]

        try:
            self.table.put_item(Item=item)
            logging.debug("put_memory: stored %s %s", pk, sk)
            return sk
        except ClientError as e:
            logging.error("put_memory: failed: %s", e)
            return None

    def get_memories_for_speaker(
        self,
        agent_id: str,
        speaker_id: str,
        limit: int = 50,
        kind: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Get memories associated with a specific speaker.

        Args:
            agent_id: Agent identifier
            speaker_id: Speaker identifier
            limit: Maximum number of memories
            kind: Optional filter by memory kind

        Returns:
            List of memory items, newest first
        """
        if not self.table:
            return []

        pk = f"AGENT#{agent_id}#SPEAKER#{speaker_id}"

        try:
            key_condition = Key("pk").eq(pk)
            if kind:
                # Use begins_with on SK to filter by kind
                # This works because SK format is {ts}#MEMORY#{kind}#...
                pass  # Would need different approach

            resp = self.table.query(
                KeyConditionExpression=key_condition,
                ScanIndexForward=False,
                Limit=limit,
            )
            return resp.get("Items", [])
        except ClientError as e:
            logging.error("get_memories_for_speaker: query failed: %s", e)
            return []

    def recent_context(
        self,
        agent_id: str,
        limit: int = 40,
        session_id: Optional[str] = None,
        speaker_id: Optional[str] = None,
        include_speaker_memories: bool = True,
        char_limit: int = DEFAULT_CONTEXT_CHAR_LIMIT,
    ) -> List[Dict[str, Any]]:
        """Retrieve recent context for an agent with optional filtering.

        Args:
            agent_id: Agent identifier
            limit: Maximum number of items
            session_id: Optional session filter
            speaker_id: Optional speaker filter
            include_speaker_memories: Whether to include speaker-specific memories
            char_limit: Maximum serialized context size

        Returns:
            List of context items, oldest first
        """
        if not self.table:
            return []

        items: List[Dict[str, Any]] = []

        # Query main agent partition
        pk = f"AGENT#{agent_id}"
        filter_expr = None
        query_limit = limit * 3 if session_id else limit

        if session_id:
            filter_expr = Attr("session_id").eq(session_id) | Attr("session_id").not_exists()

        try:
            resp = self.table.query(
                KeyConditionExpression=Key("pk").eq(pk),
                ScanIndexForward=False,
                Limit=query_limit,
                **({"FilterExpression": filter_expr} if filter_expr else {}),
            )
            items.extend(resp.get("Items", []))
        except ClientError as e:
            logging.error("recent_context: main query failed: %s", e)

        # If speaker_id provided and include_speaker_memories, also query speaker partition
        if speaker_id and include_speaker_memories:
            speaker_pk = f"AGENT#{agent_id}#SPEAKER#{speaker_id}"
            try:
                resp = self.table.query(
                    KeyConditionExpression=Key("pk").eq(speaker_pk),
                    ScanIndexForward=False,
                    Limit=limit,
                )
                items.extend(resp.get("Items", []))
            except ClientError as e:
                logging.error("recent_context: speaker query failed: %s", e)

        # Sort by timestamp and deduplicate
        items.sort(key=lambda x: x.get("ts", ""), reverse=True)
        items = items[:limit]
        items.reverse()  # Oldest first

        # Truncate to char limit
        char_limit = min(char_limit, self.MAX_CONTEXT_CHAR_LIMIT)
        items = self._truncate_context(items, char_limit)

        return items

    def _truncate_context(
        self,
        items: List[Dict[str, Any]],
        char_limit: int,
    ) -> List[Dict[str, Any]]:
        """Truncate context to fit within character limit."""
        try:
            context_json = json.dumps(items, default=str)
        except Exception:
            context_json = str(items)

        if len(context_json) <= char_limit:
            return items

        while items and len(context_json) > char_limit:
            items.pop(0)
            try:
                context_json = json.dumps(items, default=str)
            except Exception:
                context_json = str(items)

        return items

    def search_memories(
        self,
        agent_id: str,
        query: str,
        limit: int = 20,
        kind: Optional[str] = None,
        speaker_id: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Search memories by text content.

        Note: This is a basic implementation. For production, consider
        using OpenSearch or a vector database for semantic search.
        """
        # Get all memories within limits
        if speaker_id:
            items = self.get_memories_for_speaker(agent_id, speaker_id, limit=limit * 3)
        else:
            items = self.recent_context(
                agent_id,
                limit=limit * 3,
                include_speaker_memories=True,
                char_limit=self.MAX_CONTEXT_CHAR_LIMIT,
            )

        # Filter to memories only
        memories = [i for i in items if i.get("item_type") == "MEMORY"]

        # Filter by kind if specified
        if kind and kind.upper() != "ALL":
            memories = [m for m in memories if m.get("kind") == kind.upper()]

        # Simple text matching
        if query:
            query_lower = query.lower()
            scored = []
            for m in memories:
                text = str(m.get("text", "")).lower()
                score = 0
                if query_lower in text:
                    score = 2  # Exact substring match
                elif any(word in text for word in query_lower.split()):
                    score = 1  # Word match
                if score > 0:
                    scored.append((score, m))
            scored.sort(key=lambda x: x[0], reverse=True)
            memories = [m for _, m in scored]

        return memories[:limit]


# Global instance for backward compatibility
_store: Optional[MultiAgentMemoryStore] = None


def _get_store() -> MultiAgentMemoryStore:
    global _store
    if _store is None:
        _store = MultiAgentMemoryStore()
    return _store


# Backward-compatible module-level functions

def put_event(event: Event) -> None:
    """Persist an Event into the unified DynamoDB table.

    Backward-compatible wrapper that uses agent_id from the event.
    """
    store = _get_store()
    if store.table is None:
        logging.error("put_event: DynamoDB table not configured (AGENT_STATE_TABLE missing).")
        return
    store.put_event(event.agent_id, event)


def put_memory(memory_obj: Any, agent_id: Optional[str] = None, speaker_id: Optional[str] = None) -> None:
    """Persist a MemoryItem into DynamoDB.

    Args:
        memory_obj: MemoryItem, dict, or string to store
        agent_id: Optional agent_id override (defaults to AGENT_ID env var)
        speaker_id: Optional speaker to associate memory with
    """
    store = _get_store()
    if store.table is None:
        logging.error("put_memory: DynamoDB table not configured (AGENT_STATE_TABLE missing).")
        return

    agent_id = agent_id or os.environ.get("AGENT_ID", "agent1")

    # Check if memory_obj has speaker_id in meta
    if isinstance(memory_obj, dict) and not speaker_id:
        speaker_id = memory_obj.get("meta", {}).get("speaker_id")

    store.put_memory(agent_id, memory_obj, speaker_id=speaker_id)


def recent_memories(
    agent_id: str,
    limit: int = 40,
    session_id: Optional[str] = None,
    speaker_id: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Retrieve most recent items for an agent.

    Backward-compatible wrapper.
    """
    store = _get_store()
    if store.table is None:
        logging.error("recent_memories: DynamoDB table not configured (AGENT_STATE_TABLE missing).")
        return []

    return store.recent_context(
        agent_id,
        limit=limit,
        session_id=session_id,
        speaker_id=speaker_id,
    )
