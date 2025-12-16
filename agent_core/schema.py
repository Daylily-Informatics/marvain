from __future__ import annotations

from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any, Dict, Optional, List
from datetime import datetime, timezone
import uuid


class MemoryKind(str, Enum):
    FACT = "FACT"
    SPECULATION = "SPECULATION"
    AI_INSIGHT = "AI_INSIGHT"
    ACTION = "ACTION"
    META = "META"


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class Event:
    agent_id: str
    session_id: str
    source: str
    channel: str
    ts: str = field(default_factory=utc_now_iso)
    payload: Dict[str, Any] = field(default_factory=dict)
    event_id: str = field(default_factory=lambda: str(uuid.uuid4()))

    def to_dict(self) -> Dict[str, Any]:
        return {
            "agent_id": self.agent_id,
            "session_id": self.session_id,
            "source": self.source,
            "channel": self.channel,
            "ts": self.ts,
            "payload": self.payload,
            "event_id": self.event_id,
        }


@dataclass
class Memory:
    agent_id: str
    kind: MemoryKind
    content: str
    ts: str = field(default_factory=utc_now_iso)
    session_id: Optional[str] = None
    source: Optional[str] = None
    speaker_name: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    memory_id: str = field(default_factory=lambda: str(uuid.uuid4()))

    def to_dict(self) -> Dict[str, Any]:
        return {
            "agent_id": self.agent_id,
            "kind": self.kind.value if isinstance(self.kind, Enum) else str(self.kind),
            "content": self.content,
            "ts": self.ts,
            "session_id": self.session_id,
            "source": self.source,
            "speaker_name": self.speaker_name,
            "metadata": self.metadata or {},
            "memory_id": self.memory_id,
        }


@dataclass
class Action:
    kind: str
    payload: Dict[str, Any] = field(default_factory=dict)
    ts: str = field(default_factory=utc_now_iso)
    action_id: str = field(default_factory=lambda: str(uuid.uuid4()))

    def to_dict(self) -> Dict[str, Any]:
        return {
            "kind": self.kind,
            "payload": self.payload or {},
            "ts": self.ts,
            "action_id": self.action_id,
        }


def coerce_memory_kind(kind: Any) -> MemoryKind:
    if isinstance(kind, MemoryKind):
        return kind
    if isinstance(kind, str):
        try:
            return MemoryKind(kind)
        except ValueError:
            # be forgiving: default to META
            return MemoryKind.META
    return MemoryKind.META


def memory_from_obj(agent_id: str, obj: Any, *, session_id: Optional[str] = None, source: Optional[str] = None, speaker_name: Optional[str] = None) -> Memory:
    """Best-effort conversion from dict-ish objects into a Memory dataclass."""
    if isinstance(obj, Memory):
        return obj
    if not isinstance(obj, dict):
        return Memory(agent_id=agent_id, kind=MemoryKind.META, content=str(obj), session_id=session_id, source=source, speaker_name=speaker_name)

    kind = coerce_memory_kind(obj.get("kind"))
    content = str(obj.get("content", "")).strip()
    metadata = obj.get("metadata") or {}
    ts = obj.get("ts") or utc_now_iso()
    memory_id = obj.get("memory_id") or str(uuid.uuid4())
    return Memory(
        agent_id=agent_id,
        kind=kind,
        content=content,
        ts=ts,
        session_id=obj.get("session_id") or session_id,
        source=obj.get("source") or source,
        speaker_name=obj.get("speaker_name") or speaker_name,
        metadata=metadata,
        memory_id=memory_id,
    )
