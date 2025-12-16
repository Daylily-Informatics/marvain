from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, Optional


class MemoryKind(str, Enum):
    FACT = "FACT"
    SPECULATION = "SPECULATION"
    AI_INSIGHT = "AI_INSIGHT"
    ACTION = "ACTION"
    META = "META"


@dataclass
class Event:
    agent_id: str
    session_id: str
    source: str  # e.g. "user", "agent", "system"
    channel: str  # e.g. "audio", "text", "timer"
    ts: Optional[str]  # ISO8601 UTC timestamp; filled in by store if missing
    payload: Dict[str, Any]


@dataclass
class MemoryItem:
    kind: MemoryKind = MemoryKind.FACT
    text: str = ""
    ts: Optional[str] = None
    meta: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "kind": self.kind.value if isinstance(self.kind, MemoryKind) else str(self.kind),
            "text": self.text,
            "ts": self.ts,
            **({"meta": self.meta} if self.meta else {}),
        }

    @staticmethod
    def from_obj(obj: Any) -> "MemoryItem":
        if isinstance(obj, MemoryItem):
            return obj
        if isinstance(obj, str):
            return MemoryItem(kind=MemoryKind.FACT, text=obj)
        if isinstance(obj, dict):
            kind_raw = obj.get("kind", MemoryKind.FACT)
            try:
                kind = MemoryKind(kind_raw)
            except Exception:
                kind = MemoryKind.META
            text = obj.get("text") or obj.get("value") or ""
            ts = obj.get("ts")
            meta = obj.get("meta") or {}
            return MemoryItem(kind=kind, text=str(text), ts=ts, meta=meta if isinstance(meta, dict) else {})
        # fallback
        return MemoryItem(kind=MemoryKind.META, text=str(obj))
