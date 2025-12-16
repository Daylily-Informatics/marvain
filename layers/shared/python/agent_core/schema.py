from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional


class MemoryKind(str, Enum):
    """Types of memories that can be stored."""
    FACT = "FACT"  # Confirmed factual information
    SPECULATION = "SPECULATION"  # Uncertain or hypothetical information
    AI_INSIGHT = "AI_INSIGHT"  # Agent's analysis or observations
    ACTION = "ACTION"  # Actions taken or to be taken
    META = "META"  # System/internal notes
    PREFERENCE = "PREFERENCE"  # User preferences
    RELATIONSHIP = "RELATIONSHIP"  # Information about relationships
    CONTEXT = "CONTEXT"  # Conversational context
    EMOTION = "EMOTION"  # Emotional state observations


class MemoryImportance(str, Enum):
    """Importance level for memory prioritization."""
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class EventSource(str, Enum):
    """Source of an event."""
    USER = "user"
    AGENT = "agent"
    SYSTEM = "system"
    EXTERNAL = "external"


class EventChannel(str, Enum):
    """Channel through which event was received."""
    AUDIO = "audio"
    TEXT = "text"
    TIMER = "timer"
    API = "api"
    GUI = "gui"


@dataclass
class Event:
    """Represents an event in the agent's memory."""
    agent_id: str
    session_id: str
    source: str  # e.g. "user", "agent", "system"
    channel: str  # e.g. "audio", "text", "timer"
    ts: Optional[str]  # ISO8601 UTC timestamp; filled in by store if missing
    payload: Dict[str, Any]
    speaker_id: Optional[str] = None  # Associated speaker

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for storage."""
        result = {
            "agent_id": self.agent_id,
            "session_id": self.session_id,
            "source": self.source,
            "channel": self.channel,
            "ts": self.ts,
            "payload": self.payload,
        }
        if self.speaker_id:
            result["speaker_id"] = self.speaker_id
        return result


@dataclass
class MemoryItem:
    """A single memory item with enhanced metadata."""
    kind: MemoryKind = MemoryKind.FACT
    text: str = ""
    ts: Optional[str] = None
    meta: Dict[str, Any] = field(default_factory=dict)
    speaker_id: Optional[str] = None
    importance: MemoryImportance = MemoryImportance.MEDIUM
    tags: List[str] = field(default_factory=list)
    expires_at: Optional[str] = None  # ISO8601 timestamp for expiring memories
    related_memories: List[str] = field(default_factory=list)  # IDs of related memories

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for storage."""
        result: Dict[str, Any] = {
            "kind": self.kind.value if isinstance(self.kind, MemoryKind) else str(self.kind),
            "text": self.text,
        }
        if self.ts:
            result["ts"] = self.ts
        if self.meta:
            result["meta"] = self.meta
        if self.speaker_id:
            result["speaker_id"] = self.speaker_id
        if self.importance != MemoryImportance.MEDIUM:
            result["importance"] = self.importance.value
        if self.tags:
            result["tags"] = self.tags
        if self.expires_at:
            result["expires_at"] = self.expires_at
        if self.related_memories:
            result["related_memories"] = self.related_memories
        return result

    @staticmethod
    def from_obj(obj: Any) -> "MemoryItem":
        """Create MemoryItem from various input types."""
        if isinstance(obj, MemoryItem):
            return obj

        if isinstance(obj, str):
            return MemoryItem(kind=MemoryKind.FACT, text=obj)

        if isinstance(obj, dict):
            # Parse kind
            kind_raw = obj.get("kind", MemoryKind.FACT)
            try:
                if isinstance(kind_raw, MemoryKind):
                    kind = kind_raw
                else:
                    kind = MemoryKind(str(kind_raw).upper())
            except (ValueError, KeyError):
                kind = MemoryKind.META

            # Parse text
            text = obj.get("text") or obj.get("value") or obj.get("content") or ""

            # Parse importance
            importance_raw = obj.get("importance", "MEDIUM")
            try:
                if isinstance(importance_raw, MemoryImportance):
                    importance = importance_raw
                else:
                    importance = MemoryImportance(str(importance_raw).upper())
            except (ValueError, KeyError):
                importance = MemoryImportance.MEDIUM

            # Parse other fields
            ts = obj.get("ts")
            meta = obj.get("meta") or {}
            speaker_id = obj.get("speaker_id") or meta.get("speaker_id")
            tags = obj.get("tags") or []
            expires_at = obj.get("expires_at")
            related_memories = obj.get("related_memories") or []

            return MemoryItem(
                kind=kind,
                text=str(text),
                ts=ts,
                meta=meta if isinstance(meta, dict) else {},
                speaker_id=speaker_id,
                importance=importance,
                tags=tags if isinstance(tags, list) else [tags] if tags else [],
                expires_at=expires_at,
                related_memories=related_memories,
            )

        # Fallback
        return MemoryItem(kind=MemoryKind.META, text=str(obj))


@dataclass
class SpeakerMemoryContext:
    """Context about a speaker for memory operations."""
    speaker_id: str
    speaker_name: Optional[str] = None
    relationship_summary: Optional[str] = None
    recent_topics: List[str] = field(default_factory=list)
    preferences: Dict[str, Any] = field(default_factory=dict)
    interaction_count: int = 0
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {k: v for k, v in {
            "speaker_id": self.speaker_id,
            "speaker_name": self.speaker_name,
            "relationship_summary": self.relationship_summary,
            "recent_topics": self.recent_topics if self.recent_topics else None,
            "preferences": self.preferences if self.preferences else None,
            "interaction_count": self.interaction_count if self.interaction_count > 0 else None,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
        }.items() if v is not None}


@dataclass
class ConversationContext:
    """Full context for a conversation turn."""
    agent_id: str
    session_id: str
    speaker: Optional[SpeakerMemoryContext] = None
    recent_events: List[Dict[str, Any]] = field(default_factory=list)
    relevant_memories: List[Dict[str, Any]] = field(default_factory=list)
    speaker_memories: List[Dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "agent_id": self.agent_id,
            "session_id": self.session_id,
            "speaker": self.speaker.to_dict() if self.speaker else None,
            "recent_events": self.recent_events,
            "relevant_memories": self.relevant_memories,
            "speaker_memories": self.speaker_memories,
        }


def now_iso() -> str:
    """Get current UTC timestamp in ISO8601 format."""
    return datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.%fZ")
