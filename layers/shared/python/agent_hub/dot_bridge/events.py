"""Event catalog and source envelope for the draft MCP Events webhook contract."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any

from agent_hub.dot_bridge.service import DotBinding

HANDOFF_READY = "marvain.handoff.ready"


def handoff_event_definition() -> dict[str, Any]:
    return {
        "name": HANDOFF_READY,
        "description": "A deliberate Daylily handoff addressed to the linked Marvain principal is ready for review.",
        "delivery": ["webhook"],
        "inputSchema": {
            "type": "object",
            "properties": {"scene_euid": {"type": "string"}},
            "required": ["scene_euid"],
            "additionalProperties": False,
        },
        "payloadSchema": {
            "type": "object",
            "properties": {"scene_euid": {"type": "string"}, "handoff_euid": {"type": "string"}},
            "required": ["scene_euid", "handoff_euid"],
            "additionalProperties": False,
        },
    }


@dataclass(frozen=True)
class HandoffReadyEvent:
    """Source supplies the persisted handoff and its stable event ID after commitment."""

    event_id: str
    occurred_at: datetime
    handoff_euid: str
    scene_euid: str
    recipient_principal_euid: str

    def __post_init__(self) -> None:
        if self.occurred_at.utcoffset() is None:
            raise ValueError("Handoff event occurrence time must include a timezone")
        if not all((self.event_id, self.handoff_euid, self.scene_euid, self.recipient_principal_euid)):
            raise ValueError("Handoff event requires the source event, handoff, scene and recipient identities")

    def envelope_for(self, *, binding: DotBinding, subscribed_scene_euid: str) -> dict[str, Any] | None:
        """Build a pointer-only payload for the dispatcher's currently authorized subscription."""
        if self.recipient_principal_euid != binding.principal_euid or self.scene_euid != subscribed_scene_euid:
            return None
        if not any(scene.scene_euid == subscribed_scene_euid for scene in binding.scenes):
            return None
        return self.envelope()

    def envelope(self) -> dict[str, Any]:
        """Serialize the pointer after the dispatcher has authorized its exact recipient."""
        return {
            "eventId": self.event_id,
            "name": HANDOFF_READY,
            "timestamp": self.occurred_at.isoformat(),
            "data": {"scene_euid": self.scene_euid, "handoff_euid": self.handoff_euid},
            "cursor": None,
        }
