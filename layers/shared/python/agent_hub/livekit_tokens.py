from __future__ import annotations

import json
import os
from datetime import timedelta
from typing import Any

from livekit.api import (
    AccessToken,
    RoomAgentDispatch,
    RoomConfiguration,
    VideoGrants,
)

# Agent name for explicit dispatch - must match the name in the worker's
# @server.rtc_session(agent_name=...) decorator
AGENT_NAME = os.getenv("LIVEKIT_AGENT_NAME", "forge")


def mint_livekit_join_token(
    *,
    api_key: str,
    api_secret: str,
    identity: str,
    room: str,
    name: str | None = None,
    ttl_seconds: int = 3600,
    can_publish: bool = True,
    can_subscribe: bool = True,
    can_publish_data: bool = True,
    room_create: bool = True,
    agent_name: str | None = None,
    agent_metadata: dict[str, Any] | None = None,
) -> str:
    """Mint a LiveKit access token (JWT) for joining a room with agent dispatch.

    Uses LiveKit's official SDK to generate tokens with proper agent dispatch
    configuration. When a participant connects with this token, LiveKit Cloud
    will automatically dispatch the specified agent to the room.

    This approach is more reliable than relying on automatic dispatch on room
    creation, which can fail in various edge cases (agent cold starts, room
    lifecycle timing, etc.).

    Args:
        api_key: LiveKit API key.
        api_secret: LiveKit API secret.
        identity: Participant identity (unique identifier).
        room: Room name to join.
        name: Optional display name for the participant.
        ttl_seconds: Token time-to-live in seconds (default: 3600 = 1 hour).
        can_publish: Whether participant can publish audio/video.
        can_subscribe: Whether participant can subscribe to remote tracks.
        can_publish_data: Whether participant can publish data messages.
        room_create: Whether participant can create the room if it doesn't exist.
        agent_name: Agent to dispatch on participant connection (default: AGENT_NAME).
        agent_metadata: Optional metadata to pass to the agent (will be JSON-encoded).

    Returns:
        JWT token string.
    """
    # Use default agent name if not specified
    dispatch_agent = agent_name if agent_name is not None else AGENT_NAME

    # Build video grants
    grants = VideoGrants(
        room=str(room),
        room_join=True,
        room_create=bool(room_create),
        can_publish=bool(can_publish),
        can_subscribe=bool(can_subscribe),
        can_publish_data=bool(can_publish_data),
    )

    # Build agent dispatch metadata
    metadata_str = json.dumps(agent_metadata) if agent_metadata else None

    # Build room configuration with agent dispatch
    room_config = RoomConfiguration(
        agents=[
            RoomAgentDispatch(
                agent_name=dispatch_agent,
                metadata=metadata_str,
            ),
        ],
    )

    # Build the access token using LiveKit SDK
    token = (
        AccessToken(api_key=str(api_key), api_secret=str(api_secret))
        .with_identity(str(identity))
        .with_ttl(timedelta(seconds=ttl_seconds))
        .with_grants(grants)
        .with_room_config(room_config)
    )

    # Add display name if provided
    if name:
        token = token.with_name(str(name))

    return token.to_jwt()
