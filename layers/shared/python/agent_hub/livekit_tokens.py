from __future__ import annotations

import json
import os
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
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


class LiveKitMessageValidationError(ValueError):
    """Raised when a LiveKit data message cannot be tied to its session and sender."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


@dataclass(frozen=True)
class ValidatedLiveKitMessage:
    sender_identity: str
    session_id: str
    sent_at: datetime


def _require_text(value: object, field_name: str) -> str:
    text = str(value or "").strip()
    if not text:
        raise LiveKitMessageValidationError(f"missing_{field_name}", f"{field_name} is required")
    return text


def parse_livekit_timestamp(value: object, *, field_name: str) -> datetime:
    """Parse an explicitly timezone-aware LiveKit message timestamp."""

    text = _require_text(value, field_name)
    if text.endswith("Z"):
        text = f"{text[:-1]}+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError as exc:
        raise LiveKitMessageValidationError(
            f"invalid_{field_name}", f"{field_name} must be an ISO-8601 timestamp"
        ) from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise LiveKitMessageValidationError(f"invalid_{field_name}", f"{field_name} must include a timezone")
    return parsed.astimezone(timezone.utc)


def validate_livekit_sender_session(
    *,
    sender_identity: object,
    expected_sender_identity: object,
    message_session_id: object,
    expected_session_id: object,
) -> tuple[str, str]:
    """Require exact transport-sender and durable-session correlation."""

    sender = _require_text(sender_identity, "sender_identity")
    expected_sender = _require_text(expected_sender_identity, "expected_sender_identity")
    if sender != expected_sender:
        raise LiveKitMessageValidationError(
            "unexpected_sender", f"message sender {sender!r} does not match session participant"
        )

    session_id = _require_text(message_session_id, "session_id")
    expected_session = _require_text(expected_session_id, "expected_session_id")
    if session_id != expected_session:
        raise LiveKitMessageValidationError(
            "stale_session", f"message session {session_id!r} does not match active session"
        )
    return sender, session_id


def validate_livekit_message_freshness(
    sent_at: object,
    *,
    field_name: str,
    max_age_seconds: float,
    now: datetime | None = None,
    max_future_skew_seconds: float = 5.0,
) -> datetime:
    """Reject stale or implausibly future-dated data-channel messages."""

    if max_age_seconds <= 0:
        raise ValueError("max_age_seconds must be positive")
    if max_future_skew_seconds < 0:
        raise ValueError("max_future_skew_seconds must be non-negative")

    parsed = parse_livekit_timestamp(sent_at, field_name=field_name)
    reference = now or datetime.now(timezone.utc)
    if reference.tzinfo is None or reference.utcoffset() is None:
        raise ValueError("now must include a timezone")
    age_seconds = (reference.astimezone(timezone.utc) - parsed).total_seconds()
    if age_seconds < -max_future_skew_seconds:
        raise LiveKitMessageValidationError("future_message", f"{field_name} is too far in the future")
    if age_seconds > max_age_seconds:
        raise LiveKitMessageValidationError("stale_message", f"{field_name} is older than the freshness window")
    return parsed


def validate_livekit_ack_sender_session_freshness(
    payload: Mapping[str, object],
    *,
    transport_sender_identity: object,
    expected_sender_identity: object,
    expected_session_id: object,
    expected_request_id: object,
    max_age_seconds: float,
    now: datetime | None = None,
) -> ValidatedLiveKitMessage:
    """Validate an ACK against its transport sender, request, session, and timestamp."""

    if not isinstance(payload, Mapping):
        raise LiveKitMessageValidationError("invalid_ack_payload", "ACK payload must be an object")
    claimed_sender = _require_text(payload.get("sender_identity"), "ack_sender_identity")
    transport_sender = _require_text(transport_sender_identity, "transport_sender_identity")
    if claimed_sender != transport_sender:
        raise LiveKitMessageValidationError(
            "ack_sender_mismatch", "ACK sender claim does not match the LiveKit transport sender"
        )

    sender, session_id = validate_livekit_sender_session(
        sender_identity=transport_sender,
        expected_sender_identity=expected_sender_identity,
        message_session_id=payload.get("session_id"),
        expected_session_id=expected_session_id,
    )
    request_id = _require_text(payload.get("visual_request_id"), "visual_request_id")
    expected_request = _require_text(expected_request_id, "expected_request_id")
    if request_id != expected_request:
        raise LiveKitMessageValidationError(
            "ack_request_mismatch", "ACK request id does not match the pending visual request"
        )
    acknowledged_at = validate_livekit_message_freshness(
        payload.get("acknowledged_at"),
        field_name="acknowledged_at",
        max_age_seconds=max_age_seconds,
        now=now,
    )
    return ValidatedLiveKitMessage(sender_identity=sender, session_id=session_id, sent_at=acknowledged_at)


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

    # Tie every dispatch to the participant identity carried by the same token.
    participant_identity = str(identity or "").strip()
    if not participant_identity:
        raise ValueError("identity is required")
    dispatch_metadata = dict(agent_metadata or {})
    configured_participant = str(dispatch_metadata.get("participant_identity") or "").strip()
    if configured_participant and configured_participant != participant_identity:
        raise ValueError("agent_metadata participant_identity must match token identity")
    dispatch_metadata["participant_identity"] = participant_identity
    metadata_str = json.dumps(dispatch_metadata, separators=(",", ":"), sort_keys=True)

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
        .with_identity(participant_identity)
        .with_ttl(timedelta(seconds=ttl_seconds))
        .with_grants(grants)
        .with_room_config(room_config)
    )

    # Add display name if provided
    if name:
        token = token.with_name(str(name))

    return token.to_jwt()
