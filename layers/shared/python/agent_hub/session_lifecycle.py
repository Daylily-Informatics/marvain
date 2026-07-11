"""Validated durable session state transition contracts."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from typing import Any, Mapping


class SessionLifecycleError(ValueError):
    def __init__(self, code: str, detail: str) -> None:
        super().__init__(detail)
        self.code = code
        self.detail = detail


class SessionLifecycleState(StrEnum):
    OPENING = "opening"
    ACTIVE = "active"
    RECONNECTING = "reconnecting"
    CLOSED = "closed"
    FAILED = "failed"
    RECONCILED = "reconciled"


SESSION_TRANSITIONS: dict[SessionLifecycleState, frozenset[SessionLifecycleState]] = {
    SessionLifecycleState.OPENING: frozenset(
        {SessionLifecycleState.ACTIVE, SessionLifecycleState.CLOSED, SessionLifecycleState.FAILED}
    ),
    SessionLifecycleState.ACTIVE: frozenset(
        {SessionLifecycleState.RECONNECTING, SessionLifecycleState.CLOSED, SessionLifecycleState.FAILED}
    ),
    SessionLifecycleState.RECONNECTING: frozenset(
        {SessionLifecycleState.ACTIVE, SessionLifecycleState.CLOSED, SessionLifecycleState.FAILED}
    ),
    SessionLifecycleState.CLOSED: frozenset({SessionLifecycleState.RECONCILED}),
    SessionLifecycleState.FAILED: frozenset({SessionLifecycleState.RECONCILED}),
    SessionLifecycleState.RECONCILED: frozenset(),
}


def _required_text(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value or value != value.strip():
        raise SessionLifecycleError("invalid_session_transition", f"{field} must be non-empty text")
    return value


def _state(value: Any, field: str) -> SessionLifecycleState:
    try:
        return SessionLifecycleState(_required_text(value, field))
    except ValueError as exc:
        raise SessionLifecycleError("invalid_session_transition", f"{field} is not a supported state") from exc


def _aware_datetime(value: Any, field: str) -> datetime:
    raw = _required_text(value, field)
    try:
        parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError as exc:
        raise SessionLifecycleError("invalid_session_transition", f"{field} must be ISO-8601") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise SessionLifecycleError("invalid_session_transition", f"{field} must include a timezone")
    return parsed


@dataclass(frozen=True)
class SessionTransition:
    session_id: str
    from_state: SessionLifecycleState
    to_state: SessionLifecycleState
    reason: str
    room_name: str
    worker_version: str
    occurred_at: datetime
    reconciles_event_id: str | None = None

    @property
    def terminal(self) -> bool:
        return self.to_state in {
            SessionLifecycleState.CLOSED,
            SessionLifecycleState.FAILED,
            SessionLifecycleState.RECONCILED,
        }


def validate_session_transition(
    payload: Mapping[str, Any],
    *,
    expected_session_id: str,
    current_state: str,
    expected_room_name: str,
) -> SessionTransition:
    if not isinstance(payload, Mapping):
        raise SessionLifecycleError("invalid_session_transition", "payload must be an object")
    if payload.get("contract_version") != 1:
        raise SessionLifecycleError("invalid_session_transition", "contract_version must equal 1")

    session_id = _required_text(payload.get("session_id"), "session_id")
    if session_id != _required_text(expected_session_id, "expected_session_id"):
        raise SessionLifecycleError("session_identity_mismatch", "payload session_id does not match the event session")
    room_name = _required_text(payload.get("room_name"), "room_name")
    if room_name != _required_text(expected_room_name, "expected_room_name"):
        raise SessionLifecycleError("session_room_mismatch", "payload room_name does not match the persisted session")

    from_state = _state(payload.get("from_state"), "from_state")
    persisted_state = _state(current_state, "current_state")
    if from_state is not persisted_state:
        raise SessionLifecycleError(
            "session_state_conflict",
            f"transition starts at {from_state.value}, but persisted state is {persisted_state.value}",
        )
    to_state = _state(payload.get("to_state"), "to_state")
    if to_state not in SESSION_TRANSITIONS[from_state]:
        raise SessionLifecycleError(
            "invalid_session_transition",
            f"cannot transition session from {from_state.value} to {to_state.value}",
        )

    reconciles_event_id_raw = payload.get("reconciles_event_id")
    if to_state is SessionLifecycleState.RECONCILED:
        reconciles_event_id = _required_text(reconciles_event_id_raw, "reconciles_event_id")
    elif reconciles_event_id_raw is not None:
        raise SessionLifecycleError(
            "invalid_session_transition",
            "reconciles_event_id is valid only for a reconciled transition",
        )
    else:
        reconciles_event_id = None

    return SessionTransition(
        session_id=session_id,
        from_state=from_state,
        to_state=to_state,
        reason=_required_text(payload.get("reason"), "reason"),
        room_name=room_name,
        worker_version=_required_text(payload.get("worker_version"), "worker_version"),
        occurred_at=_aware_datetime(payload.get("occurred_at"), "occurred_at"),
        reconciles_event_id=reconciles_event_id,
    )


__all__ = [
    "SESSION_TRANSITIONS",
    "SessionLifecycleError",
    "SessionLifecycleState",
    "SessionTransition",
    "validate_session_transition",
]
