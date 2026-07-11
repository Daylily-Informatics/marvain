from __future__ import annotations

from copy import deepcopy

import pytest
from agent_hub.session_lifecycle import (
    SESSION_TRANSITIONS,
    SessionLifecycleError,
    SessionLifecycleState,
    validate_session_transition,
)

SESSION_ID = "11111111-1111-1111-1111-111111111111"
ROOM_NAME = "space:session"


def _payload(*, from_state: str = "opening", to_state: str = "active") -> dict:
    return {
        "contract_version": 1,
        "session_id": SESSION_ID,
        "from_state": from_state,
        "to_state": to_state,
        "reason": "owning runtime evidence accepted",
        "room_name": ROOM_NAME,
        "worker_version": "worker-1",
        "occurred_at": "2026-07-11T03:00:00Z",
    }


def test_session_lifecycle_uses_the_six_canonical_states() -> None:
    assert {state.value for state in SessionLifecycleState} == {
        "opening",
        "active",
        "reconnecting",
        "closed",
        "failed",
        "reconciled",
    }
    assert set(SESSION_TRANSITIONS) == set(SessionLifecycleState)


def test_transition_is_validated_against_persisted_session_and_room() -> None:
    transition = validate_session_transition(
        _payload(),
        expected_session_id=SESSION_ID,
        current_state="opening",
        expected_room_name=ROOM_NAME,
    )

    assert transition.from_state is SessionLifecycleState.OPENING
    assert transition.to_state is SessionLifecycleState.ACTIVE
    assert transition.terminal is False


@pytest.mark.parametrize(
    ("change", "code"),
    [
        ({"contract_version": 2}, "invalid_session_transition"),
        ({"session_id": "other"}, "session_identity_mismatch"),
        ({"room_name": "other"}, "session_room_mismatch"),
        ({"from_state": "active"}, "session_state_conflict"),
        ({"to_state": "reconciled"}, "invalid_session_transition"),
        ({"occurred_at": "2026-07-11T03:00:00"}, "invalid_session_transition"),
    ],
)
def test_transition_rejects_unowned_or_invalid_claims(change: dict, code: str) -> None:
    payload = deepcopy(_payload())
    payload.update(change)

    with pytest.raises(SessionLifecycleError) as exc_info:
        validate_session_transition(
            payload,
            expected_session_id=SESSION_ID,
            current_state="opening",
            expected_room_name=ROOM_NAME,
        )

    assert exc_info.value.code == code


def test_reconciliation_requires_the_terminal_owning_event() -> None:
    payload = _payload(from_state="failed", to_state="reconciled")

    with pytest.raises(SessionLifecycleError, match="reconciles_event_id"):
        validate_session_transition(
            payload,
            expected_session_id=SESSION_ID,
            current_state="failed",
            expected_room_name=ROOM_NAME,
        )

    payload["reconciles_event_id"] = "event-terminal"
    transition = validate_session_transition(
        payload,
        expected_session_id=SESSION_ID,
        current_state="failed",
        expected_room_name=ROOM_NAME,
    )
    assert transition.to_state is SessionLifecycleState.RECONCILED
    assert transition.reconciles_event_id == "event-terminal"
    assert transition.terminal is True
