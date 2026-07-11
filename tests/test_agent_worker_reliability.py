from __future__ import annotations

import asyncio
import base64
import importlib.util
import json
import os
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]


def _load_agent_worker_module():
    shared = REPO_ROOT / "layers" / "shared" / "python"
    if str(shared) not in sys.path:
        sys.path.insert(0, str(shared))

    worker_py = REPO_ROOT / "apps" / "agent_worker" / "worker.py"
    os.environ.setdefault("AGENT_DISCONNECT_DELAY_SECONDS", "0")
    os.environ.setdefault("MARVAIN_AGENT_PERSONA_INSTRUCTIONS", "Test persona instructions.")
    os.environ.setdefault("MARVAIN_WORKER_VERSION", "test-worker-1")
    spec = importlib.util.spec_from_file_location("agent_worker_for_reliability_tests", worker_py)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


def _decode_jwt_payload(token: str) -> dict:
    encoded = token.split(".")[1]
    encoded += "=" * (-len(encoded) % 4)
    return json.loads(base64.urlsafe_b64decode(encoded))


def test_session_state_transition_is_durable_before_local_state_changes() -> None:
    worker = _load_agent_worker_module()
    state = worker.SessionStateMachine(session_id="session-1")

    with mock.patch.object(worker, "hub_ingest_event", return_value="event-transition-1") as ingest:
        event_id = worker.hub_transition_session_state(
            state_machine=state,
            space_id="space-1",
            to_state="active",
            reason="livekit_agent_session_started",
            room_name="space-1:room-1",
            worker_version="worker-1",
        )

    assert event_id == "event-transition-1"
    assert state.state == "active"
    assert state.last_event_id == "event-transition-1"
    payload = ingest.call_args.kwargs["payload"]
    assert ingest.call_args.kwargs["event_type"] == "session.state_transition"
    assert payload["from_state"] == "opening"
    assert payload["to_state"] == "active"
    assert payload["session_id"] == "session-1"


def test_session_state_does_not_change_when_transition_event_fails() -> None:
    worker = _load_agent_worker_module()
    state = worker.SessionStateMachine(session_id="session-1")

    with (
        mock.patch.object(worker, "hub_ingest_event", side_effect=worker.HubWriteError("event", "down")),
        pytest.raises(worker.HubWriteError),
    ):
        worker.hub_transition_session_state(
            state_machine=state,
            space_id="space-1",
            to_state="failed",
            reason="runtime_failed",
            room_name="room-1",
            worker_version="worker-1",
        )

    assert state.state == "opening"
    assert state.last_event_id is None


def test_session_state_rejects_non_durable_privacy_mode_sentinel() -> None:
    worker = _load_agent_worker_module()
    state = worker.SessionStateMachine(session_id="session-1")

    with (
        mock.patch.object(worker, "hub_ingest_event", return_value="privacy_mode"),
        pytest.raises(worker.HubWriteError, match="did not persist"),
    ):
        worker.hub_transition_session_state(
            state_machine=state,
            space_id="space-1",
            to_state="active",
            reason="livekit_agent_session_started",
            room_name="room-1",
            worker_version="worker-1",
        )

    assert state.state == "opening"
    assert state.last_event_id is None


def test_session_lifecycle_uses_only_required_states_and_rejects_compatibility_states() -> None:
    worker = _load_agent_worker_module()

    assert worker.SESSION_STATES == {
        "opening",
        "active",
        "reconnecting",
        "closed",
        "failed",
        "reconciled",
    }
    for removed_state in ("open", "paused"):
        with pytest.raises(worker.WorkerContractError, match="invalid initial session state"):
            worker.SessionStateMachine(session_id="session-1", state=removed_state)


def test_session_state_transition_matrix_is_strict() -> None:
    worker = _load_agent_worker_module()
    expected_transitions = {
        "opening": {"active", "closed", "failed"},
        "active": {"reconnecting", "closed", "failed"},
        "reconnecting": {"active", "closed", "failed"},
        "closed": {"reconciled"},
        "failed": {"reconciled"},
        "reconciled": set(),
    }

    assert worker.SESSION_STATE_TRANSITIONS == {
        state: frozenset(targets) for state, targets in expected_transitions.items()
    }
    for from_state, valid_targets in expected_transitions.items():
        state = worker.SessionStateMachine(
            session_id="session-1",
            state=from_state,
            last_event_id=None if from_state == "opening" else f"event-{from_state}",
        )
        for to_state in worker.SESSION_STATES:
            if to_state in valid_targets:
                payload = state.transition_payload(
                    to_state=to_state,
                    reason="test_transition",
                    room_name="room-1",
                    worker_version="worker-1",
                )
                assert payload["from_state"] == from_state
                assert payload["to_state"] == to_state
            else:
                with pytest.raises(worker.WorkerContractError, match=f"{from_state} -> {to_state}"):
                    state.transition_payload(
                        to_state=to_state,
                        reason="test_transition",
                        room_name="room-1",
                        worker_version="worker-1",
                    )


def test_livekit_session_becomes_active_only_after_start_and_durable_acceptance() -> None:
    worker = _load_agent_worker_module()
    state = worker.SessionStateMachine(session_id="session-1")
    lifecycle = worker.DurableSessionLifecycle(
        state_machine=state,
        space_id="space-1",
        room_name="room-1",
        worker_version="worker-1",
    )
    observed: list[tuple[str, str]] = []

    class FakeAgentSession:
        async def start(self, **kwargs: object) -> None:
            assert kwargs == {"room": "room-object"}
            observed.append(("start", lifecycle.state))

    def accept_event(**kwargs: object) -> str:
        observed.append(("persist", lifecycle.state))
        assert kwargs["event_type"] == "session.state_transition"
        return "event-active-1"

    with mock.patch.object(worker, "hub_ingest_event", side_effect=accept_event):
        event_id = asyncio.run(
            lifecycle.start_agent_session(
                session=FakeAgentSession(),
                start_kwargs={"room": "room-object"},
            )
        )

    assert observed == [("start", "opening"), ("persist", "opening")]
    assert event_id == "event-active-1"
    assert lifecycle.state == "active"
    assert state.last_event_id == "event-active-1"


def test_completed_start_does_not_reactivate_an_orderly_closed_session() -> None:
    worker = _load_agent_worker_module()
    state = worker.SessionStateMachine(session_id="session-1")
    lifecycle = worker.DurableSessionLifecycle(
        state_machine=state,
        space_id="space-1",
        room_name="room-1",
        worker_version="worker-1",
    )

    class FakeAgentSession:
        async def start(self, **_kwargs: object) -> None:
            await lifecycle.transition(
                to_state="closed",
                reason="last_human_disconnected",
            )

    with mock.patch.object(worker, "hub_ingest_event", return_value="event-closed-1") as ingest:
        event_id = asyncio.run(
            lifecycle.start_agent_session(
                session=FakeAgentSession(),
                start_kwargs={"room": "room-object"},
            )
        )

    assert event_id is None
    assert lifecycle.state == "closed"
    assert state.last_event_id == "event-closed-1"
    assert ingest.call_count == 1
    assert ingest.call_args.kwargs["payload"]["to_state"] == "closed"


def test_reconnect_transitions_are_durable_and_serialized() -> None:
    worker = _load_agent_worker_module()
    state = worker.SessionStateMachine(
        session_id="session-1",
        state="active",
        last_event_id="event-active-1",
    )
    lifecycle = worker.DurableSessionLifecycle(
        state_machine=state,
        space_id="space-1",
        room_name="room-1",
        worker_version="worker-1",
    )

    with mock.patch.object(worker, "hub_ingest_event", side_effect=["event-reconnecting-1", "event-active-2"]):

        async def exercise() -> tuple[str, str]:
            reconnecting_event = await lifecycle.transition(
                to_state="reconnecting",
                reason="livekit_room_reconnecting",
            )
            active_event = await lifecycle.transition(
                to_state="active",
                reason="livekit_room_reconnected",
            )
            return reconnecting_event, active_event

        assert asyncio.run(exercise()) == ("event-reconnecting-1", "event-active-2")

    assert lifecycle.state == "active"
    assert state.last_event_id == "event-active-2"


@pytest.mark.parametrize("terminal_state", ["closed", "failed"])
def test_terminal_state_reconciliation_references_durable_terminal_event(terminal_state: str) -> None:
    worker = _load_agent_worker_module()
    terminal_event_id = f"event-{terminal_state}-1"
    state = worker.SessionStateMachine(
        session_id="session-1",
        state=terminal_state,
        last_event_id=terminal_event_id,
    )
    lifecycle = worker.DurableSessionLifecycle(
        state_machine=state,
        space_id="space-1",
        room_name="room-1",
        worker_version="worker-1",
    )

    with mock.patch.object(worker, "hub_ingest_event", return_value="event-reconciled-1") as ingest:
        event_id = asyncio.run(lifecycle.reconcile(reason="owning_service_reconciled_runtime_state"))

    assert event_id == "event-reconciled-1"
    assert lifecycle.state == "reconciled"
    assert state.last_event_id == "event-reconciled-1"
    payload = ingest.call_args.kwargs["payload"]
    assert payload["from_state"] == terminal_state
    assert payload["to_state"] == "reconciled"
    assert payload["reconciles_event_id"] == terminal_event_id

    with pytest.raises(worker.WorkerContractError, match="reconciled -> active"):
        state.transition_payload(
            to_state="active",
            reason="invalid_reopen",
            room_name="room-1",
            worker_version="worker-1",
        )


def test_reconciliation_failure_preserves_terminal_state() -> None:
    worker = _load_agent_worker_module()
    state = worker.SessionStateMachine(
        session_id="session-1",
        state="failed",
        last_event_id="event-failed-1",
    )
    lifecycle = worker.DurableSessionLifecycle(
        state_machine=state,
        space_id="space-1",
        room_name="room-1",
        worker_version="worker-1",
    )

    with (
        mock.patch.object(worker, "hub_ingest_event", side_effect=worker.HubWriteError("event", "down")),
        pytest.raises(worker.HubWriteError),
    ):
        asyncio.run(lifecycle.reconcile(reason="owning_service_reconciled_runtime_state"))

    assert lifecycle.state == "failed"
    assert state.last_event_id == "event-failed-1"


def test_reconciliation_rejects_nonterminal_session_without_writing() -> None:
    worker = _load_agent_worker_module()
    lifecycle = worker.DurableSessionLifecycle(
        state_machine=worker.SessionStateMachine(
            session_id="session-1",
            state="active",
            last_event_id="event-active-1",
        ),
        space_id="space-1",
        room_name="room-1",
        worker_version="worker-1",
    )

    with mock.patch.object(worker, "hub_ingest_event") as ingest:
        with pytest.raises(worker.WorkerContractError, match="requires closed or failed"):
            asyncio.run(lifecycle.reconcile(reason="invalid_early_reconciliation"))

    ingest.assert_not_called()
    assert lifecycle.state == "active"


def test_hub_ingest_event_raises_instead_of_returning_none_on_failure() -> None:
    worker = _load_agent_worker_module()
    response = mock.Mock(ok=False, status_code=503, text="temporarily unavailable")

    with (
        mock.patch.dict(
            os.environ,
            {"HUB_API_BASE": "https://hub.example.test", "HUB_DEVICE_TOKEN": "device-token"},
            clear=False,
        ),
        mock.patch.object(worker.requests, "post", return_value=response),
        pytest.raises(worker.HubWriteError, match="status=503"),
    ):
        worker.hub_ingest_event(
            space_id="space-1",
            event_type="worker.health",
            payload={"state": "ready"},
            session_id="session-1",
        )


def test_classifier_unavailable_persists_structured_worker_error_event() -> None:
    worker = _load_agent_worker_module()
    from agent_hub.memory_classifier import (
        MemoryClassifierFailure,
        MemoryClassifierFailureCode,
        MemoryClassifierUnavailable,
    )

    failure = MemoryClassifierFailure(
        code=MemoryClassifierFailureCode.PROVIDER_REQUEST_FAILED,
        message="provider timed out",
        provider_id="openai",
        model_provider_id="openai:gpt-test",
        source_evidence_id="event-source-1",
        retryable=True,
    )
    with (
        mock.patch.object(worker, "classify_memory_event", side_effect=MemoryClassifierUnavailable(failure)),
        mock.patch.object(worker, "hub_ingest_event", return_value="event-error-1") as ingest,
    ):
        result = worker.classify_memory_for_capture(
            text="Remember this",
            modality="text",
            source_event_id="event-source-1",
            actor_type="user",
            source="livekit_typed_chat",
            space_id="space-1",
            session_id="session-1",
            room_name="room-1",
            worker_version="worker-1",
        )

    assert result == []
    assert ingest.call_args.kwargs["event_type"] == "worker.error"
    payload = ingest.call_args.kwargs["payload"]
    assert payload["code"] == "memory_classifier_unavailable"
    assert payload["details"]["classifier_failure"]["failure_code"] == "provider_request_failed"
    assert payload["details"]["classifier_failure"]["source_evidence_id"] == "event-source-1"


def test_visual_observations_expire_and_can_be_invalidated_on_camera_off() -> None:
    worker = _load_agent_worker_module()
    now = datetime(2026, 7, 10, 12, 0, tzinfo=timezone.utc)
    observations = [
        worker.CurrentVisualObservation("fresh", "user:u1", "session-1", now - timedelta(seconds=2)),
        worker.CurrentVisualObservation("stale", "user:u1", "session-1", now - timedelta(seconds=20)),
        worker.CurrentVisualObservation("other session", "user:u1", "session-2", now - timedelta(seconds=1)),
    ]

    fresh = worker._fresh_visual_observations(observations, current_session_id="session-1", now=now)
    assert [item.description for item in fresh] == ["fresh"]
    assert worker._invalidate_visual_observations(fresh, sender_identity="user:u1") == 1
    assert fresh == []


def test_worker_health_payload_requires_and_reports_version_identity() -> None:
    worker = _load_agent_worker_module()
    observed_at = datetime(2026, 7, 10, 12, 0, tzinfo=timezone.utc)

    payload = worker.build_worker_health_payload(
        worker_version="1.2.3",
        space_id="space-1",
        session_id="session-1",
        room_name="room-1",
        state="ready",
        observed_at=observed_at,
    )

    assert payload == {
        "type": "worker_health",
        "contract_version": 1,
        "ok": True,
        "service": "marvain-agent-worker",
        "worker_version": "1.2.3",
        "agent_name": "forge",
        "space_id": "space-1",
        "session_id": "session-1",
        "room_name": "room-1",
        "state": "ready",
        "observed_at": "2026-07-10T12:00:00Z",
    }

    with pytest.raises(worker.WorkerContractError, match="worker_version"):
        worker.build_worker_health_payload(
            worker_version="",
            space_id="space-1",
            session_id="session-1",
            room_name="room-1",
            state="ready",
        )

    with (
        mock.patch.dict(os.environ, {"MARVAIN_WORKER_VERSION": ""}, clear=False),
        pytest.raises(worker.WorkerContractError, match="MARVAIN_WORKER_VERSION"),
    ):
        worker._require_worker_version()


def test_dispatch_metadata_requires_participant_bound_session_identity() -> None:
    worker = _load_agent_worker_module()

    parsed = worker._parse_dispatch_metadata(
        json.dumps(
            {
                "space_id": "space-1",
                "agent_id": "agent-1",
                "session_id": "session-1",
                "room_session_id": "room-session-1",
                "participant_identity": "user:u1",
            }
        )
    )
    assert parsed.participant_identity == "user:u1"

    with pytest.raises(worker.WorkerContractError, match="participant_identity"):
        worker._parse_dispatch_metadata(
            json.dumps(
                {
                    "space_id": "space-1",
                    "agent_id": "agent-1",
                    "session_id": "session-1",
                    "room_session_id": "room-session-1",
                }
            )
        )


def test_join_token_binds_dispatch_metadata_to_token_participant() -> None:
    from agent_hub.livekit_tokens import mint_livekit_join_token

    token = mint_livekit_join_token(
        api_key="test-key",
        api_secret="a-secret-long-enough-for-hs256-signing-tests",
        identity="user:u1",
        room="room-1",
        agent_metadata={"session_id": "session-1"},
    )
    payload = _decode_jwt_payload(token)
    metadata = json.loads(payload["roomConfig"]["agents"][0]["metadata"])

    assert payload["sub"] == "user:u1"
    assert metadata == {"participant_identity": "user:u1", "session_id": "session-1"}

    with pytest.raises(ValueError, match="must match token identity"):
        mint_livekit_join_token(
            api_key="test-key",
            api_secret="a-secret-long-enough-for-hs256-signing-tests",
            identity="user:u1",
            room="room-1",
            agent_metadata={"participant_identity": "user:other"},
        )


def test_ack_validation_checks_transport_sender_session_request_and_freshness() -> None:
    from agent_hub.livekit_tokens import (
        LiveKitMessageValidationError,
        validate_livekit_ack_sender_session_freshness,
    )

    now = datetime(2026, 7, 10, 12, 0, tzinfo=timezone.utc)
    payload = {
        "sender_identity": "agent:forge",
        "session_id": "session-1",
        "visual_request_id": "visual-1",
        "acknowledged_at": "2026-07-10T11:59:58Z",
    }

    validated = validate_livekit_ack_sender_session_freshness(
        payload,
        transport_sender_identity="agent:forge",
        expected_sender_identity="agent:forge",
        expected_session_id="session-1",
        expected_request_id="visual-1",
        max_age_seconds=15,
        now=now,
    )
    assert validated.sender_identity == "agent:forge"
    assert validated.session_id == "session-1"

    with pytest.raises(LiveKitMessageValidationError) as exc_info:
        validate_livekit_ack_sender_session_freshness(
            payload,
            transport_sender_identity="user:spoofed",
            expected_sender_identity="agent:forge",
            expected_session_id="session-1",
            expected_request_id="visual-1",
            max_age_seconds=15,
            now=now,
        )
    assert exc_info.value.code == "ack_sender_mismatch"

    stale_payload = {**payload, "acknowledged_at": "2026-07-10T11:59:00Z"}
    with pytest.raises(LiveKitMessageValidationError) as exc_info:
        validate_livekit_ack_sender_session_freshness(
            stale_payload,
            transport_sender_identity="agent:forge",
            expected_sender_identity="agent:forge",
            expected_session_id="session-1",
            expected_request_id="visual-1",
            max_age_seconds=15,
            now=now,
        )
    assert exc_info.value.code == "stale_message"
