from __future__ import annotations

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
            to_state="closed",
            reason="last_human_disconnected",
            room_name="space-1:room-1",
            worker_version="worker-1",
        )

    assert event_id == "event-transition-1"
    assert state.state == "closed"
    payload = ingest.call_args.kwargs["payload"]
    assert ingest.call_args.kwargs["event_type"] == "session.state_transition"
    assert payload["from_state"] == "open"
    assert payload["to_state"] == "closed"
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

    assert state.state == "open"


def test_terminal_session_state_rejects_follow_on_transition() -> None:
    worker = _load_agent_worker_module()
    state = worker.SessionStateMachine(session_id="session-1", state="closed")

    with pytest.raises(worker.WorkerContractError, match="closed -> open"):
        state.transition_payload(
            to_state="open",
            reason="invalid_reopen",
            room_name="room-1",
            worker_version="worker-1",
        )


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
