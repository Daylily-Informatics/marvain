from __future__ import annotations

import dataclasses
import importlib.util
import os
import sys
import types
from pathlib import Path
from unittest import mock

from fastapi.testclient import TestClient

ROOT = Path(__file__).resolve().parents[1]


def _load_app_module():
    shared = ROOT / "layers" / "shared" / "python"
    hub_api_dir = ROOT / "functions" / "hub_api"
    for path in (shared, hub_api_dir):
        if str(path) not in sys.path:
            sys.path.insert(0, str(path))

    os.environ.setdefault("AWS_DEFAULT_REGION", "us-west-2")
    os.environ.setdefault("DB_RESOURCE_ARN", "arn:aws:rds:us-west-2:123:cluster:dummy")
    os.environ.setdefault("DB_SECRET_ARN", "arn:aws:secretsmanager:us-west-2:123:secret:dummy")
    os.environ.setdefault("DB_NAME", "dummy")
    os.environ.setdefault("STAGE", "test")
    os.environ.setdefault("ENVIRONMENT", "test")
    os.environ.setdefault("SESSION_SECRET_KEY", "test-session-secret")

    for mod_name in ["api_app", "hub_api_app_round2_functional"]:
        sys.modules.pop(mod_name, None)

    spec = importlib.util.spec_from_file_location(
        "hub_api_app_round2_functional", ROOT / "functions" / "hub_api" / "app.py"
    )
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    with mock.patch("boto3.client", return_value=mock.Mock()):
        spec.loader.exec_module(mod)
    mod._cfg = dataclasses.replace(
        mod._cfg,
        cognito_domain="marvain-dev.auth.us-west-2.amazoncognito.com",
        cognito_user_pool_id="pool-123",
        cognito_user_pool_client_id="client-123",
        cognito_redirect_uri="http://testserver/auth/callback",
    )
    return mod


def _auth_user(mod):
    return mod.AuthenticatedUser(
        user_id="11111111-1111-1111-1111-111111111111",
        cognito_sub="sub-1",
        email="u1@example.com",
    )


def test_personas_page_exposes_prompt_hydration_and_default_workflow() -> None:
    mod = _load_app_module()
    client = TestClient(mod.app, raise_server_exceptions=False)
    mod._gui_get_user = mock.Mock(return_value=_auth_user(mod))
    mod.list_agents_for_user = mock.Mock(
        return_value=[types.SimpleNamespace(agent_id="agent-1", name="Forge", role="owner")]
    )
    fake_db = mock.Mock()
    fake_db.query.return_value = [
        {
            "persona_id": "persona-1",
            "agent_id": "agent-1",
            "agent_name": "Forge",
            "name": "Home Operator",
            "instructions": "Use location, memory, and action provenance.",
            "is_default": True,
            "lifecycle_state": "active",
            "session_count": 2,
        }
    ]
    mod._get_db = mock.Mock(return_value=fake_db)

    response = client.get("/personas")

    assert response.status_code == 200
    assert "Home Operator" in response.text
    assert "/v1/agents/{agent_id}/personas/default" in response.text
    assert "Use location, memory, and action provenance." in response.text


def test_live_session_smoke_turns_chat_into_v1_lifecycle_ids() -> None:
    mod = _load_app_module()
    client = TestClient(mod.app, raise_server_exceptions=False)
    mod._gui_get_user = mock.Mock(return_value=_auth_user(mod))

    response = client.post(
        "/api/live-session/smoke",
        json={
            "seed": "round2-gui-smoke",
            "transcript_text": "Remember that the kitchen sensor needs calibration.",
            "agent_id": "agent-ui",
            "space_id": "space-kitchen",
            "device_id": "device-kitchen-node",
        },
    )

    assert response.status_code == 200
    body = response.json()
    assert body["mode"] == "local_mocked_smoke"
    report = body["report"]
    assert report["completion_score"] == 1.0
    assert report["transcript_event_id"]
    assert report["memory_id"]
    assert report["recall_result"]["matched"] is True
    assert report["recognition_observation_id"]
    assert report["action_id"]
    assert report["device_result"]["status"] == "completed"


def test_live_session_chat_persists_to_real_session_events() -> None:
    mod = _load_app_module()
    client = TestClient(mod.app, raise_server_exceptions=False)
    mod._gui_get_user = mock.Mock(return_value=_auth_user(mod))
    mod._cfg = dataclasses.replace(
        mod._cfg,
        livekit_url="wss://livekit.example.test",
        livekit_secret_arn="arn:livekit",
        openai_secret_arn="arn:openai",
    )
    mod.get_secret_json = mock.Mock(
        side_effect=lambda arn: (
            {"api_key": "lk-key", "api_secret": "lk-secret"} if arn == "arn:livekit" else {"api_key": "sk-test"}
        )
    )
    mod.broadcast_event = mock.Mock()
    fake_db = mock.Mock()
    fake_db.query.return_value = [
        {
            "session_id": "22222222-2222-2222-2222-222222222222",
            "agent_id": "33333333-3333-3333-3333-333333333333",
            "space_id": "44444444-4444-4444-4444-444444444444",
            "livekit_room": "room-1",
            "status": "open",
            "agent_name": "Forge",
            "space_name": "Kitchen",
        }
    ]
    mod._get_db = mock.Mock(return_value=fake_db)

    response = client.post(
        "/api/live-session/22222222-2222-2222-2222-222222222222/chat",
        json={"text": "Remember the pantry light is flickering."},
    )

    assert response.status_code == 200
    body = response.json()
    assert body["event"]["type"] == "chat.message"
    assert body["event"]["payload"]["text"] == "Remember the pantry light is flickering."
    assert body["event"]["memory_candidate_id"]
    event_sql, insert_params = fake_db.execute.call_args_list[0].args
    candidate_sql, candidate_params = fake_db.execute.call_args_list[1].args
    assert "INSERT INTO events" in event_sql
    assert "INSERT INTO memory_candidates" in candidate_sql
    assert insert_params["session_id"] == "22222222-2222-2222-2222-222222222222"
    assert insert_params["agent_id"] == "33333333-3333-3333-3333-333333333333"
    assert insert_params["space_id"] == "44444444-4444-4444-4444-444444444444"
    assert candidate_params["event_id"] == body["event"]["event_id"]
    assert candidate_params["session_id"] == "22222222-2222-2222-2222-222222222222"
    assert candidate_params["agent_id"] == "33333333-3333-3333-3333-333333333333"
    assert candidate_params["space_id"] == "44444444-4444-4444-4444-444444444444"
    mod.broadcast_event.assert_called_once()


def test_live_session_events_reads_persisted_session_rows() -> None:
    mod = _load_app_module()
    client = TestClient(mod.app, raise_server_exceptions=False)
    mod._gui_get_user = mock.Mock(return_value=_auth_user(mod))
    fake_db = mock.Mock()
    fake_db.query.side_effect = [
        [
            {
                "session_id": "22222222-2222-2222-2222-222222222222",
                "agent_id": "33333333-3333-3333-3333-333333333333",
                "space_id": "44444444-4444-4444-4444-444444444444",
                "livekit_room": "room-1",
                "status": "open",
                "agent_name": "Forge",
                "space_name": "Kitchen",
            }
        ],
        [
            {
                "event_id": "55555555-5555-5555-5555-555555555555",
                "session_id": "22222222-2222-2222-2222-222222222222",
                "agent_id": "33333333-3333-3333-3333-333333333333",
                "space_id": "44444444-4444-4444-4444-444444444444",
                "person_id": None,
                "type": "chat.message",
                "payload": '{"text":"hello"}',
                "created_at": "2026-04-26T12:00:00+00:00",
            }
        ],
    ]
    mod._get_db = mock.Mock(return_value=fake_db)

    response = client.get("/api/live-session/22222222-2222-2222-2222-222222222222/events")

    assert response.status_code == 200
    body = response.json()
    assert body["session"]["session_id"] == "22222222-2222-2222-2222-222222222222"
    assert body["events"] == [
        {
            "event_id": "55555555-5555-5555-5555-555555555555",
            "session_id": "22222222-2222-2222-2222-222222222222",
            "agent_id": "33333333-3333-3333-3333-333333333333",
            "space_id": "44444444-4444-4444-4444-444444444444",
            "person_id": None,
            "type": "chat.message",
            "payload": {"text": "hello"},
            "created_at": "2026-04-26T12:00:00+00:00",
        }
    ]
