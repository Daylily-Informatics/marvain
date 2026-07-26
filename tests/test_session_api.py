from __future__ import annotations

import importlib.util
import os
import sys
from pathlib import Path
from unittest import mock

import pytest
from agent_hub.auth import AuthenticatedDevice

ROOT = Path(__file__).resolve().parents[1]
SESSION_ID = "11111111-1111-1111-1111-111111111111"
AGENT_ID = "22222222-2222-2222-2222-222222222222"
SPACE_ID = "33333333-3333-3333-3333-333333333333"
DEVICE_ID = "44444444-4444-4444-4444-444444444444"
ROOM_NAME = f"{SPACE_ID}:session"


def _load_api_module():
    for path in (ROOT / "layers/shared/python", ROOT / "functions/hub_api"):
        if str(path) not in sys.path:
            sys.path.insert(0, str(path))
    os.environ.setdefault("AWS_DEFAULT_REGION", "us-east-1")
    os.environ.setdefault("DB_RESOURCE_ARN", "arn:aws:rds:us-east-1:123:cluster:test")
    os.environ.setdefault("DB_SECRET_ARN", "arn:aws:secretsmanager:us-east-1:123:secret:test")
    os.environ.setdefault("DB_NAME", "test")
    os.environ.setdefault("STAGE", "test")
    os.environ.setdefault("SESSION_SECRET_KEY", "session-api-test-secret")
    spec = importlib.util.spec_from_file_location("hub_api_session_tests", ROOT / "functions/hub_api/api_app.py")
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    with mock.patch("boto3.client", return_value=mock.Mock()):
        spec.loader.exec_module(module)
    return module


class SessionDb:
    def __init__(self, *, status: str = "opening", status_event_id: str | None = None, found: bool = True) -> None:
        self.status = status
        self.status_event_id = status_event_id
        self.found = found
        self.transaction_id = "session-tx"
        self.execute_calls: list[tuple[str, dict, str | None]] = []
        self.commits: list[str] = []
        self.rollbacks: list[str] = []

    def begin(self) -> str:
        return self.transaction_id

    def query(self, sql: str, _params: dict | None = None, *, transaction_id: str | None = None):
        if "FROM sessions" in sql:
            if not self.found:
                return []
            return [
                {
                    "session_id": SESSION_ID,
                    "agent_id": AGENT_ID,
                    "space_id": SPACE_ID,
                    "livekit_room": ROOM_NAME,
                    "status": self.status,
                    "status_event_id": self.status_event_id,
                }
            ]
        return []

    def execute(self, sql: str, params: dict | None = None, *, transaction_id: str | None = None):
        self.execute_calls.append((sql, params or {}, transaction_id))
        return {}

    def commit(self, transaction_id: str) -> None:
        self.commits.append(transaction_id)

    def rollback(self, transaction_id: str) -> None:
        self.rollbacks.append(transaction_id)


def _transition_body(module, *, from_state: str = "opening", to_state: str = "active"):
    return module.IngestEventIn(
        space_id=SPACE_ID,
        type="session.state_transition",
        session_id=SESSION_ID,
        payload={
            "contract_version": 1,
            "session_id": SESSION_ID,
            "from_state": from_state,
            "to_state": to_state,
            "reason": "LiveKit owning evidence accepted",
            "room_name": ROOM_NAME,
            "worker_version": "worker-1",
            "occurred_at": "2026-07-11T03:00:00Z",
        },
    )


def _worker(
    *,
    agent_id: str = AGENT_ID,
    scopes: list[str] | None = None,
    capabilities: dict[str, str] | None = None,
) -> AuthenticatedDevice:
    return AuthenticatedDevice(
        device_id=DEVICE_ID,
        agent_id=agent_id,
        scopes=scopes or ["events:read", "events:write"],
        capabilities=capabilities or {"kind": "worker"},
    )


def test_session_creation_uses_opening_state() -> None:
    module = _load_api_module()
    db = SessionDb()
    module._db = db

    module._create_session_record(
        agent_id=AGENT_ID,
        space_id=SPACE_ID,
        session_id=SESSION_ID,
        livekit_room=ROOM_NAME,
        room_mode="ephemeral",
        actor_type="user",
        actor_id="user-1",
    )

    sql = db.execute_calls[0][0]
    assert "'opening'" in sql
    assert "'open'" not in sql


def test_worker_lifecycle_read_returns_only_authoritative_session_identity(monkeypatch) -> None:
    module = _load_api_module()
    db = SessionDb(status="active", status_event_id="event-active-1")
    module._db = db
    monkeypatch.setattr(module, "is_agent_disabled", lambda *_args: False)

    result = module.get_worker_session_lifecycle(SESSION_ID, _worker())

    assert result == {
        "session_id": SESSION_ID,
        "agent_id": AGENT_ID,
        "space_id": SPACE_ID,
        "livekit_room": ROOM_NAME,
        "status": "active",
        "status_event_id": "event-active-1",
    }
    assert len(db.execute_calls) == 0


def test_worker_lifecycle_read_requires_events_read_scope(monkeypatch) -> None:
    module = _load_api_module()
    module._db = SessionDb()
    monkeypatch.setattr(module, "is_agent_disabled", lambda *_args: False)

    with pytest.raises(module.HTTPException) as exc_info:
        module.get_worker_session_lifecycle(SESSION_ID, _worker(scopes=["events:write"]))

    assert exc_info.value.status_code == 403


def test_worker_lifecycle_read_rejects_unrelated_nonworker_device(monkeypatch) -> None:
    module = _load_api_module()
    module._db = SessionDb()
    monkeypatch.setattr(module, "is_agent_disabled", lambda *_args: False)

    with pytest.raises(module.HTTPException) as exc_info:
        module.get_worker_session_lifecycle(
            SESSION_ID,
            _worker(
                agent_id="55555555-5555-5555-5555-555555555555",
                capabilities={"kind": "satellite"},
            ),
        )

    assert exc_info.value.status_code == 403


def test_worker_lifecycle_read_returns_not_found_for_missing_session(monkeypatch) -> None:
    module = _load_api_module()
    module._db = SessionDb(found=False)
    monkeypatch.setattr(module, "is_agent_disabled", lambda *_args: False)

    with pytest.raises(module.HTTPException) as exc_info:
        module.get_worker_session_lifecycle(SESSION_ID, _worker())

    assert exc_info.value.status_code == 404


def test_session_transition_is_projected_in_the_same_event_transaction(monkeypatch) -> None:
    module = _load_api_module()
    db = SessionDb()
    module._db = db
    monkeypatch.setattr(module, "_resolve_space_agent_for_device", lambda **_kwargs: AGENT_ID)
    monkeypatch.setattr(module, "is_agent_disabled", lambda *_args: False)
    monkeypatch.setattr(module, "is_privacy_mode", lambda *_args: True)
    monkeypatch.setattr(module, "enqueue_semantic_record", lambda *_args, **_kwargs: None)

    result = module.ingest_event(_transition_body(module), _worker())

    assert result.event_id != "privacy_mode"
    assert db.commits == [db.transaction_id]
    assert db.rollbacks == []
    assert all(transaction_id == db.transaction_id for _sql, _params, transaction_id in db.execute_calls)
    update = next((sql, params) for sql, params, _tx in db.execute_calls if "UPDATE sessions" in sql)
    assert update[1]["status"] == "active"
    assert update[1]["status_event_id"] == result.event_id
    assert any("INSERT INTO events" in sql for sql, _params, _tx in db.execute_calls)


def test_session_transition_conflict_rolls_back_without_event(monkeypatch) -> None:
    module = _load_api_module()
    db = SessionDb(status="active")
    module._db = db
    monkeypatch.setattr(module, "_resolve_space_agent_for_device", lambda **_kwargs: AGENT_ID)
    monkeypatch.setattr(module, "is_agent_disabled", lambda *_args: False)
    monkeypatch.setattr(module, "is_privacy_mode", lambda *_args: False)

    with pytest.raises(module.HTTPException) as exc_info:
        module.ingest_event(_transition_body(module), _worker())

    assert exc_info.value.status_code == 409
    assert db.commits == []
    assert db.rollbacks == [db.transaction_id]
    assert not any("INSERT INTO events" in sql for sql, _params, _tx in db.execute_calls)
