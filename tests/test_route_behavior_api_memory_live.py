from __future__ import annotations

import dataclasses
import json
from dataclasses import dataclass, field
from typing import Any

import pytest
from fastapi.testclient import TestClient
from route_behavior_receipt import record_http_evidence, record_postcondition_evidence
from test_route_behavior_api import (
    AGENT_ID,
    PERSON_ID,
    SPACE_ID,
    USER_ID,
    ApiHarness,
    RecordingDb,
    _load_api_module,
)

DEVICE_ID = "99999999-9999-9999-9999-999999999999"
OTHER_AGENT_ID = "aaaaaaaa-1111-1111-1111-111111111111"
SESSION_ID = "bbbbbbbb-2222-2222-2222-222222222222"
SOURCE_EVENT_ID = "cccccccc-3333-3333-3333-333333333333"
MEMORY_ID = "dddddddd-4444-4444-4444-444444444444"
HEARTBEAT_AT = "2026-07-11T04:30:00Z"


@dataclass
class MemoryLiveDb(RecordingDb):
    """Explicit test-only persisted state for canonical route readbacks."""

    memories: dict[str, dict[str, Any]] = field(default_factory=dict)
    memory_candidates: dict[str, dict[str, Any]] = field(default_factory=dict)
    events: dict[str, dict[str, Any]] = field(default_factory=dict)
    sessions: dict[str, dict[str, Any]] = field(default_factory=dict)
    recall_rows: list[dict[str, Any]] = field(default_factory=list)
    heartbeat_metadata: dict[str, Any] = field(default_factory=dict)
    heartbeat_at: str | None = None

    def query(
        self,
        sql: str,
        params: dict[str, object] | None = None,
        *,
        transaction_id: str | None = None,
    ) -> list[dict[str, object]]:
        normalized = " ".join(sql.lower().split())
        values = params or {}
        if "select agent_id::text as agent_id from spaces" in normalized:
            return [{"agent_id": AGENT_ID}]
        if "select livekit_room_mode from spaces" in normalized:
            return [{"livekit_room_mode": "ephemeral"}]
        if "select 1 from events" in normalized:
            event = self.events.get(str(values.get("event_id") or ""))
            if event and event["agent_id"] == values.get("agent_id") and event["space_id"] == values.get("space_id"):
                return [{"exists": 1}]
            return []
        if "from memories" in normalized and "<=> cast(:q as vector)" in normalized:
            return [dict(row) for row in self.recall_rows]
        if "from memories" in normalized and "order by created_at desc" in normalized:
            limit = int(values.get("limit") or 50)
            return [dict(row) for row in reversed(list(self.memories.values()))][:limit]
        if "from events" in normalized and "order by created_at desc" in normalized:
            space_id = str(values.get("space_id") or "")
            limit = int(values.get("limit") or 50)
            rows = [row for row in reversed(list(self.events.values())) if row["space_id"] == space_id]
            return [
                {
                    "event_id": row["event_id"],
                    "type": row["type"],
                    "person_id": row["person_id"] or None,
                    "payload_json": row["payload"],
                    "created_at": row["created_at"],
                }
                for row in rows[:limit]
            ]
        if "extract(epoch from (now() - last_heartbeat_at))" in normalized:
            return [{"lag_ms": 250.0}]
        if "select last_heartbeat_at::text as last_heartbeat_at from devices" in normalized:
            return [{"last_heartbeat_at": self.heartbeat_at}] if self.heartbeat_at else []
        if "from person_accounts" in normalized:
            return []
        return super().query(sql, params, transaction_id=transaction_id)

    def execute(
        self,
        sql: str,
        params: dict[str, object] | None = None,
        *,
        transaction_id: str | None = None,
    ) -> dict[str, object]:
        values = dict(params or {})
        normalized = " ".join(sql.lower().split())
        result = super().execute(sql, values, transaction_id=transaction_id)
        if "insert into sessions" in normalized:
            self.sessions[str(values["session_id"])] = {
                **values,
                "status": "opening",
                "metadata": json.loads(str(values["metadata"])),
            }
        elif "insert into events" in normalized:
            self.events[str(values["event_id"])] = {
                **values,
                "created_at": "2026-07-11T04:20:00Z",
            }
        elif "insert into memory_candidates" in normalized:
            self.memory_candidates[str(values["memory_candidate_id"])] = values
        elif "insert into memories" in normalized:
            self.memories[str(values["memory_id"])] = {
                "memory_id": str(values["memory_id"]),
                "tier": values["tier"],
                "content": values["content"],
                "created_at": "2026-07-11T04:25:00Z",
                "participants": values["participants"],
                "provenance": values["provenance"],
                "subject_person_id": values["subject_person_id"],
                "tags": values["tags"],
                "scene_context": values["scene_context"],
                "modality": values["modality"],
                "confidence": values["confidence"],
                "related_memory_ids": [],
                "source_event_id": values["source_event_id"],
                "memory_candidate_id": values["memory_candidate_id"],
            }
        elif "update devices set last_heartbeat_at = now()" in normalized:
            self.heartbeat_at = HEARTBEAT_AT
            raw_metadata = values.get("metadata")
            if isinstance(raw_metadata, str):
                self.heartbeat_metadata.update(json.loads(raw_metadata))
        return result


@pytest.fixture
def api_harness(monkeypatch: pytest.MonkeyPatch) -> ApiHarness:
    mod = _load_api_module()
    db = MemoryLiveDb()
    mod.api_app.dependency_overrides.clear()
    monkeypatch.setattr(mod, "_get_db", lambda: db)
    monkeypatch.setattr(
        mod,
        "_cfg",
        dataclasses.replace(
            mod._cfg,
            audit_bucket=None,
            transcript_queue_url=None,
            livekit_url=None,
            livekit_secret_arn=None,
            openai_secret_arn=None,
        ),
    )
    monkeypatch.setattr(mod, "_recognition_queue_url", None)
    harness = ApiHarness(mod=mod, client=TestClient(mod.api_app, raise_server_exceptions=False), db=db)
    yield harness
    mod.api_app.dependency_overrides.clear()


def _authenticate_user(harness: ApiHarness) -> None:
    user = harness.mod.AuthenticatedUser(user_id=USER_ID, cognito_sub="memory-live-sub", email="user@example.test")
    harness.mod.api_app.dependency_overrides[harness.mod.get_user] = lambda: user


def _authenticate_device(
    harness: ApiHarness,
    *,
    scopes: list[str],
    agent_id: str = AGENT_ID,
    kind: str = "worker",
) -> None:
    device = harness.mod.AuthenticatedDevice(
        device_id=DEVICE_ID,
        agent_id=agent_id,
        scopes=scopes,
        capabilities={"kind": kind},
    )
    harness.mod.api_app.dependency_overrides[harness.mod.get_device] = lambda: device


def _classification() -> dict[str, object]:
    return {
        "kind": "episodic",
        "provenance_class": "external_interaction",
        "confidence": 0.91,
        "rationale": "The persisted transcript describes a bounded interaction.",
        "evidence_quote": "blue mug",
        "source_evidence_id": SOURCE_EVENT_ID,
        "model_provider_id": "test-model-provider",
    }


def _seed_source_event(db: MemoryLiveDb) -> None:
    db.events[SOURCE_EVENT_ID] = {
        "event_id": SOURCE_EVENT_ID,
        "agent_id": AGENT_ID,
        "space_id": SPACE_ID,
        "device_id": DEVICE_ID,
        "person_id": PERSON_ID,
        "type": "transcript_chunk",
        "payload": json.dumps({"text": "Remember the blue mug on the kitchen shelf."}),
        "session_id": SESSION_ID,
        "created_at": "2026-07-11T04:15:00Z",
    }


def test_v1_memory_create_success_and_persisted_readback(
    request: pytest.FixtureRequest,
    api_harness: ApiHarness,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    db = api_harness.db
    assert isinstance(db, MemoryLiveDb)
    _seed_source_event(db)
    _authenticate_device(api_harness, scopes=["memories:write", "memories:read"])
    monkeypatch.setattr(api_harness.mod, "_cfg", dataclasses.replace(api_harness.mod._cfg, openai_secret_arn="secret"))
    monkeypatch.setattr(api_harness.mod, "call_embeddings", lambda **_kwargs: [0.125, 0.25, 0.5])

    response = api_harness.client.post(
        "/v1/memories",
        json={
            "space_id": SPACE_ID,
            "source_event_id": SOURCE_EVENT_ID,
            "session_id": SESSION_ID,
            "tier": "episodic",
            "content": "I remember the blue mug on the kitchen shelf.",
            "metadata": {"memory_classification": _classification()},
            "participants": [f"person:{PERSON_ID}"],
            "subject_person_id": PERSON_ID,
            "scene_context": "kitchen",
        },
    )

    assert response.status_code == 200
    body = response.json()
    assert body["created"] is True
    assert body["source_event_id"] == SOURCE_EVENT_ID
    assert body["memory_id"] in db.memories
    assert body["memory_candidate_id"] in db.memory_candidates
    assert db.memories[body["memory_id"]]["source_event_id"] == SOURCE_EVENT_ID
    assert db.memories[body["memory_id"]]["memory_candidate_id"] == body["memory_candidate_id"]
    assert db.memory_candidates[body["memory_candidate_id"]]["source_event_id"] == SOURCE_EVENT_ID
    assert db.commits == ["route-behavior-tx-1"]
    record_http_evidence(request, surface="api", method="POST", path="/v1/memories", kind="success", response=response)

    readback = api_harness.client.get("/v1/memories")
    assert readback.status_code == 200
    recalled = {row["memory_id"]: row for row in readback.json()["memories"]}
    assert recalled[body["memory_id"]]["content"] == "I remember the blue mug on the kitchen shelf."
    record_http_evidence(request, surface="api", method="GET", path="/v1/memories", kind="success", response=readback)
    record_postcondition_evidence(
        request,
        surface="api",
        method="POST",
        path="/v1/memories",
        owner="PostgreSQL memory and memory_candidates projections",
        query="GET /v1/memories plus candidate state readback",
        record_ids={"memory_id": body["memory_id"], "memory_candidate_id": body["memory_candidate_id"]},
        assertions=[
            "committed memory is returned by canonical list route",
            "candidate and memory retain the persisted source event",
            "transaction committed exactly once",
        ],
    )


def test_v1_memory_create_denies_non_worker_device(request: pytest.FixtureRequest, api_harness: ApiHarness) -> None:
    _authenticate_device(api_harness, scopes=["memories:write"], kind="admin")
    response = api_harness.client.post(
        "/v1/memories",
        json={
            "space_id": SPACE_ID,
            "source_event_id": SOURCE_EVENT_ID,
            "tier": "episodic",
            "content": "blue mug",
            "metadata": {"memory_classification": _classification()},
        },
    )

    assert response.status_code == 403
    assert "agent worker" in response.json()["detail"]
    assert not api_harness.db.execute_calls
    record_http_evidence(request, surface="api", method="POST", path="/v1/memories", kind="denial", response=response)


def test_v1_memory_create_rejects_unclassified_content(request: pytest.FixtureRequest, api_harness: ApiHarness) -> None:
    _authenticate_device(api_harness, scopes=["memories:write"])
    response = api_harness.client.post(
        "/v1/memories",
        json={
            "space_id": SPACE_ID,
            "source_event_id": SOURCE_EVENT_ID,
            "tier": "episodic",
            "content": "unclassified content",
        },
    )

    assert response.status_code == 400
    assert "memory_classification metadata is required" in response.json()["detail"]
    assert not api_harness.db.commits
    record_http_evidence(
        request, surface="api", method="POST", path="/v1/memories", kind="validation", response=response
    )


def test_v1_recall_success_returns_ranked_persisted_provenance(
    request: pytest.FixtureRequest,
    api_harness: ApiHarness,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from agent_hub.policy import PolicyCheckEvidence, PolicyDecision

    db = api_harness.db
    assert isinstance(db, MemoryLiveDb)
    _authenticate_device(api_harness, scopes=["memories:read"])
    monkeypatch.setattr(api_harness.mod, "_cfg", dataclasses.replace(api_harness.mod._cfg, openai_secret_arn="secret"))
    monkeypatch.setattr(api_harness.mod, "call_embeddings", lambda **_kwargs: [0.25, 0.5])
    monkeypatch.setattr(
        api_harness.mod,
        "evaluate_policy",
        lambda *_args, **_kwargs: PolicyDecision(
            operation="memory.recall",
            allowed=True,
            reason="allowed",
            evidence=(
                PolicyCheckEvidence("space_privacy", True, {"privacy_mode": False}),
                PolicyCheckEvidence("active_consent", True, {"consent_type": "memory"}),
            ),
        ),
    )
    db.recall_rows = [
        {
            "memory_id": MEMORY_ID,
            "tier": "episodic",
            "content": "The blue mug is on the kitchen shelf.",
            "created_at": "2026-07-11T04:25:00Z",
            "provenance_json": json.dumps({"device_id": DEVICE_ID, "provenance_class": "external_interaction"}),
            "source_event_id": SOURCE_EVENT_ID,
            "session_id": SESSION_ID,
            "space_id": SPACE_ID,
            "subject_person_id": PERSON_ID,
            "provenance_class": "external_interaction",
            "interacting_agent_id": None,
            "tapdb_euid": None,
            "recall_explanation_json": json.dumps({"commit_policy": "device_memory_create_v1"}),
            "source_event_type": "transcript_chunk",
            "source_event_payload_json": json.dumps({"text": "Remember the blue mug."}),
            "source_event_device_id": DEVICE_ID,
            "source_event_space_id": SPACE_ID,
            "source_event_session_id": SESSION_ID,
            "source_event_person_id": PERSON_ID,
            "distance": 0.125,
        }
    ]

    response = api_harness.client.post(
        "/v1/recall",
        json={
            "agent_id": AGENT_ID,
            "space_id": SPACE_ID,
            "person_id": PERSON_ID,
            "query": "blue mug kitchen",
            "tiers": ["episodic"],
            "k": 3,
        },
    )

    assert response.status_code == 200
    memory = response.json()["memories"][0]
    explanation = memory["explanation"]
    assert memory["memory_id"] == MEMORY_ID
    assert explanation["ranking"] == {
        "rank": 1,
        "distance": 0.125,
        "embedding_distance": 0.125,
        "method": "pgvector_cosine",
        "keyword_match": ["blue", "kitchen", "mug"],
    }
    assert explanation["source_event_id"] == SOURCE_EVENT_ID
    assert explanation["device_id"] == DEVICE_ID
    assert explanation["space_id"] == SPACE_ID
    assert explanation["session_id"] == SESSION_ID
    assert explanation["person_id"] == PERSON_ID
    assert explanation["consent_filters"]["applied"] is True
    assert explanation["privacy_filters"]["applied"] is True
    record_http_evidence(request, surface="api", method="POST", path="/v1/recall", kind="success", response=response)
    record_postcondition_evidence(
        request,
        surface="api",
        method="POST",
        path="/v1/recall",
        owner="PostgreSQL committed memory and source event projections",
        query="pgvector recall joined to persisted source event",
        record_ids={"memory_id": MEMORY_ID, "source_event_id": SOURCE_EVENT_ID},
        assertions=[
            "ranking exposes embedding distance and keyword match",
            "source device, space, session, and person are preserved",
            "consent and privacy checks are evidenced",
        ],
    )


def test_v1_recall_denies_cross_agent_device(request: pytest.FixtureRequest, api_harness: ApiHarness) -> None:
    _authenticate_device(api_harness, scopes=["memories:read"], agent_id=OTHER_AGENT_ID, kind="satellite")
    response = api_harness.client.post(
        "/v1/recall",
        json={"agent_id": AGENT_ID, "space_id": SPACE_ID, "query": "blue mug"},
    )

    assert response.status_code == 403
    assert "different agent" in response.json()["detail"]
    record_http_evidence(request, surface="api", method="POST", path="/v1/recall", kind="denial", response=response)


def test_v1_recall_rejects_empty_query(request: pytest.FixtureRequest, api_harness: ApiHarness) -> None:
    _authenticate_device(api_harness, scopes=["memories:read"])
    response = api_harness.client.post("/v1/recall", json={"agent_id": AGENT_ID, "query": ""})

    assert response.status_code == 422
    record_http_evidence(request, surface="api", method="POST", path="/v1/recall", kind="validation", response=response)


def test_v1_livekit_user_token_success_persists_session(
    request: pytest.FixtureRequest,
    api_harness: ApiHarness,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    db = api_harness.db
    assert isinstance(db, MemoryLiveDb)
    _authenticate_user(api_harness)
    monkeypatch.setattr(api_harness.mod, "check_agent_permission", lambda *_args, **_kwargs: True)
    monkeypatch.setattr(
        api_harness.mod,
        "_cfg",
        dataclasses.replace(
            api_harness.mod._cfg,
            livekit_url="wss://livekit.example.test",
            livekit_secret_arn="livekit-secret",
        ),
    )
    monkeypatch.setattr(api_harness.mod, "get_secret_json", lambda _arn: {"api_key": "key", "api_secret": "secret"})
    monkeypatch.setattr(api_harness.mod, "mint_livekit_join_token", lambda **_kwargs: "signed-livekit-token")

    response = api_harness.client.post("/v1/livekit/token", json={"space_id": SPACE_ID})

    assert response.status_code == 200
    body = response.json()
    assert body["identity"] == f"user:{USER_ID}"
    assert body["room"].startswith(f"{SPACE_ID}:")
    assert body["session_id"] in db.sessions
    persisted_session = db.sessions[body["session_id"]]
    assert persisted_session["livekit_room"] == body["room"]
    assert persisted_session["status"] == "opening"
    assert persisted_session["metadata"] == {
        "room_mode": "ephemeral",
        "actor_type": "user",
        "actor_id": USER_ID,
    }
    record_http_evidence(
        request, surface="api", method="POST", path="/v1/livekit/token", kind="success", response=response
    )
    record_postcondition_evidence(
        request,
        surface="api",
        method="POST",
        path="/v1/livekit/token",
        owner="PostgreSQL sessions projection",
        query="session_id returned by token response",
        record_ids={"session_id": body["session_id"]},
        assertions=[
            "session is opening",
            "session room matches minted token room",
            "session records authenticated user actor",
        ],
    )


def test_v1_livekit_user_token_denies_non_member(
    request: pytest.FixtureRequest,
    api_harness: ApiHarness,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _authenticate_user(api_harness)
    monkeypatch.setattr(api_harness.mod, "check_agent_permission", lambda *_args, **_kwargs: False)
    response = api_harness.client.post("/v1/livekit/token", json={"space_id": SPACE_ID})

    assert response.status_code == 403
    assert not api_harness.db.execute_calls
    record_http_evidence(
        request, surface="api", method="POST", path="/v1/livekit/token", kind="denial", response=response
    )


def test_v1_livekit_user_token_rejects_missing_space(request: pytest.FixtureRequest, api_harness: ApiHarness) -> None:
    _authenticate_user(api_harness)
    response = api_harness.client.post("/v1/livekit/token", json={})

    assert response.status_code == 422
    record_http_evidence(
        request, surface="api", method="POST", path="/v1/livekit/token", kind="validation", response=response
    )


def test_v1_livekit_device_token_success_persists_stable_session(
    request: pytest.FixtureRequest,
    api_harness: ApiHarness,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    db = api_harness.db
    assert isinstance(db, MemoryLiveDb)
    _authenticate_device(api_harness, scopes=["events:write"])
    monkeypatch.setattr(api_harness.mod, "is_agent_disabled", lambda *_args, **_kwargs: False)
    monkeypatch.setattr(
        api_harness.mod,
        "_cfg",
        dataclasses.replace(
            api_harness.mod._cfg,
            livekit_url="wss://livekit.example.test",
            livekit_secret_arn="livekit-secret",
        ),
    )
    monkeypatch.setattr(api_harness.mod, "get_secret_json", lambda _arn: {"api_key": "key", "api_secret": "secret"})
    monkeypatch.setattr(api_harness.mod, "mint_livekit_join_token", lambda **_kwargs: "device-livekit-token")

    response = api_harness.client.post(
        "/v1/livekit/device-token",
        json={
            "space_id": SPACE_ID,
            "room_mode": "stable",
            "capabilities": {"publish_audio": True, "publish_video": True, "subscribe_audio": True},
        },
    )

    assert response.status_code == 200
    body = response.json()
    assert body["room"] == SPACE_ID
    assert body["identity"] == f"device:{DEVICE_ID}"
    assert body["session_id"] in db.sessions
    persisted_session = db.sessions[body["session_id"]]
    assert persisted_session["status"] == "opening"
    assert persisted_session["metadata"] == {
        "room_mode": "stable",
        "actor_type": "device",
        "actor_id": DEVICE_ID,
    }
    record_http_evidence(
        request, surface="api", method="POST", path="/v1/livekit/device-token", kind="success", response=response
    )
    record_postcondition_evidence(
        request,
        surface="api",
        method="POST",
        path="/v1/livekit/device-token",
        owner="PostgreSQL sessions projection",
        query="stable device session by returned session_id",
        record_ids={"session_id": body["session_id"], "device_id": DEVICE_ID},
        assertions=["stable session uses the persistent space room", "session records authenticated device actor"],
    )


def test_v1_livekit_device_token_denies_missing_scope(request: pytest.FixtureRequest, api_harness: ApiHarness) -> None:
    _authenticate_device(api_harness, scopes=[])
    response = api_harness.client.post("/v1/livekit/device-token", json={"space_id": SPACE_ID, "room_mode": "stable"})

    assert response.status_code == 403
    record_http_evidence(
        request, surface="api", method="POST", path="/v1/livekit/device-token", kind="denial", response=response
    )


def test_v1_livekit_device_token_rejects_ephemeral_mode(
    request: pytest.FixtureRequest, api_harness: ApiHarness
) -> None:
    _authenticate_device(api_harness, scopes=["events:write"])
    response = api_harness.client.post(
        "/v1/livekit/device-token", json={"space_id": SPACE_ID, "room_mode": "ephemeral"}
    )

    assert response.status_code == 400
    assert "stable" in response.json()["detail"]
    record_http_evidence(
        request,
        surface="api",
        method="POST",
        path="/v1/livekit/device-token",
        kind="validation",
        response=response,
    )


def test_v1_event_ingest_success_and_space_readback(
    request: pytest.FixtureRequest,
    api_harness: ApiHarness,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    db = api_harness.db
    assert isinstance(db, MemoryLiveDb)
    _authenticate_device(api_harness, scopes=["events:write", "events:read"])
    monkeypatch.setattr(api_harness.mod, "is_agent_disabled", lambda *_args, **_kwargs: False)
    monkeypatch.setattr(api_harness.mod, "is_privacy_mode", lambda *_args, **_kwargs: False)
    monkeypatch.setattr(api_harness.mod, "broadcast_event", lambda **_kwargs: None)

    response = api_harness.client.post(
        "/v1/events",
        json={
            "space_id": SPACE_ID,
            "session_id": SESSION_ID,
            "person_id": PERSON_ID,
            "type": "transcript_chunk",
            "payload": {"text": "Remember the blue mug.", "role": "user"},
        },
    )

    assert response.status_code == 200
    event_id = response.json()["event_id"]
    assert event_id in db.events
    assert db.events[event_id]["session_id"] == SESSION_ID
    assert db.events[event_id]["space_id"] == SPACE_ID
    assert db.events[event_id]["device_id"] == DEVICE_ID
    assert db.events[event_id]["person_id"] == PERSON_ID
    assert db.commits == ["route-behavior-tx-1"]
    record_http_evidence(request, surface="api", method="POST", path="/v1/events", kind="success", response=response)

    readback = api_harness.client.get(f"/v1/spaces/{SPACE_ID}/events")
    assert readback.status_code == 200
    assert readback.json()["events"] == [
        {
            "event_id": event_id,
            "type": "transcript_chunk",
            "person_id": PERSON_ID,
            "payload": {"text": "Remember the blue mug.", "role": "user"},
            "created_at": "2026-07-11T04:20:00Z",
        }
    ]
    record_http_evidence(
        request,
        surface="api",
        method="GET",
        path="/v1/spaces/{space_id}/events",
        kind="success",
        response=readback,
    )
    record_postcondition_evidence(
        request,
        surface="api",
        method="POST",
        path="/v1/events",
        owner="PostgreSQL events projection",
        query="GET /v1/spaces/{space_id}/events",
        record_ids={"event_id": event_id, "session_id": SESSION_ID},
        assertions=["event is durable and readable", "space, session, device, and person attribution are preserved"],
    )


def test_v1_event_ingest_denies_missing_scope(request: pytest.FixtureRequest, api_harness: ApiHarness) -> None:
    _authenticate_device(api_harness, scopes=["events:read"])
    response = api_harness.client.post(
        "/v1/events", json={"space_id": SPACE_ID, "type": "sensor.reading", "payload": {"value": 1}}
    )

    assert response.status_code == 403
    assert not api_harness.db.commits
    record_http_evidence(request, surface="api", method="POST", path="/v1/events", kind="denial", response=response)


def test_v1_event_ingest_rejects_missing_type(request: pytest.FixtureRequest, api_harness: ApiHarness) -> None:
    _authenticate_device(api_harness, scopes=["events:write"])
    response = api_harness.client.post("/v1/events", json={"space_id": SPACE_ID, "payload": {}})

    assert response.status_code == 422
    record_http_evidence(request, surface="api", method="POST", path="/v1/events", kind="validation", response=response)


def test_v1_space_events_denies_cross_agent_device(request: pytest.FixtureRequest, api_harness: ApiHarness) -> None:
    _authenticate_device(api_harness, scopes=["events:read"], agent_id=OTHER_AGENT_ID, kind="satellite")
    response = api_harness.client.get(f"/v1/spaces/{SPACE_ID}/events")

    assert response.status_code == 403
    record_http_evidence(
        request,
        surface="api",
        method="GET",
        path="/v1/spaces/{space_id}/events",
        kind="denial",
        response=response,
    )


def test_v1_space_events_clamps_invalid_limit_to_supported_range(
    request: pytest.FixtureRequest,
    api_harness: ApiHarness,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _authenticate_device(api_harness, scopes=["events:read"])
    monkeypatch.setattr(api_harness.mod, "is_privacy_mode", lambda *_args, **_kwargs: False)
    response = api_harness.client.get(f"/v1/spaces/{SPACE_ID}/events?limit=0")

    assert response.status_code == 200
    assert response.json() == {"events": []}
    record_http_evidence(
        request,
        surface="api",
        method="GET",
        path="/v1/spaces/{space_id}/events",
        kind="success",
        response=response,
    )


def test_v1_device_heartbeat_success_persists_metadata(
    request: pytest.FixtureRequest,
    api_harness: ApiHarness,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    db = api_harness.db
    assert isinstance(db, MemoryLiveDb)
    _authenticate_device(api_harness, scopes=["presence:write"])
    monkeypatch.setattr(api_harness.mod, "broadcast_event", lambda **_kwargs: None)
    monkeypatch.setattr(api_harness.mod, "emit_count", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(api_harness.mod, "emit_ms", lambda *_args, **_kwargs: None)

    response = api_harness.client.post(
        "/v1/devices/heartbeat",
        json={"metadata": {"worker_version": "test-version", "media_state": "ready"}},
    )

    assert response.status_code == 200
    assert response.json() == {"ok": True, "device_id": DEVICE_ID, "last_heartbeat_at": HEARTBEAT_AT}
    assert db.heartbeat_metadata == {"worker_version": "test-version", "media_state": "ready"}
    record_http_evidence(
        request, surface="api", method="POST", path="/v1/devices/heartbeat", kind="success", response=response
    )
    record_postcondition_evidence(
        request,
        surface="api",
        method="POST",
        path="/v1/devices/heartbeat",
        owner="PostgreSQL devices projection",
        query="device heartbeat timestamp and metadata readback",
        record_ids={"device_id": DEVICE_ID},
        assertions=["heartbeat timestamp is persisted", "reported worker metadata is merged into device state"],
    )


def test_v1_device_heartbeat_denies_missing_scope(request: pytest.FixtureRequest, api_harness: ApiHarness) -> None:
    _authenticate_device(api_harness, scopes=[])
    response = api_harness.client.post("/v1/devices/heartbeat", json={})

    assert response.status_code == 403
    assert not api_harness.db.execute_calls
    record_http_evidence(
        request, surface="api", method="POST", path="/v1/devices/heartbeat", kind="denial", response=response
    )


def test_v1_device_heartbeat_rejects_non_object_metadata(
    request: pytest.FixtureRequest, api_harness: ApiHarness
) -> None:
    _authenticate_device(api_harness, scopes=["presence:write"])
    response = api_harness.client.post("/v1/devices/heartbeat", json={"metadata": "not-an-object"})

    assert response.status_code == 422
    record_http_evidence(
        request,
        surface="api",
        method="POST",
        path="/v1/devices/heartbeat",
        kind="validation",
        response=response,
    )
