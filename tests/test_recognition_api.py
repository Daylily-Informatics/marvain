from __future__ import annotations

import dataclasses
import importlib.util
import json
import os
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock

import pytest
from agent_hub.auth import AuthenticatedDevice, AuthenticatedUser
from agent_hub.recognition_service import (
    ActorType,
    ArtifactEvidence,
    AuthenticatedReviewer,
    ConsentProof,
    HypothesisKind,
    ObservationState,
    RecognitionHypothesis,
    RecognitionLifecycleService,
    RecognitionModality,
    RecognitionObservation,
    ReviewDecision,
)

_ROOT = Path(__file__).resolve().parents[1]
_HUB_API_DIR = _ROOT / "functions" / "hub_api"
if str(_HUB_API_DIR) not in sys.path:
    sys.path.insert(0, str(_HUB_API_DIR))

AGENT_ID = "11111111-1111-1111-1111-111111111111"
SPACE_ID = "22222222-2222-2222-2222-222222222222"
SOURCE_DEVICE_ID = "33333333-3333-3333-3333-333333333333"
WORKER_DEVICE_ID = "44444444-4444-4444-4444-444444444444"
EVENT_ID = "55555555-5555-5555-5555-555555555555"
ARTIFACT_ID = "66666666-6666-6666-6666-666666666666"
OBSERVATION_ID = "77777777-7777-7777-7777-777777777777"
HYPOTHESIS_ID = "88888888-8888-8888-8888-888888888888"
PERSON_ID = "99999999-9999-9999-9999-999999999999"
CONSENT_ID = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
LOCATION_ID = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"
SESSION_ID = "cccccccc-cccc-cccc-cccc-cccccccccccc"
OUTBOX_ID = "dddddddd-dddd-dddd-dddd-dddddddddddd"
SYNC_ID = "eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee"
NOW = datetime(2026, 7, 11, 2, 0, tzinfo=timezone.utc)


def _load_api_module():
    root = Path(__file__).resolve().parents[1]
    for path in (root / "layers" / "shared" / "python", root / "functions" / "hub_api"):
        if str(path) not in sys.path:
            sys.path.insert(0, str(path))
    os.environ.setdefault("AWS_DEFAULT_REGION", "us-east-1")
    os.environ.setdefault("DB_RESOURCE_ARN", "arn:aws:rds:us-east-1:123:cluster:test")
    os.environ.setdefault("DB_SECRET_ARN", "arn:aws:secretsmanager:us-east-1:123:secret:test")
    os.environ.setdefault("DB_NAME", "test")
    os.environ.setdefault("ENVIRONMENT", "test")
    os.environ.setdefault("HTTPS_ENABLED", "false")
    os.environ.setdefault("SESSION_SECRET_KEY", "recognition-api-test-secret")
    path = root / "functions" / "hub_api" / "api_app.py"
    spec = importlib.util.spec_from_file_location("hub_api_recognition_tests", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    with mock.patch("boto3.client", return_value=mock.Mock()):
        spec.loader.exec_module(module)
    return module


class RecordingDb:
    def __init__(self) -> None:
        self.transaction_id = "recognition-tx"
        self.commits: list[str] = []
        self.rollbacks: list[str] = []
        self.query_calls: list[tuple[str, dict, str | None]] = []
        self.execute_calls: list[tuple[str, dict, str | None]] = []
        self.source_row: dict[str, object] | None = None
        self.observation_rows: list[dict[str, object]] = []
        self.observation_by_id: dict[str, object] | None = None
        self.hypothesis_rows: list[dict[str, object]] = []
        self.person_rows: list[dict[str, object]] = []
        self.consent_rows: list[dict[str, object]] = []
        self.worker_rows: list[dict[str, object]] = []
        self.heartbeat_rows: list[dict[str, object]] = []

    def begin(self) -> str:
        return self.transaction_id

    def commit(self, transaction_id: str) -> None:
        self.commits.append(transaction_id)

    def rollback(self, transaction_id: str) -> None:
        self.rollbacks.append(transaction_id)

    def execute(self, sql: str, params: dict | None = None, *, transaction_id: str | None = None):
        self.execute_calls.append((sql, params or {}, transaction_id))
        return {}

    def query(self, sql: str, params: dict | None = None, *, transaction_id: str | None = None):
        params = params or {}
        self.query_calls.append((sql, params, transaction_id))
        squashed = " ".join(sql.split()).lower()
        if "from events e" in squashed:
            return [dict(self.source_row)] if self.source_row else []
        if "from recognition_observations" in squashed and "source_event_id =" in squashed:
            return list(self.observation_rows)
        if "from recognition_observations" in squashed and "recognition_observation_id =" in squashed:
            if "artifact_id::text as artifact_id" in squashed:
                return [dict(self.observation_by_id)] if self.observation_by_id else []
            return [{"observation_id": OBSERVATION_ID}] if self.observation_by_id else []
        if "from recognition_hypotheses rh" in squashed:
            return list(self.hypothesis_rows)
        if "from recognition_hypotheses" in squashed:
            return list(self.hypothesis_rows)
        if "from people" in squashed:
            return list(self.person_rows)
        if "from consent_grants" in squashed:
            return list(self.consent_rows)
        if "insert into semantic_sync_status" in squashed:
            return [
                {
                    "semantic_outbox_id": OUTBOX_ID,
                    "semantic_sync_id": SYNC_ID,
                    "agent_id": AGENT_ID,
                    "idempotency_key": params["idempotency_key"],
                }
            ]
        if "from recognition_workers" in squashed:
            return list(self.worker_rows)
        if "from recognition_worker_heartbeats" in squashed:
            return list(self.heartbeat_rows)
        if "insert into recognition_worker_heartbeats" in squashed:
            return [{"received_at": NOW.isoformat()}]
        if "from events" in squashed and "last_event_id" not in squashed:
            return [{"agent_id": AGENT_ID}]
        return []


def _source_row() -> dict[str, object]:
    return {
        "source_event_id": EVENT_ID,
        "event_agent_id": AGENT_ID,
        "event_space_id": SPACE_ID,
        "event_location_id": LOCATION_ID,
        "event_session_id": SESSION_ID,
        "event_device_id": SOURCE_DEVICE_ID,
        "event_type": "voice.sample",
        "event_payload_json": json.dumps(
            {
                "artifact_bucket": "recognition-test",
                "artifact_key": "recognition/sample.wav",
                "artifact_sha256": "a" * 64,
                "content_type": "audio/wav",
            }
        ),
        "event_created_at": NOW.isoformat(),
        "space_agent_id": AGENT_ID,
        "space_location_id": LOCATION_ID,
        "source_device_agent_id": AGENT_ID,
        "source_device_location_id": LOCATION_ID,
        "session_agent_id": AGENT_ID,
        "session_space_id": SPACE_ID,
        "artifact_id": None,
    }


def _artifact() -> ArtifactEvidence:
    return ArtifactEvidence(
        artifact_id=ARTIFACT_ID,
        agent_id=AGENT_ID,
        device_id=SOURCE_DEVICE_ID,
        bucket="recognition-test",
        object_key="recognition/sample.wav",
        uri="s3://recognition-test/recognition/sample.wav",
        media_type="audio/wav",
        sha256="a" * 64,
        captured_at=NOW,
        source_event_id=EVENT_ID,
        space_id=SPACE_ID,
        location_id=LOCATION_ID,
        session_id=SESSION_ID,
    )


def _observation() -> RecognitionObservation:
    return RecognitionObservation(
        observation_id=OBSERVATION_ID,
        artifact_id=ARTIFACT_ID,
        agent_id=AGENT_ID,
        device_id=SOURCE_DEVICE_ID,
        modality=RecognitionModality.VOICE,
        model_id="voice-model",
        model_version="1.0.0",
        embedding_sha256="f" * 64,
        state=ObservationState.EMBEDDED,
        created_at=NOW,
        space_id=SPACE_ID,
        location_id=LOCATION_ID,
        session_id=SESSION_ID,
        source_event_id=EVENT_ID,
    )


def _observation_row() -> dict[str, object]:
    observation = _observation()
    return {
        "observation_id": observation.observation_id,
        "artifact_id": observation.artifact_id,
        "agent_id": observation.agent_id,
        "device_id": observation.device_id,
        "modality": observation.modality.value,
        "model_id": observation.model_id,
        "model_version": observation.model_version,
        "embedding_sha256": observation.embedding_sha256,
        "lifecycle_state": observation.state.value,
        "created_at": observation.created_at.isoformat(),
        "space_id": observation.space_id,
        "location_id": observation.location_id,
        "session_id": observation.session_id,
        "source_event_id": observation.source_event_id,
    }


def _hypothesis() -> RecognitionHypothesis:
    return RecognitionHypothesis(
        hypothesis_id=HYPOTHESIS_ID,
        observation_id=OBSERVATION_ID,
        kind=HypothesisKind.CANDIDATE,
        confidence=0.95,
        rationale="reviewed candidate",
        candidate_person_id=PERSON_ID,
        distance=0.05,
        decision="proposed",
        created_at=NOW,
    )


def _hypothesis_row() -> dict[str, object]:
    hypothesis = _hypothesis()
    return {
        "hypothesis_id": hypothesis.hypothesis_id,
        "observation_id": hypothesis.observation_id,
        "kind": hypothesis.kind.value,
        "candidate_person_id": hypothesis.candidate_person_id,
        "confidence": hypothesis.confidence,
        "distance": hypothesis.distance,
        "decision": hypothesis.decision,
        "rationale": hypothesis.rationale,
        "requested_projection": True,
        "consent_id": CONSENT_ID,
        "created_at": hypothesis.created_at.isoformat(),
        "agent_id": AGENT_ID,
    }


def _worker_device(*, kind: str = "recognition_worker") -> AuthenticatedDevice:
    return AuthenticatedDevice(
        device_id=WORKER_DEVICE_ID,
        agent_id=AGENT_ID,
        scopes=["biometrics:write", "events:read"],
        capabilities={
            "kind": kind,
            "worker_key": "recognition-cleanroom-1",
            "allowed_agent_ids": [AGENT_ID],
        },
    )


def test_repository_persists_observation_artifact_and_outbox_in_one_transaction(monkeypatch) -> None:
    import recognition_repository as repository_module

    db = RecordingDb()
    db.source_row = _source_row()
    repository = repository_module.RdsRecognitionRepository(db, agent_id=AGENT_ID)
    prepared = repository.prepare_observation(
        source_event_id=EVENT_ID,
        claimed_agent_id=AGENT_ID,
        claimed_space_id=SPACE_ID,
        claimed_location_id=LOCATION_ID,
        claimed_session_id=SESSION_ID,
        source_device_id=SOURCE_DEVICE_ID,
        artifact_payload={
            "bucket": "recognition-test",
            "object_key": "recognition/sample.wav",
            "uri": "s3://recognition-test/recognition/sample.wav",
            "media_type": "audio/wav",
            "sha256": "a" * 64,
        },
        modality=RecognitionModality.VOICE,
        model_id="voice-model",
        model_version="1.0.0",
        embedding_sha256="f" * 64,
    )
    assert prepared.existing is None
    observation = dataclasses.replace(_observation(), artifact_id=prepared.artifact.artifact_id)
    repository.persist_observation(artifact=prepared.artifact, observation=observation)
    repository.commit()

    executed = "\n".join(sql for sql, _params, _tx in db.execute_calls)
    assert "INSERT INTO artifact_references" in executed
    assert "UPDATE events" in executed
    assert "INSERT INTO recognition_observations" in executed
    outbox_sources = [
        params["source_table"] for sql, params, _tx in db.query_calls if "INSERT INTO semantic_sync_status" in sql
    ]
    assert outbox_sources == ["artifact_references", "recognition_observations"]
    assert all(tx == db.transaction_id for _sql, _params, tx in db.execute_calls)
    assert all(tx == db.transaction_id for _sql, _params, tx in db.query_calls)
    assert db.commits == [db.transaction_id]
    assert db.rollbacks == []


def test_repository_rejects_artifact_claim_that_differs_from_source_event() -> None:
    import recognition_repository as repository_module

    db = RecordingDb()
    db.source_row = _source_row()
    repository = repository_module.RdsRecognitionRepository(db, agent_id=AGENT_ID)
    with pytest.raises(repository_module.RecognitionConflictError, match="immutable source event"):
        repository.prepare_observation(
            source_event_id=EVENT_ID,
            claimed_agent_id=AGENT_ID,
            claimed_space_id=SPACE_ID,
            claimed_location_id=LOCATION_ID,
            claimed_session_id=SESSION_ID,
            source_device_id=SOURCE_DEVICE_ID,
            artifact_payload={
                "bucket": "recognition-test",
                "object_key": "recognition/other.wav",
                "uri": "s3://recognition-test/recognition/other.wav",
                "media_type": "audio/wav",
                "sha256": "a" * 64,
            },
            modality=RecognitionModality.VOICE,
            model_id="voice-model",
            model_version="1.0.0",
            embedding_sha256="f" * 64,
        )
    repository.rollback()
    assert db.rollbacks == [db.transaction_id]


def test_repository_heartbeat_is_immutable_and_semantically_outboxed() -> None:
    import recognition_repository as repository_module
    from agent_hub.recognition_service import RecognitionWorkerHeartbeat

    db = RecordingDb()
    heartbeat = RecognitionWorkerHeartbeat(
        worker_id="recognition-cleanroom-1",
        worker_version="1.2.3",
        host_id="i-123",
        voice_model_id="voice-model",
        voice_model_version="1.0.0",
        face_model_id="face-model",
        face_model_version="2.0.0",
        state="ready",
        started_at=NOW - timedelta(minutes=5),
        observed_at=NOW,
        processed_messages=4,
        failed_messages=1,
        last_event_id=EVENT_ID,
        last_error=None,
    )
    repository = repository_module.RdsRecognitionRepository(db, agent_id=AGENT_ID)
    receipt = repository.persist_worker_heartbeat(
        heartbeat,
        authenticated_device_id=WORKER_DEVICE_ID,
        allowed_agent_ids=[AGENT_ID],
    )
    repository.commit()
    assert receipt.replayed is False
    assert receipt.received_at == NOW.isoformat()
    assert any("INSERT INTO recognition_workers" in sql for sql, _params, _tx in db.execute_calls)
    outbox_calls = [params for sql, params, _tx in db.query_calls if "INSERT INTO semantic_sync_status" in sql]
    assert len(outbox_calls) == 1
    assert outbox_calls[0]["source_table"] == "recognition_worker_heartbeats"


def test_repository_persists_proposed_hypothesis_and_outbox_in_one_transaction() -> None:
    import recognition_repository as repository_module

    db = RecordingDb()
    db.observation_by_id = _observation_row()
    db.person_rows = [{"person_id": PERSON_ID}]
    db.consent_rows = [{"consent_id": CONSENT_ID}]
    repository = repository_module.RdsRecognitionRepository(db, agent_id=AGENT_ID)
    prepared = repository.prepare_hypothesis(
        observation_id=OBSERVATION_ID,
        kind=HypothesisKind.CANDIDATE,
        candidate_person_id=PERSON_ID,
        confidence=0.95,
        distance=0.05,
        rationale="reviewed candidate",
        requested_projection=True,
    )
    assert prepared.existing is None
    assert prepared.consent_id == CONSENT_ID
    hypothesis = RecognitionLifecycleService(repository).propose_candidate(
        observation_id=OBSERVATION_ID,
        candidate_person_id=PERSON_ID,
        confidence=0.95,
        distance=0.05,
        rationale="reviewed candidate",
        created_at=NOW,
    )
    repository.commit()
    assert hypothesis.decision == "proposed"
    assert any("INSERT INTO recognition_hypotheses" in sql for sql, _params, _tx in db.execute_calls)
    outbox_calls = [params for sql, params, _tx in db.query_calls if "INSERT INTO semantic_sync_status" in sql]
    assert len(outbox_calls) == 1
    assert outbox_calls[0]["source_table"] == "recognition_hypotheses"
    assert all(tx == db.transaction_id for _sql, _params, tx in db.execute_calls)


def test_repository_review_atomically_persists_decision_projection_presence_and_outbox() -> None:
    import recognition_repository as repository_module

    db = RecordingDb()
    db.observation_by_id = _observation_row()
    db.hypothesis_rows = [_hypothesis_row()]
    repository = repository_module.RdsRecognitionRepository(db, agent_id=AGENT_ID)
    repository.configure_review(reviewer_auth_subject="reviewer-sub", no_match_retention_until=None)
    application = RecognitionLifecycleService(repository).review(
        hypothesis_id=HYPOTHESIS_ID,
        decision=ReviewDecision.ACCEPTED,
        reviewer=AuthenticatedReviewer(actor_id="reviewer-user", actor_type=ActorType.USER),
        reason="source artifact and active consent reviewed",
        consent=ConsentProof(
            consent_id=CONSENT_ID,
            agent_id=AGENT_ID,
            person_id=PERSON_ID,
            consent_type="voice",
            valid_from=NOW - timedelta(days=1),
            expires_at=NOW + timedelta(days=1),
        ),
        create_biometric_projection=True,
        assert_presence=True,
        decided_at=NOW,
    )
    repository.commit()
    assert application.decision.decision == ReviewDecision.ACCEPTED
    executed = "\n".join(sql for sql, _params, _tx in db.execute_calls)
    assert "INSERT INTO recognition_decisions" in executed
    assert "INSERT INTO biometric_projections" in executed
    assert "INSERT INTO presence_assertions" in executed
    outbox_sources = [
        params["source_table"] for sql, params, _tx in db.query_calls if "INSERT INTO semantic_sync_status" in sql
    ]
    assert outbox_sources == ["presence_assertions", "recognition_decisions"]
    assert all(tx == db.transaction_id for _sql, _params, tx in db.execute_calls)
    assert db.commits == [db.transaction_id]


@pytest.fixture(scope="module")
def api_module():
    return _load_api_module()


@pytest.fixture()
def client(api_module):
    from fastapi.testclient import TestClient

    api_module.api_app.dependency_overrides.clear()
    api_module.api_app.dependency_overrides[api_module.get_device] = _worker_device
    api_module._cfg = dataclasses.replace(api_module._cfg, artifact_bucket="recognition-test", audit_bucket=None)
    yield TestClient(api_module.api_app, raise_server_exceptions=False)
    api_module.api_app.dependency_overrides.clear()


def _observation_body() -> dict[str, object]:
    return {
        "idempotency_key": f"recognition-observation:{EVENT_ID}",
        "source_event_id": EVENT_ID,
        "agent_id": AGENT_ID,
        "space_id": SPACE_ID,
        "location_id": LOCATION_ID,
        "session_id": SESSION_ID,
        "device_id": SOURCE_DEVICE_ID,
        "artifact": {
            "bucket": "recognition-test",
            "object_key": "recognition/sample.wav",
            "uri": "s3://recognition-test/recognition/sample.wav",
            "media_type": "audio/wav",
            "sha256": "a" * 64,
        },
        "modality": "voice",
        "model_id": "voice-model",
        "model_version": "1.0.0",
        "embedding": [0.1, 0.2],
    }


def test_observation_route_rejects_generic_worker_capability(api_module, client) -> None:
    api_module.api_app.dependency_overrides[api_module.get_device] = lambda: _worker_device(kind="worker")
    response = client.post("/v1/recognition/observations", json=_observation_body())
    assert response.status_code == 403
    assert response.json()["detail"] == "Recognition worker capability is required"


def test_observation_route_uses_lifecycle_service_and_commits(api_module, client, monkeypatch) -> None:
    class FakeRepository:
        def __init__(self, _db, *, agent_id):
            assert agent_id == AGENT_ID
            self.committed = False
            self.rolled_back = False
            self.persisted = None

        def prepare_observation(self, **_kwargs):
            return type("Prepared", (), {"artifact": _artifact(), "existing": None})()

        def persist_observation(self, *, artifact, observation):
            self.persisted = (artifact, observation)

        def commit(self):
            self.committed = True

        def rollback(self):
            self.rolled_back = True

    created: list[FakeRepository] = []

    def factory(*args, **kwargs):
        instance = FakeRepository(*args, **kwargs)
        created.append(instance)
        return instance

    monkeypatch.setattr(api_module, "RdsRecognitionRepository", factory)
    monkeypatch.setattr(api_module, "_get_db", lambda: object())
    response = client.post("/v1/recognition/observations", json=_observation_body())
    assert response.status_code == 200, response.text
    payload = response.json()
    assert payload["source_event_id"] == EVENT_ID
    assert payload["state"] == "embedded"
    assert payload["replayed"] is False
    assert created[0].committed is True
    assert created[0].rolled_back is False
    assert created[0].persisted[1].embedding_sha256 == payload["embedding_sha256"]


def test_worker_heartbeat_route_requires_bound_worker_key(api_module, client) -> None:
    body = {
        "schema": "marvain.recognition.worker.v1",
        "evidence_kind": "recognition_worker_heartbeat",
        "worker_id": "different-worker",
        "worker_version": "1.0.0",
        "host_id": "i-123",
        "models": {
            "voice": {"id": "voice-model", "version": "1"},
            "face": {"id": "face-model", "version": "1"},
        },
        "state": "ready",
        "started_at": (NOW - timedelta(minutes=1)).isoformat(),
        "observed_at": NOW.isoformat(),
        "processed_messages": 1,
        "failed_messages": 0,
        "last_event_id": None,
        "last_error": None,
    }
    response = client.post("/v1/recognition/workers/recognition-cleanroom-1/heartbeat", json=body)
    assert response.status_code == 400
    assert response.json()["detail"] == "worker_id does not match the heartbeat route"


def test_hypothesis_route_persists_proposal_without_identity_decision(api_module, client, monkeypatch) -> None:
    class AgentLookupDb:
        def query(self, *_args, **_kwargs):
            return [{"agent_id": AGENT_ID}]

    class HypothesisRepository:
        def __init__(self, _db, *, agent_id):
            assert agent_id == AGENT_ID
            self.observation = _observation()
            self.persisted = None
            self.committed = False

        def prepare_hypothesis(self, **kwargs):
            assert kwargs["requested_projection"] is True
            return type(
                "Prepared",
                (),
                {"observation": self.observation, "existing": None, "consent_id": CONSENT_ID},
            )()

        def get_observation(self, observation_id):
            assert observation_id == OBSERVATION_ID
            return self.observation

        def persist_hypothesis(self, hypothesis):
            self.persisted = hypothesis

        def commit(self):
            self.committed = True

        def rollback(self):
            pass

    repositories: list[HypothesisRepository] = []

    def factory(*args, **kwargs):
        instance = HypothesisRepository(*args, **kwargs)
        repositories.append(instance)
        return instance

    monkeypatch.setattr(api_module, "_get_db", lambda: AgentLookupDb())
    monkeypatch.setattr(api_module, "RdsRecognitionRepository", factory)
    response = client.post(
        f"/v1/recognition/observations/{OBSERVATION_ID}/hypotheses",
        json={
            "idempotency_key": f"recognition-hypothesis:{EVENT_ID}",
            "kind": "candidate",
            "candidate_person_id": PERSON_ID,
            "confidence": 0.95,
            "distance": 0.05,
            "rationale": "configured model candidate requiring review",
            "requested_projection": True,
        },
    )
    assert response.status_code == 200, response.text
    payload = response.json()
    assert payload["decision"] == "proposed"
    assert payload["consent_id"] == CONSENT_ID
    assert payload["requested_projection"] is True
    assert repositories[0].persisted.decision == "proposed"
    assert repositories[0].committed is True


def test_worker_heartbeat_route_persists_measured_receipt(api_module, client, monkeypatch) -> None:
    class HeartbeatRepository:
        def __init__(self, _db, *, agent_id):
            assert agent_id == AGENT_ID
            self.heartbeat = None

        def persist_worker_heartbeat(self, heartbeat, **kwargs):
            assert kwargs == {
                "authenticated_device_id": WORKER_DEVICE_ID,
                "allowed_agent_ids": [AGENT_ID],
            }
            self.heartbeat = heartbeat
            return type(
                "Receipt",
                (),
                {
                    "worker_id": "abababab-abab-abab-abab-abababababab",
                    "heartbeat_id": "cdcdcdcd-cdcd-cdcd-cdcd-cdcdcdcdcdcd",
                    "received_at": NOW.isoformat(),
                    "replayed": False,
                },
            )()

        def commit(self):
            pass

        def rollback(self):
            pass

    repositories: list[HeartbeatRepository] = []

    def factory(*args, **kwargs):
        instance = HeartbeatRepository(*args, **kwargs)
        repositories.append(instance)
        return instance

    monkeypatch.setattr(api_module, "_get_db", lambda: object())
    monkeypatch.setattr(api_module, "RdsRecognitionRepository", factory)
    response = client.post(
        "/v1/recognition/workers/recognition-cleanroom-1/heartbeat",
        json={
            "schema": "marvain.recognition.worker.v1",
            "evidence_kind": "recognition_worker_heartbeat",
            "worker_id": "recognition-cleanroom-1",
            "worker_version": "1.0.0",
            "host_id": "i-123",
            "models": {
                "voice": {"id": "voice-model", "version": "1"},
                "face": {"id": "face-model", "version": "1"},
            },
            "state": "degraded",
            "started_at": (NOW - timedelta(minutes=1)).isoformat(),
            "observed_at": NOW.isoformat(),
            "processed_messages": 7,
            "failed_messages": 2,
            "last_event_id": EVENT_ID,
            "last_error": "model timeout",
        },
    )
    assert response.status_code == 200, response.text
    assert response.json()["ok"] is True
    assert repositories[0].heartbeat.state == "degraded"
    assert repositories[0].heartbeat.processed_messages == 7


def test_authenticated_review_applies_consent_without_direct_worker_identity_decision(
    api_module, client, monkeypatch
) -> None:
    user = AuthenticatedUser(user_id="reviewer-user", cognito_sub="reviewer-sub", email="reviewer@example.test")
    api_module.api_app.dependency_overrides[api_module.get_user] = lambda: user
    monkeypatch.setattr(api_module, "check_agent_permission", lambda *_args, **_kwargs: True)
    monkeypatch.setattr(
        api_module,
        "get_recognition_hypothesis_detail",
        lambda _db, *, hypothesis_id: {"hypothesis_id": hypothesis_id, "agent_id": AGENT_ID},
    )

    class ReviewRepository:
        def __init__(self, _db, *, agent_id):
            assert agent_id == AGENT_ID
            self.observation = _observation()
            self.hypothesis = _hypothesis()
            self.application = None
            self.review_config = None

        def get_hypothesis(self, hypothesis_id):
            assert hypothesis_id == HYPOTHESIS_ID
            return self.hypothesis

        def get_observation(self, observation_id):
            assert observation_id == OBSERVATION_ID
            return self.observation

        def load_active_consent(self, *, observation, person_id):
            assert observation == self.observation and person_id == PERSON_ID
            return ConsentProof(
                consent_id=CONSENT_ID,
                agent_id=AGENT_ID,
                person_id=PERSON_ID,
                consent_type="voice",
                valid_from=NOW - timedelta(days=1),
                expires_at=NOW + timedelta(days=1),
            )

        def configure_review(self, **kwargs):
            self.review_config = kwargs

        def apply_decision(self, application):
            self.application = application

        def commit(self):
            pass

        def rollback(self):
            pass

    repositories: list[ReviewRepository] = []

    def factory(*args, **kwargs):
        instance = ReviewRepository(*args, **kwargs)
        repositories.append(instance)
        return instance

    monkeypatch.setattr(api_module, "RdsRecognitionRepository", factory)
    monkeypatch.setattr(api_module, "_get_db", lambda: object())
    response = client.post(
        f"/v1/recognition/hypotheses/{HYPOTHESIS_ID}/review",
        json={
            "decision": "accepted",
            "reason": "source evidence and consent reviewed",
            "create_biometric_projection": True,
            "assert_presence": True,
        },
    )
    assert response.status_code == 200, response.text
    payload = response.json()
    assert payload["decision"] == "accepted"
    assert payload["consent_id"] == CONSENT_ID
    assert payload["projection_id"]
    assert payload["presence_assertion_id"]
    repository = repositories[0]
    assert repository.review_config["reviewer_auth_subject"] == "reviewer-sub"
    assert repository.application.decision.reviewer.actor_id == "reviewer-user"
    assert repository.application.decision.reviewer.actor_type.value == "user"


def test_no_match_review_requires_explicit_future_retention(api_module, client) -> None:
    user = AuthenticatedUser(user_id="reviewer-user", cognito_sub="reviewer-sub", email=None)
    api_module.api_app.dependency_overrides[api_module.get_user] = lambda: user
    response = client.post(
        f"/v1/recognition/hypotheses/{HYPOTHESIS_ID}/review",
        json={"decision": "no_match", "reason": "unknown person"},
    )
    assert response.status_code == 400
    assert response.json()["detail"] == "no_match requires an explicit retention deadline"
