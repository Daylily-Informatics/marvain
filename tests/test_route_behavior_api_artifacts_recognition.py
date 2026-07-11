from __future__ import annotations

import base64
import dataclasses
import importlib.util
import os
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

import pytest
from agent_hub.artifact_service import (
    ArtifactLifecycleState,
    ArtifactServiceError,
    ArtifactUploadIntent,
    VerifiedArtifact,
)
from agent_hub.auth import AuthenticatedDevice, AuthenticatedUser
from agent_hub.recognition_service import (
    ArtifactEvidence,
    ConsentProof,
    RecognitionHypothesis,
    RecognitionObservation,
)
from fastapi.testclient import TestClient
from route_behavior_receipt import record_http_evidence, record_postcondition_evidence

ROOT = Path(__file__).resolve().parents[1]
HUB_API_DIR = ROOT / "functions" / "hub_api"

AGENT_ID = "11111111-1111-4111-8111-111111111111"
SPACE_ID = "22222222-2222-4222-8222-222222222222"
SESSION_ID = "33333333-3333-4333-8333-333333333333"
EVENT_ID = "44444444-4444-4444-8444-444444444444"
SOURCE_DEVICE_ID = "55555555-5555-4555-8555-555555555555"
WORKER_DEVICE_ID = "66666666-6666-4666-8666-666666666666"
ARTIFACT_ID = "77777777-7777-4777-8777-777777777777"
PERSON_ID = "88888888-8888-4888-8888-888888888888"
CONSENT_ID = "99999999-9999-4999-8999-999999999999"
LOCATION_ID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
DIGEST = "a" * 64
NOW = datetime(2026, 7, 11, 4, 30, tzinfo=timezone.utc)


def _load_api_module():
    for path in (ROOT / "layers" / "shared" / "python", HUB_API_DIR):
        if str(path) not in sys.path:
            sys.path.insert(0, str(path))
    os.environ.setdefault("AWS_DEFAULT_REGION", "us-east-1")
    os.environ.setdefault("DB_RESOURCE_ARN", "arn:aws:rds:us-east-1:123:cluster:test")
    os.environ.setdefault("DB_SECRET_ARN", "arn:aws:secretsmanager:us-east-1:123:secret:test")
    os.environ.setdefault("DB_NAME", "test")
    os.environ.setdefault("ENVIRONMENT", "test")
    os.environ.setdefault("HTTPS_ENABLED", "false")
    os.environ.setdefault("SESSION_SECRET_KEY", "artifact-recognition-route-test-secret")
    spec = importlib.util.spec_from_file_location(
        "hub_api_artifact_recognition_route_behavior_tests",
        HUB_API_DIR / "api_app.py",
    )
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    with mock.patch("boto3.client", return_value=mock.Mock()):
        spec.loader.exec_module(module)
    return module


class RouteDatabase:
    def __init__(self, recognition_state: RecognitionState) -> None:
        self.recognition_state = recognition_state
        self.event_exists = True

    def query(self, sql: str, params: dict | None = None, **_kwargs):
        normalized = " ".join(sql.lower().split())
        if "from events" in normalized:
            if not self.event_exists:
                return []
            return [
                {
                    "event_id": EVENT_ID,
                    "agent_id": AGENT_ID,
                    "space_id": SPACE_ID,
                    "session_id": SESSION_ID,
                    "type": "voice.sample",
                }
            ]
        if "from spaces" in normalized:
            return [{"ok": 1}]
        if "from recognition_observations" in normalized:
            observation_id = str((params or {}).get("observation_id") or "")
            observation = self.recognition_state.observations.get(observation_id)
            return [{"agent_id": observation.agent_id}] if observation else []
        raise AssertionError(f"unexpected query: {normalized}")


class ArtifactRepository:
    def __init__(self) -> None:
        self.intents: dict[str, ArtifactUploadIntent] = {}
        self.verified: dict[str, VerifiedArtifact] = {}

    def persist_upload_intent(self, intent: ArtifactUploadIntent) -> None:
        if intent.artifact_id in self.intents:
            raise ArtifactServiceError("artifact upload intent was not persisted")
        self.intents[intent.artifact_id] = intent

    def get_upload_intent(self, artifact_id: str) -> ArtifactUploadIntent:
        try:
            return self.intents[artifact_id]
        except KeyError as exc:
            raise ArtifactServiceError("artifact upload intent was not found") from exc

    def persist_verified_completion(self, artifact: VerifiedArtifact) -> None:
        available = dataclasses.replace(
            artifact,
            intent=dataclasses.replace(
                artifact.intent,
                lifecycle_state=ArtifactLifecycleState.AVAILABLE,
            ),
        )
        self.intents[artifact.intent.artifact_id] = available.intent
        self.verified[artifact.intent.artifact_id] = available

    def get_verified_artifact(self, artifact_id: str) -> VerifiedArtifact:
        try:
            return self.verified[artifact_id]
        except KeyError as exc:
            raise ArtifactServiceError("artifact is not verified and available") from exc


class ArtifactS3:
    def generate_presigned_url(self, **_kwargs) -> str:
        return "https://artifact-upload.example.test/signed"

    def head_object(self, **_kwargs) -> dict:
        return {
            "ContentLength": 1024,
            "ContentType": "audio/webm",
            "Metadata": {"sha256": DIGEST},
            "ChecksumSHA256": base64.b64encode(bytes.fromhex(DIGEST)).decode("ascii"),
            "ETag": '"etag-route-test"',
            "VersionId": "version-route-test",
        }


@dataclasses.dataclass
class RecognitionState:
    observations: dict[str, RecognitionObservation] = dataclasses.field(default_factory=dict)
    hypotheses: dict[str, RecognitionHypothesis] = dataclasses.field(default_factory=dict)
    decisions: dict[str, object] = dataclasses.field(default_factory=dict)
    heartbeats: dict[str, object] = dataclasses.field(default_factory=dict)
    commits: int = 0
    rollbacks: int = 0


class RecognitionRepository:
    def __init__(self, state: RecognitionState, *, agent_id: str) -> None:
        assert agent_id == AGENT_ID
        self.state = state
        self.reviewer_auth_subject: str | None = None
        self.no_match_retention_until: datetime | None = None

    def prepare_observation(self, **kwargs):
        source_event_id = kwargs["source_event_id"]
        existing = next(
            (item for item in self.state.observations.values() if item.source_event_id == source_event_id),
            None,
        )
        artifact_payload = kwargs["artifact_payload"]
        return SimpleNamespace(
            existing=existing,
            artifact=ArtifactEvidence(
                artifact_id=ARTIFACT_ID,
                agent_id=AGENT_ID,
                device_id=SOURCE_DEVICE_ID,
                bucket=artifact_payload["bucket"],
                object_key=artifact_payload["object_key"],
                uri=artifact_payload["uri"],
                media_type=artifact_payload["media_type"],
                sha256=artifact_payload["sha256"],
                captured_at=NOW,
                source_event_id=source_event_id,
                space_id=str(kwargs["claimed_space_id"]),
                location_id=str(kwargs["claimed_location_id"]),
                session_id=str(kwargs["claimed_session_id"]),
            ),
        )

    def persist_observation(self, *, artifact, observation) -> None:
        assert artifact.artifact_id == ARTIFACT_ID
        self.state.observations[observation.observation_id] = observation

    def get_observation(self, observation_id: str) -> RecognitionObservation:
        return self.state.observations[observation_id]

    def prepare_hypothesis(self, **kwargs):
        observation = self.get_observation(kwargs["observation_id"])
        existing = next(
            (item for item in self.state.hypotheses.values() if item.observation_id == observation.observation_id),
            None,
        )
        return SimpleNamespace(
            observation=observation,
            existing=existing,
            consent_id=CONSENT_ID if kwargs["candidate_person_id"] else None,
        )

    def persist_hypothesis(self, hypothesis: RecognitionHypothesis) -> None:
        self.state.hypotheses[hypothesis.hypothesis_id] = hypothesis

    def get_hypothesis(self, hypothesis_id: str) -> RecognitionHypothesis:
        return self.state.hypotheses[hypothesis_id]

    def load_active_consent(self, *, observation, person_id) -> ConsentProof:
        assert observation.agent_id == AGENT_ID
        assert person_id == PERSON_ID
        return ConsentProof(
            consent_id=CONSENT_ID,
            agent_id=AGENT_ID,
            person_id=PERSON_ID,
            consent_type="voice",
            valid_from=NOW - timedelta(days=1),
            expires_at=NOW + timedelta(days=1),
        )

    def configure_review(self, **kwargs) -> None:
        self.reviewer_auth_subject = kwargs["reviewer_auth_subject"]
        self.no_match_retention_until = kwargs["no_match_retention_until"]

    def apply_decision(self, application) -> None:
        self.state.observations[application.observation.observation_id] = application.observation
        self.state.hypotheses[application.hypothesis.hypothesis_id] = application.hypothesis
        self.state.decisions[application.hypothesis.hypothesis_id] = application

    def persist_worker_heartbeat(self, heartbeat, **kwargs):
        assert kwargs == {
            "authenticated_device_id": WORKER_DEVICE_ID,
            "allowed_agent_ids": [AGENT_ID],
        }
        self.state.heartbeats[heartbeat.worker_id] = heartbeat
        return SimpleNamespace(
            worker_id="abababab-abab-4bab-8bab-abababababab",
            heartbeat_id="cdcdcdcd-cdcd-4dcd-8dcd-cdcdcdcdcdcd",
            received_at=NOW.isoformat(),
            replayed=False,
        )

    def commit(self) -> None:
        self.state.commits += 1

    def rollback(self) -> None:
        self.state.rollbacks += 1


def _worker_device(*, kind: str = "recognition_worker") -> AuthenticatedDevice:
    return AuthenticatedDevice(
        device_id=WORKER_DEVICE_ID,
        agent_id=AGENT_ID,
        scopes=["artifacts:write", "biometrics:write", "events:read"],
        capabilities={
            "kind": kind,
            "worker_key": "recognition-cleanroom-1",
            "allowed_agent_ids": [AGENT_ID],
        },
    )


def _reviewer() -> AuthenticatedUser:
    return AuthenticatedUser(
        user_id="reviewer-user",
        cognito_sub="reviewer-sub",
        email="reviewer@example.test",
    )


def _hypothesis_detail(state: RecognitionState, hypothesis_id: str) -> dict | None:
    hypothesis = state.hypotheses.get(hypothesis_id)
    if hypothesis is None:
        return None
    observation = state.observations[hypothesis.observation_id]
    application = state.decisions.get(hypothesis_id)
    return {
        "hypothesis_id": hypothesis.hypothesis_id,
        "observation_id": hypothesis.observation_id,
        "agent_id": observation.agent_id,
        "kind": hypothesis.kind.value,
        "candidate_person_id": hypothesis.candidate_person_id,
        "confidence": hypothesis.confidence,
        "distance": hypothesis.distance,
        "decision": hypothesis.decision,
        "rationale": hypothesis.rationale,
        "reviewer_actor_id": application.decision.reviewer.actor_id if application else None,
    }


@pytest.fixture(scope="module")
def api_module():
    return _load_api_module()


@pytest.fixture()
def harness(api_module, monkeypatch):
    artifact_repository = ArtifactRepository()
    recognition_state = RecognitionState()
    database = RouteDatabase(recognition_state)
    api_module.api_app.dependency_overrides.clear()
    api_module.api_app.dependency_overrides[api_module.get_device] = _worker_device
    api_module.api_app.dependency_overrides[api_module.get_user] = _reviewer
    monkeypatch.setattr(
        api_module,
        "_cfg",
        dataclasses.replace(api_module._cfg, artifact_bucket="recognition-test", audit_bucket=None),
    )
    monkeypatch.setattr(api_module, "_get_db", lambda: database)
    monkeypatch.setattr(api_module, "_get_s3", ArtifactS3)
    monkeypatch.setattr(api_module, "RdsArtifactRepository", lambda _db: artifact_repository)
    monkeypatch.setattr(
        api_module,
        "RdsRecognitionRepository",
        lambda _db, *, agent_id: RecognitionRepository(recognition_state, agent_id=agent_id),
    )
    monkeypatch.setattr(
        api_module,
        "get_recognition_hypothesis_detail",
        lambda _db, *, hypothesis_id: _hypothesis_detail(recognition_state, hypothesis_id),
    )
    monkeypatch.setattr(api_module, "check_agent_permission", lambda *_args, **_kwargs: True)
    client = TestClient(api_module.api_app, raise_server_exceptions=False)
    yield api_module, client, artifact_repository, recognition_state, database
    api_module.api_app.dependency_overrides.clear()


def _artifact_intent_body(**overrides) -> dict:
    body = {
        "idempotency_key": "voice-route-behavior-1",
        "agent_id": AGENT_ID,
        "purpose": "recognition",
        "filename": "voice.webm",
        "media_type": "audio/webm",
        "expected_sha256": DIGEST,
        "expected_byte_count": 1024,
        "upload_ttl_seconds": 900,
        "space_id": SPACE_ID,
        "session_id": SESSION_ID,
        "source_event_id": EVENT_ID,
    }
    body.update(overrides)
    return body


def _observation_body(**overrides) -> dict:
    body = {
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
            "sha256": DIGEST,
        },
        "modality": "voice",
        "model_id": "voice-model",
        "model_version": "1.0.0",
        "embedding": [0.1, 0.2],
    }
    body.update(overrides)
    return body


def _heartbeat_body(**overrides) -> dict:
    body = {
        "schema": "marvain.recognition.worker.v1",
        "evidence_kind": "recognition_worker_heartbeat",
        "worker_id": "recognition-cleanroom-1",
        "worker_version": "1.0.0",
        "host_id": "i-route-test",
        "models": {
            "voice": {"id": "voice-model", "version": "1"},
            "face": {"id": "face-model", "version": "1"},
        },
        "state": "ready",
        "started_at": (NOW - timedelta(minutes=1)).isoformat(),
        "observed_at": NOW.isoformat(),
        "processed_messages": 4,
        "failed_messages": 0,
        "last_event_id": EVENT_ID,
        "last_error": None,
    }
    body.update(overrides)
    return body


def test_artifact_upload_completion_and_get_have_persisted_postconditions(
    request: pytest.FixtureRequest,
    harness,
) -> None:
    _module, client, repository, _recognition, _database = harness

    intent_response = client.post("/v1/artifacts/upload-intents", json=_artifact_intent_body())
    assert intent_response.status_code == 201, intent_response.text
    intent = intent_response.json()
    persisted_intent = repository.get_upload_intent(intent["artifact_id"])
    assert persisted_intent.lifecycle_state is ArtifactLifecycleState.PENDING_UPLOAD
    record_http_evidence(
        request,
        surface="api",
        method="POST",
        path="/v1/artifacts/upload-intents",
        kind="success",
        response=intent_response,
    )
    record_postcondition_evidence(
        request,
        surface="api",
        method="POST",
        path="/v1/artifacts/upload-intents",
        owner="ArtifactRepository",
        query="get_upload_intent(artifact_id)",
        record_ids={"artifact_id": intent["artifact_id"]},
        assertions=["upload intent persisted in pending_upload state"],
    )

    completion_response = client.post(f"/v1/artifacts/{intent['artifact_id']}/complete")
    assert completion_response.status_code == 200, completion_response.text
    assert completion_response.json()["actual_sha256"] == DIGEST
    persisted_artifact = repository.get_verified_artifact(intent["artifact_id"])
    assert persisted_artifact.actual_sha256 == DIGEST
    record_http_evidence(
        request,
        surface="api",
        method="POST",
        path="/v1/artifacts/{artifact_id}/complete",
        kind="success",
        response=completion_response,
    )
    record_postcondition_evidence(
        request,
        surface="api",
        method="POST",
        path="/v1/artifacts/{artifact_id}/complete",
        owner="ArtifactRepository",
        query="get_verified_artifact(artifact_id)",
        record_ids={"artifact_id": intent["artifact_id"]},
        assertions=["verified artifact persisted with the owning S3 SHA-256 evidence"],
    )

    readback = client.get(f"/v1/artifacts/{intent['artifact_id']}")
    assert readback.status_code == 200, readback.text
    assert readback.json()["lifecycle_state"] == "available"
    assert readback.json()["source_event_id"] == EVENT_ID
    assert readback.json()["actual_sha256"] == DIGEST
    record_http_evidence(
        request,
        surface="api",
        method="GET",
        path="/v1/artifacts/{artifact_id}",
        kind="success",
        response=readback,
    )


def test_artifact_routes_enforce_scope_validation_and_device_ownership(
    request: pytest.FixtureRequest,
    harness,
) -> None:
    module, client, repository, _recognition, _database = harness
    module.api_app.dependency_overrides[module.get_device] = lambda: dataclasses.replace(
        _worker_device(),
        scopes=[],
    )
    denied = client.post("/v1/artifacts/upload-intents", json=_artifact_intent_body())
    assert denied.status_code == 403
    assert repository.intents == {}
    record_http_evidence(
        request,
        surface="api",
        method="POST",
        path="/v1/artifacts/upload-intents",
        kind="denial",
        response=denied,
    )

    module.api_app.dependency_overrides[module.get_device] = _worker_device
    invalid = client.post(
        "/v1/artifacts/upload-intents",
        json=_artifact_intent_body(expected_sha256="not-a-digest"),
    )
    assert invalid.status_code == 422
    assert repository.intents == {}
    record_http_evidence(
        request,
        surface="api",
        method="POST",
        path="/v1/artifacts/upload-intents",
        kind="validation",
        response=invalid,
    )

    intent = client.post("/v1/artifacts/upload-intents", json=_artifact_intent_body()).json()
    module.api_app.dependency_overrides[module.get_device] = lambda: dataclasses.replace(
        _worker_device(),
        scopes=[],
    )
    completion_denied = client.post(f"/v1/artifacts/{intent['artifact_id']}/complete")
    get_denied = client.get(f"/v1/artifacts/{intent['artifact_id']}")
    assert completion_denied.status_code == 403
    assert get_denied.status_code == 403
    record_http_evidence(
        request,
        surface="api",
        method="POST",
        path="/v1/artifacts/{artifact_id}/complete",
        kind="denial",
        response=completion_denied,
    )
    record_http_evidence(
        request,
        surface="api",
        method="GET",
        path="/v1/artifacts/{artifact_id}",
        kind="denial",
        response=get_denied,
    )

    module.api_app.dependency_overrides[module.get_device] = _worker_device
    invalid_completion = client.post("/v1/artifacts/not-a-uuid/complete")
    invalid_get = client.get("/v1/artifacts/not-a-uuid")
    assert invalid_completion.status_code == 400
    assert invalid_get.status_code == 400
    record_http_evidence(
        request,
        surface="api",
        method="POST",
        path="/v1/artifacts/{artifact_id}/complete",
        kind="validation",
        response=invalid_completion,
    )
    record_http_evidence(
        request,
        surface="api",
        method="GET",
        path="/v1/artifacts/{artifact_id}",
        kind="validation",
        response=invalid_get,
    )

    assert client.post(f"/v1/artifacts/{intent['artifact_id']}/complete").status_code == 200
    module.api_app.dependency_overrides[module.get_device] = lambda: dataclasses.replace(
        _worker_device(),
        device_id="bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
    )
    hidden = client.get(f"/v1/artifacts/{intent['artifact_id']}")
    assert hidden.status_code == 404


def test_recognition_observation_hypothesis_get_and_review_persist_lifecycle(
    request: pytest.FixtureRequest,
    harness,
) -> None:
    _module, client, _artifacts, state, _database = harness
    observation_response = client.post("/v1/recognition/observations", json=_observation_body())
    assert observation_response.status_code == 200, observation_response.text
    observation_id = observation_response.json()["observation_id"]
    persisted_observation = state.observations[observation_id]
    assert persisted_observation.state.value == "embedded"
    record_http_evidence(
        request,
        surface="api",
        method="POST",
        path="/v1/recognition/observations",
        kind="success",
        response=observation_response,
    )
    record_postcondition_evidence(
        request,
        surface="api",
        method="POST",
        path="/v1/recognition/observations",
        owner="RecognitionRepository",
        query="observations[observation_id]",
        record_ids={"observation_id": observation_id, "artifact_id": persisted_observation.artifact_id},
        assertions=["artifact-backed observation persisted in embedded state"],
    )

    hypothesis_response = client.post(
        f"/v1/recognition/observations/{observation_id}/hypotheses",
        json={
            "idempotency_key": f"recognition-hypothesis:{EVENT_ID}",
            "kind": "candidate",
            "candidate_person_id": PERSON_ID,
            "confidence": 0.96,
            "distance": 0.04,
            "rationale": "model evidence requires authenticated review",
            "requested_projection": True,
        },
    )
    assert hypothesis_response.status_code == 200, hypothesis_response.text
    hypothesis_id = hypothesis_response.json()["hypothesis_id"]
    assert state.hypotheses[hypothesis_id].decision == "proposed"
    record_http_evidence(
        request,
        surface="api",
        method="POST",
        path="/v1/recognition/observations/{observation_id}/hypotheses",
        kind="success",
        response=hypothesis_response,
    )
    record_postcondition_evidence(
        request,
        surface="api",
        method="POST",
        path="/v1/recognition/observations/{observation_id}/hypotheses",
        owner="RecognitionRepository",
        query="hypotheses[hypothesis_id]",
        record_ids={"observation_id": observation_id, "hypothesis_id": hypothesis_id},
        assertions=["candidate hypothesis persisted as proposed without an identity decision"],
    )

    proposed = client.get(f"/v1/recognition/hypotheses/{hypothesis_id}")
    assert proposed.status_code == 200, proposed.text
    assert proposed.json()["decision"] == "proposed"

    review = client.post(
        f"/v1/recognition/hypotheses/{hypothesis_id}/review",
        json={
            "decision": "accepted",
            "reason": "artifact provenance and active consent reviewed",
            "create_biometric_projection": True,
            "assert_presence": True,
        },
    )
    assert review.status_code == 200, review.text
    assert review.json()["reviewer_actor_id"] == "reviewer-user"
    assert state.hypotheses[hypothesis_id].decision == "accepted"
    assert state.observations[observation_id].state.value == "matched"
    record_http_evidence(
        request,
        surface="api",
        method="POST",
        path="/v1/recognition/hypotheses/{hypothesis_id}/review",
        kind="success",
        response=review,
    )
    record_postcondition_evidence(
        request,
        surface="api",
        method="POST",
        path="/v1/recognition/hypotheses/{hypothesis_id}/review",
        owner="RecognitionRepository",
        query="decisions[hypothesis_id] with hypothesis and observation readback",
        record_ids={"observation_id": observation_id, "hypothesis_id": hypothesis_id},
        assertions=[
            "review decision persisted with authenticated reviewer",
            "hypothesis transitioned to accepted",
            "observation transitioned to matched",
        ],
    )

    reviewed = client.get(f"/v1/recognition/hypotheses/{hypothesis_id}")
    assert reviewed.status_code == 200, reviewed.text
    assert reviewed.json()["decision"] == "accepted"
    assert reviewed.json()["reviewer_actor_id"] == "reviewer-user"
    record_http_evidence(
        request,
        surface="api",
        method="GET",
        path="/v1/recognition/hypotheses/{hypothesis_id}",
        kind="success",
        response=reviewed,
    )


def test_recognition_observation_denial_and_validation_leave_no_state(
    request: pytest.FixtureRequest,
    harness,
) -> None:
    module, client, _artifacts, state, _database = harness
    module.api_app.dependency_overrides[module.get_device] = lambda: _worker_device(kind="worker")
    denied = client.post("/v1/recognition/observations", json=_observation_body())
    assert denied.status_code == 403
    assert state.observations == {}
    record_http_evidence(
        request,
        surface="api",
        method="POST",
        path="/v1/recognition/observations",
        kind="denial",
        response=denied,
    )

    module.api_app.dependency_overrides[module.get_device] = _worker_device
    invalid = client.post(
        "/v1/recognition/observations",
        json=_observation_body(modality="unknown"),
    )
    assert invalid.status_code == 400
    assert state.observations == {}
    record_http_evidence(
        request,
        surface="api",
        method="POST",
        path="/v1/recognition/observations",
        kind="validation",
        response=invalid,
    )


def test_recognition_hypothesis_validation_has_no_persisted_side_effect(
    request: pytest.FixtureRequest,
    harness,
) -> None:
    module, client, _artifacts, state, _database = harness
    observation_response = client.post("/v1/recognition/observations", json=_observation_body())
    observation_id = observation_response.json()["observation_id"]

    module.api_app.dependency_overrides[module.get_device] = lambda: _worker_device(kind="worker")
    denied = client.post(
        f"/v1/recognition/observations/{observation_id}/hypotheses",
        json={
            "idempotency_key": f"recognition-hypothesis:{EVENT_ID}",
            "kind": "no_match",
            "confidence": 0.8,
            "rationale": "generic workers cannot submit recognition evidence",
        },
    )
    assert denied.status_code == 403
    record_http_evidence(
        request,
        surface="api",
        method="POST",
        path="/v1/recognition/observations/{observation_id}/hypotheses",
        kind="denial",
        response=denied,
    )

    module.api_app.dependency_overrides[module.get_device] = _worker_device

    invalid = client.post(
        f"/v1/recognition/observations/{observation_id}/hypotheses",
        json={
            "idempotency_key": f"recognition-hypothesis:{EVENT_ID}",
            "kind": "candidate",
            "confidence": 0.9,
            "rationale": "candidate omitted by malformed worker output",
        },
    )
    assert invalid.status_code == 400
    assert state.hypotheses == {}
    record_http_evidence(
        request,
        surface="api",
        method="POST",
        path="/v1/recognition/observations/{observation_id}/hypotheses",
        kind="validation",
        response=invalid,
    )


def test_recognition_hypothesis_get_and_review_require_admin_authorization(
    request: pytest.FixtureRequest,
    harness,
    monkeypatch,
) -> None:
    module, client, _artifacts, state, _database = harness
    observation_id = client.post("/v1/recognition/observations", json=_observation_body()).json()["observation_id"]
    hypothesis_id = client.post(
        f"/v1/recognition/observations/{observation_id}/hypotheses",
        json={
            "idempotency_key": f"recognition-hypothesis:{EVENT_ID}",
            "kind": "no_match",
            "candidate_person_id": None,
            "confidence": 0.8,
            "distance": None,
            "rationale": "no configured identity exceeded threshold",
        },
    ).json()["hypothesis_id"]
    monkeypatch.setattr(module, "check_agent_permission", lambda *_args, **_kwargs: False)

    denied_get = client.get(f"/v1/recognition/hypotheses/{hypothesis_id}")
    denied_review = client.post(
        f"/v1/recognition/hypotheses/{hypothesis_id}/review",
        json={
            "decision": "rejected",
            "reason": "reviewer lacks the owning agent role",
        },
    )
    assert denied_get.status_code == 403
    assert denied_review.status_code == 403
    assert state.hypotheses[hypothesis_id].decision == "proposed"
    record_http_evidence(
        request,
        surface="api",
        method="GET",
        path="/v1/recognition/hypotheses/{hypothesis_id}",
        kind="denial",
        response=denied_get,
    )
    record_http_evidence(
        request,
        surface="api",
        method="POST",
        path="/v1/recognition/hypotheses/{hypothesis_id}/review",
        kind="denial",
        response=denied_review,
    )

    invalid_get = client.get("/v1/recognition/hypotheses/not-a-uuid")
    assert invalid_get.status_code == 400
    record_http_evidence(
        request,
        surface="api",
        method="GET",
        path="/v1/recognition/hypotheses/{hypothesis_id}",
        kind="validation",
        response=invalid_get,
    )


def test_recognition_no_match_review_requires_explicit_retention(
    request: pytest.FixtureRequest,
    harness,
) -> None:
    _module, client, _artifacts, state, _database = harness
    observation_id = client.post("/v1/recognition/observations", json=_observation_body()).json()["observation_id"]
    hypothesis_id = client.post(
        f"/v1/recognition/observations/{observation_id}/hypotheses",
        json={
            "idempotency_key": f"recognition-hypothesis:{EVENT_ID}",
            "kind": "no_match",
            "confidence": 0.8,
            "rationale": "unknown identity",
        },
    ).json()["hypothesis_id"]

    invalid = client.post(
        f"/v1/recognition/hypotheses/{hypothesis_id}/review",
        json={"decision": "no_match", "reason": "retain unknown evidence for review"},
    )
    assert invalid.status_code == 400
    assert invalid.json()["detail"] == "no_match requires an explicit retention deadline"
    assert state.hypotheses[hypothesis_id].decision == "proposed"
    record_http_evidence(
        request,
        surface="api",
        method="POST",
        path="/v1/recognition/hypotheses/{hypothesis_id}/review",
        kind="validation",
        response=invalid,
    )


def test_recognition_worker_heartbeat_persists_owning_evidence(
    request: pytest.FixtureRequest,
    harness,
) -> None:
    _module, client, _artifacts, state, _database = harness
    response = client.post(
        "/v1/recognition/workers/recognition-cleanroom-1/heartbeat",
        json=_heartbeat_body(),
    )
    assert response.status_code == 200, response.text
    assert response.json()["heartbeat_id"] == "cdcdcdcd-cdcd-4dcd-8dcd-cdcdcdcdcdcd"
    persisted = state.heartbeats["recognition-cleanroom-1"]
    assert persisted.state == "ready"
    assert persisted.processed_messages == 4
    assert persisted.last_event_id == EVENT_ID
    record_http_evidence(
        request,
        surface="api",
        method="POST",
        path="/v1/recognition/workers/{worker_key}/heartbeat",
        kind="success",
        response=response,
    )
    record_postcondition_evidence(
        request,
        surface="api",
        method="POST",
        path="/v1/recognition/workers/{worker_key}/heartbeat",
        owner="RecognitionRepository",
        query="heartbeats[worker_id]",
        record_ids={
            "heartbeat_id": response.json()["heartbeat_id"],
            "worker_id": "recognition-cleanroom-1",
        },
        assertions=["immutable worker heartbeat evidence persisted with counters and source event"],
    )


def test_recognition_worker_heartbeat_rejects_unbound_or_invalid_evidence(
    request: pytest.FixtureRequest,
    harness,
) -> None:
    module, client, _artifacts, state, _database = harness
    unbound = client.post(
        "/v1/recognition/workers/recognition-cleanroom-1/heartbeat",
        json=_heartbeat_body(worker_id="another-worker"),
    )
    invalid = client.post(
        "/v1/recognition/workers/recognition-cleanroom-1/heartbeat",
        json=_heartbeat_body(state="invented"),
    )
    module.api_app.dependency_overrides[module.get_device] = lambda: _worker_device(kind="worker")
    denied = client.post(
        "/v1/recognition/workers/recognition-cleanroom-1/heartbeat",
        json=_heartbeat_body(),
    )
    assert unbound.status_code == 400
    assert invalid.status_code == 400
    assert denied.status_code == 403
    assert state.heartbeats == {}
    record_http_evidence(
        request,
        surface="api",
        method="POST",
        path="/v1/recognition/workers/{worker_key}/heartbeat",
        kind="validation",
        response=unbound,
    )
    record_http_evidence(
        request,
        surface="api",
        method="POST",
        path="/v1/recognition/workers/{worker_key}/heartbeat",
        kind="denial",
        response=denied,
    )
