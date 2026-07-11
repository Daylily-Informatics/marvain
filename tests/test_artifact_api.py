from __future__ import annotations

import base64
import dataclasses
import importlib.util
import os
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock

import pytest
from agent_hub.artifact_service import (
    ArtifactLifecycleState,
    ArtifactServiceError,
    ArtifactUploadIntent,
    VerifiedArtifact,
)
from agent_hub.auth import AuthenticatedDevice
from fastapi.testclient import TestClient

ROOT = Path(__file__).resolve().parents[1]
HUB_API_DIR = ROOT / "functions" / "hub_api"
if str(HUB_API_DIR) not in sys.path:
    sys.path.insert(0, str(HUB_API_DIR))

AGENT_ID = "11111111-1111-4111-8111-111111111111"
SPACE_ID = "22222222-2222-4222-8222-222222222222"
SESSION_ID = "33333333-3333-4333-8333-333333333333"
EVENT_ID = "44444444-4444-4444-8444-444444444444"
DEVICE_ID = "55555555-5555-4555-8555-555555555555"
DIGEST = "a" * 64


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
    os.environ.setdefault("SESSION_SECRET_KEY", "artifact-api-test-secret")
    path = HUB_API_DIR / "api_app.py"
    spec = importlib.util.spec_from_file_location("hub_api_artifact_tests", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    with mock.patch("boto3.client", return_value=mock.Mock()):
        spec.loader.exec_module(module)
    return module


class ArtifactContextDb:
    def __init__(self) -> None:
        self.event_exists = True

    def query(self, sql: str, params: dict | None = None, **_kwargs):
        normalized = " ".join(sql.lower().split())
        if "from events" in normalized:
            if not self.event_exists:
                return []
            assert params == {"source_event_id": EVENT_ID, "agent_id": AGENT_ID}
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
        raise AssertionError(f"unexpected query: {normalized}")


class FakeArtifactRepository:
    def __init__(self, sequence: list[str]) -> None:
        self.sequence = sequence
        self.intents: dict[str, ArtifactUploadIntent] = {}
        self.verified: dict[str, VerifiedArtifact] = {}
        self.persist_count = 0
        self.race_on_intent = False
        self.race_on_completion = False

    def persist_upload_intent(self, intent: ArtifactUploadIntent) -> None:
        self.sequence.append("persist_intent")
        self.persist_count += 1
        if intent.artifact_id in self.intents:
            raise ArtifactServiceError("artifact upload intent was not persisted")
        self.intents[intent.artifact_id] = intent
        if self.race_on_intent:
            raise RuntimeError("simulated insert race")

    def get_upload_intent(self, artifact_id: str) -> ArtifactUploadIntent:
        try:
            return self.intents[artifact_id]
        except KeyError as exc:
            raise ArtifactServiceError("artifact upload intent was not found") from exc

    def persist_verified_completion(self, artifact: VerifiedArtifact) -> None:
        available = dataclasses.replace(
            artifact,
            intent=dataclasses.replace(artifact.intent, lifecycle_state=ArtifactLifecycleState.AVAILABLE),
        )
        self.intents[artifact.intent.artifact_id] = available.intent
        self.verified[artifact.intent.artifact_id] = available
        if self.race_on_completion:
            raise ArtifactServiceError("verified artifact completion was not persisted")

    def get_verified_artifact(self, artifact_id: str) -> VerifiedArtifact:
        try:
            return self.verified[artifact_id]
        except KeyError as exc:
            raise ArtifactServiceError("artifact is not verified and available") from exc


class FakeS3:
    def __init__(self, repository: FakeArtifactRepository) -> None:
        self.repository = repository
        self.presign_calls: list[dict] = []
        self.head_calls: list[dict] = []
        self.head_response: dict = {
            "ContentLength": 1024,
            "ContentType": "audio/webm",
            "Metadata": {"sha256": DIGEST},
            "ChecksumSHA256": base64.b64encode(bytes.fromhex(DIGEST)).decode("ascii"),
            "ETag": '"etag-1"',
            "VersionId": "version-1",
        }

    def generate_presigned_url(self, **kwargs) -> str:
        assert self.repository.persist_count == 1
        self.repository.sequence.append("presign")
        self.presign_calls.append(kwargs)
        return "https://artifact-upload.example.test/signed"

    def head_object(self, **kwargs) -> dict:
        self.head_calls.append(kwargs)
        return self.head_response


@pytest.fixture(scope="module")
def api_module():
    return _load_api_module()


@pytest.fixture()
def harness(api_module, monkeypatch):
    sequence: list[str] = []
    repository = FakeArtifactRepository(sequence)
    database = ArtifactContextDb()
    s3 = FakeS3(repository)
    device = AuthenticatedDevice(
        device_id=DEVICE_ID,
        agent_id=AGENT_ID,
        scopes=["artifacts:write"],
        capabilities={"kind": "worker"},
    )
    api_module.api_app.dependency_overrides.clear()
    api_module.api_app.dependency_overrides[api_module.get_device] = lambda: device
    monkeypatch.setattr(api_module, "_cfg", dataclasses.replace(api_module._cfg, artifact_bucket="artifact-test"))
    monkeypatch.setattr(api_module, "_get_db", lambda: database)
    monkeypatch.setattr(api_module, "RdsArtifactRepository", lambda _db: repository)
    monkeypatch.setattr(api_module, "_get_s3", lambda: s3)
    yield api_module, TestClient(api_module.api_app, raise_server_exceptions=False), repository, database, s3
    api_module.api_app.dependency_overrides.clear()


def _intent_body(**overrides) -> dict:
    body = {
        "idempotency_key": "voice-sample-1",
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


def _create_intent(client: TestClient) -> dict:
    response = client.post("/v1/artifacts/upload-intents", json=_intent_body())
    assert response.status_code == 201, response.text
    return response.json()


def test_upload_intent_is_persisted_before_exact_presign(harness) -> None:
    _module, client, repository, _database, s3 = harness

    payload = _create_intent(client)

    assert repository.sequence == ["persist_intent", "presign"]
    assert payload["lifecycle_state"] == "pending_upload"
    assert payload["source_event_id"] == EVENT_ID
    assert payload["upload_url"].startswith("https://")
    assert payload["required_headers"]["x-amz-meta-sha256"] == DIGEST
    params = s3.presign_calls[0]["Params"]
    assert params["Bucket"] == "artifact-test"
    assert params["Key"] == payload["object_key"]
    assert params["ContentType"] == "audio/webm"
    assert params["ContentLength"] == 1024
    assert params["Metadata"] == {"sha256": DIGEST}
    assert params["ChecksumSHA256"] == payload["required_headers"]["x-amz-checksum-sha256"]


def test_weak_presign_route_is_removed(harness) -> None:
    _module, client, _repository, _database, _s3 = harness

    response = client.post("/v1/artifacts/presign", json={"filename": "sample.bin"})

    assert response.status_code == 405
    assert "/v1/artifacts/presign" not in client.get("/openapi.json").json()["paths"]


def test_upload_intent_rejects_missing_scope(harness) -> None:
    module, client, repository, _database, _s3 = harness
    module.api_app.dependency_overrides[module.get_device] = lambda: AuthenticatedDevice(
        device_id=DEVICE_ID,
        agent_id=AGENT_ID,
        scopes=[],
        capabilities={"kind": "worker"},
    )

    response = client.post("/v1/artifacts/upload-intents", json=_intent_body())

    assert response.status_code == 403
    assert repository.persist_count == 0


def test_upload_intent_does_not_normalize_invalid_purpose(harness) -> None:
    _module, client, repository, _database, _s3 = harness

    response = client.post("/v1/artifacts/upload-intents", json=_intent_body(purpose="unknown"))

    assert response.status_code == 422
    assert repository.persist_count == 0


def test_upload_intent_requires_owned_source_event(harness) -> None:
    _module, client, repository, database, _s3 = harness
    database.event_exists = False

    response = client.post("/v1/artifacts/upload-intents", json=_intent_body())

    assert response.status_code == 404
    assert response.json()["detail"] == "Source event was not found for the artifact agent"
    assert repository.persist_count == 0


def test_upload_intent_is_idempotent_and_rejects_changed_replay(harness) -> None:
    _module, client, repository, _database, _s3 = harness
    first = _create_intent(client)

    replay = client.post("/v1/artifacts/upload-intents", json=_intent_body())
    conflict = client.post(
        "/v1/artifacts/upload-intents",
        json=_intent_body(expected_byte_count=2048),
    )

    assert replay.status_code == 201
    assert replay.json()["artifact_id"] == first["artifact_id"]
    assert replay.json()["replayed"] is True
    assert repository.persist_count == 1
    assert conflict.status_code == 409


def test_upload_intent_insert_race_returns_matching_persisted_intent(harness) -> None:
    _module, client, repository, _database, _s3 = harness
    repository.race_on_intent = True

    response = client.post("/v1/artifacts/upload-intents", json=_intent_body())

    assert response.status_code == 201, response.text
    assert response.json()["replayed"] is True
    assert repository.persist_count == 1


def test_completion_uses_only_owning_s3_head_evidence(harness) -> None:
    _module, client, repository, _database, s3 = harness
    intent = _create_intent(client)

    response = client.post(
        f"/v1/artifacts/{intent['artifact_id']}/complete",
        json={"sha256": "b" * 64, "byte_count": 1, "etag": "client-value"},
    )

    assert response.status_code == 200, response.text
    payload = response.json()
    assert payload["actual_sha256"] == DIGEST
    assert payload["actual_byte_count"] == 1024
    assert payload["etag"] == '"etag-1"'
    assert payload["version_id"] == "version-1"
    assert payload["replayed"] is False
    assert s3.head_calls == [
        {
            "Bucket": intent["bucket"],
            "Key": intent["object_key"],
            "ChecksumMode": "ENABLED",
        }
    ]
    assert repository.verified[intent["artifact_id"]].actual_sha256 == DIGEST


def test_completion_rejects_malformed_or_mismatched_s3_evidence(harness) -> None:
    _module, client, _repository, _database, s3 = harness
    intent = _create_intent(client)
    s3.head_response.pop("ChecksumSHA256")

    malformed = client.post(f"/v1/artifacts/{intent['artifact_id']}/complete")

    assert malformed.status_code == 502
    assert "valid SHA-256 checksum" in malformed.json()["detail"]


def test_completion_rejects_checksum_mismatch(harness) -> None:
    _module, client, _repository, _database, s3 = harness
    intent = _create_intent(client)
    other_digest = "b" * 64
    s3.head_response["Metadata"] = {"sha256": other_digest}
    s3.head_response["ChecksumSHA256"] = base64.b64encode(bytes.fromhex(other_digest)).decode("ascii")

    response = client.post(f"/v1/artifacts/{intent['artifact_id']}/complete")

    assert response.status_code == 409
    assert "checksum" in response.json()["detail"]


def test_completion_rejects_expired_intent_without_s3_call(harness) -> None:
    _module, client, repository, _database, s3 = harness
    payload = _create_intent(client)
    artifact_id = payload["artifact_id"]
    repository.intents[artifact_id] = dataclasses.replace(
        repository.intents[artifact_id],
        upload_expires_at=datetime.now(timezone.utc) - timedelta(seconds=1),
    )

    response = client.post(f"/v1/artifacts/{artifact_id}/complete")

    assert response.status_code == 409
    assert s3.head_calls == []


def test_completion_race_replays_matching_persisted_evidence(harness) -> None:
    _module, client, repository, _database, _s3 = harness
    payload = _create_intent(client)
    repository.race_on_completion = True

    response = client.post(f"/v1/artifacts/{payload['artifact_id']}/complete")

    assert response.status_code == 200, response.text
    assert response.json()["replayed"] is True


def test_verified_artifact_get_proves_persisted_postcondition(harness) -> None:
    _module, client, _repository, _database, _s3 = harness
    payload = _create_intent(client)
    completed = client.post(f"/v1/artifacts/{payload['artifact_id']}/complete")
    assert completed.status_code == 200

    response = client.get(f"/v1/artifacts/{payload['artifact_id']}")

    assert response.status_code == 200
    assert response.json()["lifecycle_state"] == "available"
    assert response.json()["actual_sha256"] == DIGEST


def test_verified_artifact_is_not_visible_to_another_device(harness) -> None:
    module, client, _repository, _database, _s3 = harness
    payload = _create_intent(client)
    assert client.post(f"/v1/artifacts/{payload['artifact_id']}/complete").status_code == 200
    module.api_app.dependency_overrides[module.get_device] = lambda: AuthenticatedDevice(
        device_id="66666666-6666-4666-8666-666666666666",
        agent_id=AGENT_ID,
        scopes=["artifacts:write"],
        capabilities={"kind": "worker"},
    )

    response = client.get(f"/v1/artifacts/{payload['artifact_id']}")

    assert response.status_code == 404
