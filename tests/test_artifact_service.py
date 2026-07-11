from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from agent_hub.artifact_service import (
    ArtifactLifecycleService,
    ArtifactLifecycleState,
    ArtifactObjectEvidence,
    ArtifactServiceError,
    ArtifactUploadIntent,
    VerifiedArtifact,
)

NOW = datetime(2026, 7, 11, 12, 0, tzinfo=timezone.utc)
DIGEST = "a" * 64


class FakeRepository:
    def __init__(self) -> None:
        self.intent: ArtifactUploadIntent | None = None
        self.completed: VerifiedArtifact | None = None

    def persist_upload_intent(self, intent: ArtifactUploadIntent) -> None:
        self.intent = intent

    def get_upload_intent(self, artifact_id: str) -> ArtifactUploadIntent:
        assert self.intent is not None and self.intent.artifact_id == artifact_id
        return self.intent

    def persist_verified_completion(self, artifact: VerifiedArtifact) -> None:
        self.completed = artifact


def _service() -> tuple[ArtifactLifecycleService, FakeRepository]:
    repository = FakeRepository()
    return ArtifactLifecycleService(repository, id_factory=lambda: "artifact-1"), repository


def _intent(service: ArtifactLifecycleService) -> ArtifactUploadIntent:
    return service.create_upload_intent(
        agent_id="agent-1",
        device_id="device-1",
        purpose="recognition",
        filename="voice.webm",
        media_type="audio/webm",
        bucket="artifact-bucket",
        expected_sha256=DIGEST,
        expected_byte_count=1024,
        created_at=NOW,
        upload_ttl_seconds=900,
        space_id="space-1",
        session_id="session-1",
        source_event_id="event-1",
    )


def test_upload_intent_is_explicit_and_durable() -> None:
    service, repository = _service()

    intent = _intent(service)

    assert repository.intent == intent
    assert intent.lifecycle_state is ArtifactLifecycleState.PENDING_UPLOAD
    assert intent.object_key == "recognition/agent_id=agent-1/artifact-1/voice.webm"
    assert intent.uri == f"s3://artifact-bucket/{intent.object_key}"
    assert intent.upload_expires_at == NOW + timedelta(seconds=900)


@pytest.mark.parametrize("purpose", ["", "other", None])
def test_upload_intent_rejects_unknown_or_missing_purpose(purpose: str | None) -> None:
    service, _ = _service()

    with pytest.raises(ArtifactServiceError, match="purpose must be"):
        service.create_upload_intent(
            agent_id="agent-1",
            device_id="device-1",
            purpose=purpose,
            filename="sample.bin",
            media_type="application/octet-stream",
            bucket="artifact-bucket",
            expected_sha256=DIGEST,
            expected_byte_count=1,
            created_at=NOW,
            upload_ttl_seconds=900,
        )


@pytest.mark.parametrize("filename", ["../secret", "folder/file", r"folder\file"])
def test_upload_intent_rejects_path_filenames(filename: str) -> None:
    service, _ = _service()

    with pytest.raises(ArtifactServiceError, match="must not contain a path"):
        service.create_upload_intent(
            agent_id="agent-1",
            device_id="device-1",
            purpose="general",
            filename=filename,
            media_type="application/octet-stream",
            bucket="artifact-bucket",
            expected_sha256=DIGEST,
            expected_byte_count=1,
            created_at=NOW,
            upload_ttl_seconds=900,
        )


def test_completion_requires_exact_object_evidence() -> None:
    service, repository = _service()
    intent = _intent(service)
    evidence = ArtifactObjectEvidence(
        bucket=intent.bucket,
        object_key=intent.object_key,
        sha256=DIGEST,
        byte_count=1024,
        etag="etag-1",
        version_id="version-1",
        media_type="audio/webm",
        observed_at=NOW + timedelta(seconds=30),
    )

    completed = service.verify_completion(
        artifact_id=intent.artifact_id,
        evidence=evidence,
        completed_at=NOW + timedelta(seconds=31),
    )

    assert repository.completed == completed
    assert completed.lifecycle_state is ArtifactLifecycleState.AVAILABLE
    assert completed.intent.lifecycle_state is ArtifactLifecycleState.AVAILABLE
    assert completed.actual_sha256 == DIGEST
    assert completed.verification_observed_at == evidence.observed_at


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("sha256", "b" * 64, "checksum"),
        ("byte_count", 2048, "size"),
        ("media_type", "audio/wav", "media type"),
        ("object_key", "wrong/key", "key"),
    ],
)
def test_completion_rejects_mismatched_evidence(field: str, value: object, message: str) -> None:
    service, _ = _service()
    intent = _intent(service)
    values = {
        "bucket": intent.bucket,
        "object_key": intent.object_key,
        "sha256": DIGEST,
        "byte_count": 1024,
        "etag": "etag-1",
        "version_id": "version-1",
        "media_type": "audio/webm",
        "observed_at": NOW + timedelta(seconds=30),
    }
    values[field] = value

    with pytest.raises(ArtifactServiceError, match=message):
        service.verify_completion(
            artifact_id=intent.artifact_id,
            evidence=ArtifactObjectEvidence(**values),
            completed_at=NOW + timedelta(seconds=31),
        )


def test_completion_rejects_expired_intent() -> None:
    service, _ = _service()
    intent = _intent(service)

    with pytest.raises(ArtifactServiceError, match="expired"):
        service.verify_completion(
            artifact_id=intent.artifact_id,
            evidence=ArtifactObjectEvidence(
                bucket=intent.bucket,
                object_key=intent.object_key,
                sha256=DIGEST,
                byte_count=1024,
                etag="etag-1",
                version_id="version-1",
                media_type="audio/webm",
                observed_at=NOW + timedelta(seconds=30),
            ),
            completed_at=NOW + timedelta(seconds=901),
        )
