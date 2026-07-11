"""Strict artifact upload and verification lifecycle contracts."""

from __future__ import annotations

import re
import uuid
from dataclasses import dataclass, replace
from datetime import datetime, timedelta, timezone
from enum import StrEnum
from pathlib import PurePath
from typing import Callable, Protocol


class ArtifactServiceError(ValueError):
    """Raised when artifact evidence violates the storage contract."""


class ArtifactPurpose(StrEnum):
    GENERAL = "general"
    RECOGNITION = "recognition"
    VISUAL = "visual"


class ArtifactLifecycleState(StrEnum):
    PENDING_UPLOAD = "pending_upload"
    AVAILABLE = "available"
    EXPIRED = "expired"
    REDACTED = "redacted"


_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


def _required(value: str | None, field: str) -> str:
    normalized = str(value or "").strip()
    if not normalized:
        raise ArtifactServiceError(f"{field} is required")
    return normalized


def _sha256(value: str, field: str) -> str:
    normalized = _required(value, field).lower()
    if not _SHA256_RE.fullmatch(normalized):
        raise ArtifactServiceError(f"{field} must be a lowercase SHA-256 digest")
    return normalized


def _aware(value: datetime, field: str) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ArtifactServiceError(f"{field} must be timezone-aware")
    return value


def _filename(value: str) -> str:
    normalized = _required(value, "filename")
    if PurePath(normalized).name != normalized or "/" in normalized or "\\" in normalized:
        raise ArtifactServiceError("filename must not contain a path")
    if normalized in {".", ".."}:
        raise ArtifactServiceError("filename is invalid")
    return normalized


@dataclass(frozen=True)
class ArtifactUploadIntent:
    artifact_id: str
    agent_id: str
    device_id: str
    purpose: ArtifactPurpose
    filename: str
    media_type: str
    bucket: str
    object_key: str
    uri: str
    expected_sha256: str
    expected_byte_count: int
    lifecycle_state: ArtifactLifecycleState
    created_at: datetime
    upload_expires_at: datetime
    space_id: str | None = None
    session_id: str | None = None
    source_event_id: str | None = None


@dataclass(frozen=True)
class ArtifactObjectEvidence:
    bucket: str
    object_key: str
    sha256: str
    byte_count: int
    etag: str
    version_id: str
    media_type: str
    observed_at: datetime


@dataclass(frozen=True)
class VerifiedArtifact:
    intent: ArtifactUploadIntent
    actual_sha256: str
    actual_byte_count: int
    etag: str
    version_id: str
    verification_observed_at: datetime
    completed_at: datetime
    lifecycle_state: ArtifactLifecycleState = ArtifactLifecycleState.AVAILABLE


class ArtifactRepository(Protocol):
    """Transactional persistence boundary for SQL, outbox, lineage, and audit."""

    def persist_upload_intent(self, intent: ArtifactUploadIntent) -> None: ...

    def get_upload_intent(self, artifact_id: str) -> ArtifactUploadIntent: ...

    def persist_verified_completion(self, artifact: VerifiedArtifact) -> None: ...


class ArtifactLifecycleService:
    def __init__(
        self,
        repository: ArtifactRepository,
        *,
        id_factory: Callable[[], str] | None = None,
    ) -> None:
        self.repository = repository
        self.id_factory = id_factory or (lambda: str(uuid.uuid4()))

    def create_upload_intent(
        self,
        *,
        agent_id: str,
        device_id: str,
        purpose: ArtifactPurpose | str,
        filename: str,
        media_type: str,
        bucket: str,
        expected_sha256: str,
        expected_byte_count: int,
        created_at: datetime | None = None,
        upload_ttl_seconds: int,
        space_id: str | None = None,
        session_id: str | None = None,
        source_event_id: str | None = None,
    ) -> ArtifactUploadIntent:
        try:
            resolved_purpose = ArtifactPurpose(str(purpose))
        except ValueError as exc:
            raise ArtifactServiceError("purpose must be general, recognition, or visual") from exc
        if not isinstance(expected_byte_count, int) or isinstance(expected_byte_count, bool) or expected_byte_count < 1:
            raise ArtifactServiceError("expected_byte_count must be a positive integer")
        if not isinstance(upload_ttl_seconds, int) or isinstance(upload_ttl_seconds, bool):
            raise ArtifactServiceError("upload_ttl_seconds must be an integer")
        if upload_ttl_seconds < 60 or upload_ttl_seconds > 3600:
            raise ArtifactServiceError("upload_ttl_seconds must be between 60 and 3600")

        artifact_id = _required(self.id_factory(), "artifact_id")
        agent_id = _required(agent_id, "agent_id")
        device_id = _required(device_id, "device_id")
        bucket = _required(bucket, "bucket")
        filename = _filename(filename)
        created_at = _aware(created_at or datetime.now(timezone.utc), "created_at")
        object_key = f"{resolved_purpose.value}/agent_id={agent_id}/{artifact_id}/{filename}"
        intent = ArtifactUploadIntent(
            artifact_id=artifact_id,
            agent_id=agent_id,
            device_id=device_id,
            purpose=resolved_purpose,
            filename=filename,
            media_type=_required(media_type, "media_type"),
            bucket=bucket,
            object_key=object_key,
            uri=f"s3://{bucket}/{object_key}",
            expected_sha256=_sha256(expected_sha256, "expected_sha256"),
            expected_byte_count=expected_byte_count,
            lifecycle_state=ArtifactLifecycleState.PENDING_UPLOAD,
            created_at=created_at,
            upload_expires_at=created_at + timedelta(seconds=upload_ttl_seconds),
            space_id=_required(space_id, "space_id") if space_id is not None else None,
            session_id=_required(session_id, "session_id") if session_id is not None else None,
            source_event_id=_required(source_event_id, "source_event_id") if source_event_id is not None else None,
        )
        self.repository.persist_upload_intent(intent)
        return intent

    def verify_completion(
        self,
        *,
        artifact_id: str,
        evidence: ArtifactObjectEvidence,
        completed_at: datetime | None = None,
    ) -> VerifiedArtifact:
        intent = self.repository.get_upload_intent(_required(artifact_id, "artifact_id"))
        if intent.lifecycle_state is not ArtifactLifecycleState.PENDING_UPLOAD:
            raise ArtifactServiceError("artifact is not awaiting upload completion")
        completed_at = _aware(completed_at or datetime.now(timezone.utc), "completed_at")
        if completed_at > intent.upload_expires_at:
            raise ArtifactServiceError("artifact upload intent has expired")
        if _required(evidence.bucket, "evidence.bucket") != intent.bucket:
            raise ArtifactServiceError("uploaded object bucket does not match intent")
        if _required(evidence.object_key, "evidence.object_key") != intent.object_key:
            raise ArtifactServiceError("uploaded object key does not match intent")
        if _required(evidence.media_type, "evidence.media_type") != intent.media_type:
            raise ArtifactServiceError("uploaded object media type does not match intent")
        if not isinstance(evidence.byte_count, int) or isinstance(evidence.byte_count, bool):
            raise ArtifactServiceError("evidence.byte_count must be an integer")
        if evidence.byte_count != intent.expected_byte_count:
            raise ArtifactServiceError("uploaded object size does not match intent")
        actual_sha256 = _sha256(evidence.sha256, "evidence.sha256")
        if actual_sha256 != intent.expected_sha256:
            raise ArtifactServiceError("uploaded object checksum does not match intent")
        _aware(evidence.observed_at, "evidence.observed_at")
        if evidence.observed_at > completed_at:
            raise ArtifactServiceError("object evidence cannot be observed after completion")

        artifact = VerifiedArtifact(
            intent=replace(intent, lifecycle_state=ArtifactLifecycleState.AVAILABLE),
            actual_sha256=actual_sha256,
            actual_byte_count=evidence.byte_count,
            etag=_required(evidence.etag, "evidence.etag"),
            version_id=_required(evidence.version_id, "evidence.version_id"),
            verification_observed_at=evidence.observed_at,
            completed_at=completed_at,
        )
        self.repository.persist_verified_completion(artifact)
        return artifact


__all__ = [
    "ArtifactLifecycleService",
    "ArtifactLifecycleState",
    "ArtifactObjectEvidence",
    "ArtifactPurpose",
    "ArtifactRepository",
    "ArtifactServiceError",
    "ArtifactUploadIntent",
    "VerifiedArtifact",
]
