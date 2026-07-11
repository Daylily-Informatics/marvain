"""RDS persistence boundary for verified artifact lifecycles."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from agent_hub.artifact_service import (
    ArtifactLifecycleState,
    ArtifactPurpose,
    ArtifactServiceError,
    ArtifactUploadIntent,
    VerifiedArtifact,
)
from agent_hub.rds_data import RdsData
from agent_hub.semantic_outbox import enqueue_semantic_record
from agent_hub.semantic_tapdb import TEMPLATE_CODES


def _datetime(value: Any, field: str) -> datetime:
    if isinstance(value, datetime):
        result = value
    elif isinstance(value, str):
        try:
            result = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError as exc:
            raise ArtifactServiceError(f"persisted {field} is invalid") from exc
    else:
        raise ArtifactServiceError(f"persisted {field} is invalid")
    if result.tzinfo is None or result.utcoffset() is None:
        raise ArtifactServiceError(f"persisted {field} must be timezone-aware")
    return result


def _optional_text(value: Any) -> str | None:
    normalized = str(value or "").strip()
    return normalized or None


class RdsArtifactRepository:
    def __init__(self, db: RdsData) -> None:
        self.db = db

    def persist_upload_intent(self, intent: ArtifactUploadIntent) -> None:
        tx = self.db.begin()
        try:
            rows = self.db.query(
                """
                INSERT INTO artifact_references(
                  artifact_id, agent_id, space_id, device_id, session_id, source_event_id,
                  purpose, filename, bucket, object_key, uri, media_type,
                  expected_sha256, expected_byte_count, lifecycle_state,
                  created_at, upload_expires_at
                ) VALUES (
                  :artifact_id::uuid, :agent_id::uuid,
                  NULLIF(CAST(:space_id AS text), '')::uuid,
                  :device_id::uuid,
                  NULLIF(CAST(:session_id AS text), '')::uuid,
                  NULLIF(CAST(:source_event_id AS text), '')::uuid,
                  :purpose, :filename, :bucket, :object_key, :uri, :media_type,
                  :expected_sha256, :expected_byte_count, 'pending_upload',
                  :created_at::timestamptz, :upload_expires_at::timestamptz
                )
                RETURNING artifact_id::TEXT AS artifact_id
                """,
                {
                    "artifact_id": intent.artifact_id,
                    "agent_id": intent.agent_id,
                    "space_id": intent.space_id,
                    "device_id": intent.device_id,
                    "session_id": intent.session_id,
                    "source_event_id": intent.source_event_id,
                    "purpose": intent.purpose.value,
                    "filename": intent.filename,
                    "bucket": intent.bucket,
                    "object_key": intent.object_key,
                    "uri": intent.uri,
                    "media_type": intent.media_type,
                    "expected_sha256": intent.expected_sha256,
                    "expected_byte_count": intent.expected_byte_count,
                    "created_at": intent.created_at.isoformat(),
                    "upload_expires_at": intent.upload_expires_at.isoformat(),
                },
                transaction_id=tx,
            )
            if not rows or str(rows[0].get("artifact_id") or "") != intent.artifact_id:
                raise ArtifactServiceError("artifact upload intent was not persisted")
            self.db.commit(tx)
        except Exception:
            self.db.rollback(tx)
            raise

    def get_upload_intent(self, artifact_id: str) -> ArtifactUploadIntent:
        rows = self.db.query(
            """
            SELECT artifact_id::TEXT AS artifact_id,
                   agent_id::TEXT AS agent_id,
                   space_id::TEXT AS space_id,
                   device_id::TEXT AS device_id,
                   session_id::TEXT AS session_id,
                   source_event_id::TEXT AS source_event_id,
                   purpose, filename, bucket, object_key, uri, media_type,
                   expected_sha256, expected_byte_count, lifecycle_state,
                   created_at::TEXT AS created_at,
                   upload_expires_at::TEXT AS upload_expires_at
            FROM artifact_references
            WHERE artifact_id = :artifact_id::uuid
            LIMIT 1
            """,
            {"artifact_id": artifact_id},
        )
        if not rows:
            raise ArtifactServiceError("artifact upload intent was not found")
        row = rows[0]
        try:
            purpose = ArtifactPurpose(str(row.get("purpose") or ""))
            state = ArtifactLifecycleState(str(row.get("lifecycle_state") or ""))
        except ValueError as exc:
            raise ArtifactServiceError("persisted artifact lifecycle is invalid") from exc
        return ArtifactUploadIntent(
            artifact_id=str(row["artifact_id"]),
            agent_id=str(row["agent_id"]),
            device_id=str(row["device_id"]),
            purpose=purpose,
            filename=str(row["filename"]),
            media_type=str(row["media_type"]),
            bucket=str(row["bucket"]),
            object_key=str(row["object_key"]),
            uri=str(row["uri"]),
            expected_sha256=str(row["expected_sha256"]),
            expected_byte_count=int(row["expected_byte_count"]),
            lifecycle_state=state,
            created_at=_datetime(row.get("created_at"), "created_at"),
            upload_expires_at=_datetime(row.get("upload_expires_at"), "upload_expires_at"),
            space_id=_optional_text(row.get("space_id")),
            session_id=_optional_text(row.get("session_id")),
            source_event_id=_optional_text(row.get("source_event_id")),
        )

    def persist_verified_completion(self, artifact: VerifiedArtifact) -> None:
        intent = artifact.intent
        tx = self.db.begin()
        try:
            rows = self.db.query(
                """
                UPDATE artifact_references
                SET actual_sha256 = :actual_sha256,
                    actual_byte_count = :actual_byte_count,
                    verification_observed_at = :verification_observed_at::timestamptz,
                    completed_at = :completed_at::timestamptz,
                    s3_version_id = :s3_version_id,
                    s3_etag = :s3_etag,
                    lifecycle_state = 'available'
                WHERE artifact_id = :artifact_id::uuid
                  AND agent_id = :agent_id::uuid
                  AND lifecycle_state = 'pending_upload'
                  AND expected_sha256 = :actual_sha256
                  AND expected_byte_count = :actual_byte_count
                  AND upload_expires_at >= :completed_at::timestamptz
                RETURNING artifact_id::TEXT AS artifact_id
                """,
                {
                    "artifact_id": intent.artifact_id,
                    "agent_id": intent.agent_id,
                    "actual_sha256": artifact.actual_sha256,
                    "actual_byte_count": artifact.actual_byte_count,
                    "verification_observed_at": artifact.verification_observed_at.isoformat(),
                    "completed_at": artifact.completed_at.isoformat(),
                    "s3_version_id": artifact.version_id,
                    "s3_etag": artifact.etag,
                },
                transaction_id=tx,
            )
            if not rows or str(rows[0].get("artifact_id") or "") != intent.artifact_id:
                raise ArtifactServiceError("verified artifact completion was not persisted")
            enqueue_semantic_record(
                self.db,
                transaction_id=tx,
                agent_id=intent.agent_id,
                source_table="artifact_references",
                source_id=intent.artifact_id,
                target_template_code=TEMPLATE_CODES["artifact_reference"],
                name=f"artifact:{intent.artifact_id}",
                lifecycle_state="available",
                properties={
                    "agent_id": intent.agent_id,
                    "artifact_id": intent.artifact_id,
                    "purpose": intent.purpose.value,
                    "media_type": intent.media_type,
                    "sha256": artifact.actual_sha256,
                    "byte_count": artifact.actual_byte_count,
                    "space_id": intent.space_id or "",
                    "session_id": intent.session_id or "",
                    "source_event_id": intent.source_event_id or "",
                },
            )
            self.db.commit(tx)
        except Exception:
            self.db.rollback(tx)
            raise


__all__ = ["RdsArtifactRepository"]
