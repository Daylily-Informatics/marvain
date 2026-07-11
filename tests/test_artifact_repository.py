from __future__ import annotations

from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

import pytest
from agent_hub.artifact_service import (
    ArtifactLifecycleState,
    ArtifactPurpose,
    ArtifactServiceError,
    ArtifactUploadIntent,
    VerifiedArtifact,
)

from functions.hub_api.artifact_repository import RdsArtifactRepository

NOW = datetime(2026, 7, 11, 12, 0, tzinfo=timezone.utc)
DIGEST = "a" * 64


def _intent(state: ArtifactLifecycleState = ArtifactLifecycleState.PENDING_UPLOAD) -> ArtifactUploadIntent:
    return ArtifactUploadIntent(
        artifact_id="11111111-1111-4111-8111-111111111111",
        agent_id="22222222-2222-4222-8222-222222222222",
        device_id="33333333-3333-4333-8333-333333333333",
        purpose=ArtifactPurpose.RECOGNITION,
        filename="voice.webm",
        media_type="audio/webm",
        bucket="artifacts",
        object_key="recognition/agent_id=agent/111/voice.webm",
        uri="s3://artifacts/recognition/agent_id=agent/111/voice.webm",
        expected_sha256=DIGEST,
        expected_byte_count=1024,
        lifecycle_state=state,
        created_at=NOW,
        upload_expires_at=NOW + timedelta(minutes=15),
        space_id="44444444-4444-4444-8444-444444444444",
        session_id="55555555-5555-4555-8555-555555555555",
        source_event_id="66666666-6666-4666-8666-666666666666",
    )


def test_upload_intent_commits_without_premature_semantic_record() -> None:
    db = MagicMock()
    db.begin.return_value = "tx-1"
    db.query.return_value = [{"artifact_id": _intent().artifact_id}]
    repository = RdsArtifactRepository(db)

    with patch("functions.hub_api.artifact_repository.enqueue_semantic_record") as enqueue:
        repository.persist_upload_intent(_intent())

    db.commit.assert_called_once_with("tx-1")
    db.rollback.assert_not_called()
    enqueue.assert_not_called()
    assert "pending_upload" in db.query.call_args.args[0]
    assert db.query.call_args.kwargs["transaction_id"] == "tx-1"


def test_upload_intent_failure_rolls_back() -> None:
    db = MagicMock()
    db.begin.return_value = "tx-1"
    db.query.return_value = []
    repository = RdsArtifactRepository(db)

    with pytest.raises(ArtifactServiceError, match="was not persisted"):
        repository.persist_upload_intent(_intent())

    db.rollback.assert_called_once_with("tx-1")
    db.commit.assert_not_called()


def test_get_upload_intent_rejects_malformed_persisted_state() -> None:
    db = MagicMock()
    db.query.return_value = [
        {
            "artifact_id": _intent().artifact_id,
            "agent_id": _intent().agent_id,
            "device_id": _intent().device_id,
            "purpose": "unknown",
            "lifecycle_state": "pending_upload",
        }
    ]

    with pytest.raises(ArtifactServiceError, match="persisted artifact lifecycle is invalid"):
        RdsArtifactRepository(db).get_upload_intent(_intent().artifact_id)


def test_verified_completion_and_semantic_outbox_share_transaction() -> None:
    db = MagicMock()
    db.begin.return_value = "tx-2"
    db.query.return_value = [{"artifact_id": _intent().artifact_id}]
    repository = RdsArtifactRepository(db)
    verified = VerifiedArtifact(
        intent=_intent(ArtifactLifecycleState.AVAILABLE),
        actual_sha256=DIGEST,
        actual_byte_count=1024,
        etag="etag-1",
        version_id="version-1",
        verification_observed_at=NOW + timedelta(seconds=29),
        completed_at=NOW + timedelta(seconds=30),
    )

    with patch("functions.hub_api.artifact_repository.enqueue_semantic_record") as enqueue:
        repository.persist_verified_completion(verified)

    db.commit.assert_called_once_with("tx-2")
    enqueue.assert_called_once()
    assert enqueue.call_args.kwargs["transaction_id"] == "tx-2"
    assert enqueue.call_args.kwargs["source_table"] == "artifact_references"
    assert enqueue.call_args.kwargs["lifecycle_state"] == "available"
    assert "upload_expires_at >=" in db.query.call_args.args[0]
