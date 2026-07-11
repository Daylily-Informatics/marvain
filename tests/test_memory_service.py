"""Focused tests for memory commit state and hybrid recall scoring."""

from __future__ import annotations

import math
from dataclasses import FrozenInstanceError
from datetime import UTC, datetime, timedelta

import pytest
from agent_hub.memory_service import (
    HYBRID_RECALL_METHOD,
    MemoryAnnotation,
    MemoryAnnotationType,
    MemoryCommitDecision,
    MemoryCommitRecord,
    MemoryCommitState,
    MemoryEmbeddingFailure,
    MemoryEmbeddingReceipt,
    MemoryServiceError,
    MemorySourceContext,
    RecallCandidate,
    RecallContext,
    rank_hybrid_recall,
    score_hybrid_recall,
)

BASE_TIME = datetime(2026, 7, 10, 12, 0, tzinfo=UTC)


def _receipt(succeeded_at: datetime) -> MemoryEmbeddingReceipt:
    return MemoryEmbeddingReceipt(
        provider_id="openai",
        model="text-embedding-test",
        dimensions=1536,
        vector_sha256="a" * 64,
        succeeded_at=succeeded_at,
    )


def _decision(decided_at: datetime) -> MemoryCommitDecision:
    return MemoryCommitDecision(
        decision_id="decision-1",
        actor_type="user",
        actor_id="user-1",
        basis="manual_candidate_review_v1",
        decided_at=decided_at,
    )


def _candidate(
    memory_id: str,
    *,
    content: str = "Major prefers concise status reports during incidents.",
    created_at: datetime = BASE_TIME - timedelta(days=30),
    embedding_distance: float = 0.2,
    salience: float = 0.8,
    confidence: float = 0.9,
    space_id: str | None = "space-1",
) -> RecallCandidate:
    return RecallCandidate(
        memory_id=memory_id,
        content=content,
        created_at=created_at,
        embedding_distance=embedding_distance,
        salience=salience,
        confidence=confidence,
        source_context=MemorySourceContext(
            source_evidence_id=f"event-{memory_id}",
            provenance_class="external_interaction",
            space_id=space_id,
            session_id="session-1",
            person_id="person-1",
            device_id="device-1",
        ),
        lifecycle_state=MemoryCommitState.COMMITTED,
    )


def _annotation(annotation_id: str, memory_id: str, weight_delta: float) -> MemoryAnnotation:
    return MemoryAnnotation(
        annotation_id=annotation_id,
        memory_id=memory_id,
        annotation_type=MemoryAnnotationType.DOWNWEIGHT,
        weight_delta=weight_delta,
        author_id="user-1",
        created_at=BASE_TIME,
    )


def test_memory_commit_cannot_skip_embedding_success() -> None:
    record = MemoryCommitRecord.create(
        candidate_id="candidate-1",
        source_evidence_id="event-1",
        created_at=BASE_TIME,
    )

    with pytest.raises(MemoryServiceError, match="embedding_required"):
        record.commit(_decision(BASE_TIME + timedelta(seconds=1)))

    pending = record.begin_embedding(
        request_id="embedding-request-1",
        requested_at=BASE_TIME + timedelta(seconds=1),
    )
    with pytest.raises(MemoryServiceError, match="embedding_required"):
        pending.commit(_decision(BASE_TIME + timedelta(seconds=2)))

    embedded = pending.embedding_succeeded(_receipt(BASE_TIME + timedelta(seconds=2)))
    committed = embedded.commit(_decision(BASE_TIME + timedelta(seconds=3)))

    assert record.state is MemoryCommitState.CANDIDATE
    assert pending.state is MemoryCommitState.EMBEDDING_PENDING
    assert embedded.state is MemoryCommitState.EMBEDDED
    assert committed.state is MemoryCommitState.COMMITTED
    assert committed.embedding_receipt is not None
    assert committed.commit_decision is not None
    assert [transition.to_state for transition in committed.transitions] == [
        MemoryCommitState.EMBEDDING_PENDING,
        MemoryCommitState.EMBEDDED,
        MemoryCommitState.COMMITTED,
    ]


def test_memory_commit_constructor_rejects_committed_state_without_transition_receipts() -> None:
    with pytest.raises(MemoryServiceError, match="state does not match transition history"):
        MemoryCommitRecord(
            candidate_id="candidate-1",
            source_evidence_id="event-1",
            created_at=BASE_TIME,
            state=MemoryCommitState.COMMITTED,
        )


def test_embedding_failure_record_is_preserved_across_retry_and_commit() -> None:
    initial = MemoryCommitRecord.create(
        candidate_id="candidate-2",
        source_evidence_id="event-2",
        created_at=BASE_TIME,
    )
    first_pending = initial.begin_embedding(
        request_id="embedding-request-1",
        requested_at=BASE_TIME + timedelta(seconds=1),
    )
    failure = MemoryEmbeddingFailure(
        code="provider_timeout",
        message="embedding provider timed out",
        retryable=True,
        failed_at=BASE_TIME + timedelta(seconds=2),
        details=(("provider", "openai"),),
    )
    failed = first_pending.embedding_failed(failure)

    assert failed.state is MemoryCommitState.EMBEDDING_FAILED
    assert failed.embedding_failures == (failure,)
    assert failure.as_record()["status"] == "embedding_failed"

    retry_pending = failed.begin_embedding(
        request_id="embedding-request-2",
        requested_at=BASE_TIME + timedelta(seconds=3),
    )
    embedded = retry_pending.embedding_succeeded(_receipt(BASE_TIME + timedelta(seconds=4)))
    committed = embedded.commit(_decision(BASE_TIME + timedelta(seconds=5)))

    assert committed.state is MemoryCommitState.COMMITTED
    assert committed.embedding_failures == (failure,)
    assert [transition.to_state for transition in committed.transitions] == [
        MemoryCommitState.EMBEDDING_PENDING,
        MemoryCommitState.EMBEDDING_FAILED,
        MemoryCommitState.EMBEDDING_PENDING,
        MemoryCommitState.EMBEDDED,
        MemoryCommitState.COMMITTED,
    ]


def test_hybrid_score_explains_every_feature_and_annotation_contribution() -> None:
    candidate = _candidate("memory-1")
    annotation = _annotation("annotation-1", candidate.memory_id, -0.25)
    context = RecallContext(
        space_id="space-1",
        session_id="session-1",
        person_id="person-1",
        device_id="device-1",
        provenance_class="external_interaction",
    )

    score = score_hybrid_recall(
        query="concise status reports",
        candidate=candidate,
        context=context,
        annotations=(annotation,),
        now=BASE_TIME,
    )
    explanation = score.as_explanation(rank=1)
    ranking = explanation["ranking"]

    assert ranking["method"] == HYBRID_RECALL_METHOD
    assert ranking["rank"] == 1
    assert set(ranking["features"]) == {
        "embedding",
        "keyword",
        "recency",
        "salience",
        "confidence",
        "source_context",
        "annotation_adjustment",
    }
    assert math.isclose(score.features.embedding, 0.9)
    assert math.isclose(score.features.keyword, 1.0)
    assert math.isclose(score.features.recency, 0.5)
    assert math.isclose(score.features.source_context, 1.0)
    assert score.features.annotation_adjustment == -0.25
    assert math.isclose(sum(ranking["contributions"].values()), score.raw_score)
    assert ranking["annotation_adjustment"]["annotations"] == [
        {
            "annotation_id": "annotation-1",
            "annotation_type": "downweight",
            "weight_delta": -0.25,
        }
    ]
    assert all(item["matched"] for item in ranking["source_context"]["matches"])
    assert explanation["source_evidence_id"] == "event-memory-1"


def test_annotation_adjustment_is_derived_without_mutating_memory_or_annotation() -> None:
    candidate = _candidate("memory-2")
    annotation = _annotation("annotation-2", candidate.memory_id, -0.4)
    original_content = candidate.content

    without_annotation = score_hybrid_recall(
        query="concise status reports",
        candidate=candidate,
        context=RecallContext(space_id="space-1"),
        annotations=(),
        now=BASE_TIME,
    )
    with_annotation = score_hybrid_recall(
        query="concise status reports",
        candidate=candidate,
        context=RecallContext(space_id="space-1"),
        annotations=(annotation,),
        now=BASE_TIME,
    )

    assert math.isclose(without_annotation.raw_score - with_annotation.raw_score, 0.4 * 0.15)
    assert candidate.content == original_content
    assert annotation.weight_delta == -0.4
    with pytest.raises(FrozenInstanceError):
        annotation.weight_delta = 0.0
    with pytest.raises(FrozenInstanceError):
        candidate.content = "mutated"


def test_annotation_total_clamps_transparently() -> None:
    candidate = _candidate("memory-3")

    score = score_hybrid_recall(
        query="concise status reports",
        candidate=candidate,
        context=RecallContext(space_id="space-1"),
        annotations=(
            _annotation("annotation-a", candidate.memory_id, -0.8),
            _annotation("annotation-b", candidate.memory_id, -0.8),
        ),
        now=BASE_TIME,
    )

    assert math.isclose(score.annotation_adjustment.raw_adjustment, -1.6)
    assert score.annotation_adjustment.applied_adjustment == -1.0
    assert score.annotation_adjustment.clamped is True


def test_hybrid_ranking_can_reorder_embedding_results_using_immutable_annotations() -> None:
    initially_best = _candidate("memory-a")
    second = _candidate(
        "memory-b",
        embedding_distance=0.4,
        salience=0.6,
        confidence=0.8,
    )
    context = RecallContext(space_id="space-1")

    unannotated = rank_hybrid_recall(
        query="concise status reports",
        candidates=(initially_best, second),
        context=context,
        annotations=(),
        now=BASE_TIME,
    )
    annotated = rank_hybrid_recall(
        query="concise status reports",
        candidates=(initially_best, second),
        context=context,
        annotations=(_annotation("annotation-rank", "memory-a", -1.0),),
        now=BASE_TIME,
    )

    assert [item.candidate.memory_id for item in unannotated] == ["memory-a", "memory-b"]
    assert [item.candidate.memory_id for item in annotated] == ["memory-b", "memory-a"]
    assert annotated[0].as_explanation()["ranking"]["rank"] == 1


def test_recall_rejects_noncommitted_candidate() -> None:
    with pytest.raises(MemoryServiceError, match="recall candidates must be committed"):
        RecallCandidate(
            memory_id="memory-pending",
            content="Not ready for recall.",
            created_at=BASE_TIME,
            embedding_distance=0.2,
            salience=0.5,
            confidence=0.5,
            source_context=MemorySourceContext(
                source_evidence_id="event-pending",
                provenance_class="external_interaction",
            ),
            lifecycle_state=MemoryCommitState.EMBEDDED,
        )
