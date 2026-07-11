"""Evidence and immutability tests for agent-owned memory learning."""

from __future__ import annotations

import inspect
from dataclasses import FrozenInstanceError, fields
from datetime import UTC, datetime, timedelta

import pytest
from agent_hub.auth import AuthenticatedAgent, AuthenticatedUser
from agent_hub.memory_learning import (
    MEMORY_LEARNING_SCOPE,
    CandidateOrigin,
    DerivedMemoryCandidate,
    ImmutableMemoryReference,
    MemoryConfidenceAssessment,
    MemoryLearningError,
    RankingDisposition,
    RankingPolicyMode,
    SourceEventReference,
    append_confidence_assessment,
    apply_ranking_policy,
    derive_self_reflection_candidate,
    propose_memory_consolidation,
    ranking_disposition_at,
    ranking_multiplier_at,
    record_memory_contradiction,
    restore_ranking_policy,
    schedule_self_reflection,
)

NOW = datetime(2026, 7, 11, 12, 0, tzinfo=UTC)


def _agent(agent_id: str = "agent-1", *, scopes: list[str] | None = None) -> AuthenticatedAgent:
    return AuthenticatedAgent(
        token_id=f"token:{agent_id}",
        issuer_agent_id=agent_id,
        target_agent_id=agent_id,
        scopes=[MEMORY_LEARNING_SCOPE] if scopes is None else scopes,
        allowed_spaces=[],
    )


def _event(
    event_id: str,
    *,
    owner: str = "agent-1",
    occurred_at: datetime = NOW,
    digest_character: str = "a",
) -> SourceEventReference:
    return SourceEventReference(
        event_id=event_id,
        owning_agent_id=owner,
        payload_sha256=digest_character * 64,
        occurred_at=occurred_at,
    )


def _memory(
    memory_id: str,
    *event_ids: str,
    owner: str = "agent-1",
    committed_at: datetime = NOW + timedelta(seconds=1),
    digest_character: str = "b",
) -> ImmutableMemoryReference:
    return ImmutableMemoryReference(
        memory_id=memory_id,
        owning_agent_id=owner,
        content_sha256=digest_character * 64,
        source_event_ids=tuple(event_ids),
        committed_at=committed_at,
    )


def _reflection_request():
    event = _event("event-1")
    memory = _memory("memory-1", event.event_id)
    request = schedule_self_reflection(
        authenticated_agent=_agent(),
        owning_agent_id="agent-1",
        request_id="reflection-1",
        source_memories=(memory,),
        source_events=(event,),
        objective="Reconsider this memory in light of its source evidence.",
        requested_at=NOW + timedelta(seconds=2),
        scheduled_for=NOW + timedelta(hours=1),
    )
    return request, memory, event


def test_source_references_require_content_addressed_persisted_evidence() -> None:
    event = _event("event-1")
    memory = _memory("memory-1", "event-1")

    assert event.payload_sha256 == "a" * 64
    assert memory.content_sha256 == "b" * 64
    assert memory.source_event_ids == ("event-1",)

    with pytest.raises(MemoryLearningError, match="invalid_digest"):
        _event("event-2", digest_character="x")
    with pytest.raises(MemoryLearningError, match="source_event_ids must contain unique"):
        _memory("memory-2", "event-1", "event-1")
    with pytest.raises(MemoryLearningError, match="timezone-aware"):
        _event("event-3", occurred_at=datetime(2026, 7, 11, 12, 0))


def test_schedule_self_reflection_binds_authenticated_owner_and_all_sources() -> None:
    request, memory, event = _reflection_request()

    assert request.request_id == "reflection-1"
    assert request.authenticated_agent_id == "agent-1"
    assert request.authentication_id == "token:agent-1"
    assert request.source_memories == (memory,)
    assert request.source_events == (event,)
    assert request.scheduled_for == NOW + timedelta(hours=1)


@pytest.mark.parametrize(
    ("authenticated", "error_code"),
    [
        (_agent("agent-2"), "memory_owner_mismatch"),
        (_agent(scopes=["memory:read"]), "memory_learning_scope_required"),
        (
            AuthenticatedUser(user_id="user-1", cognito_sub="sub-1", email="user@example.test"),
            "agent_authentication_required",
        ),
    ],
)
def test_schedule_self_reflection_denies_non_owner_unscoped_and_human_actors(
    authenticated: object,
    error_code: str,
) -> None:
    event = _event("event-1")
    memory = _memory("memory-1", event.event_id)

    with pytest.raises(MemoryLearningError, match=error_code):
        schedule_self_reflection(
            authenticated_agent=authenticated,
            owning_agent_id="agent-1",
            request_id="reflection-1",
            source_memories=(memory,),
            source_events=(event,),
            objective="Review evidence.",
            requested_at=NOW + timedelta(seconds=2),
            scheduled_for=NOW + timedelta(hours=1),
        )


def test_schedule_self_reflection_rejects_missing_mismatched_or_future_evidence() -> None:
    event = _event("event-1")
    memory = _memory("memory-1", event.event_id)

    with pytest.raises(MemoryLearningError, match="source_events_required"):
        schedule_self_reflection(
            authenticated_agent=_agent(),
            owning_agent_id="agent-1",
            request_id="reflection-1",
            source_memories=(memory,),
            source_events=(),
            objective="Review evidence.",
            requested_at=NOW + timedelta(seconds=2),
            scheduled_for=NOW + timedelta(hours=1),
        )
    with pytest.raises(MemoryLearningError, match="source event receipts are missing"):
        schedule_self_reflection(
            authenticated_agent=_agent(),
            owning_agent_id="agent-1",
            request_id="reflection-1",
            source_memories=(memory,),
            source_events=(_event("different-event"),),
            objective="Review evidence.",
            requested_at=NOW + timedelta(seconds=2),
            scheduled_for=NOW + timedelta(hours=1),
        )
    with pytest.raises(MemoryLearningError, match="future_evidence"):
        schedule_self_reflection(
            authenticated_agent=_agent(),
            owning_agent_id="agent-1",
            request_id="reflection-1",
            source_memories=(memory,),
            source_events=(event, _event("future-event", occurred_at=NOW + timedelta(minutes=2))),
            objective="Review evidence.",
            requested_at=NOW + timedelta(minutes=1),
            scheduled_for=NOW + timedelta(hours=1),
        )
    with pytest.raises(MemoryLearningError, match="future_memory"):
        schedule_self_reflection(
            authenticated_agent=_agent(),
            owning_agent_id="agent-1",
            request_id="reflection-1",
            source_memories=(
                _memory(
                    "memory-1",
                    "event-1",
                    committed_at=NOW + timedelta(minutes=2),
                ),
            ),
            source_events=(event,),
            objective="Review evidence.",
            requested_at=NOW + timedelta(minutes=1),
            scheduled_for=NOW + timedelta(hours=1),
        )
    with pytest.raises(MemoryLearningError, match="invalid_memory_evidence_time"):
        schedule_self_reflection(
            authenticated_agent=_agent(),
            owning_agent_id="agent-1",
            request_id="reflection-1",
            source_memories=(memory,),
            source_events=(_event("event-1", occurred_at=NOW + timedelta(seconds=2)),),
            objective="Review evidence.",
            requested_at=NOW + timedelta(minutes=1),
            scheduled_for=NOW + timedelta(hours=1),
        )
    with pytest.raises(MemoryLearningError, match="invalid_schedule"):
        schedule_self_reflection(
            authenticated_agent=_agent(),
            owning_agent_id="agent-1",
            request_id="reflection-1",
            source_memories=(memory,),
            source_events=(event,),
            objective="Review evidence.",
            requested_at=NOW + timedelta(hours=1),
            scheduled_for=NOW + timedelta(minutes=1),
        )


def test_reflection_creates_only_an_immutable_derived_candidate() -> None:
    request, memory, _ = _reflection_request()
    created_at = request.scheduled_for + timedelta(seconds=1)

    candidate = derive_self_reflection_candidate(
        authenticated_agent=_agent(),
        request=request,
        candidate_id="candidate-1",
        memory_kind="semantic",
        content="The earlier observations support a narrower conclusion.",
        rationale="Both source statements refer to the same bounded situation.",
        confidence=0.83,
        created_at=created_at,
    )

    assert candidate.state == "candidate"
    assert candidate.origin is CandidateOrigin.SELF_REFLECTION
    assert candidate.provenance_class == "self_reflection"
    assert candidate.derivation_reference_id == request.request_id
    assert candidate.source_memories == request.source_memories
    assert not hasattr(candidate, "commit")
    assert memory.content_sha256 == "b" * 64
    with pytest.raises(FrozenInstanceError):
        candidate.content = "rewritten"
    with pytest.raises(FrozenInstanceError):
        memory.content_sha256 = "c" * 64


def test_reflection_candidate_denies_early_invalid_or_cross_owner_derivation() -> None:
    request, _, _ = _reflection_request()

    with pytest.raises(MemoryLearningError, match="reflection_not_due"):
        derive_self_reflection_candidate(
            authenticated_agent=_agent(),
            request=request,
            candidate_id="candidate-1",
            memory_kind="semantic",
            content="Derived content.",
            rationale="Evidence rationale.",
            confidence=0.8,
            created_at=request.scheduled_for - timedelta(seconds=1),
        )
    with pytest.raises(MemoryLearningError, match="memory_owner_mismatch"):
        derive_self_reflection_candidate(
            authenticated_agent=_agent("agent-2"),
            request=request,
            candidate_id="candidate-1",
            memory_kind="semantic",
            content="Derived content.",
            rationale="Evidence rationale.",
            confidence=0.8,
            created_at=request.scheduled_for,
        )
    with pytest.raises(MemoryLearningError, match="invalid_memory_kind"):
        derive_self_reflection_candidate(
            authenticated_agent=_agent(),
            request=request,
            candidate_id="candidate-1",
            memory_kind="invented-kind",
            content="Derived content.",
            rationale="Evidence rationale.",
            confidence=0.8,
            created_at=request.scheduled_for,
        )
    with pytest.raises(TypeError, match="state"):
        DerivedMemoryCandidate(
            candidate_id="candidate-1",
            owning_agent_id="agent-1",
            created_by_agent_id="agent-1",
            authentication_id="token:agent-1",
            origin=CandidateOrigin.SELF_REFLECTION,
            derivation_reference_id="reflection-1",
            memory_kind="semantic",
            content="Derived content.",
            rationale="Evidence rationale.",
            confidence=0.8,
            source_memories=request.source_memories,
            source_events=request.source_events,
            created_at=request.scheduled_for,
            state="committed",
        )


def test_contradiction_edge_preserves_both_immutable_memory_versions_and_evidence() -> None:
    event_a = _event("event-a", digest_character="a")
    event_b = _event("event-b", digest_character="b")
    memory_b = _memory("memory-b", "event-b", digest_character="d")
    memory_a = _memory("memory-a", "event-a", digest_character="c")

    edge = record_memory_contradiction(
        authenticated_agent=_agent(),
        owning_agent_id="agent-1",
        edge_id="contradiction-1",
        left_memory=memory_b,
        right_memory=memory_a,
        evidence_events=(event_a, event_b),
        rationale="The two immutable statements make mutually exclusive claims.",
        confidence=0.91,
        assessed_at=NOW + timedelta(minutes=1),
    )

    assert edge.relation == "contradicts"
    assert edge.left_memory.memory_id == "memory-a"
    assert edge.right_memory.memory_id == "memory-b"
    assert edge.evidence_events == (event_a, event_b)
    assert memory_a.content_sha256 == "c" * 64
    assert memory_b.content_sha256 == "d" * 64


def test_contradiction_edge_denies_self_edges_missing_evidence_and_zero_confidence() -> None:
    event = _event("event-1")
    memory = _memory("memory-1", "event-1")
    other = _memory("memory-2", "event-2")

    with pytest.raises(MemoryLearningError, match="self_contradiction"):
        record_memory_contradiction(
            authenticated_agent=_agent(),
            owning_agent_id="agent-1",
            edge_id="edge-1",
            left_memory=memory,
            right_memory=memory,
            evidence_events=(event,),
            rationale="Invalid self edge.",
            confidence=0.9,
            assessed_at=NOW + timedelta(minutes=1),
        )
    with pytest.raises(MemoryLearningError, match="source event receipts are missing"):
        record_memory_contradiction(
            authenticated_agent=_agent(),
            owning_agent_id="agent-1",
            edge_id="edge-1",
            left_memory=memory,
            right_memory=other,
            evidence_events=(event,),
            rationale="Incomplete evidence.",
            confidence=0.9,
            assessed_at=NOW + timedelta(minutes=1),
        )
    with pytest.raises(MemoryLearningError, match="invalid_confidence"):
        record_memory_contradiction(
            authenticated_agent=_agent(),
            owning_agent_id="agent-1",
            edge_id="edge-1",
            left_memory=memory,
            right_memory=_memory("memory-2", "event-1"),
            evidence_events=(event,),
            rationale="No confidence.",
            confidence=0.0,
            assessed_at=NOW + timedelta(minutes=1),
        )


def test_confidence_revisions_are_append_only_and_content_version_bound() -> None:
    event = _event("event-1")
    memory = _memory("memory-1", "event-1")
    first = append_confidence_assessment(
        authenticated_agent=_agent(),
        memory=memory,
        previous_assessments=(),
        assessment_id="assessment-1",
        confidence=0.7,
        rationale="Initial reassessment against source evidence.",
        evidence_events=(event,),
        assessed_at=NOW + timedelta(minutes=1),
    )
    second = append_confidence_assessment(
        authenticated_agent=_agent(),
        memory=memory,
        previous_assessments=(first,),
        assessment_id="assessment-2",
        confidence=0.4,
        rationale="A contradiction edge reduces derived ranking confidence.",
        evidence_events=(event,),
        assessed_at=NOW + timedelta(minutes=2),
    )

    assert first.revision == 1
    assert first.supersedes_assessment_id is None
    assert second.revision == 2
    assert second.supersedes_assessment_id == first.assessment_id
    assert first.confidence == 0.7
    assert memory.content_sha256 == "b" * 64
    with pytest.raises(FrozenInstanceError):
        first.confidence = 0.4


def test_confidence_revision_denies_disconnected_history_and_nonmonotonic_time() -> None:
    event = _event("event-1")
    memory = _memory("memory-1", "event-1")
    first = append_confidence_assessment(
        authenticated_agent=_agent(),
        memory=memory,
        previous_assessments=(),
        assessment_id="assessment-1",
        confidence=0.7,
        rationale="Initial reassessment.",
        evidence_events=(event,),
        assessed_at=NOW + timedelta(minutes=1),
    )
    malformed = MemoryConfidenceAssessment(
        assessment_id="assessment-3",
        owning_agent_id="agent-1",
        memory=memory,
        revision=3,
        confidence=0.5,
        rationale="Disconnected record.",
        evidence_events=(event,),
        assessed_at=NOW + timedelta(minutes=2),
        assessed_by_agent_id="agent-1",
        authentication_id="token:agent-1",
        supersedes_assessment_id="assessment-2",
    )

    with pytest.raises(MemoryLearningError, match="revisions must be contiguous"):
        append_confidence_assessment(
            authenticated_agent=_agent(),
            memory=memory,
            previous_assessments=(first, malformed),
            assessment_id="assessment-4",
            confidence=0.3,
            rationale="Would extend malformed history.",
            evidence_events=(event,),
            assessed_at=NOW + timedelta(minutes=3),
        )
    with pytest.raises(MemoryLearningError, match="must follow the previous"):
        append_confidence_assessment(
            authenticated_agent=_agent(),
            memory=memory,
            previous_assessments=(first,),
            assessment_id="assessment-2",
            confidence=0.6,
            rationale="Timestamp regression.",
            evidence_events=(event,),
            assessed_at=first.assessed_at,
        )


def test_consolidation_references_every_source_and_only_produces_a_candidate() -> None:
    event_a = _event("event-a", digest_character="a")
    event_b = _event("event-b", digest_character="b")
    memory_a = _memory("memory-a", "event-a", digest_character="c")
    memory_b = _memory("memory-b", "event-b", digest_character="d")

    proposal = propose_memory_consolidation(
        authenticated_agent=_agent(),
        owning_agent_id="agent-1",
        proposal_id="consolidation-1",
        candidate_id="candidate-1",
        source_memories=(memory_a, memory_b),
        source_events=(event_a, event_b),
        memory_kind="semantic",
        content="The two observations describe one stable operating preference.",
        rationale="Both source memories agree and have independent evidence.",
        confidence=0.88,
        proposed_at=NOW + timedelta(minutes=1),
    )

    assert proposal.state == "proposed"
    assert proposal.source_memories == (memory_a, memory_b)
    assert proposal.candidate.state == "candidate"
    assert proposal.candidate.origin is CandidateOrigin.CONSOLIDATION
    assert proposal.candidate.source_memories == proposal.source_memories
    assert not hasattr(proposal.candidate, "commit")
    assert memory_a.content_sha256 == "c" * 64
    assert memory_b.content_sha256 == "d" * 64


def test_consolidation_denies_single_duplicate_and_incompletely_evidenced_sources() -> None:
    event_a = _event("event-a")
    memory_a = _memory("memory-a", "event-a")
    memory_b = _memory("memory-b", "event-b")
    common = {
        "authenticated_agent": _agent(),
        "owning_agent_id": "agent-1",
        "proposal_id": "consolidation-1",
        "candidate_id": "candidate-1",
        "memory_kind": "semantic",
        "content": "Derived candidate.",
        "rationale": "Explicit rationale.",
        "confidence": 0.8,
        "proposed_at": NOW + timedelta(minutes=1),
    }

    with pytest.raises(MemoryLearningError, match="at least 2"):
        propose_memory_consolidation(
            **common,
            source_memories=(memory_a,),
            source_events=(event_a,),
        )
    with pytest.raises(MemoryLearningError, match="source memory IDs must be unique"):
        propose_memory_consolidation(
            **common,
            source_memories=(memory_a, memory_a),
            source_events=(event_a,),
        )
    with pytest.raises(MemoryLearningError, match="source event receipts are missing"):
        propose_memory_consolidation(
            **common,
            source_memories=(memory_a, memory_b),
            source_events=(event_a,),
        )


def test_decay_is_an_expiring_ranking_multiplier_not_a_memory_mutation() -> None:
    event = _event("event-1")
    memory = _memory("memory-1", "event-1")
    applied_at = NOW + timedelta(minutes=1)
    expires_at = NOW + timedelta(days=7)

    policy = apply_ranking_policy(
        authenticated_agent=_agent(),
        memory=memory,
        policy_id="ranking-policy-1",
        application_event_id="ranking-event-1",
        mode=RankingPolicyMode.DECAY,
        weight_multiplier=0.35,
        reason="Temporarily reduce ranking while contradictory evidence is reviewed.",
        evidence_events=(event,),
        applied_at=applied_at,
        expires_at=expires_at,
    )

    assert ranking_disposition_at(policy, at=applied_at - timedelta(seconds=1)) is RankingDisposition.ACTIVE
    assert ranking_disposition_at(policy, at=applied_at) is RankingDisposition.DECAYED
    assert ranking_multiplier_at(policy, at=applied_at) == 0.35
    assert ranking_disposition_at(policy, at=expires_at) is RankingDisposition.EXPIRED
    assert ranking_multiplier_at(policy, at=expires_at) == 1.0
    assert memory.content_sha256 == "b" * 64
    assert {item.name for item in fields(policy)}.isdisjoint({"deleted_at", "tombstoned_at", "lifecycle_state"})


def test_forgetting_is_reversible_with_an_append_only_restoration_event() -> None:
    event = _event("event-1")
    memory = _memory("memory-1", "event-1")
    applied_at = NOW + timedelta(minutes=1)
    policy = apply_ranking_policy(
        authenticated_agent=_agent(),
        memory=memory,
        policy_id="ranking-policy-1",
        application_event_id="ranking-event-1",
        mode=RankingPolicyMode.FORGET,
        weight_multiplier=0.0,
        reason="Suppress recall pending a time-bounded agent review.",
        evidence_events=(event,),
        applied_at=applied_at,
        expires_at=NOW + timedelta(days=7),
    )
    restored_at = applied_at + timedelta(hours=1)
    restored = restore_ranking_policy(
        authenticated_agent=_agent(),
        policy=policy,
        restoration_event_id="ranking-event-2",
        reason="The review resolved the concern and ranking may resume.",
        restored_at=restored_at,
    )

    assert ranking_disposition_at(policy, at=restored_at) is RankingDisposition.FORGOTTEN
    assert ranking_multiplier_at(policy, at=restored_at) == 0.0
    assert ranking_disposition_at(restored, at=restored_at) is RankingDisposition.RESTORED
    assert ranking_multiplier_at(restored, at=restored_at) == 1.0
    assert len(policy.history) == 1
    assert len(restored.history) == 2
    assert policy.history[0] is restored.history[0]


def test_ranking_policy_denies_invalid_weights_owner_restore_and_expiry_transitions() -> None:
    event = _event("event-1")
    memory = _memory("memory-1", "event-1")
    applied_at = NOW + timedelta(minutes=1)
    expires_at = NOW + timedelta(days=1)

    with pytest.raises(MemoryLearningError, match="decay multiplier"):
        apply_ranking_policy(
            authenticated_agent=_agent(),
            memory=memory,
            policy_id="policy-1",
            application_event_id="apply-1",
            mode=RankingPolicyMode.DECAY,
            weight_multiplier=0.0,
            reason="Invalid decay.",
            evidence_events=(event,),
            applied_at=applied_at,
            expires_at=expires_at,
        )
    with pytest.raises(MemoryLearningError, match="forget multiplier"):
        apply_ranking_policy(
            authenticated_agent=_agent(),
            memory=memory,
            policy_id="policy-1",
            application_event_id="apply-1",
            mode=RankingPolicyMode.FORGET,
            weight_multiplier=0.1,
            reason="Invalid forgetting.",
            evidence_events=(event,),
            applied_at=applied_at,
            expires_at=expires_at,
        )
    with pytest.raises(MemoryLearningError, match="invalid_ranking_mode"):
        apply_ranking_policy(
            authenticated_agent=_agent(),
            memory=memory,
            policy_id="policy-1",
            application_event_id="apply-1",
            mode="unrecognized",
            weight_multiplier=0.5,
            reason="Invalid mode.",
            evidence_events=(event,),
            applied_at=applied_at,
            expires_at=expires_at,
        )

    policy = apply_ranking_policy(
        authenticated_agent=_agent(),
        memory=memory,
        policy_id="policy-1",
        application_event_id="apply-1",
        mode=RankingPolicyMode.DECAY,
        weight_multiplier=0.5,
        reason="Time-bounded decay.",
        evidence_events=(event,),
        applied_at=applied_at,
        expires_at=expires_at,
    )
    with pytest.raises(MemoryLearningError, match="memory_owner_mismatch"):
        restore_ranking_policy(
            authenticated_agent=_agent("agent-2"),
            policy=policy,
            restoration_event_id="restore-1",
            reason="Wrong owner.",
            restored_at=applied_at + timedelta(hours=1),
        )
    with pytest.raises(MemoryLearningError, match="ranking_policy_expired"):
        restore_ranking_policy(
            authenticated_agent=_agent(),
            policy=policy,
            restoration_event_id="restore-1",
            reason="Too late.",
            restored_at=expires_at,
        )
    restored = restore_ranking_policy(
        authenticated_agent=_agent(),
        policy=policy,
        restoration_event_id="restore-1",
        reason="Restore ranking.",
        restored_at=applied_at + timedelta(hours=1),
    )
    with pytest.raises(MemoryLearningError, match="already has a restoration"):
        restore_ranking_policy(
            authenticated_agent=_agent(),
            policy=restored,
            restoration_event_id="restore-2",
            reason="Duplicate restoration.",
            restored_at=applied_at + timedelta(hours=2),
        )


def test_service_has_no_runtime_clock_id_generation_or_mutating_memory_operations() -> None:
    import agent_hub.memory_learning as module

    source = inspect.getsource(module)
    assert "datetime.now" not in source
    assert "datetime.utcnow" not in source
    assert "uuid" not in source
    assert "secrets" not in source
    assert "def commit" not in source
    assert "def delete" not in source
    assert "def tombstone" not in source
