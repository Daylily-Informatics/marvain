"""Immutable, evidence-first contracts for agent-owned memory learning.

This module is deliberately persistence-free. Callers authenticate an agent,
load immutable memory and event references from their owning stores, call these
functions, and atomically persist the returned records. Nothing here commits,
rewrites, tombstones, or deletes a canonical memory.
"""

from __future__ import annotations

import math
import re
from collections.abc import Sequence
from dataclasses import dataclass, field, replace
from datetime import datetime
from enum import StrEnum
from typing import Final

from agent_hub.auth import AuthenticatedAgent
from agent_hub.memory_taxonomy import normalize_memory_kind

MEMORY_LEARNING_SCOPE: Final = "memory:learn"
_SHA256_RE: Final = re.compile(r"^[0-9a-f]{64}$")


class MemoryLearningError(ValueError):
    """An authentication, evidence, or immutable-transition contract failed."""

    def __init__(self, code: str, message: str) -> None:
        self.code = code
        super().__init__(f"{code}: {message}")


class CandidateOrigin(StrEnum):
    SELF_REFLECTION = "self_reflection"
    CONSOLIDATION = "consolidation"


class RankingPolicyMode(StrEnum):
    DECAY = "decay"
    FORGET = "forget"


class RankingPolicyEventKind(StrEnum):
    APPLIED = "applied"
    RESTORED = "restored"


class RankingDisposition(StrEnum):
    ACTIVE = "active"
    DECAYED = "decayed"
    FORGOTTEN = "forgotten"
    RESTORED = "restored"
    EXPIRED = "expired"


def _require_text(value: object, field_name: str) -> str:
    if not isinstance(value, str):
        raise MemoryLearningError("invalid_field", f"{field_name} must be a string")
    normalized = value.strip()
    if not normalized:
        raise MemoryLearningError("invalid_field", f"{field_name} is required")
    return normalized


def _require_aware_datetime(value: object, field_name: str) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise MemoryLearningError("invalid_timestamp", f"{field_name} must be timezone-aware")
    return value


def _require_sha256(value: object, field_name: str) -> str:
    digest = _require_text(value, field_name).lower()
    if _SHA256_RE.fullmatch(digest) is None:
        raise MemoryLearningError("invalid_digest", f"{field_name} must be a SHA-256 hex digest")
    return digest


def _require_confidence(value: object, field_name: str, *, allow_zero: bool) -> float:
    if isinstance(value, bool) or not isinstance(value, int | float):
        raise MemoryLearningError("invalid_confidence", f"{field_name} must be numeric")
    normalized = float(value)
    lower_bound_valid = normalized >= 0.0 if allow_zero else normalized > 0.0
    if not math.isfinite(normalized) or not lower_bound_valid or normalized > 1.0:
        qualifier = "from 0 to 1" if allow_zero else "greater than 0 and at most 1"
        raise MemoryLearningError("invalid_confidence", f"{field_name} must be finite and {qualifier}")
    return normalized


def _require_unique_ids(values: object, field_name: str, *, minimum: int = 1) -> tuple[str, ...]:
    if isinstance(values, str) or not isinstance(values, Sequence):
        raise MemoryLearningError("invalid_evidence", f"{field_name} must be an explicit sequence")
    normalized = tuple(_require_text(value, field_name) for value in values)
    if len(normalized) < minimum:
        raise MemoryLearningError(
            "evidence_required",
            f"{field_name} must contain at least {minimum} persisted reference(s)",
        )
    if len(normalized) != len(set(normalized)):
        raise MemoryLearningError("duplicate_evidence", f"{field_name} must contain unique references")
    return normalized


def _require_owning_agent(authenticated: object, owning_agent_id: str) -> AuthenticatedAgent:
    owner = _require_text(owning_agent_id, "owning_agent_id")
    if not isinstance(authenticated, AuthenticatedAgent):
        raise MemoryLearningError(
            "agent_authentication_required",
            "memory learning requires an authenticated agent identity",
        )
    token_id = _require_text(authenticated.token_id, "token_id")
    issuer_agent_id = _require_text(authenticated.issuer_agent_id, "issuer_agent_id")
    target_agent_id = _require_text(authenticated.target_agent_id, "target_agent_id")
    if target_agent_id != owner:
        raise MemoryLearningError(
            "memory_owner_mismatch",
            "the authenticated agent may only learn from its own memories",
        )
    scopes = _require_unique_ids(authenticated.scopes, "scopes")
    if MEMORY_LEARNING_SCOPE not in scopes:
        raise MemoryLearningError(
            "memory_learning_scope_required",
            f"authenticated agent requires {MEMORY_LEARNING_SCOPE!r}",
        )
    if (
        token_id != authenticated.token_id
        or issuer_agent_id != authenticated.issuer_agent_id
        or target_agent_id != authenticated.target_agent_id
        or scopes != tuple(authenticated.scopes)
    ):
        raise MemoryLearningError(
            "invalid_authentication",
            "authenticated agent identity fields must not contain surrounding whitespace",
        )
    return authenticated


@dataclass(frozen=True)
class SourceEventReference:
    """Receipt for a persisted source event; an ID alone is not evidence."""

    event_id: str
    owning_agent_id: str
    payload_sha256: str
    occurred_at: datetime

    def __post_init__(self) -> None:
        object.__setattr__(self, "event_id", _require_text(self.event_id, "event_id"))
        object.__setattr__(self, "owning_agent_id", _require_text(self.owning_agent_id, "owning_agent_id"))
        object.__setattr__(self, "payload_sha256", _require_sha256(self.payload_sha256, "payload_sha256"))
        object.__setattr__(self, "occurred_at", _require_aware_datetime(self.occurred_at, "occurred_at"))


@dataclass(frozen=True)
class ImmutableMemoryReference:
    """A content-addressed reference to one immutable committed memory."""

    memory_id: str
    owning_agent_id: str
    content_sha256: str
    source_event_ids: tuple[str, ...]
    committed_at: datetime

    def __post_init__(self) -> None:
        object.__setattr__(self, "memory_id", _require_text(self.memory_id, "memory_id"))
        object.__setattr__(self, "owning_agent_id", _require_text(self.owning_agent_id, "owning_agent_id"))
        object.__setattr__(self, "content_sha256", _require_sha256(self.content_sha256, "content_sha256"))
        object.__setattr__(
            self,
            "source_event_ids",
            _require_unique_ids(self.source_event_ids, "source_event_ids"),
        )
        object.__setattr__(self, "committed_at", _require_aware_datetime(self.committed_at, "committed_at"))


def _validate_source_bundle(
    *,
    owning_agent_id: str,
    source_memories: Sequence[ImmutableMemoryReference],
    source_events: Sequence[SourceEventReference],
    minimum_memories: int,
) -> tuple[tuple[ImmutableMemoryReference, ...], tuple[SourceEventReference, ...]]:
    if isinstance(source_memories, str) or not isinstance(source_memories, Sequence):
        raise MemoryLearningError("invalid_evidence", "source_memories must be an explicit sequence")
    if isinstance(source_events, str) or not isinstance(source_events, Sequence):
        raise MemoryLearningError("invalid_evidence", "source_events must be an explicit sequence")
    memories = tuple(source_memories)
    events = tuple(source_events)
    if len(memories) < minimum_memories:
        raise MemoryLearningError(
            "source_memories_required",
            f"at least {minimum_memories} immutable source memory reference(s) are required",
        )
    if not events:
        raise MemoryLearningError("source_events_required", "at least one persisted source event receipt is required")
    if any(not isinstance(memory, ImmutableMemoryReference) for memory in memories):
        raise MemoryLearningError("invalid_evidence", "source_memories contains an invalid memory reference")
    if any(not isinstance(event, SourceEventReference) for event in events):
        raise MemoryLearningError("invalid_evidence", "source_events contains an invalid event receipt")

    memory_ids = [memory.memory_id for memory in memories]
    event_ids = [event.event_id for event in events]
    if len(memory_ids) != len(set(memory_ids)):
        raise MemoryLearningError("duplicate_evidence", "source memory IDs must be unique")
    if len(event_ids) != len(set(event_ids)):
        raise MemoryLearningError("duplicate_evidence", "source event IDs must be unique")
    if any(memory.owning_agent_id != owning_agent_id for memory in memories):
        raise MemoryLearningError("memory_owner_mismatch", "every source memory must belong to the owning agent")
    if any(event.owning_agent_id != owning_agent_id for event in events):
        raise MemoryLearningError("event_owner_mismatch", "every source event must belong to the owning agent")

    supplied_event_ids = set(event_ids)
    required_event_ids = {event_id for memory in memories for event_id in memory.source_event_ids}
    missing_event_ids = sorted(required_event_ids - supplied_event_ids)
    if missing_event_ids:
        raise MemoryLearningError(
            "source_event_receipt_missing",
            f"source event receipts are missing for: {', '.join(missing_event_ids)}",
        )
    events_by_id = {event.event_id: event for event in events}
    if any(
        events_by_id[event_id].occurred_at > memory.committed_at
        for memory in memories
        for event_id in memory.source_event_ids
    ):
        raise MemoryLearningError(
            "invalid_memory_evidence_time",
            "a source event cannot occur after the memory that cites it was committed",
        )
    return memories, events


def _validate_source_time(
    source_memories: Sequence[ImmutableMemoryReference],
    source_events: Sequence[SourceEventReference],
    recorded_at: datetime,
) -> None:
    if any(memory.committed_at > recorded_at for memory in source_memories):
        raise MemoryLearningError("future_memory", "a source memory cannot be committed after the derived record")
    if any(event.occurred_at > recorded_at for event in source_events):
        raise MemoryLearningError("future_evidence", "source evidence cannot occur after the derived record")


@dataclass(frozen=True)
class SelfReflectionRequest:
    request_id: str
    owning_agent_id: str
    authenticated_agent_id: str
    authentication_id: str
    source_memories: tuple[ImmutableMemoryReference, ...]
    source_events: tuple[SourceEventReference, ...]
    objective: str
    requested_at: datetime
    scheduled_for: datetime

    def __post_init__(self) -> None:
        object.__setattr__(self, "request_id", _require_text(self.request_id, "request_id"))
        object.__setattr__(self, "owning_agent_id", _require_text(self.owning_agent_id, "owning_agent_id"))
        object.__setattr__(
            self,
            "authenticated_agent_id",
            _require_text(self.authenticated_agent_id, "authenticated_agent_id"),
        )
        object.__setattr__(self, "authentication_id", _require_text(self.authentication_id, "authentication_id"))
        object.__setattr__(self, "objective", _require_text(self.objective, "objective"))
        requested_at = _require_aware_datetime(self.requested_at, "requested_at")
        scheduled_for = _require_aware_datetime(self.scheduled_for, "scheduled_for")
        object.__setattr__(self, "requested_at", requested_at)
        object.__setattr__(self, "scheduled_for", scheduled_for)
        memories, events = _validate_source_bundle(
            owning_agent_id=self.owning_agent_id,
            source_memories=self.source_memories,
            source_events=self.source_events,
            minimum_memories=1,
        )
        object.__setattr__(self, "source_memories", memories)
        object.__setattr__(self, "source_events", events)
        if self.authenticated_agent_id != self.owning_agent_id:
            raise MemoryLearningError("memory_owner_mismatch", "reflection author must be the owning agent")
        _validate_source_time(memories, events, requested_at)
        if scheduled_for < requested_at:
            raise MemoryLearningError("invalid_schedule", "scheduled_for cannot precede requested_at")


def schedule_self_reflection(
    *,
    authenticated_agent: AuthenticatedAgent,
    owning_agent_id: str,
    request_id: str,
    source_memories: Sequence[ImmutableMemoryReference],
    source_events: Sequence[SourceEventReference],
    objective: str,
    requested_at: datetime,
    scheduled_for: datetime,
) -> SelfReflectionRequest:
    """Create an authenticated, scheduled self-reflection request."""

    authenticated = _require_owning_agent(authenticated_agent, owning_agent_id)
    memories, events = _validate_source_bundle(
        owning_agent_id=owning_agent_id,
        source_memories=source_memories,
        source_events=source_events,
        minimum_memories=1,
    )
    return SelfReflectionRequest(
        request_id=request_id,
        owning_agent_id=owning_agent_id,
        authenticated_agent_id=authenticated.target_agent_id,
        authentication_id=authenticated.token_id,
        source_memories=memories,
        source_events=events,
        objective=objective,
        requested_at=requested_at,
        scheduled_for=scheduled_for,
    )


@dataclass(frozen=True)
class DerivedMemoryCandidate:
    """A derived candidate. This type intentionally has no commit operation."""

    candidate_id: str
    owning_agent_id: str
    created_by_agent_id: str
    authentication_id: str
    origin: CandidateOrigin
    derivation_reference_id: str
    memory_kind: str
    content: str
    rationale: str
    confidence: float
    source_memories: tuple[ImmutableMemoryReference, ...]
    source_events: tuple[SourceEventReference, ...]
    created_at: datetime
    provenance_class: str = field(default="self_reflection", init=False)
    state: str = field(default="candidate", init=False)

    def __post_init__(self) -> None:
        object.__setattr__(self, "candidate_id", _require_text(self.candidate_id, "candidate_id"))
        object.__setattr__(self, "owning_agent_id", _require_text(self.owning_agent_id, "owning_agent_id"))
        object.__setattr__(
            self,
            "created_by_agent_id",
            _require_text(self.created_by_agent_id, "created_by_agent_id"),
        )
        object.__setattr__(self, "authentication_id", _require_text(self.authentication_id, "authentication_id"))
        try:
            origin = CandidateOrigin(self.origin)
        except ValueError as exc:
            raise MemoryLearningError("invalid_origin", "unknown candidate origin") from exc
        object.__setattr__(self, "origin", origin)
        object.__setattr__(
            self,
            "derivation_reference_id",
            _require_text(self.derivation_reference_id, "derivation_reference_id"),
        )
        kind_text = _require_text(self.memory_kind, "memory_kind")
        try:
            memory_kind = normalize_memory_kind(kind_text)
        except ValueError as exc:
            raise MemoryLearningError("invalid_memory_kind", str(exc)) from exc
        object.__setattr__(self, "memory_kind", memory_kind)
        object.__setattr__(self, "content", _require_text(self.content, "content"))
        object.__setattr__(self, "rationale", _require_text(self.rationale, "rationale"))
        object.__setattr__(
            self,
            "confidence",
            _require_confidence(self.confidence, "confidence", allow_zero=False),
        )
        created_at = _require_aware_datetime(self.created_at, "created_at")
        object.__setattr__(self, "created_at", created_at)
        memories, events = _validate_source_bundle(
            owning_agent_id=self.owning_agent_id,
            source_memories=self.source_memories,
            source_events=self.source_events,
            minimum_memories=1,
        )
        object.__setattr__(self, "source_memories", memories)
        object.__setattr__(self, "source_events", events)
        if self.created_by_agent_id != self.owning_agent_id:
            raise MemoryLearningError("memory_owner_mismatch", "derived candidate author must be the owning agent")
        _validate_source_time(memories, events, created_at)


def derive_self_reflection_candidate(
    *,
    authenticated_agent: AuthenticatedAgent,
    request: SelfReflectionRequest,
    candidate_id: str,
    memory_kind: str,
    content: str,
    rationale: str,
    confidence: float,
    created_at: datetime,
) -> DerivedMemoryCandidate:
    """Materialize reflection output as a candidate, never a committed memory."""

    if not isinstance(request, SelfReflectionRequest):
        raise MemoryLearningError("invalid_reflection_request", "request must be a self-reflection request")
    authenticated = _require_owning_agent(authenticated_agent, request.owning_agent_id)
    created_at = _require_aware_datetime(created_at, "created_at")
    if created_at < request.scheduled_for:
        raise MemoryLearningError("reflection_not_due", "reflection cannot run before scheduled_for")
    return DerivedMemoryCandidate(
        candidate_id=candidate_id,
        owning_agent_id=request.owning_agent_id,
        created_by_agent_id=authenticated.target_agent_id,
        authentication_id=authenticated.token_id,
        origin=CandidateOrigin.SELF_REFLECTION,
        derivation_reference_id=request.request_id,
        memory_kind=memory_kind,
        content=content,
        rationale=rationale,
        confidence=confidence,
        source_memories=request.source_memories,
        source_events=request.source_events,
        created_at=created_at,
    )


@dataclass(frozen=True)
class MemoryContradictionEdge:
    edge_id: str
    owning_agent_id: str
    left_memory: ImmutableMemoryReference
    right_memory: ImmutableMemoryReference
    evidence_events: tuple[SourceEventReference, ...]
    rationale: str
    confidence: float
    assessed_at: datetime
    relation: str = field(default="contradicts", init=False)

    def __post_init__(self) -> None:
        object.__setattr__(self, "edge_id", _require_text(self.edge_id, "edge_id"))
        object.__setattr__(self, "owning_agent_id", _require_text(self.owning_agent_id, "owning_agent_id"))
        if not isinstance(self.left_memory, ImmutableMemoryReference) or not isinstance(
            self.right_memory, ImmutableMemoryReference
        ):
            raise MemoryLearningError("invalid_evidence", "contradiction endpoints must be immutable memory references")
        if self.left_memory.memory_id == self.right_memory.memory_id:
            raise MemoryLearningError("self_contradiction", "a memory cannot contradict itself")
        memories, events = _validate_source_bundle(
            owning_agent_id=self.owning_agent_id,
            source_memories=(self.left_memory, self.right_memory),
            source_events=self.evidence_events,
            minimum_memories=2,
        )
        object.__setattr__(self, "left_memory", memories[0])
        object.__setattr__(self, "right_memory", memories[1])
        object.__setattr__(self, "evidence_events", events)
        object.__setattr__(self, "rationale", _require_text(self.rationale, "rationale"))
        object.__setattr__(
            self,
            "confidence",
            _require_confidence(self.confidence, "confidence", allow_zero=False),
        )
        assessed_at = _require_aware_datetime(self.assessed_at, "assessed_at")
        object.__setattr__(self, "assessed_at", assessed_at)
        _validate_source_time(memories, events, assessed_at)


def record_memory_contradiction(
    *,
    authenticated_agent: AuthenticatedAgent,
    owning_agent_id: str,
    edge_id: str,
    left_memory: ImmutableMemoryReference,
    right_memory: ImmutableMemoryReference,
    evidence_events: Sequence[SourceEventReference],
    rationale: str,
    confidence: float,
    assessed_at: datetime,
) -> MemoryContradictionEdge:
    """Create a symmetric contradiction edge without editing either memory."""

    _require_owning_agent(authenticated_agent, owning_agent_id)
    if not isinstance(left_memory, ImmutableMemoryReference) or not isinstance(right_memory, ImmutableMemoryReference):
        raise MemoryLearningError("invalid_evidence", "contradiction endpoints must be immutable memory references")
    if left_memory.memory_id == right_memory.memory_id:
        raise MemoryLearningError("self_contradiction", "a memory cannot contradict itself")
    left, right = sorted((left_memory, right_memory), key=lambda memory: memory.memory_id)
    memories, events = _validate_source_bundle(
        owning_agent_id=owning_agent_id,
        source_memories=(left, right),
        source_events=evidence_events,
        minimum_memories=2,
    )
    return MemoryContradictionEdge(
        edge_id=edge_id,
        owning_agent_id=owning_agent_id,
        left_memory=memories[0],
        right_memory=memories[1],
        evidence_events=events,
        rationale=rationale,
        confidence=confidence,
        assessed_at=assessed_at,
    )


@dataclass(frozen=True)
class MemoryConfidenceAssessment:
    assessment_id: str
    owning_agent_id: str
    memory: ImmutableMemoryReference
    revision: int
    confidence: float
    rationale: str
    evidence_events: tuple[SourceEventReference, ...]
    assessed_at: datetime
    assessed_by_agent_id: str
    authentication_id: str
    supersedes_assessment_id: str | None

    def __post_init__(self) -> None:
        object.__setattr__(self, "assessment_id", _require_text(self.assessment_id, "assessment_id"))
        object.__setattr__(self, "owning_agent_id", _require_text(self.owning_agent_id, "owning_agent_id"))
        if not isinstance(self.memory, ImmutableMemoryReference):
            raise MemoryLearningError("invalid_evidence", "assessment memory must be an immutable memory reference")
        if self.memory.owning_agent_id != self.owning_agent_id:
            raise MemoryLearningError("memory_owner_mismatch", "assessment memory must belong to the owning agent")
        if isinstance(self.revision, bool) or not isinstance(self.revision, int) or self.revision < 1:
            raise MemoryLearningError("invalid_revision", "revision must be a positive integer")
        object.__setattr__(
            self,
            "confidence",
            _require_confidence(self.confidence, "confidence", allow_zero=True),
        )
        object.__setattr__(self, "rationale", _require_text(self.rationale, "rationale"))
        _, events = _validate_source_bundle(
            owning_agent_id=self.owning_agent_id,
            source_memories=(self.memory,),
            source_events=self.evidence_events,
            minimum_memories=1,
        )
        object.__setattr__(self, "evidence_events", events)
        assessed_at = _require_aware_datetime(self.assessed_at, "assessed_at")
        object.__setattr__(self, "assessed_at", assessed_at)
        object.__setattr__(
            self,
            "assessed_by_agent_id",
            _require_text(self.assessed_by_agent_id, "assessed_by_agent_id"),
        )
        object.__setattr__(self, "authentication_id", _require_text(self.authentication_id, "authentication_id"))
        if self.assessed_by_agent_id != self.owning_agent_id:
            raise MemoryLearningError("memory_owner_mismatch", "assessment author must be the owning agent")
        if self.revision == 1 and self.supersedes_assessment_id is not None:
            raise MemoryLearningError("invalid_revision", "the first assessment cannot supersede another assessment")
        if self.revision > 1:
            object.__setattr__(
                self,
                "supersedes_assessment_id",
                _require_text(self.supersedes_assessment_id, "supersedes_assessment_id"),
            )
        _validate_source_time((self.memory,), events, assessed_at)


def _validate_assessment_history(
    memory: ImmutableMemoryReference,
    previous_assessments: Sequence[MemoryConfidenceAssessment],
) -> tuple[MemoryConfidenceAssessment, ...]:
    if isinstance(previous_assessments, str) or not isinstance(previous_assessments, Sequence):
        raise MemoryLearningError("invalid_assessment_history", "previous_assessments must be an explicit sequence")
    history = tuple(previous_assessments)
    seen_ids: set[str] = set()
    previous: MemoryConfidenceAssessment | None = None
    for expected_revision, assessment in enumerate(history, start=1):
        if not isinstance(assessment, MemoryConfidenceAssessment):
            raise MemoryLearningError("invalid_assessment_history", "history contains an invalid assessment")
        if assessment.assessment_id in seen_ids:
            raise MemoryLearningError("invalid_assessment_history", "assessment IDs must be unique")
        seen_ids.add(assessment.assessment_id)
        if assessment.memory.memory_id != memory.memory_id or assessment.memory.content_sha256 != memory.content_sha256:
            raise MemoryLearningError(
                "invalid_assessment_history", "assessment history references another memory version"
            )
        if assessment.owning_agent_id != memory.owning_agent_id:
            raise MemoryLearningError("invalid_assessment_history", "assessment history has another owner")
        if assessment.revision != expected_revision:
            raise MemoryLearningError("invalid_assessment_history", "assessment revisions must be contiguous")
        if previous is not None:
            if assessment.supersedes_assessment_id != previous.assessment_id:
                raise MemoryLearningError("invalid_assessment_history", "assessment supersession chain is disconnected")
            if assessment.assessed_at <= previous.assessed_at:
                raise MemoryLearningError("invalid_assessment_history", "assessment timestamps must increase")
        previous = assessment
    return history


def append_confidence_assessment(
    *,
    authenticated_agent: AuthenticatedAgent,
    memory: ImmutableMemoryReference,
    previous_assessments: Sequence[MemoryConfidenceAssessment],
    assessment_id: str,
    confidence: float,
    rationale: str,
    evidence_events: Sequence[SourceEventReference],
    assessed_at: datetime,
) -> MemoryConfidenceAssessment:
    """Return the next append-only confidence assessment for a memory version."""

    if not isinstance(memory, ImmutableMemoryReference):
        raise MemoryLearningError("invalid_evidence", "memory must be an immutable memory reference")
    authenticated = _require_owning_agent(authenticated_agent, memory.owning_agent_id)
    history = _validate_assessment_history(memory, previous_assessments)
    _, events = _validate_source_bundle(
        owning_agent_id=memory.owning_agent_id,
        source_memories=(memory,),
        source_events=evidence_events,
        minimum_memories=1,
    )
    assessed_at = _require_aware_datetime(assessed_at, "assessed_at")
    if history and assessed_at <= history[-1].assessed_at:
        raise MemoryLearningError("invalid_assessment_time", "new assessment must follow the previous assessment")
    return MemoryConfidenceAssessment(
        assessment_id=assessment_id,
        owning_agent_id=memory.owning_agent_id,
        memory=memory,
        revision=len(history) + 1,
        confidence=confidence,
        rationale=rationale,
        evidence_events=events,
        assessed_at=assessed_at,
        assessed_by_agent_id=authenticated.target_agent_id,
        authentication_id=authenticated.token_id,
        supersedes_assessment_id=history[-1].assessment_id if history else None,
    )


@dataclass(frozen=True)
class MemoryConsolidationProposal:
    proposal_id: str
    owning_agent_id: str
    source_memories: tuple[ImmutableMemoryReference, ...]
    source_events: tuple[SourceEventReference, ...]
    candidate: DerivedMemoryCandidate
    proposed_at: datetime
    state: str = field(default="proposed", init=False)

    def __post_init__(self) -> None:
        object.__setattr__(self, "proposal_id", _require_text(self.proposal_id, "proposal_id"))
        object.__setattr__(self, "owning_agent_id", _require_text(self.owning_agent_id, "owning_agent_id"))
        memories, events = _validate_source_bundle(
            owning_agent_id=self.owning_agent_id,
            source_memories=self.source_memories,
            source_events=self.source_events,
            minimum_memories=2,
        )
        object.__setattr__(self, "source_memories", memories)
        object.__setattr__(self, "source_events", events)
        proposed_at = _require_aware_datetime(self.proposed_at, "proposed_at")
        object.__setattr__(self, "proposed_at", proposed_at)
        if not isinstance(self.candidate, DerivedMemoryCandidate):
            raise MemoryLearningError("invalid_consolidation", "proposal candidate is invalid")
        if self.candidate.origin is not CandidateOrigin.CONSOLIDATION:
            raise MemoryLearningError("invalid_consolidation", "proposal candidate must have consolidation origin")
        if self.candidate.derivation_reference_id != self.proposal_id:
            raise MemoryLearningError("invalid_consolidation", "candidate must reference its consolidation proposal")
        if self.candidate.source_memories != memories or self.candidate.source_events != events:
            raise MemoryLearningError("invalid_consolidation", "candidate must preserve every proposal source")
        if self.candidate.created_at != proposed_at:
            raise MemoryLearningError("invalid_consolidation", "candidate and proposal timestamps must match")


def propose_memory_consolidation(
    *,
    authenticated_agent: AuthenticatedAgent,
    owning_agent_id: str,
    proposal_id: str,
    candidate_id: str,
    source_memories: Sequence[ImmutableMemoryReference],
    source_events: Sequence[SourceEventReference],
    memory_kind: str,
    content: str,
    rationale: str,
    confidence: float,
    proposed_at: datetime,
) -> MemoryConsolidationProposal:
    """Propose a candidate derived from all sources without rewriting them."""

    authenticated = _require_owning_agent(authenticated_agent, owning_agent_id)
    memories, events = _validate_source_bundle(
        owning_agent_id=owning_agent_id,
        source_memories=source_memories,
        source_events=source_events,
        minimum_memories=2,
    )
    proposed_at = _require_aware_datetime(proposed_at, "proposed_at")
    candidate = DerivedMemoryCandidate(
        candidate_id=candidate_id,
        owning_agent_id=owning_agent_id,
        created_by_agent_id=authenticated.target_agent_id,
        authentication_id=authenticated.token_id,
        origin=CandidateOrigin.CONSOLIDATION,
        derivation_reference_id=proposal_id,
        memory_kind=memory_kind,
        content=content,
        rationale=rationale,
        confidence=confidence,
        source_memories=memories,
        source_events=events,
        created_at=proposed_at,
    )
    return MemoryConsolidationProposal(
        proposal_id=proposal_id,
        owning_agent_id=owning_agent_id,
        source_memories=memories,
        source_events=events,
        candidate=candidate,
        proposed_at=proposed_at,
    )


@dataclass(frozen=True)
class RankingPolicyEvent:
    event_id: str
    kind: RankingPolicyEventKind
    occurred_at: datetime
    reason: str
    authenticated_agent_id: str
    authentication_id: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "event_id", _require_text(self.event_id, "event_id"))
        try:
            kind = RankingPolicyEventKind(self.kind)
        except ValueError as exc:
            raise MemoryLearningError("invalid_ranking_event", "unknown ranking policy event") from exc
        object.__setattr__(self, "kind", kind)
        object.__setattr__(self, "occurred_at", _require_aware_datetime(self.occurred_at, "occurred_at"))
        object.__setattr__(self, "reason", _require_text(self.reason, "reason"))
        object.__setattr__(
            self,
            "authenticated_agent_id",
            _require_text(self.authenticated_agent_id, "authenticated_agent_id"),
        )
        object.__setattr__(self, "authentication_id", _require_text(self.authentication_id, "authentication_id"))


@dataclass(frozen=True)
class MemoryRankingPolicy:
    """Append-only ranking policy; canonical memory lifecycle is untouched."""

    policy_id: str
    owning_agent_id: str
    memory: ImmutableMemoryReference
    mode: RankingPolicyMode
    weight_multiplier: float
    expires_at: datetime
    evidence_events: tuple[SourceEventReference, ...]
    history: tuple[RankingPolicyEvent, ...]

    def __post_init__(self) -> None:
        object.__setattr__(self, "policy_id", _require_text(self.policy_id, "policy_id"))
        object.__setattr__(self, "owning_agent_id", _require_text(self.owning_agent_id, "owning_agent_id"))
        if not isinstance(self.memory, ImmutableMemoryReference):
            raise MemoryLearningError("invalid_evidence", "ranking memory must be an immutable memory reference")
        if self.memory.owning_agent_id != self.owning_agent_id:
            raise MemoryLearningError("memory_owner_mismatch", "ranking policy memory must belong to owning agent")
        try:
            mode = RankingPolicyMode(self.mode)
        except ValueError as exc:
            raise MemoryLearningError("invalid_ranking_mode", "unknown ranking policy mode") from exc
        object.__setattr__(self, "mode", mode)
        multiplier = _require_confidence(self.weight_multiplier, "weight_multiplier", allow_zero=True)
        if mode is RankingPolicyMode.DECAY and not 0.0 < multiplier < 1.0:
            raise MemoryLearningError(
                "invalid_ranking_weight", "decay multiplier must be greater than 0 and less than 1"
            )
        if mode is RankingPolicyMode.FORGET and multiplier != 0.0:
            raise MemoryLearningError("invalid_ranking_weight", "forget multiplier must be exactly 0")
        object.__setattr__(self, "weight_multiplier", multiplier)
        expires_at = _require_aware_datetime(self.expires_at, "expires_at")
        object.__setattr__(self, "expires_at", expires_at)
        _, events = _validate_source_bundle(
            owning_agent_id=self.owning_agent_id,
            source_memories=(self.memory,),
            source_events=self.evidence_events,
            minimum_memories=1,
        )
        object.__setattr__(self, "evidence_events", events)
        history = tuple(self.history)
        if not history or len(history) > 2:
            raise MemoryLearningError(
                "invalid_ranking_history", "ranking history requires apply and optional restore events"
            )
        if any(not isinstance(event, RankingPolicyEvent) for event in history):
            raise MemoryLearningError("invalid_ranking_history", "ranking history contains an invalid event")
        if len({event.event_id for event in history}) != len(history):
            raise MemoryLearningError("invalid_ranking_history", "ranking event IDs must be unique")
        applied = history[0]
        if applied.kind is not RankingPolicyEventKind.APPLIED:
            raise MemoryLearningError("invalid_ranking_history", "first ranking event must apply the policy")
        if applied.authenticated_agent_id != self.owning_agent_id:
            raise MemoryLearningError("memory_owner_mismatch", "ranking policy author must be the owning agent")
        if applied.occurred_at < self.memory.committed_at:
            raise MemoryLearningError("invalid_ranking_time", "ranking policy cannot predate the memory")
        if expires_at <= applied.occurred_at:
            raise MemoryLearningError("invalid_ranking_expiry", "expires_at must follow the apply event")
        _validate_source_time((self.memory,), events, applied.occurred_at)
        if len(history) == 2:
            restored = history[1]
            if restored.kind is not RankingPolicyEventKind.RESTORED:
                raise MemoryLearningError("invalid_ranking_history", "second ranking event must restore the policy")
            if restored.authenticated_agent_id != self.owning_agent_id:
                raise MemoryLearningError(
                    "memory_owner_mismatch", "ranking restoration author must be the owning agent"
                )
            if not applied.occurred_at < restored.occurred_at < expires_at:
                raise MemoryLearningError(
                    "invalid_ranking_time",
                    "restoration must occur after application and before expiry",
                )
        object.__setattr__(self, "history", history)

    @property
    def applied_at(self) -> datetime:
        return self.history[0].occurred_at


def apply_ranking_policy(
    *,
    authenticated_agent: AuthenticatedAgent,
    memory: ImmutableMemoryReference,
    policy_id: str,
    application_event_id: str,
    mode: RankingPolicyMode | str,
    weight_multiplier: float,
    reason: str,
    evidence_events: Sequence[SourceEventReference],
    applied_at: datetime,
    expires_at: datetime,
) -> MemoryRankingPolicy:
    """Apply reversible decay/forgetting only to derived recall ranking."""

    if not isinstance(memory, ImmutableMemoryReference):
        raise MemoryLearningError("invalid_evidence", "memory must be an immutable memory reference")
    authenticated = _require_owning_agent(authenticated_agent, memory.owning_agent_id)
    _, events = _validate_source_bundle(
        owning_agent_id=memory.owning_agent_id,
        source_memories=(memory,),
        source_events=evidence_events,
        minimum_memories=1,
    )
    event = RankingPolicyEvent(
        event_id=application_event_id,
        kind=RankingPolicyEventKind.APPLIED,
        occurred_at=applied_at,
        reason=reason,
        authenticated_agent_id=authenticated.target_agent_id,
        authentication_id=authenticated.token_id,
    )
    return MemoryRankingPolicy(
        policy_id=policy_id,
        owning_agent_id=memory.owning_agent_id,
        memory=memory,
        mode=mode,
        weight_multiplier=weight_multiplier,
        expires_at=expires_at,
        evidence_events=events,
        history=(event,),
    )


def restore_ranking_policy(
    *,
    authenticated_agent: AuthenticatedAgent,
    policy: MemoryRankingPolicy,
    restoration_event_id: str,
    reason: str,
    restored_at: datetime,
) -> MemoryRankingPolicy:
    """Append an early restoration event, preserving the original policy record."""

    if not isinstance(policy, MemoryRankingPolicy):
        raise MemoryLearningError("invalid_ranking_policy", "policy must be a memory ranking policy")
    authenticated = _require_owning_agent(authenticated_agent, policy.owning_agent_id)
    if len(policy.history) != 1:
        raise MemoryLearningError("ranking_policy_already_restored", "ranking policy already has a restoration event")
    restored_at = _require_aware_datetime(restored_at, "restored_at")
    if restored_at >= policy.expires_at:
        raise MemoryLearningError("ranking_policy_expired", "an expired policy cannot be restored")
    event = RankingPolicyEvent(
        event_id=restoration_event_id,
        kind=RankingPolicyEventKind.RESTORED,
        occurred_at=restored_at,
        reason=reason,
        authenticated_agent_id=authenticated.target_agent_id,
        authentication_id=authenticated.token_id,
    )
    return replace(policy, history=(*policy.history, event))


def ranking_disposition_at(policy: MemoryRankingPolicy, *, at: datetime) -> RankingDisposition:
    """Return the derived ranking state without changing canonical memory state."""

    if not isinstance(policy, MemoryRankingPolicy):
        raise MemoryLearningError("invalid_ranking_policy", "policy must be a memory ranking policy")
    at = _require_aware_datetime(at, "at")
    if at < policy.applied_at:
        return RankingDisposition.ACTIVE
    if len(policy.history) == 2 and at >= policy.history[1].occurred_at:
        return RankingDisposition.RESTORED
    if at >= policy.expires_at:
        return RankingDisposition.EXPIRED
    if policy.mode is RankingPolicyMode.DECAY:
        return RankingDisposition.DECAYED
    return RankingDisposition.FORGOTTEN


def ranking_multiplier_at(policy: MemoryRankingPolicy, *, at: datetime) -> float:
    """Return the transparent multiplier contributed by this ranking policy."""

    disposition = ranking_disposition_at(policy, at=at)
    if disposition in {RankingDisposition.DECAYED, RankingDisposition.FORGOTTEN}:
        return policy.weight_multiplier
    return 1.0
