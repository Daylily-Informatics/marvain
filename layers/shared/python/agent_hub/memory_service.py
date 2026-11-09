"""Pure memory lifecycle and transparent recall-ranking service contracts."""

from __future__ import annotations

import math
import re
from dataclasses import dataclass, replace
from datetime import datetime
from enum import StrEnum
from typing import Final, Iterable, Self

from agent_hub.memory_taxonomy import normalize_memory_kind, normalize_memory_provenance_class

HYBRID_RECALL_METHOD: Final = "marvain_hybrid_v1"
_TOKEN_RE: Final = re.compile(r"[A-Za-z0-9]+(?:'[A-Za-z0-9]+)?")
_SHA256_RE: Final = re.compile(r"[0-9a-f]{64}")


class MemoryServiceError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        self.code = code
        super().__init__(f"{code}: {message}")


class MemoryCommitState(StrEnum):
    CANDIDATE = "candidate"
    EMBEDDING_PENDING = "embedding_pending"
    EMBEDDING_FAILED = "embedding_failed"
    EMBEDDED = "embedded"
    COMMITTED = "committed"
    REJECTED = "rejected"
    SUPERSEDED = "superseded"
    TOMBSTONED = "tombstoned"


class MemoryPurpose(StrEnum):
    RECALL = "recall"
    DETAIL = "detail"
    HISTORY = "history"
    EXPORT = "export"


class MemoryLayer(StrEnum):
    RAW_ARTIFACT = "raw_artifact"
    ATTRIBUTED_EVENT = "attributed_event"
    EPISODE = "episode"
    KNOWLEDGE = "knowledge"


@dataclass(frozen=True)
class RetentionDecision:
    """An explicit retention decision; expiry excludes access, not physical deletion."""

    expires_at: datetime | None = None
    retain_until_revoked: bool = False

    def __post_init__(self) -> None:
        if not isinstance(self.retain_until_revoked, bool):
            raise MemoryServiceError("retention_required", "retain_until_revoked must be explicit")
        if self.expires_at is not None:
            _require_aware_datetime(self.expires_at, "expires_at")
        if (self.expires_at is None) == (not self.retain_until_revoked):
            raise MemoryServiceError("retention_required", "choose expires_at or retain_until_revoked")

    def permits_at(self, at: datetime) -> bool:
        at = _require_aware_datetime(at, "at")
        return self.expires_at is None or at < self.expires_at


@dataclass(frozen=True)
class MemoryAccessPolicy:
    """Immutable policy values; principal references are backed by TapDB lineage."""

    owner_principal_id: str
    reader_principal_ids: tuple[str, ...]
    allowed_purposes: frozenset[MemoryPurpose]
    raw_capture_allowed: bool
    retention: tuple[tuple[MemoryLayer, RetentionDecision], ...]
    revoked_at: datetime | None = None

    def __post_init__(self) -> None:
        _require_text(self.owner_principal_id, "owner_principal_id")
        if not self.reader_principal_ids or len(set(self.reader_principal_ids)) != len(self.reader_principal_ids):
            raise MemoryServiceError("readers_required", "explicit, unique reader principals are required")
        for principal in self.reader_principal_ids:
            _require_text(principal, "reader_principal_id")
        if not self.allowed_purposes:
            raise MemoryServiceError("purposes_required", "explicit allowed purposes are required")
        try:
            purposes = frozenset(MemoryPurpose(purpose) for purpose in self.allowed_purposes)
            layers = tuple((MemoryLayer(layer), decision) for layer, decision in self.retention)
        except (ValueError, TypeError) as exc:
            raise MemoryServiceError("invalid_policy", "unknown purpose or retention layer") from exc
        if not isinstance(self.raw_capture_allowed, bool):
            raise MemoryServiceError("invalid_policy", "raw_capture_allowed must be explicit")
        if self.revoked_at is not None:
            _require_aware_datetime(self.revoked_at, "revoked_at")
        if len(layers) != len(MemoryLayer) or {layer for layer, _ in layers} != set(MemoryLayer):
            raise MemoryServiceError("retention_required", "each memory layer needs exactly one retention decision")
        if not all(isinstance(decision, RetentionDecision) for _, decision in layers):
            raise MemoryServiceError("retention_required", "invalid retention decision")
        object.__setattr__(self, "allowed_purposes", purposes)
        object.__setattr__(self, "retention", layers)

    def permits(self, *, authenticated_principal_id: str, purpose: MemoryPurpose, layer: MemoryLayer, at: datetime) -> bool:
        """Caller supplies a principal established by the authentication boundary."""
        principal = _require_text(authenticated_principal_id, "authenticated_principal_id")
        purpose = MemoryPurpose(purpose)
        layer = MemoryLayer(layer)
        decision = dict(self.retention)[layer]
        return (principal in self.reader_principal_ids and purpose in self.allowed_purposes
                and (self.revoked_at is None or at < self.revoked_at) and decision.permits_at(at))

    def as_properties(self) -> dict[str, object]:
        """Only scalar policy values; principal relationships are stored as lineage."""
        return {
            "allowed_purposes": sorted(p.value for p in self.allowed_purposes),
            "raw_capture_allowed": self.raw_capture_allowed,
            "revoked_at": self.revoked_at.isoformat() if self.revoked_at else None,
            "retention": {layer.value: {"expires_at": decision.expires_at.isoformat() if decision.expires_at else None,
                                       "retain_until_revoked": decision.retain_until_revoked}
                          for layer, decision in self.retention},
        }


@dataclass(frozen=True)
class MemoryPolicyConstraint:
    policy: MemoryAccessPolicy
    layer: MemoryLayer


def permits_scoped_memory(
    *, authenticated_principal_id: str, purpose: MemoryPurpose, layer: MemoryLayer,
    policies: Iterable[MemoryPolicyConstraint], at: datetime,
) -> bool:
    """Require all policies of a derived item and its sources to permit disclosure."""
    values = tuple(policies)
    if not values:
        raise MemoryServiceError("policy_required", "source and item policies are required")
    if not any(constraint.layer == layer for constraint in values):
        raise MemoryServiceError("policy_required", "item policy for requested layer is required")
    return all(constraint.policy.permits(authenticated_principal_id=authenticated_principal_id,
                                         purpose=purpose, layer=constraint.layer, at=at) for constraint in values)


@dataclass(frozen=True)
class TemporalMemoryVersion:
    """A canonical assertion and all policies inherited from its source material."""

    memory_id: str
    recorded_at: datetime
    effective_at: datetime
    policies: tuple[MemoryPolicyConstraint, ...]
    retracted_at: datetime | None = None

    def __post_init__(self) -> None:
        _require_text(self.memory_id, "memory_id")
        _require_aware_datetime(self.recorded_at, "recorded_at")
        _require_aware_datetime(self.effective_at, "effective_at")
        if self.retracted_at is not None:
            _require_aware_datetime(self.retracted_at, "retracted_at")
        if not self.policies:
            raise MemoryServiceError("policy_required", "memory and source policies are required")


@dataclass(frozen=True)
class TemporalMemoryCorrection:
    correction_id: str
    target_memory_id: str
    replacement_memory_id: str
    recorded_at: datetime
    effective_at: datetime

    def __post_init__(self) -> None:
        for field in ("correction_id", "target_memory_id", "replacement_memory_id"):
            _require_text(getattr(self, field), field)
        if self.target_memory_id == self.replacement_memory_id:
            raise MemoryServiceError("invalid_correction", "replacement must differ from target")
        _require_aware_datetime(self.recorded_at, "recorded_at")
        _require_aware_datetime(self.effective_at, "effective_at")


@dataclass(frozen=True)
class VisibleMemoryVersion:
    version: TemporalMemoryVersion
    superseded_by: tuple[str, ...]


def select_temporal_memory(
    *, versions: Iterable[TemporalMemoryVersion], corrections: Iterable[TemporalMemoryCorrection],
    authenticated_principal_id: str, as_of: datetime, access_at: datetime, historical: bool = False,
) -> tuple[VisibleMemoryVersion, ...]:
    """Select authorized current or historical assertions before ranking.

    The authenticated boundary supplies the principal and complete source policy
    set; the canonical lineage reader supplies versions and correction edges.
    Retention is evaluated at access time, including for historical reads.
    """
    as_of = _require_aware_datetime(as_of, "as_of")
    access_at = _require_aware_datetime(access_at, "access_at")
    if as_of > access_at:
        raise MemoryServiceError("invalid_timestamp", "as_of cannot be later than access_at")
    purpose = MemoryPurpose.HISTORY if historical else MemoryPurpose.RECALL
    active_corrections = tuple(c for c in corrections if c.recorded_at <= as_of and c.effective_at <= as_of)
    results = []
    for version in versions:
        if version.recorded_at > as_of or version.effective_at > as_of:
            continue
        if version.retracted_at is not None and version.retracted_at <= as_of:
            continue
        if not permits_scoped_memory(authenticated_principal_id=authenticated_principal_id,
                                     purpose=purpose, layer=MemoryLayer.KNOWLEDGE,
                                     policies=version.policies, at=access_at):
            continue
        superseded = tuple(c.correction_id for c in active_corrections if c.target_memory_id == version.memory_id)
        if superseded and not historical:
            continue
        results.append(VisibleMemoryVersion(version=version, superseded_by=superseded))
    return tuple(results)


_ALLOWED_COMMIT_TRANSITIONS: Final[dict[MemoryCommitState, frozenset[MemoryCommitState]]] = {
    MemoryCommitState.CANDIDATE: frozenset({MemoryCommitState.EMBEDDING_PENDING, MemoryCommitState.REJECTED}),
    MemoryCommitState.EMBEDDING_PENDING: frozenset({MemoryCommitState.EMBEDDED, MemoryCommitState.EMBEDDING_FAILED}),
    MemoryCommitState.EMBEDDING_FAILED: frozenset({MemoryCommitState.EMBEDDING_PENDING, MemoryCommitState.REJECTED}),
    MemoryCommitState.EMBEDDED: frozenset({MemoryCommitState.COMMITTED, MemoryCommitState.REJECTED}),
    MemoryCommitState.COMMITTED: frozenset({MemoryCommitState.SUPERSEDED, MemoryCommitState.TOMBSTONED}),
    MemoryCommitState.SUPERSEDED: frozenset({MemoryCommitState.TOMBSTONED}),
    MemoryCommitState.REJECTED: frozenset(),
    MemoryCommitState.TOMBSTONED: frozenset(),
}


def _require_text(value: object, field: str) -> str:
    if not isinstance(value, str):
        raise MemoryServiceError("invalid_field", f"{field} must be a string")
    normalized = value.strip()
    if not normalized:
        raise MemoryServiceError("invalid_field", f"{field} is required")
    return normalized


def _optional_text(value: str | None, field: str) -> str | None:
    if value is None:
        return None
    return _require_text(value, field)


def _require_aware_datetime(value: datetime, field: str) -> datetime:
    if not isinstance(value, datetime):
        raise MemoryServiceError("invalid_timestamp", f"{field} must be a datetime")
    if value.tzinfo is None or value.utcoffset() is None:
        raise MemoryServiceError("invalid_timestamp", f"{field} must be timezone-aware")
    return value


def _require_number(value: object, field: str, *, minimum: float, maximum: float) -> float:
    if isinstance(value, bool) or not isinstance(value, int | float):
        raise MemoryServiceError("invalid_score", f"{field} must be numeric")
    normalized = float(value)
    if not math.isfinite(normalized) or not minimum <= normalized <= maximum:
        raise MemoryServiceError(
            "invalid_score",
            f"{field} must be finite and from {minimum} to {maximum}",
        )
    return normalized


@dataclass(frozen=True)
class MemoryStateTransition:
    from_state: MemoryCommitState
    to_state: MemoryCommitState
    occurred_at: datetime
    reason: str

    def __post_init__(self) -> None:
        try:
            from_state = MemoryCommitState(self.from_state)
            to_state = MemoryCommitState(self.to_state)
        except ValueError as exc:
            raise MemoryServiceError("invalid_transition", "transition contains an unknown state") from exc
        if to_state not in _ALLOWED_COMMIT_TRANSITIONS[from_state]:
            raise MemoryServiceError(
                "invalid_transition",
                f"cannot transition memory from {from_state.value} to {to_state.value}",
            )
        object.__setattr__(self, "from_state", from_state)
        object.__setattr__(self, "to_state", to_state)
        object.__setattr__(self, "occurred_at", _require_aware_datetime(self.occurred_at, "occurred_at"))
        object.__setattr__(self, "reason", _require_text(self.reason, "reason"))


@dataclass(frozen=True)
class MemoryEmbeddingReceipt:
    provider_id: str
    model: str
    dimensions: int
    vector_sha256: str
    succeeded_at: datetime

    def __post_init__(self) -> None:
        object.__setattr__(self, "provider_id", _require_text(self.provider_id, "provider_id"))
        object.__setattr__(self, "model", _require_text(self.model, "model"))
        if isinstance(self.dimensions, bool) or not isinstance(self.dimensions, int) or self.dimensions <= 0:
            raise MemoryServiceError("invalid_embedding_receipt", "dimensions must be a positive integer")
        digest = _require_text(self.vector_sha256, "vector_sha256").lower()
        if _SHA256_RE.fullmatch(digest) is None:
            raise MemoryServiceError("invalid_embedding_receipt", "vector_sha256 must be a SHA-256 hex digest")
        object.__setattr__(self, "vector_sha256", digest)
        object.__setattr__(self, "succeeded_at", _require_aware_datetime(self.succeeded_at, "succeeded_at"))


@dataclass(frozen=True)
class MemoryEmbeddingFailure:
    code: str
    message: str
    retryable: bool
    failed_at: datetime
    details: tuple[tuple[str, str], ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "code", _require_text(self.code, "code"))
        object.__setattr__(self, "message", _require_text(self.message, "message"))
        object.__setattr__(self, "failed_at", _require_aware_datetime(self.failed_at, "failed_at"))
        names = [name for name, _ in self.details]
        if any(not name.strip() for name in names) or len(names) != len(set(names)):
            raise MemoryServiceError("invalid_embedding_failure", "detail names must be nonblank and unique")

    def as_record(self) -> dict[str, object]:
        return {
            "status": MemoryCommitState.EMBEDDING_FAILED.value,
            "failure_code": self.code,
            "message": self.message,
            "retryable": self.retryable,
            "failed_at": self.failed_at.isoformat(),
            "details": dict(self.details),
        }


@dataclass(frozen=True)
class MemoryCommitDecision:
    decision_id: str
    actor_type: str
    actor_id: str
    basis: str
    decided_at: datetime

    def __post_init__(self) -> None:
        object.__setattr__(self, "decision_id", _require_text(self.decision_id, "decision_id"))
        object.__setattr__(self, "actor_type", _require_text(self.actor_type, "actor_type"))
        object.__setattr__(self, "actor_id", _require_text(self.actor_id, "actor_id"))
        object.__setattr__(self, "basis", _require_text(self.basis, "basis"))
        object.__setattr__(self, "decided_at", _require_aware_datetime(self.decided_at, "decided_at"))


@dataclass(frozen=True)
class MemoryCommitRecord:
    """Immutable candidate state whose commit edge requires an embedding receipt."""

    candidate_id: str
    source_evidence_id: str
    created_at: datetime
    state: MemoryCommitState = MemoryCommitState.CANDIDATE
    embedding_receipt: MemoryEmbeddingReceipt | None = None
    embedding_failures: tuple[MemoryEmbeddingFailure, ...] = ()
    commit_decision: MemoryCommitDecision | None = None
    transitions: tuple[MemoryStateTransition, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "candidate_id", _require_text(self.candidate_id, "candidate_id"))
        object.__setattr__(
            self,
            "source_evidence_id",
            _require_text(self.source_evidence_id, "source_evidence_id"),
        )
        created_at = _require_aware_datetime(self.created_at, "created_at")
        object.__setattr__(self, "created_at", created_at)
        try:
            state = MemoryCommitState(self.state)
        except ValueError as exc:
            raise MemoryServiceError("invalid_state", "unknown memory commit state") from exc
        object.__setattr__(self, "state", state)

        replay_state = MemoryCommitState.CANDIDATE
        previous_at = created_at
        failed_transitions: list[MemoryStateTransition] = []
        embedded_transition: MemoryStateTransition | None = None
        committed_transition: MemoryStateTransition | None = None
        for transition in self.transitions:
            if transition.from_state != replay_state:
                raise MemoryServiceError("invalid_transition_history", "memory transition history is disconnected")
            if transition.occurred_at < previous_at:
                raise MemoryServiceError("invalid_transition_history", "memory transition timestamps are not monotonic")
            replay_state = transition.to_state
            previous_at = transition.occurred_at
            if transition.to_state is MemoryCommitState.EMBEDDING_FAILED:
                failed_transitions.append(transition)
            elif transition.to_state is MemoryCommitState.EMBEDDED:
                embedded_transition = transition
            elif transition.to_state is MemoryCommitState.COMMITTED:
                committed_transition = transition
        if replay_state is not state:
            raise MemoryServiceError("invalid_transition_history", "memory state does not match transition history")

        if len(failed_transitions) != len(self.embedding_failures):
            raise MemoryServiceError(
                "invalid_transition_history",
                "embedding failure records must match embedding_failed transitions",
            )
        for transition, failure in zip(failed_transitions, self.embedding_failures, strict=True):
            if transition.occurred_at != failure.failed_at:
                raise MemoryServiceError(
                    "invalid_transition_history",
                    "embedding failure timestamp must match its transition",
                )

        if bool(embedded_transition) != bool(self.embedding_receipt):
            raise MemoryServiceError(
                "invalid_transition_history",
                "an embedded transition requires exactly one embedding receipt",
            )
        if embedded_transition and self.embedding_receipt:
            if embedded_transition.occurred_at != self.embedding_receipt.succeeded_at:
                raise MemoryServiceError(
                    "invalid_transition_history",
                    "embedding receipt timestamp must match the embedded transition",
                )

        if bool(committed_transition) != bool(self.commit_decision):
            raise MemoryServiceError(
                "invalid_transition_history",
                "a committed transition requires exactly one commit decision",
            )
        if committed_transition and self.commit_decision:
            if committed_transition.occurred_at != self.commit_decision.decided_at:
                raise MemoryServiceError(
                    "invalid_transition_history",
                    "commit decision timestamp must match the committed transition",
                )

    @classmethod
    def create(cls, *, candidate_id: str, source_evidence_id: str, created_at: datetime) -> Self:
        return cls(
            candidate_id=candidate_id,
            source_evidence_id=source_evidence_id,
            created_at=created_at,
        )

    def _advance(
        self,
        *,
        target: MemoryCommitState,
        occurred_at: datetime,
        reason: str,
        embedding_receipt: MemoryEmbeddingReceipt | None = None,
        embedding_failure: MemoryEmbeddingFailure | None = None,
        commit_decision: MemoryCommitDecision | None = None,
    ) -> Self:
        occurred_at = _require_aware_datetime(occurred_at, "occurred_at")
        allowed = _ALLOWED_COMMIT_TRANSITIONS[self.state]
        if target not in allowed:
            raise MemoryServiceError(
                "invalid_transition",
                f"cannot transition memory from {self.state.value} to {target.value}",
            )
        previous_at = self.transitions[-1].occurred_at if self.transitions else self.created_at
        if occurred_at < previous_at:
            raise MemoryServiceError("invalid_transition", "transition timestamp precedes current state")

        receipt = self.embedding_receipt
        failures = self.embedding_failures
        decision = self.commit_decision
        if target is MemoryCommitState.EMBEDDED:
            if embedding_receipt is None or embedding_receipt.succeeded_at != occurred_at:
                raise MemoryServiceError(
                    "embedding_receipt_required",
                    "embedding success requires a receipt with the transition timestamp",
                )
            receipt = embedding_receipt
        elif embedding_receipt is not None:
            raise MemoryServiceError("invalid_transition", "embedding receipt is only valid for embedding success")

        if target is MemoryCommitState.EMBEDDING_FAILED:
            if embedding_failure is None or embedding_failure.failed_at != occurred_at:
                raise MemoryServiceError(
                    "embedding_failure_required",
                    "embedding failure requires a failure record with the transition timestamp",
                )
            failures = (*failures, embedding_failure)
        elif embedding_failure is not None:
            raise MemoryServiceError("invalid_transition", "embedding failure is only valid for a failed attempt")

        if target is MemoryCommitState.COMMITTED:
            if receipt is None:
                raise MemoryServiceError("embedding_required", "memory cannot be committed before embedding succeeds")
            if commit_decision is None or commit_decision.decided_at != occurred_at:
                raise MemoryServiceError(
                    "commit_decision_required",
                    "memory commit requires a decision with the transition timestamp",
                )
            decision = commit_decision
        elif commit_decision is not None:
            raise MemoryServiceError("invalid_transition", "commit decision is only valid for commit")

        transition = MemoryStateTransition(
            from_state=self.state,
            to_state=target,
            occurred_at=occurred_at,
            reason=reason,
        )
        return replace(
            self,
            state=target,
            embedding_receipt=receipt,
            embedding_failures=failures,
            commit_decision=decision,
            transitions=(*self.transitions, transition),
        )

    def begin_embedding(self, *, request_id: str, requested_at: datetime) -> Self:
        request_id = _require_text(request_id, "request_id")
        return self._advance(
            target=MemoryCommitState.EMBEDDING_PENDING,
            occurred_at=requested_at,
            reason=f"embedding_requested:{request_id}",
        )

    def embedding_succeeded(self, receipt: MemoryEmbeddingReceipt) -> Self:
        return self._advance(
            target=MemoryCommitState.EMBEDDED,
            occurred_at=receipt.succeeded_at,
            reason=f"embedding_succeeded:{receipt.provider_id}:{receipt.model}",
            embedding_receipt=receipt,
        )

    def embedding_failed(self, failure: MemoryEmbeddingFailure) -> Self:
        return self._advance(
            target=MemoryCommitState.EMBEDDING_FAILED,
            occurred_at=failure.failed_at,
            reason=f"embedding_failed:{failure.code}",
            embedding_failure=failure,
        )

    def commit(self, decision: MemoryCommitDecision) -> Self:
        if self.embedding_receipt is None:
            raise MemoryServiceError("embedding_required", "memory cannot be committed before embedding succeeds")
        return self._advance(
            target=MemoryCommitState.COMMITTED,
            occurred_at=decision.decided_at,
            reason=f"commit_decision:{decision.decision_id}:{decision.basis}",
            commit_decision=decision,
        )

    def reject(self, *, reason: str, rejected_at: datetime) -> Self:
        return self._advance(
            target=MemoryCommitState.REJECTED,
            occurred_at=rejected_at,
            reason=f"rejected:{_require_text(reason, 'reason')}",
        )

    def supersede(self, *, reason: str, superseded_at: datetime) -> Self:
        return self._advance(
            target=MemoryCommitState.SUPERSEDED,
            occurred_at=superseded_at,
            reason=f"superseded:{_require_text(reason, 'reason')}",
        )

    def tombstone(self, *, reason: str, tombstoned_at: datetime) -> Self:
        return self._advance(
            target=MemoryCommitState.TOMBSTONED,
            occurred_at=tombstoned_at,
            reason=f"tombstoned:{_require_text(reason, 'reason')}",
        )


class MemoryAnnotationType(StrEnum):
    COMMENT = "comment"
    DISPUTE = "dispute"
    DOWNWEIGHT = "downweight"
    INCORRECT = "incorrect"
    PROPOSED_CLASSIFICATION = "proposed_classification"


@dataclass(frozen=True)
class MemoryAnnotation:
    """Append-only user opinion; influence is derived without changing memory content."""

    annotation_id: str
    memory_id: str
    annotation_type: MemoryAnnotationType
    weight_delta: float
    author_id: str
    created_at: datetime
    proposed_kind: str | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "annotation_id", _require_text(self.annotation_id, "annotation_id"))
        object.__setattr__(self, "memory_id", _require_text(self.memory_id, "memory_id"))
        object.__setattr__(self, "author_id", _require_text(self.author_id, "author_id"))
        object.__setattr__(self, "created_at", _require_aware_datetime(self.created_at, "created_at"))
        try:
            annotation_type = MemoryAnnotationType(self.annotation_type)
        except ValueError as exc:
            raise MemoryServiceError("invalid_annotation", "unknown annotation type") from exc
        object.__setattr__(self, "annotation_type", annotation_type)
        object.__setattr__(
            self,
            "weight_delta",
            _require_number(self.weight_delta, "weight_delta", minimum=-1.0, maximum=1.0),
        )
        proposed_kind = self.proposed_kind
        if annotation_type is MemoryAnnotationType.PROPOSED_CLASSIFICATION:
            if proposed_kind is None:
                raise MemoryServiceError(
                    "invalid_annotation",
                    "proposed_classification requires proposed_kind",
                )
            proposed_kind = normalize_memory_kind(proposed_kind)
        elif proposed_kind is not None:
            raise MemoryServiceError(
                "invalid_annotation",
                "proposed_kind is only valid for proposed_classification",
            )
        object.__setattr__(self, "proposed_kind", proposed_kind)


@dataclass(frozen=True)
class MemorySourceContext:
    source_evidence_id: str
    provenance_class: str
    space_id: str | None = None
    session_id: str | None = None
    person_id: str | None = None
    device_id: str | None = None

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "source_evidence_id",
            _require_text(self.source_evidence_id, "source_evidence_id"),
        )
        object.__setattr__(
            self,
            "provenance_class",
            normalize_memory_provenance_class(_require_text(self.provenance_class, "provenance_class")),
        )
        for field in ("space_id", "session_id", "person_id", "device_id"):
            object.__setattr__(self, field, _optional_text(getattr(self, field), field))

    def as_dict(self) -> dict[str, str | None]:
        return {
            "source_evidence_id": self.source_evidence_id,
            "provenance_class": self.provenance_class,
            "space_id": self.space_id,
            "session_id": self.session_id,
            "person_id": self.person_id,
            "device_id": self.device_id,
        }


@dataclass(frozen=True)
class RecallContext:
    space_id: str | None = None
    session_id: str | None = None
    person_id: str | None = None
    device_id: str | None = None
    provenance_class: str | None = None

    def __post_init__(self) -> None:
        for field in ("space_id", "session_id", "person_id", "device_id"):
            object.__setattr__(self, field, _optional_text(getattr(self, field), field))
        provenance_class = self.provenance_class
        if provenance_class is not None:
            provenance_class = normalize_memory_provenance_class(provenance_class)
        object.__setattr__(self, "provenance_class", provenance_class)

    def as_dict(self) -> dict[str, str | None]:
        return {
            "space_id": self.space_id,
            "session_id": self.session_id,
            "person_id": self.person_id,
            "device_id": self.device_id,
            "provenance_class": self.provenance_class,
        }


@dataclass(frozen=True)
class RecallCandidate:
    memory_id: str
    content: str
    created_at: datetime
    embedding_distance: float
    salience: float
    confidence: float
    source_context: MemorySourceContext
    lifecycle_state: MemoryCommitState

    def __post_init__(self) -> None:
        object.__setattr__(self, "memory_id", _require_text(self.memory_id, "memory_id"))
        object.__setattr__(self, "content", _require_text(self.content, "content"))
        object.__setattr__(self, "created_at", _require_aware_datetime(self.created_at, "created_at"))
        object.__setattr__(
            self,
            "embedding_distance",
            _require_number(self.embedding_distance, "embedding_distance", minimum=0.0, maximum=2.0),
        )
        object.__setattr__(self, "salience", _require_number(self.salience, "salience", minimum=0.0, maximum=1.0))
        object.__setattr__(
            self,
            "confidence",
            _require_number(self.confidence, "confidence", minimum=0.0, maximum=1.0),
        )
        try:
            lifecycle_state = MemoryCommitState(self.lifecycle_state)
        except ValueError as exc:
            raise MemoryServiceError("invalid_recall_candidate", "unknown memory lifecycle state") from exc
        if lifecycle_state is not MemoryCommitState.COMMITTED:
            raise MemoryServiceError("invalid_recall_candidate", "recall candidates must be committed")
        object.__setattr__(self, "lifecycle_state", lifecycle_state)


@dataclass(frozen=True)
class HybridRecallWeights:
    embedding: float = 0.40
    keyword: float = 0.20
    recency: float = 0.10
    salience: float = 0.10
    confidence: float = 0.10
    source_context: float = 0.10
    annotation_adjustment: float = 0.15

    def __post_init__(self) -> None:
        base_names = ("embedding", "keyword", "recency", "salience", "confidence", "source_context")
        base_total = 0.0
        for field in (*base_names, "annotation_adjustment"):
            value = getattr(self, field)
            if isinstance(value, bool) or not isinstance(value, int | float):
                raise MemoryServiceError("invalid_ranking_policy", f"{field} weight must be numeric")
            value = float(value)
            if not math.isfinite(value) or value < 0.0:
                raise MemoryServiceError("invalid_ranking_policy", f"{field} weight must be finite and nonnegative")
            object.__setattr__(self, field, value)
            if field in base_names:
                base_total += value
        if not math.isclose(base_total, 1.0, rel_tol=0.0, abs_tol=1e-9):
            raise MemoryServiceError("invalid_ranking_policy", "base recall weights must sum to 1.0")

    def as_dict(self) -> dict[str, float]:
        return {
            "embedding": self.embedding,
            "keyword": self.keyword,
            "recency": self.recency,
            "salience": self.salience,
            "confidence": self.confidence,
            "source_context": self.source_context,
            "annotation_adjustment": self.annotation_adjustment,
        }


DEFAULT_HYBRID_RECALL_WEIGHTS: Final = HybridRecallWeights()


@dataclass(frozen=True)
class HybridRecallPolicy:
    weights: HybridRecallWeights = DEFAULT_HYBRID_RECALL_WEIGHTS
    recency_half_life_days: float = 30.0

    def __post_init__(self) -> None:
        half_life = self.recency_half_life_days
        if isinstance(half_life, bool) or not isinstance(half_life, int | float):
            raise MemoryServiceError("invalid_ranking_policy", "recency_half_life_days must be numeric")
        half_life = float(half_life)
        if not math.isfinite(half_life) or half_life <= 0.0:
            raise MemoryServiceError("invalid_ranking_policy", "recency_half_life_days must be finite and positive")
        object.__setattr__(self, "recency_half_life_days", half_life)


DEFAULT_HYBRID_RECALL_POLICY: Final = HybridRecallPolicy()


@dataclass(frozen=True)
class AnnotationContribution:
    annotation_id: str
    annotation_type: MemoryAnnotationType
    weight_delta: float


@dataclass(frozen=True)
class AnnotationAdjustment:
    raw_adjustment: float
    applied_adjustment: float
    clamped: bool
    contributions: tuple[AnnotationContribution, ...]


@dataclass(frozen=True)
class SourceContextMatch:
    field: str
    requested_value: str
    source_value: str | None
    matched: bool


@dataclass(frozen=True)
class HybridRecallFeatures:
    embedding: float
    keyword: float
    recency: float
    salience: float
    confidence: float
    source_context: float
    annotation_adjustment: float

    def as_dict(self) -> dict[str, float]:
        return {
            "embedding": self.embedding,
            "keyword": self.keyword,
            "recency": self.recency,
            "salience": self.salience,
            "confidence": self.confidence,
            "source_context": self.source_context,
            "annotation_adjustment": self.annotation_adjustment,
        }


@dataclass(frozen=True)
class HybridRecallContributions:
    embedding: float
    keyword: float
    recency: float
    salience: float
    confidence: float
    source_context: float
    annotation_adjustment: float

    def as_dict(self) -> dict[str, float]:
        return {
            "embedding": self.embedding,
            "keyword": self.keyword,
            "recency": self.recency,
            "salience": self.salience,
            "confidence": self.confidence,
            "source_context": self.source_context,
            "annotation_adjustment": self.annotation_adjustment,
        }


@dataclass(frozen=True)
class HybridRecallScore:
    memory_id: str
    score: float
    raw_score: float
    score_was_clamped: bool
    features: HybridRecallFeatures
    contributions: HybridRecallContributions
    embedding_distance: float
    query_terms: tuple[str, ...]
    keyword_matches: tuple[str, ...]
    age_days: float
    annotation_adjustment: AnnotationAdjustment
    requested_context: RecallContext
    source_context: MemorySourceContext
    context_matches: tuple[SourceContextMatch, ...]
    policy: HybridRecallPolicy

    def as_explanation(self, *, rank: int | None = None) -> dict[str, object]:
        ranking: dict[str, object] = {
            "method": HYBRID_RECALL_METHOD,
            "score": self.score,
            "raw_score": self.raw_score,
            "score_was_clamped": self.score_was_clamped,
            "weights": self.policy.weights.as_dict(),
            "features": self.features.as_dict(),
            "contributions": self.contributions.as_dict(),
            "embedding": {
                "cosine_distance": self.embedding_distance,
                "normalized_similarity": self.features.embedding,
            },
            "keyword": {
                "query_terms": list(self.query_terms),
                "matches": list(self.keyword_matches),
                "query_coverage": self.features.keyword,
            },
            "recency": {
                "age_days": self.age_days,
                "half_life_days": self.policy.recency_half_life_days,
                "score": self.features.recency,
            },
            "annotation_adjustment": {
                "raw": self.annotation_adjustment.raw_adjustment,
                "applied": self.annotation_adjustment.applied_adjustment,
                "clamped": self.annotation_adjustment.clamped,
                "annotations": [
                    {
                        "annotation_id": contribution.annotation_id,
                        "annotation_type": contribution.annotation_type.value,
                        "weight_delta": contribution.weight_delta,
                    }
                    for contribution in self.annotation_adjustment.contributions
                ],
            },
            "source_context": {
                "requested": self.requested_context.as_dict(),
                "source": self.source_context.as_dict(),
                "matches": [
                    {
                        "field": match.field,
                        "requested_value": match.requested_value,
                        "source_value": match.source_value,
                        "matched": match.matched,
                    }
                    for match in self.context_matches
                ],
                "score": self.features.source_context,
            },
        }
        if rank is not None:
            ranking["rank"] = rank
        return {
            "ranking": ranking,
            "source_evidence_id": self.source_context.source_evidence_id,
            "provenance_class": self.source_context.provenance_class,
            "device_id": self.source_context.device_id,
            "space_id": self.source_context.space_id,
            "session_id": self.source_context.session_id,
            "person_id": self.source_context.person_id,
        }


@dataclass(frozen=True)
class RankedRecall:
    rank: int
    candidate: RecallCandidate
    score: HybridRecallScore

    def as_explanation(self) -> dict[str, object]:
        return self.score.as_explanation(rank=self.rank)


def _tokenize(value: str) -> tuple[str, ...]:
    return tuple(sorted({match.group(0).casefold() for match in _TOKEN_RE.finditer(value)}))


def _annotation_adjustment(memory_id: str, annotations: Iterable[MemoryAnnotation]) -> AnnotationAdjustment:
    contributions: list[AnnotationContribution] = []
    seen_ids: set[str] = set()
    for annotation in annotations:
        if annotation.memory_id != memory_id:
            raise MemoryServiceError(
                "annotation_memory_mismatch",
                f"annotation {annotation.annotation_id} does not belong to memory {memory_id}",
            )
        if annotation.annotation_id in seen_ids:
            raise MemoryServiceError("duplicate_annotation", f"duplicate annotation {annotation.annotation_id}")
        seen_ids.add(annotation.annotation_id)
        contributions.append(
            AnnotationContribution(
                annotation_id=annotation.annotation_id,
                annotation_type=annotation.annotation_type,
                weight_delta=annotation.weight_delta,
            )
        )
    contributions.sort(key=lambda item: item.annotation_id)
    raw = math.fsum(item.weight_delta for item in contributions)
    applied = min(1.0, max(-1.0, raw))
    return AnnotationAdjustment(
        raw_adjustment=raw,
        applied_adjustment=applied,
        clamped=not math.isclose(raw, applied, rel_tol=0.0, abs_tol=1e-12),
        contributions=tuple(contributions),
    )


def _source_context_score(
    requested: RecallContext,
    source: MemorySourceContext,
) -> tuple[float, tuple[SourceContextMatch, ...]]:
    matches: list[SourceContextMatch] = []
    for field in ("space_id", "session_id", "person_id", "device_id", "provenance_class"):
        requested_value = getattr(requested, field)
        if requested_value is None:
            continue
        source_value = getattr(source, field)
        matches.append(
            SourceContextMatch(
                field=field,
                requested_value=requested_value,
                source_value=source_value,
                matched=requested_value == source_value,
            )
        )
    if not matches:
        return 0.0, ()
    return math.fsum(1.0 for match in matches if match.matched) / len(matches), tuple(matches)


def score_hybrid_recall(
    *,
    query: str,
    candidate: RecallCandidate,
    context: RecallContext,
    annotations: Iterable[MemoryAnnotation],
    now: datetime,
    policy: HybridRecallPolicy = DEFAULT_HYBRID_RECALL_POLICY,
) -> HybridRecallScore:
    """Score one committed memory and preserve every feature contribution."""

    query = _require_text(query, "query")
    now = _require_aware_datetime(now, "now")
    if candidate.created_at > now:
        raise MemoryServiceError("invalid_recency", "candidate created_at cannot be later than now")
    query_terms = _tokenize(query)
    if not query_terms:
        raise MemoryServiceError("invalid_query", "query must contain at least one searchable term")
    content_terms = set(_tokenize(candidate.content))
    keyword_matches = tuple(sorted(set(query_terms) & content_terms))

    embedding_score = 1.0 - (candidate.embedding_distance / 2.0)
    keyword_score = len(keyword_matches) / len(query_terms)
    age_days = (now - candidate.created_at).total_seconds() / 86400.0
    recency_score = 2.0 ** (-age_days / policy.recency_half_life_days)
    context_score, context_matches = _source_context_score(context, candidate.source_context)
    annotation = _annotation_adjustment(candidate.memory_id, annotations)

    features = HybridRecallFeatures(
        embedding=embedding_score,
        keyword=keyword_score,
        recency=recency_score,
        salience=candidate.salience,
        confidence=candidate.confidence,
        source_context=context_score,
        annotation_adjustment=annotation.applied_adjustment,
    )
    weights = policy.weights
    contributions = HybridRecallContributions(
        embedding=features.embedding * weights.embedding,
        keyword=features.keyword * weights.keyword,
        recency=features.recency * weights.recency,
        salience=features.salience * weights.salience,
        confidence=features.confidence * weights.confidence,
        source_context=features.source_context * weights.source_context,
        annotation_adjustment=features.annotation_adjustment * weights.annotation_adjustment,
    )
    raw_score = math.fsum(contributions.as_dict().values())
    score = min(1.0, max(0.0, raw_score))
    return HybridRecallScore(
        memory_id=candidate.memory_id,
        score=score,
        raw_score=raw_score,
        score_was_clamped=not math.isclose(score, raw_score, rel_tol=0.0, abs_tol=1e-12),
        features=features,
        contributions=contributions,
        embedding_distance=candidate.embedding_distance,
        query_terms=query_terms,
        keyword_matches=keyword_matches,
        age_days=age_days,
        annotation_adjustment=annotation,
        requested_context=context,
        source_context=candidate.source_context,
        context_matches=context_matches,
        policy=policy,
    )


def rank_hybrid_recall(
    *,
    query: str,
    candidates: Iterable[RecallCandidate],
    context: RecallContext,
    annotations: Iterable[MemoryAnnotation],
    now: datetime,
    policy: HybridRecallPolicy = DEFAULT_HYBRID_RECALL_POLICY,
) -> tuple[RankedRecall, ...]:
    """Rank committed memories by hybrid score with a stable memory-id tie break."""

    candidate_values = tuple(candidates)
    candidate_ids = [candidate.memory_id for candidate in candidate_values]
    if len(candidate_ids) != len(set(candidate_ids)):
        raise MemoryServiceError("duplicate_candidate", "recall candidate memory IDs must be unique")
    annotations_by_memory: dict[str, list[MemoryAnnotation]] = {memory_id: [] for memory_id in candidate_ids}
    for annotation in annotations:
        if annotation.memory_id not in annotations_by_memory:
            raise MemoryServiceError(
                "annotation_memory_mismatch",
                f"annotation {annotation.annotation_id} has no recall candidate",
            )
        annotations_by_memory[annotation.memory_id].append(annotation)

    scored = [
        (
            candidate,
            score_hybrid_recall(
                query=query,
                candidate=candidate,
                context=context,
                annotations=annotations_by_memory[candidate.memory_id],
                now=now,
                policy=policy,
            ),
        )
        for candidate in candidate_values
    ]
    scored.sort(key=lambda item: (-item[1].score, item[0].memory_id))
    return tuple(
        RankedRecall(rank=rank, candidate=candidate, score=score)
        for rank, (candidate, score) in enumerate(scored, start=1)
    )
