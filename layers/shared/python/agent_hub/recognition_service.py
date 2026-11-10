"""Recognition lifecycle and quality contracts.

Model output is evidence, not an identity decision.  This module deliberately
separates observation, hypothesis, reviewed decision, optional biometric
projection, and presence so a worker cannot assert identity on its own.
"""

from __future__ import annotations

import hashlib
import json
import math
import uuid
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from enum import StrEnum
from typing import Protocol, Sequence


class RecognitionServiceError(ValueError):
    """Raised when recognition evidence violates the lifecycle contract."""


class RecognitionModality(StrEnum):
    VOICE = "voice"
    FACE = "face"


class ObservationState(StrEnum):
    OBSERVED = "observed"
    EMBEDDED = "embedded"
    MATCHED = "matched"
    NO_MATCH = "no_match"
    EXPIRED = "expired"


class HypothesisKind(StrEnum):
    CANDIDATE = "candidate"
    NO_MATCH = "no_match"


class ReviewDecision(StrEnum):
    ACCEPTED = "accepted"
    REJECTED = "rejected"
    NO_MATCH = "no_match"


class ActorType(StrEnum):
    USER = "user"
    AGENT = "agent"


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _required(value: str | None, field: str) -> str:
    normalized = str(value or "").strip()
    if not normalized:
        raise RecognitionServiceError(f"{field} is required")
    return normalized


def _probability(value: float, field: str) -> float:
    normalized = float(value)
    if not math.isfinite(normalized) or normalized < 0.0 or normalized > 1.0:
        raise RecognitionServiceError(f"{field} must be between 0 and 1")
    return normalized


def _sha256(value: str, field: str) -> str:
    normalized = _required(value, field).lower()
    if len(normalized) != 64 or any(char not in "0123456789abcdef" for char in normalized):
        raise RecognitionServiceError(f"{field} must be a lowercase SHA-256 digest")
    return normalized


@dataclass(frozen=True)
class ArtifactEvidence:
    artifact_id: str
    agent_id: str
    device_id: str
    bucket: str
    object_key: str
    uri: str
    media_type: str
    sha256: str
    captured_at: datetime
    source_event_id: str
    space_id: str | None = None
    location_id: str | None = None
    session_id: str | None = None

    def validated(self) -> ArtifactEvidence:
        artifact_id = _required(self.artifact_id, "artifact_id")
        agent_id = _required(self.agent_id, "agent_id")
        device_id = _required(self.device_id, "device_id")
        bucket = _required(self.bucket, "bucket")
        object_key = _required(self.object_key, "object_key")
        expected_uri = f"s3://{bucket}/{object_key}"
        if self.uri != expected_uri:
            raise RecognitionServiceError("artifact uri must match its bucket and object_key")
        if self.captured_at.tzinfo is None:
            raise RecognitionServiceError("captured_at must be timezone-aware")
        return replace(
            self,
            artifact_id=artifact_id,
            agent_id=agent_id,
            device_id=device_id,
            bucket=bucket,
            object_key=object_key,
            uri=expected_uri,
            media_type=_required(self.media_type, "media_type"),
            sha256=_sha256(self.sha256, "sha256"),
            source_event_id=_required(self.source_event_id, "source_event_id"),
            space_id=str(self.space_id).strip() if self.space_id else None,
            location_id=str(self.location_id).strip() if self.location_id else None,
            session_id=str(self.session_id).strip() if self.session_id else None,
        )


@dataclass(frozen=True)
class RecognitionObservation:
    observation_id: str
    artifact_id: str
    agent_id: str
    device_id: str
    modality: RecognitionModality
    model_id: str
    model_version: str
    embedding_sha256: str | None
    state: ObservationState
    created_at: datetime
    space_id: str | None = None
    location_id: str | None = None
    session_id: str | None = None
    source_event_id: str | None = None


@dataclass(frozen=True)
class RecognitionHypothesis:
    hypothesis_id: str
    observation_id: str
    kind: HypothesisKind
    confidence: float
    rationale: str
    candidate_person_id: str | None
    distance: float | None
    decision: str
    created_at: datetime


@dataclass(frozen=True)
class AuthenticatedReviewer:
    actor_id: str
    actor_type: ActorType

    def validated(self) -> AuthenticatedReviewer:
        return replace(self, actor_id=_required(self.actor_id, "reviewer.actor_id"))


@dataclass(frozen=True)
class ConsentProof:
    consent_id: str
    agent_id: str
    person_id: str
    consent_type: str
    valid_from: datetime
    expires_at: datetime | None = None
    revoked_at: datetime | None = None

    def permits(self, *, observation: RecognitionObservation, person_id: str, at: datetime) -> bool:
        return (
            bool(_required(self.consent_id, "consent_id"))
            and self.agent_id == observation.agent_id
            and self.person_id == person_id
            and self.consent_type in {observation.modality.value, "global"}
            and self.revoked_at is None
            and self.valid_from <= at
            and (self.expires_at is None or self.expires_at > at)
        )


@dataclass(frozen=True)
class RecognitionDecisionRecord:
    decision_id: str
    hypothesis_id: str
    decision: ReviewDecision
    reviewer: AuthenticatedReviewer
    reason: str
    decided_at: datetime
    consent_id: str | None = None


@dataclass(frozen=True)
class BiometricProjection:
    projection_id: str
    observation_id: str
    person_id: str
    modality: RecognitionModality
    consent_id: str
    model_id: str
    model_version: str
    embedding_sha256: str | None


@dataclass(frozen=True)
class PresenceAssertion:
    presence_assertion_id: str
    agent_id: str
    person_id: str
    hypothesis_id: str
    confidence: float
    asserted_at: datetime
    space_id: str | None
    location_id: str | None


@dataclass(frozen=True)
class DecisionApplication:
    observation: RecognitionObservation
    hypothesis: RecognitionHypothesis
    decision: RecognitionDecisionRecord
    projection: BiometricProjection | None
    presence: PresenceAssertion | None
    retract_observation_presence: bool
    retract_conflicting_space_presence: bool


class RecognitionRepository(Protocol):
    """Transactional persistence boundary implemented by the owning API."""

    def persist_observation(self, *, artifact: ArtifactEvidence, observation: RecognitionObservation) -> None: ...

    def get_observation(self, observation_id: str) -> RecognitionObservation: ...

    def persist_hypothesis(self, hypothesis: RecognitionHypothesis) -> None: ...

    def get_hypothesis(self, hypothesis_id: str) -> RecognitionHypothesis: ...

    def apply_decision(self, application: DecisionApplication) -> None:
        """Persist the decision, state changes, retractions, projection, and presence atomically."""
        ...


class RecognitionLifecycleService:
    def __init__(self, repository: RecognitionRepository) -> None:
        self.repository = repository

    def record_observation(
        self,
        *,
        artifact: ArtifactEvidence,
        modality: RecognitionModality,
        model_id: str,
        model_version: str,
        embedding: Sequence[float],
        created_at: datetime | None = None,
    ) -> RecognitionObservation:
        artifact = artifact.validated()
        if not embedding:
            raise RecognitionServiceError("embedding is required")
        normalized_embedding = [float(value) for value in embedding]
        if any(not math.isfinite(value) for value in normalized_embedding):
            raise RecognitionServiceError("embedding values must be finite")
        serialized = json.dumps(normalized_embedding, separators=(",", ":"), allow_nan=False).encode("utf-8")
        observation = RecognitionObservation(
            observation_id=str(uuid.uuid4()),
            artifact_id=artifact.artifact_id,
            agent_id=artifact.agent_id,
            device_id=artifact.device_id,
            modality=RecognitionModality(modality),
            model_id=_required(model_id, "model_id"),
            model_version=_required(model_version, "model_version"),
            embedding_sha256=hashlib.sha256(serialized).hexdigest(),
            state=ObservationState.EMBEDDED,
            created_at=created_at or _now(),
            space_id=artifact.space_id,
            location_id=artifact.location_id,
            session_id=artifact.session_id,
            source_event_id=artifact.source_event_id,
        )
        self.repository.persist_observation(artifact=artifact, observation=observation)
        return observation

    def propose_candidate(
        self,
        *,
        observation_id: str,
        candidate_person_id: str,
        confidence: float,
        distance: float,
        rationale: str,
        created_at: datetime | None = None,
    ) -> RecognitionHypothesis:
        observation = self.repository.get_observation(_required(observation_id, "observation_id"))
        if observation.state != ObservationState.EMBEDDED and not (
            observation.modality == RecognitionModality.FACE and observation.model_id == "aws-rekognition-comparefaces"
        ):
            raise RecognitionServiceError("candidate hypotheses require an embedded observation")
        normalized_distance = float(distance)
        if not math.isfinite(normalized_distance) or normalized_distance < 0:
            raise RecognitionServiceError("distance must be finite and non-negative")
        hypothesis = RecognitionHypothesis(
            hypothesis_id=str(uuid.uuid4()),
            observation_id=observation.observation_id,
            kind=HypothesisKind.CANDIDATE,
            confidence=_probability(confidence, "confidence"),
            rationale=_required(rationale, "rationale"),
            candidate_person_id=_required(candidate_person_id, "candidate_person_id"),
            distance=normalized_distance,
            decision="proposed",
            created_at=created_at or _now(),
        )
        self.repository.persist_hypothesis(hypothesis)
        return hypothesis

    def propose_no_match(
        self,
        *,
        observation_id: str,
        confidence: float,
        rationale: str,
        created_at: datetime | None = None,
    ) -> RecognitionHypothesis:
        observation = self.repository.get_observation(_required(observation_id, "observation_id"))
        if observation.state != ObservationState.EMBEDDED and not (
            observation.modality == RecognitionModality.FACE and observation.model_id == "aws-rekognition-comparefaces"
        ):
            raise RecognitionServiceError("no-match hypotheses require an embedded observation")
        hypothesis = RecognitionHypothesis(
            hypothesis_id=str(uuid.uuid4()),
            observation_id=observation.observation_id,
            kind=HypothesisKind.NO_MATCH,
            confidence=_probability(confidence, "confidence"),
            rationale=_required(rationale, "rationale"),
            candidate_person_id=None,
            distance=None,
            decision="proposed",
            created_at=created_at or _now(),
        )
        self.repository.persist_hypothesis(hypothesis)
        return hypothesis

    def review(
        self,
        *,
        hypothesis_id: str,
        decision: ReviewDecision,
        reviewer: AuthenticatedReviewer,
        reason: str,
        consent: ConsentProof | None,
        create_biometric_projection: bool,
        assert_presence: bool,
        decided_at: datetime | None = None,
    ) -> DecisionApplication:
        hypothesis = self.repository.get_hypothesis(_required(hypothesis_id, "hypothesis_id"))
        if hypothesis.decision != "proposed":
            raise RecognitionServiceError("hypothesis has already been decided")
        observation = self.repository.get_observation(hypothesis.observation_id)
        reviewer = reviewer.validated()
        reason = _required(reason, "reason")
        decision = ReviewDecision(decision)
        decided_at = decided_at or _now()
        person_id = hypothesis.candidate_person_id
        consent_id: str | None = None

        if decision == ReviewDecision.ACCEPTED:
            if hypothesis.kind != HypothesisKind.CANDIDATE or not person_id:
                raise RecognitionServiceError("only a candidate hypothesis can be accepted")
            if consent is None or not consent.permits(observation=observation, person_id=person_id, at=decided_at):
                raise RecognitionServiceError("accepted recognition requires active matching consent")
            consent_id = consent.consent_id
        elif create_biometric_projection or assert_presence:
            raise RecognitionServiceError("projection and presence require an accepted decision")

        resolved_observation = replace(
            observation,
            state=(
                ObservationState.MATCHED
                if decision == ReviewDecision.ACCEPTED
                else ObservationState.NO_MATCH
                if decision == ReviewDecision.NO_MATCH
                else observation.state
            ),
        )
        resolved_hypothesis = replace(hypothesis, decision=decision.value)
        decision_record = RecognitionDecisionRecord(
            decision_id=str(uuid.uuid4()),
            hypothesis_id=hypothesis.hypothesis_id,
            decision=decision,
            reviewer=reviewer,
            reason=reason,
            decided_at=decided_at,
            consent_id=consent_id,
        )
        projection = None
        if create_biometric_projection:
            assert person_id is not None and consent_id is not None
            projection = BiometricProjection(
                projection_id=str(uuid.uuid4()),
                observation_id=observation.observation_id,
                person_id=person_id,
                modality=observation.modality,
                consent_id=consent_id,
                model_id=observation.model_id,
                model_version=observation.model_version,
                embedding_sha256=observation.embedding_sha256,
            )
        presence = None
        if assert_presence:
            assert person_id is not None
            if not observation.space_id:
                raise RecognitionServiceError("presence requires observation space_id")
            presence = PresenceAssertion(
                presence_assertion_id=str(uuid.uuid4()),
                agent_id=observation.agent_id,
                person_id=person_id,
                hypothesis_id=hypothesis.hypothesis_id,
                confidence=hypothesis.confidence,
                asserted_at=decided_at,
                space_id=observation.space_id,
                location_id=observation.location_id,
            )
        application = DecisionApplication(
            observation=resolved_observation,
            hypothesis=resolved_hypothesis,
            decision=decision_record,
            projection=projection,
            presence=presence,
            retract_observation_presence=decision != ReviewDecision.ACCEPTED,
            retract_conflicting_space_presence=presence is not None,
        )
        self.repository.apply_decision(application)
        return application


@dataclass(frozen=True)
class RecognitionQualitySample:
    expected_person_id: str | None
    predicted_person_id: str | None
    confidence: float


@dataclass(frozen=True)
class RecognitionQualityThresholds:
    max_false_accept_rate: float
    max_false_reject_rate: float
    min_unknown_recall: float
    min_identification_accuracy: float
    max_expected_calibration_error: float

    def validated(self) -> RecognitionQualityThresholds:
        for field in (
            "max_false_accept_rate",
            "max_false_reject_rate",
            "min_unknown_recall",
            "min_identification_accuracy",
            "max_expected_calibration_error",
        ):
            _probability(getattr(self, field), field)
        return self


@dataclass(frozen=True)
class RecognitionQualityReport:
    sample_count: int
    known_count: int
    unknown_count: int
    false_accept_rate: float
    false_reject_rate: float
    unknown_recall: float
    identification_accuracy: float
    expected_calibration_error: float
    passed: bool


def evaluate_recognition_quality(
    samples: Sequence[RecognitionQualitySample],
    *,
    thresholds: RecognitionQualityThresholds,
    calibration_bins: int,
) -> RecognitionQualityReport:
    thresholds = thresholds.validated()
    if not samples:
        raise RecognitionServiceError("quality evaluation requires samples")
    if calibration_bins < 2:
        raise RecognitionServiceError("calibration_bins must be at least 2")
    known = [sample for sample in samples if sample.expected_person_id is not None]
    unknown = [sample for sample in samples if sample.expected_person_id is None]
    if not known or not unknown:
        raise RecognitionServiceError("quality evaluation requires known and unknown samples")
    for sample in samples:
        _probability(sample.confidence, "sample.confidence")

    false_accepts = sum(sample.predicted_person_id is not None for sample in unknown)
    false_rejects = sum(sample.predicted_person_id != sample.expected_person_id for sample in known)
    correct = sum(sample.predicted_person_id == sample.expected_person_id for sample in known)
    unknown_correct = sum(sample.predicted_person_id is None for sample in unknown)
    far = false_accepts / len(unknown)
    frr = false_rejects / len(known)
    accuracy = correct / len(known)
    unknown_recall = unknown_correct / len(unknown)

    ece = 0.0
    for bin_index in range(calibration_bins):
        lower = bin_index / calibration_bins
        upper = (bin_index + 1) / calibration_bins
        bucket = [
            sample
            for sample in samples
            if lower <= sample.confidence < upper or (bin_index == calibration_bins - 1 and sample.confidence == 1.0)
        ]
        if not bucket:
            continue
        bucket_accuracy = sum(sample.predicted_person_id == sample.expected_person_id for sample in bucket) / len(
            bucket
        )
        bucket_confidence = sum(sample.confidence for sample in bucket) / len(bucket)
        ece += (len(bucket) / len(samples)) * abs(bucket_accuracy - bucket_confidence)

    passed = (
        far <= thresholds.max_false_accept_rate
        and frr <= thresholds.max_false_reject_rate
        and unknown_recall >= thresholds.min_unknown_recall
        and accuracy >= thresholds.min_identification_accuracy
        and ece <= thresholds.max_expected_calibration_error
    )
    return RecognitionQualityReport(
        sample_count=len(samples),
        known_count=len(known),
        unknown_count=len(unknown),
        false_accept_rate=far,
        false_reject_rate=frr,
        unknown_recall=unknown_recall,
        identification_accuracy=accuracy,
        expected_calibration_error=ece,
        passed=passed,
    )


@dataclass(frozen=True)
class RecognitionWorkerHeartbeat:
    worker_id: str
    worker_version: str
    host_id: str
    voice_model_id: str
    voice_model_version: str
    face_model_id: str
    face_model_version: str
    state: str
    started_at: datetime
    observed_at: datetime
    processed_messages: int
    failed_messages: int
    last_event_id: str | None
    last_error: str | None

    def as_payload(self) -> dict[str, object]:
        return {
            "schema": "marvain.recognition.worker.v1",
            "evidence_kind": "recognition_worker_heartbeat",
            "worker_id": _required(self.worker_id, "worker_id"),
            "worker_version": _required(self.worker_version, "worker_version"),
            "host_id": _required(self.host_id, "host_id"),
            "models": {
                "voice": {"id": self.voice_model_id, "version": self.voice_model_version},
                "face": {"id": self.face_model_id, "version": self.face_model_version},
            },
            "state": _required(self.state, "state"),
            "started_at": self.started_at.isoformat(),
            "observed_at": self.observed_at.isoformat(),
            "processed_messages": int(self.processed_messages),
            "failed_messages": int(self.failed_messages),
            "last_event_id": self.last_event_id,
            "last_error": self.last_error,
        }
