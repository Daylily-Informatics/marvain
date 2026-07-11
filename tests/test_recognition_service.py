from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from agent_hub.recognition_service import (
    ActorType,
    ArtifactEvidence,
    AuthenticatedReviewer,
    ConsentProof,
    DecisionApplication,
    HypothesisKind,
    ObservationState,
    RecognitionLifecycleService,
    RecognitionModality,
    RecognitionQualitySample,
    RecognitionQualityThresholds,
    RecognitionServiceError,
    ReviewDecision,
    evaluate_recognition_quality,
)


class RecordingRepository:
    def __init__(self) -> None:
        self.artifacts = {}
        self.observations = {}
        self.hypotheses = {}
        self.applications: list[DecisionApplication] = []

    def persist_observation(self, *, artifact, observation) -> None:
        self.artifacts[artifact.artifact_id] = artifact
        self.observations[observation.observation_id] = observation

    def get_observation(self, observation_id):
        return self.observations[observation_id]

    def persist_hypothesis(self, hypothesis) -> None:
        self.hypotheses[hypothesis.hypothesis_id] = hypothesis

    def get_hypothesis(self, hypothesis_id):
        return self.hypotheses[hypothesis_id]

    def apply_decision(self, application: DecisionApplication) -> None:
        self.observations[application.observation.observation_id] = application.observation
        self.hypotheses[application.hypothesis.hypothesis_id] = application.hypothesis
        self.applications.append(application)


NOW = datetime(2026, 7, 11, 1, 0, tzinfo=timezone.utc)


def _artifact(*, with_space: bool = True) -> ArtifactEvidence:
    return ArtifactEvidence(
        artifact_id="artifact-1",
        agent_id="agent-1",
        device_id="device-1",
        bucket="recognition-artifacts",
        object_key="recognition/sample.wav",
        uri="s3://recognition-artifacts/recognition/sample.wav",
        media_type="audio/wav",
        sha256="a" * 64,
        captured_at=NOW,
        source_event_id="event-1",
        space_id="space-1" if with_space else None,
        location_id="location-1",
        session_id="session-1",
    )


def _candidate(repo: RecordingRepository, *, with_space: bool = True):
    service = RecognitionLifecycleService(repo)
    observation = service.record_observation(
        artifact=_artifact(with_space=with_space),
        modality=RecognitionModality.VOICE,
        model_id="voice-model",
        model_version="1.2.3",
        embedding=[0.1, 0.2, 0.3],
        created_at=NOW,
    )
    hypothesis = service.propose_candidate(
        observation_id=observation.observation_id,
        candidate_person_id="person-1",
        confidence=0.93,
        distance=0.07,
        rationale="nearest consented candidate",
        created_at=NOW,
    )
    return service, observation, hypothesis


def _consent() -> ConsentProof:
    return ConsentProof(
        consent_id="consent-1",
        agent_id="agent-1",
        person_id="person-1",
        consent_type="voice",
        valid_from=NOW - timedelta(days=1),
        expires_at=NOW + timedelta(days=1),
    )


def test_model_output_stops_at_proposed_hypothesis() -> None:
    repo = RecordingRepository()
    _service, observation, hypothesis = _candidate(repo)

    assert observation.state == ObservationState.EMBEDDED
    assert hypothesis.kind == HypothesisKind.CANDIDATE
    assert hypothesis.decision == "proposed"
    assert repo.applications == []


def test_authenticated_review_atomically_creates_projection_and_presence() -> None:
    repo = RecordingRepository()
    service, _observation, hypothesis = _candidate(repo)

    result = service.review(
        hypothesis_id=hypothesis.hypothesis_id,
        decision=ReviewDecision.ACCEPTED,
        reviewer=AuthenticatedReviewer(actor_id="reviewer-user-1", actor_type=ActorType.USER),
        reason="reviewed against the source sample",
        consent=_consent(),
        create_biometric_projection=True,
        assert_presence=True,
        decided_at=NOW,
    )

    assert result.observation.state == ObservationState.MATCHED
    assert result.hypothesis.decision == "accepted"
    assert result.decision.reviewer.actor_id == "reviewer-user-1"
    assert result.projection is not None
    assert result.projection.consent_id == "consent-1"
    assert result.presence is not None
    assert result.presence.space_id == "space-1"
    assert result.retract_conflicting_space_presence is True
    assert repo.applications == [result]


def test_acceptance_requires_current_matching_consent() -> None:
    repo = RecordingRepository()
    service, _observation, hypothesis = _candidate(repo)
    revoked = ConsentProof(
        consent_id="consent-1",
        agent_id="agent-1",
        person_id="person-1",
        consent_type="voice",
        valid_from=NOW - timedelta(days=1),
        revoked_at=NOW - timedelta(minutes=1),
    )

    with pytest.raises(RecognitionServiceError, match="active matching consent"):
        service.review(
            hypothesis_id=hypothesis.hypothesis_id,
            decision=ReviewDecision.ACCEPTED,
            reviewer=AuthenticatedReviewer(actor_id="reviewer-1", actor_type=ActorType.USER),
            reason="attempted acceptance",
            consent=revoked,
            create_biometric_projection=False,
            assert_presence=False,
            decided_at=NOW,
        )

    assert repo.applications == []


def test_no_match_is_persisted_and_retracts_observation_presence() -> None:
    repo = RecordingRepository()
    service = RecognitionLifecycleService(repo)
    observation = service.record_observation(
        artifact=_artifact(),
        modality=RecognitionModality.VOICE,
        model_id="voice-model",
        model_version="1.2.3",
        embedding=[0.1, 0.2],
        created_at=NOW,
    )
    hypothesis = service.propose_no_match(
        observation_id=observation.observation_id,
        confidence=0.88,
        rationale="no enrolled identity met threshold",
        created_at=NOW,
    )

    result = service.review(
        hypothesis_id=hypothesis.hypothesis_id,
        decision=ReviewDecision.NO_MATCH,
        reviewer=AuthenticatedReviewer(actor_id="reviewer-1", actor_type=ActorType.USER),
        reason="confirmed unknown person",
        consent=None,
        create_biometric_projection=False,
        assert_presence=False,
        decided_at=NOW,
    )

    assert result.observation.state == ObservationState.NO_MATCH
    assert result.hypothesis.decision == "no_match"
    assert result.projection is None
    assert result.presence is None
    assert result.retract_observation_presence is True


def test_presence_requires_source_space() -> None:
    repo = RecordingRepository()
    service, _observation, hypothesis = _candidate(repo, with_space=False)

    with pytest.raises(RecognitionServiceError, match="presence requires observation space_id"):
        service.review(
            hypothesis_id=hypothesis.hypothesis_id,
            decision=ReviewDecision.ACCEPTED,
            reviewer=AuthenticatedReviewer(actor_id="reviewer-1", actor_type=ActorType.USER),
            reason="identity confirmed",
            consent=_consent(),
            create_biometric_projection=False,
            assert_presence=True,
            decided_at=NOW,
        )


def test_artifact_checksum_and_uri_are_mandatory() -> None:
    repo = RecordingRepository()
    service = RecognitionLifecycleService(repo)
    invalid = ArtifactEvidence(**{**_artifact().__dict__, "uri": "s3://other/key"})

    with pytest.raises(RecognitionServiceError, match="uri must match"):
        service.record_observation(
            artifact=invalid,
            modality=RecognitionModality.VOICE,
            model_id="voice-model",
            model_version="1.2.3",
            embedding=[0.1],
        )


def test_quality_evaluator_measures_known_unknown_and_calibration() -> None:
    report = evaluate_recognition_quality(
        [
            RecognitionQualitySample("person-1", "person-1", 0.95),
            RecognitionQualitySample("person-2", "person-2", 0.85),
            RecognitionQualitySample(None, None, 0.90),
            RecognitionQualitySample(None, None, 0.95),
        ],
        thresholds=RecognitionQualityThresholds(
            max_false_accept_rate=0.0,
            max_false_reject_rate=0.0,
            min_unknown_recall=1.0,
            min_identification_accuracy=1.0,
            max_expected_calibration_error=0.10,
        ),
        calibration_bins=5,
    )

    assert report.passed is True
    assert report.false_accept_rate == 0.0
    assert report.false_reject_rate == 0.0
    assert report.unknown_recall == 1.0
    assert report.identification_accuracy == 1.0
    assert report.expected_calibration_error == pytest.approx(0.0875)


def test_quality_evaluator_fails_false_accept_and_false_reject_gates() -> None:
    report = evaluate_recognition_quality(
        [
            RecognitionQualitySample("person-1", None, 0.20),
            RecognitionQualitySample(None, "person-2", 0.80),
        ],
        thresholds=RecognitionQualityThresholds(
            max_false_accept_rate=0.05,
            max_false_reject_rate=0.05,
            min_unknown_recall=0.95,
            min_identification_accuracy=0.95,
            max_expected_calibration_error=0.20,
        ),
        calibration_bins=2,
    )

    assert report.passed is False
    assert report.false_accept_rate == 1.0
    assert report.false_reject_rate == 1.0
