"""Transactional RDS persistence for the canonical recognition lifecycle.

Workers may persist evidence and proposed hypotheses only. Identity decisions,
biometric projections, and presence assertions are applied separately by the
authenticated review path in :mod:`functions.hub_api.api_app`.
"""

from __future__ import annotations

import json
import math
import uuid
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Mapping, Sequence

from agent_hub.rds_data import RdsData
from agent_hub.recognition_service import (
    ActorType,
    ArtifactEvidence,
    AuthenticatedReviewer,
    BiometricProjection,
    ConsentProof,
    DecisionApplication,
    HypothesisKind,
    ObservationState,
    PresenceAssertion,
    RecognitionHypothesis,
    RecognitionModality,
    RecognitionObservation,
    RecognitionWorkerHeartbeat,
    ReviewDecision,
)
from agent_hub.semantic_outbox import GraphSourceRef, enqueue_semantic_graph, enqueue_semantic_record
from agent_hub.semantic_tapdb import TEMPLATE_CODES, GraphLinkWrite, GraphObjectRef, GraphObjectWrite


class RecognitionPersistenceError(RuntimeError):
    """Base exception for recognition persistence failures."""


class RecognitionNotFoundError(RecognitionPersistenceError):
    """Raised when authoritative source evidence is absent."""


class RecognitionConflictError(RecognitionPersistenceError):
    """Raised when an idempotent replay differs from persisted evidence."""


def _text(value: Any) -> str:
    return str(value or "").strip()


def _optional_text(value: Any) -> str | None:
    normalized = _text(value)
    return normalized or None


def _datetime(value: Any, field: str) -> datetime:
    if isinstance(value, datetime):
        result = value
    else:
        normalized = _text(value)
        if not normalized:
            raise RecognitionPersistenceError(f"persisted {field} is missing")
        try:
            result = datetime.fromisoformat(normalized.replace("Z", "+00:00"))
        except ValueError as exc:
            raise RecognitionPersistenceError(f"persisted {field} is invalid") from exc
    if result.tzinfo is None:
        raise RecognitionPersistenceError(f"persisted {field} must be timezone-aware")
    return result


def _json_object(value: Any, field: str) -> dict[str, Any]:
    if isinstance(value, dict):
        return dict(value)
    if not isinstance(value, str):
        raise RecognitionPersistenceError(f"persisted {field} must be a JSON object")
    try:
        parsed = json.loads(value)
    except json.JSONDecodeError as exc:
        raise RecognitionPersistenceError(f"persisted {field} contains invalid JSON") from exc
    if not isinstance(parsed, dict):
        raise RecognitionPersistenceError(f"persisted {field} must be a JSON object")
    return parsed


def _same_float(left: Any, right: float | None) -> bool:
    if left is None or right is None:
        return left is None and right is None
    return math.isclose(float(left), float(right), rel_tol=1e-9, abs_tol=1e-9)


def _observation_from_row(row: Mapping[str, Any]) -> RecognitionObservation:
    try:
        return RecognitionObservation(
            observation_id=_text(row.get("observation_id")),
            artifact_id=_text(row.get("artifact_id")),
            agent_id=_text(row.get("agent_id")),
            device_id=_text(row.get("device_id")),
            modality=RecognitionModality(_text(row.get("modality"))),
            model_id=_text(row.get("model_id")),
            model_version=_text(row.get("model_version")),
            embedding_sha256=_text(row.get("embedding_sha256")),
            state=ObservationState(_text(row.get("lifecycle_state"))),
            created_at=_datetime(row.get("created_at"), "observation.created_at"),
            space_id=_optional_text(row.get("space_id")),
            location_id=_optional_text(row.get("location_id")),
            session_id=_optional_text(row.get("session_id")),
            source_event_id=_optional_text(row.get("source_event_id")),
        )
    except ValueError as exc:
        raise RecognitionPersistenceError("persisted observation has an invalid enum value") from exc


def _hypothesis_from_row(row: Mapping[str, Any]) -> RecognitionHypothesis:
    try:
        return RecognitionHypothesis(
            hypothesis_id=_text(row.get("hypothesis_id")),
            observation_id=_text(row.get("observation_id")),
            kind=HypothesisKind(_text(row.get("kind"))),
            confidence=float(row.get("confidence")),
            rationale=_text(row.get("rationale")),
            candidate_person_id=_optional_text(row.get("candidate_person_id")),
            distance=float(row["distance"]) if row.get("distance") is not None else None,
            decision=_text(row.get("decision")),
            created_at=_datetime(row.get("created_at"), "hypothesis.created_at"),
        )
    except (TypeError, ValueError) as exc:
        raise RecognitionPersistenceError("persisted hypothesis is malformed") from exc


@dataclass(frozen=True)
class ObservationPreparation:
    artifact: ArtifactEvidence
    existing: RecognitionObservation | None


@dataclass(frozen=True)
class HypothesisPreparation:
    observation: RecognitionObservation
    existing: RecognitionHypothesis | None
    consent_id: str | None


@dataclass(frozen=True)
class WorkerHeartbeatReceipt:
    worker_id: str
    heartbeat_id: str
    received_at: str
    replayed: bool


class RdsRecognitionRepository:
    """One-transaction implementation of the recognition repository protocol."""

    def __init__(self, db: RdsData, *, agent_id: str) -> None:
        self.db = db
        self.agent_id = _text(agent_id)
        if not self.agent_id:
            raise RecognitionPersistenceError("agent_id is required")
        self.transaction_id = db.begin()
        self._closed = False
        self._hypothesis_requested_projection = False
        self._hypothesis_consent_id: str | None = None
        self._review_auth_subject: str | None = None
        self._reviewer_principal_euid: str | None = None
        self._no_match_retention_until: datetime | None = None

    def commit(self) -> None:
        if self._closed:
            raise RecognitionPersistenceError("recognition transaction is already closed")
        self.db.commit(self.transaction_id)
        self._closed = True

    def rollback(self) -> None:
        if not self._closed:
            self.db.rollback(self.transaction_id)
            self._closed = True

    def prepare_observation(
        self,
        *,
        source_event_id: str,
        claimed_agent_id: str,
        claimed_space_id: str | None,
        claimed_location_id: str | None,
        claimed_session_id: str | None,
        source_device_id: str,
        artifact_payload: Mapping[str, Any],
        modality: RecognitionModality,
        model_id: str,
        model_version: str,
        embedding_sha256: str,
    ) -> ObservationPreparation:
        rows = self.db.query(
            """
            SELECT e.event_id::text AS source_event_id,
                   e.agent_id::text AS event_agent_id,
                   e.space_id::text AS event_space_id,
                   e.location_id::text AS event_location_id,
                   e.session_id::text AS event_session_id,
                   e.device_id::text AS event_device_id,
                   e.type AS event_type,
                   e.payload::text AS event_payload_json,
                   e.created_at::text AS event_created_at,
                   s.agent_id::text AS space_agent_id,
                   s.location_id::text AS space_location_id,
                   d.agent_id::text AS source_device_agent_id,
                   d.location_id::text AS source_device_location_id,
                   sess.agent_id::text AS session_agent_id,
                   sess.space_id::text AS session_space_id,
                   ar.artifact_id::text AS artifact_id,
                   ar.agent_id::text AS artifact_agent_id,
                   ar.space_id::text AS artifact_space_id,
                   ar.device_id::text AS artifact_device_id,
                   ar.session_id::text AS artifact_session_id,
                   ar.bucket AS artifact_bucket,
                   ar.object_key AS artifact_object_key,
                   ar.uri AS artifact_uri,
                   ar.media_type AS artifact_media_type,
                   ar.actual_sha256 AS artifact_sha256,
                   ar.lifecycle_state AS artifact_lifecycle_state
            FROM events e
            JOIN spaces s ON s.space_id = e.space_id
            JOIN devices d ON d.device_id = e.device_id
            LEFT JOIN sessions sess ON sess.session_id = e.session_id
            JOIN artifact_references ar ON ar.artifact_id = e.artifact_id
            WHERE e.event_id = :source_event_id::uuid
            FOR UPDATE OF e
            """,
            {"source_event_id": source_event_id},
            transaction_id=self.transaction_id,
        )
        if len(rows) != 1:
            raise RecognitionNotFoundError("source event was not found")
        row = rows[0]
        event_agent_id = _text(row.get("event_agent_id"))
        event_space_id = _text(row.get("event_space_id"))
        event_device_id = _text(row.get("event_device_id"))
        event_session_id = _optional_text(row.get("event_session_id"))
        authoritative_location_id = _optional_text(row.get("event_location_id"))

        expected_event_type = "voice.sample" if modality == RecognitionModality.VOICE else "face.snapshot"
        identity_values = {
            event_agent_id,
            _text(row.get("space_agent_id")),
            _text(row.get("source_device_agent_id")),
            _text(claimed_agent_id),
            self.agent_id,
        }
        if len(identity_values) != 1:
            raise RecognitionConflictError("source event, space, device, and worker agent scopes do not match")
        if _text(row.get("event_type")) != expected_event_type:
            raise RecognitionConflictError("source event type does not match recognition modality")
        if event_device_id != _text(source_device_id):
            raise RecognitionConflictError("source event device does not match the worker claim")
        if claimed_space_id and event_space_id != _text(claimed_space_id):
            raise RecognitionConflictError("source event space does not match the worker claim")
        if claimed_session_id and event_session_id != _text(claimed_session_id):
            raise RecognitionConflictError("source event session does not match the worker claim")
        if claimed_location_id and authoritative_location_id != _text(claimed_location_id):
            raise RecognitionConflictError("source event location does not match the worker claim")
        if event_session_id and (
            _text(row.get("session_agent_id")) != event_agent_id or _text(row.get("session_space_id")) != event_space_id
        ):
            raise RecognitionConflictError("source event session is not scoped to the source agent and space")

        event_payload = _json_object(row.get("event_payload_json"), "source event payload")
        expected_bucket = _text(artifact_payload.get("bucket"))
        expected_key = _text(artifact_payload.get("object_key"))
        expected_uri = _text(artifact_payload.get("uri"))
        expected_media_type = _text(artifact_payload.get("media_type"))
        expected_sha256 = _text(artifact_payload.get("sha256")).lower()
        if expected_uri != f"s3://{expected_bucket}/{expected_key}":
            raise RecognitionConflictError("artifact URI does not match bucket and object key")
        event_artifact_values = {
            "artifact_bucket": expected_bucket,
            "artifact_key": expected_key,
            "artifact_sha256": expected_sha256,
        }
        for field, expected in event_artifact_values.items():
            if _text(event_payload.get(field)).lower() != expected.lower():
                raise RecognitionConflictError(f"artifact {field} does not match immutable source event evidence")
        event_content_type = _text(event_payload.get("content_type"))
        if event_content_type != expected_media_type:
            raise RecognitionConflictError("artifact media type does not match immutable source event evidence")
        if modality == RecognitionModality.VOICE and not expected_media_type.startswith("audio/"):
            raise RecognitionConflictError("voice observations require an audio artifact")
        if modality == RecognitionModality.FACE and not expected_media_type.startswith(("image/", "video/")):
            raise RecognitionConflictError("face observations require an image or video artifact")

        artifact_id = _optional_text(row.get("artifact_id"))
        if artifact_id is None:
            raise RecognitionConflictError("recognition requires a verified artifact reference")
        persisted = {
            "agent_id": _text(row.get("artifact_agent_id")),
            "space_id": _optional_text(row.get("artifact_space_id")),
            "device_id": _text(row.get("artifact_device_id")),
            "session_id": _optional_text(row.get("artifact_session_id")),
            "bucket": _text(row.get("artifact_bucket")),
            "object_key": _text(row.get("artifact_object_key")),
            "uri": _text(row.get("artifact_uri")),
            "media_type": _text(row.get("artifact_media_type")),
            "sha256": _text(row.get("artifact_sha256")).lower(),
        }
        expected = {
            "agent_id": event_agent_id,
            "space_id": event_space_id,
            "device_id": event_device_id,
            "session_id": event_session_id,
            "bucket": expected_bucket,
            "object_key": expected_key,
            "uri": expected_uri,
            "media_type": expected_media_type,
            "sha256": expected_sha256,
        }
        if persisted != expected or _text(row.get("artifact_lifecycle_state")) != "available":
            raise RecognitionConflictError("persisted artifact reference conflicts with source evidence")

        artifact = ArtifactEvidence(
            artifact_id=artifact_id,
            agent_id=event_agent_id,
            device_id=event_device_id,
            bucket=expected_bucket,
            object_key=expected_key,
            uri=expected_uri,
            media_type=expected_media_type,
            sha256=expected_sha256,
            captured_at=_datetime(event_payload.get("captured_at"), "source event payload captured_at"),
            source_event_id=_text(row.get("source_event_id")),
            space_id=event_space_id,
            location_id=authoritative_location_id,
            session_id=event_session_id,
        ).validated()

        existing_rows = self.db.query(
            """
            SELECT recognition_observation_id::text AS observation_id,
                   artifact_id::text AS artifact_id,
                   agent_id::text AS agent_id,
                   device_id::text AS device_id,
                   modality,
                   model_id,
                   model_version,
                   embedding_sha256,
                   lifecycle_state,
                   created_at::text AS created_at,
                   space_id::text AS space_id,
                   location_id::text AS location_id,
                   session_id::text AS session_id,
                   source_event_id::text AS source_event_id
            FROM recognition_observations
            WHERE source_event_id = :source_event_id::uuid
            ORDER BY created_at
            LIMIT 2
            """,
            {"source_event_id": source_event_id},
            transaction_id=self.transaction_id,
        )
        if len(existing_rows) > 1:
            raise RecognitionConflictError("source event has duplicate recognition observations")
        existing = _observation_from_row(existing_rows[0]) if existing_rows else None
        if existing:
            expected_existing = (
                existing.artifact_id == artifact.artifact_id
                and existing.agent_id == artifact.agent_id
                and existing.device_id == artifact.device_id
                and existing.space_id == artifact.space_id
                and existing.location_id == artifact.location_id
                and existing.session_id == artifact.session_id
                and existing.source_event_id == artifact.source_event_id
                and existing.modality == modality
                and existing.model_id == _text(model_id)
                and existing.model_version == _text(model_version)
                and existing.embedding_sha256 == embedding_sha256
                and existing.state != ObservationState.EXPIRED
            )
            if not expected_existing:
                raise RecognitionConflictError("observation idempotency replay conflicts with persisted evidence")
        return ObservationPreparation(artifact=artifact, existing=existing)

    def persist_observation(self, *, artifact: ArtifactEvidence, observation: RecognitionObservation) -> None:
        if observation.agent_id != self.agent_id:
            raise RecognitionConflictError("observation agent scope does not match repository scope")
        self.db.execute(
            """
            INSERT INTO recognition_observations(
                recognition_observation_id, agent_id, space_id, location_id, session_id, device_id,
                artifact_id, source_event_id, modality, lifecycle_state, model_id, model_version,
                embedding_sha256, created_at
            ) VALUES(
                :observation_id::uuid, :agent_id::uuid, :space_id::uuid,
                NULLIF(CAST(:location_id AS text), '')::uuid,
                NULLIF(CAST(:session_id AS text), '')::uuid,
                :device_id::uuid, :artifact_id::uuid, :source_event_id::uuid, :modality,
                :lifecycle_state, :model_id, :model_version, :embedding_sha256, :created_at::timestamptz
            )
            """,
            {
                "observation_id": observation.observation_id,
                "agent_id": observation.agent_id,
                "space_id": observation.space_id,
                "location_id": observation.location_id or "",
                "session_id": observation.session_id or "",
                "device_id": observation.device_id,
                "artifact_id": observation.artifact_id,
                "source_event_id": observation.source_event_id,
                "modality": observation.modality.value,
                "lifecycle_state": observation.state.value,
                "model_id": observation.model_id,
                "model_version": observation.model_version,
                "embedding_sha256": observation.embedding_sha256,
                "created_at": observation.created_at.isoformat(),
            },
            transaction_id=self.transaction_id,
        )
        if not observation.source_event_id:
            raise RecognitionPersistenceError("canonical observation requires source event identity")
        source_template = TEMPLATE_CODES["event_sensor"]
        objects = (GraphObjectWrite("observation", TEMPLATE_CODES["recognition_observation"],
            f"recognition-observation:{observation.observation_id}",
            {"observation_id": observation.observation_id, "artifact_id": observation.artifact_id,
             "modality": observation.modality.value, "model_id": observation.model_id,
             "model_version": observation.model_version, "embedding_sha256": observation.embedding_sha256,
             "created_at": observation.created_at.isoformat()}, observation.state.value),)
        links = (GraphLinkWrite(GraphObjectRef(key="observation"),
            GraphSourceRef("events", observation.source_event_id, source_template), "BASED_ON"),)
        enqueue_semantic_graph(self.db, transaction_id=self.transaction_id, agent_id=observation.agent_id,
            source_table="recognition_observations", source_id=observation.observation_id,
            objects=objects, links=links, primary_key="observation")

    def get_observation(self, observation_id: str) -> RecognitionObservation:
        rows = self.db.query(
            """
            SELECT recognition_observation_id::text AS observation_id,
                   artifact_id::text AS artifact_id,
                   agent_id::text AS agent_id,
                   device_id::text AS device_id,
                   modality, model_id, model_version, embedding_sha256, lifecycle_state,
                   created_at::text AS created_at,
                   space_id::text AS space_id,
                   location_id::text AS location_id,
                   session_id::text AS session_id,
                   source_event_id::text AS source_event_id
            FROM recognition_observations
            WHERE recognition_observation_id = :observation_id::uuid
            LIMIT 1
            """,
            {"observation_id": observation_id},
            transaction_id=self.transaction_id,
        )
        if not rows:
            raise RecognitionNotFoundError("recognition observation was not found")
        observation = _observation_from_row(rows[0])
        if observation.agent_id != self.agent_id:
            raise RecognitionNotFoundError("recognition observation was not found")
        return observation

    def prepare_hypothesis(
        self,
        *,
        observation_id: str,
        kind: HypothesisKind,
        candidate_person_id: str | None,
        confidence: float,
        distance: float | None,
        rationale: str,
        requested_projection: bool,
    ) -> HypothesisPreparation:
        self.db.query(
            """
            SELECT recognition_observation_id::text AS observation_id
            FROM recognition_observations
            WHERE recognition_observation_id = :observation_id::uuid
            FOR UPDATE
            """,
            {"observation_id": observation_id},
            transaction_id=self.transaction_id,
        )
        observation = self.get_observation(observation_id)
        consent_id = None
        candidate_person_id_n = _optional_text(candidate_person_id)
        if kind == HypothesisKind.CANDIDATE:
            person_rows = self.db.query(
                """
                SELECT person_id::text AS person_id
                FROM people
                WHERE person_id = :person_id::uuid
                  AND agent_id = :agent_id::uuid
                LIMIT 1
                """,
                {"person_id": candidate_person_id_n, "agent_id": observation.agent_id},
                transaction_id=self.transaction_id,
            )
            if not person_rows:
                raise RecognitionNotFoundError("candidate person was not found for the observation agent")
            if requested_projection:
                consent_rows = self.db.query(
                    """
                    SELECT consent_id::text AS consent_id
                    FROM consent_grants
                    WHERE agent_id = :agent_id::uuid
                      AND person_id = :person_id::uuid
                      AND consent_type IN (:modality, 'global')
                      AND revoked_at IS NULL
                      AND granted_at <= now()
                      AND (expires_at IS NULL OR expires_at > now())
                    ORDER BY granted_at DESC
                    LIMIT 1
                    """,
                    {
                        "agent_id": observation.agent_id,
                        "person_id": candidate_person_id_n,
                        "modality": observation.modality.value,
                    },
                    transaction_id=self.transaction_id,
                )
                if not consent_rows:
                    raise RecognitionConflictError("requested biometric projection lacks active matching consent")
                consent_id = _text(consent_rows[0].get("consent_id"))
        elif requested_projection:
            raise RecognitionConflictError("no-match hypotheses cannot request a biometric projection")

        existing_rows = self.db.query(
            """
            SELECT identity_hypothesis_id::text AS hypothesis_id,
                   recognition_observation_id::text AS observation_id,
                   kind, candidate_person_id::text AS candidate_person_id,
                   confidence, distance, decision, rationale, requested_projection,
                   consent_id::text AS consent_id, created_at::text AS created_at
            FROM recognition_hypotheses
            WHERE recognition_observation_id = :observation_id::uuid
            ORDER BY created_at
            LIMIT 2
            """,
            {"observation_id": observation_id},
            transaction_id=self.transaction_id,
        )
        if len(existing_rows) > 1:
            raise RecognitionConflictError("observation has multiple worker hypotheses")
        existing = _hypothesis_from_row(existing_rows[0]) if existing_rows else None
        if existing:
            row = existing_rows[0]
            exact = (
                existing.kind == kind
                and existing.candidate_person_id == candidate_person_id_n
                and _same_float(existing.confidence, confidence)
                and _same_float(existing.distance, distance)
                and existing.rationale == _text(rationale)
                and bool(row.get("requested_projection")) == requested_projection
                and _optional_text(row.get("consent_id")) == consent_id
            )
            if not exact:
                raise RecognitionConflictError("hypothesis idempotency replay conflicts with persisted evidence")
        self._hypothesis_requested_projection = requested_projection
        self._hypothesis_consent_id = consent_id
        return HypothesisPreparation(observation=observation, existing=existing, consent_id=consent_id)

    def persist_hypothesis(self, hypothesis: RecognitionHypothesis) -> None:
        observation = self.get_observation(hypothesis.observation_id)
        self.db.execute(
            """
            INSERT INTO recognition_hypotheses(
                identity_hypothesis_id, recognition_observation_id, candidate_person_id, consent_id,
                kind, confidence, distance, decision, rationale, requested_projection, created_at
            ) VALUES(
                :hypothesis_id::uuid, :observation_id::uuid,
                NULLIF(CAST(:candidate_person_id AS text), '')::uuid,
                NULLIF(CAST(:consent_id AS text), '')::uuid,
                :kind, :confidence, :distance, 'proposed', :rationale,
                :requested_projection, :created_at::timestamptz
            )
            """,
            {
                "hypothesis_id": hypothesis.hypothesis_id,
                "observation_id": hypothesis.observation_id,
                "candidate_person_id": hypothesis.candidate_person_id or "",
                "consent_id": self._hypothesis_consent_id or "",
                "kind": hypothesis.kind.value,
                "confidence": hypothesis.confidence,
                "distance": hypothesis.distance,
                "rationale": hypothesis.rationale,
                "requested_projection": self._hypothesis_requested_projection,
                "created_at": hypothesis.created_at.isoformat(),
            },
            transaction_id=self.transaction_id,
        )
        objects = (GraphObjectWrite("hypothesis", TEMPLATE_CODES["recognition_hypothesis"],
            f"recognition-hypothesis:{hypothesis.hypothesis_id}",
            {"kind": hypothesis.kind.value, "confidence": hypothesis.confidence, "distance": hypothesis.distance,
             "rationale": hypothesis.rationale, "created_at": hypothesis.created_at.isoformat()}, "proposed"),)
        links = (GraphLinkWrite(GraphObjectRef(key="hypothesis"),
            GraphSourceRef("recognition_observations", hypothesis.observation_id, TEMPLATE_CODES["recognition_observation"]),
            "BASED_ON"),)
        enqueue_semantic_graph(self.db, transaction_id=self.transaction_id, agent_id=observation.agent_id,
            source_table="recognition_hypotheses", source_id=hypothesis.hypothesis_id,
            objects=objects, links=links, primary_key="hypothesis")

    def get_hypothesis(self, hypothesis_id: str) -> RecognitionHypothesis:
        rows = self.db.query(
            """
            SELECT rh.identity_hypothesis_id::text AS hypothesis_id,
                   rh.recognition_observation_id::text AS observation_id,
                   rh.kind, rh.candidate_person_id::text AS candidate_person_id,
                   rh.confidence, rh.distance, rh.decision, rh.rationale,
                   rh.created_at::text AS created_at,
                   ro.agent_id::text AS agent_id
            FROM recognition_hypotheses rh
            JOIN recognition_observations ro
              ON ro.recognition_observation_id = rh.recognition_observation_id
            WHERE rh.identity_hypothesis_id = :hypothesis_id::uuid
            LIMIT 1
            FOR UPDATE OF rh
            """,
            {"hypothesis_id": hypothesis_id},
            transaction_id=self.transaction_id,
        )
        if not rows or _text(rows[0].get("agent_id")) != self.agent_id:
            raise RecognitionNotFoundError("recognition hypothesis was not found")
        return _hypothesis_from_row(rows[0])

    def load_active_consent(self, *, observation: RecognitionObservation, person_id: str) -> ConsentProof | None:
        rows = self.db.query(
            """
            SELECT consent_id::text AS consent_id, agent_id::text AS agent_id,
                   person_id::text AS person_id, consent_type,
                   granted_at::text AS valid_from, expires_at::text AS expires_at,
                   revoked_at::text AS revoked_at
            FROM consent_grants
            WHERE agent_id = :agent_id::uuid
              AND person_id = :person_id::uuid
              AND consent_type IN (:modality, 'global')
              AND revoked_at IS NULL
              AND granted_at <= now()
              AND (expires_at IS NULL OR expires_at > now())
            ORDER BY granted_at DESC
            LIMIT 1
            """,
            {
                "agent_id": observation.agent_id,
                "person_id": person_id,
                "modality": observation.modality.value,
            },
            transaction_id=self.transaction_id,
        )
        if not rows:
            return None
        row = rows[0]
        return ConsentProof(
            consent_id=_text(row.get("consent_id")),
            agent_id=_text(row.get("agent_id")),
            person_id=_text(row.get("person_id")),
            consent_type=_text(row.get("consent_type")),
            valid_from=_datetime(row.get("valid_from"), "consent.valid_from"),
            expires_at=_datetime(row.get("expires_at"), "consent.expires_at") if row.get("expires_at") else None,
            revoked_at=_datetime(row.get("revoked_at"), "consent.revoked_at") if row.get("revoked_at") else None,
        )

    def configure_review(
        self,
        *,
        reviewer_auth_subject: str,
        reviewer_principal_euid: str,
        no_match_retention_until: datetime | None,
    ) -> None:
        self._review_auth_subject = _text(reviewer_auth_subject)
        self._reviewer_principal_euid = _text(reviewer_principal_euid)
        self._no_match_retention_until = no_match_retention_until

    def apply_decision(self, application: DecisionApplication) -> None:
        if not self._review_auth_subject or not self._reviewer_principal_euid:
            raise RecognitionPersistenceError("authenticated reviewer subject and principal are required")
        observation = application.observation
        hypothesis = application.hypothesis
        decision = application.decision
        self.db.execute(
            """
            INSERT INTO recognition_decisions(
                recognition_decision_id, agent_id, identity_hypothesis_id, decision,
                reviewer_actor_type, reviewer_actor_id, reviewer_auth_subject, reason,
                consent_id, decided_at
            ) VALUES(
                :decision_id::uuid, :agent_id::uuid, :hypothesis_id::uuid, :decision,
                :reviewer_actor_type, :reviewer_actor_id, :reviewer_auth_subject, :reason,
                NULLIF(CAST(:consent_id AS text), '')::uuid, :decided_at::timestamptz
            )
            """,
            {
                "decision_id": decision.decision_id,
                "agent_id": observation.agent_id,
                "hypothesis_id": hypothesis.hypothesis_id,
                "decision": decision.decision.value,
                "reviewer_actor_type": decision.reviewer.actor_type.value,
                "reviewer_actor_id": decision.reviewer.actor_id,
                "reviewer_auth_subject": self._review_auth_subject,
                "reason": decision.reason,
                "consent_id": decision.consent_id or "",
                "decided_at": decision.decided_at.isoformat(),
            },
            transaction_id=self.transaction_id,
        )
        self.db.execute(
            """
            UPDATE recognition_hypotheses
            SET decision = :decision,
                decided_at = :decided_at::timestamptz,
                consent_id = COALESCE(NULLIF(CAST(:consent_id AS text), '')::uuid, consent_id)
            WHERE identity_hypothesis_id = :hypothesis_id::uuid
              AND decision = 'proposed'
            """,
            {
                "decision": hypothesis.decision,
                "decided_at": decision.decided_at.isoformat(),
                "consent_id": decision.consent_id or "",
                "hypothesis_id": hypothesis.hypothesis_id,
            },
            transaction_id=self.transaction_id,
        )
        self.db.execute(
            """
            UPDATE recognition_observations
            SET lifecycle_state = :lifecycle_state
            WHERE recognition_observation_id = :observation_id::uuid
            """,
            {"lifecycle_state": observation.state.value, "observation_id": observation.observation_id},
            transaction_id=self.transaction_id,
        )

        if decision.decision == ReviewDecision.NO_MATCH:
            if self._no_match_retention_until is None:
                raise RecognitionPersistenceError("no-match review requires an explicit retention_until")
            no_match_id = str(uuid.uuid4())
            self.db.execute(
                """
                INSERT INTO recognition_no_matches(
                    recognition_no_match_id, agent_id, recognition_observation_id,
                    identity_hypothesis_id, recognition_decision_id, rationale, confidence,
                    lifecycle_state, retention_until, retained_at
                ) VALUES(
                    :no_match_id::uuid, :agent_id::uuid, :observation_id::uuid,
                    :hypothesis_id::uuid, :decision_id::uuid, :rationale, :confidence,
                    'retained', :retention_until::timestamptz, :retained_at::timestamptz
                )
                """,
                {
                    "no_match_id": no_match_id,
                    "agent_id": observation.agent_id,
                    "observation_id": observation.observation_id,
                    "hypothesis_id": hypothesis.hypothesis_id,
                    "decision_id": decision.decision_id,
                    "rationale": decision.reason,
                    "confidence": hypothesis.confidence,
                    "retention_until": self._no_match_retention_until.isoformat(),
                    "retained_at": decision.decided_at.isoformat(),
                },
                transaction_id=self.transaction_id,
            )

        if application.retract_observation_presence:
            self.db.execute(
                """
                UPDATE presence_assertions
                SET status = 'retracted', retracted_at = :decided_at::timestamptz,
                    retraction_reason = :reason, retracted_by_decision_id = :decision_id::uuid,
                    retracted_by_actor_type = :actor_type, retracted_by_actor_id = :actor_id
                WHERE identity_hypothesis_id = :hypothesis_id::uuid
                  AND status = 'present'
                """,
                {
                    "decided_at": decision.decided_at.isoformat(),
                    "reason": decision.reason,
                    "decision_id": decision.decision_id,
                    "actor_type": decision.reviewer.actor_type.value,
                    "actor_id": decision.reviewer.actor_id,
                    "hypothesis_id": hypothesis.hypothesis_id,
                },
                transaction_id=self.transaction_id,
            )

        if application.projection:
            projection: BiometricProjection = application.projection
            self.db.execute(
                """
                INSERT INTO biometric_projections(
                    biometric_projection_id, agent_id, recognition_observation_id,
                    recognition_decision_id, person_id, consent_id, modality, model_id,
                    model_version, embedding_sha256, lifecycle_state, created_at
                ) VALUES(
                    :projection_id::uuid, :agent_id::uuid, :observation_id::uuid,
                    :decision_id::uuid, :person_id::uuid, :consent_id::uuid, :modality,
                    :model_id, :model_version, :embedding_sha256, 'active', :created_at::timestamptz
                )
                """,
                {
                    "projection_id": projection.projection_id,
                    "agent_id": observation.agent_id,
                    "observation_id": projection.observation_id,
                    "decision_id": decision.decision_id,
                    "person_id": projection.person_id,
                    "consent_id": projection.consent_id,
                    "modality": projection.modality.value,
                    "model_id": projection.model_id,
                    "model_version": projection.model_version,
                    "embedding_sha256": projection.embedding_sha256,
                    "created_at": decision.decided_at.isoformat(),
                },
                transaction_id=self.transaction_id,
            )

        if application.presence:
            presence: PresenceAssertion = application.presence
            if application.retract_conflicting_space_presence:
                self.db.execute(
                    """
                    UPDATE presence_assertions
                    SET status = 'retracted', retracted_at = :asserted_at::timestamptz,
                        retraction_reason = 'superseded by reviewed recognition in another space',
                        retracted_by_decision_id = :decision_id::uuid,
                        retracted_by_actor_type = :actor_type,
                        retracted_by_actor_id = :actor_id,
                        superseded_by_presence_assertion_id = :presence_id::uuid
                    WHERE agent_id = :agent_id::uuid
                      AND person_id = :person_id::uuid
                      AND status = 'present'
                      AND space_id IS DISTINCT FROM :space_id::uuid
                    """,
                    {
                        "asserted_at": presence.asserted_at.isoformat(),
                        "decision_id": decision.decision_id,
                        "actor_type": decision.reviewer.actor_type.value,
                        "actor_id": decision.reviewer.actor_id,
                        "presence_id": presence.presence_assertion_id,
                        "agent_id": presence.agent_id,
                        "person_id": presence.person_id,
                        "space_id": presence.space_id,
                    },
                    transaction_id=self.transaction_id,
                )
            self.db.execute(
                """
                INSERT INTO presence_assertions(
                    presence_assertion_id, agent_id, space_id, location_id, person_id,
                    identity_hypothesis_id, confidence, status, asserted_at
                ) VALUES(
                    :presence_id::uuid, :agent_id::uuid, :space_id::uuid,
                    NULLIF(CAST(:location_id AS text), '')::uuid, :person_id::uuid,
                    :hypothesis_id::uuid, :confidence, 'present', :asserted_at::timestamptz
                )
                """,
                {
                    "presence_id": presence.presence_assertion_id,
                    "agent_id": presence.agent_id,
                    "space_id": presence.space_id,
                    "location_id": presence.location_id or "",
                    "person_id": presence.person_id,
                    "hypothesis_id": presence.hypothesis_id,
                    "confidence": presence.confidence,
                    "asserted_at": presence.asserted_at.isoformat(),
                },
                transaction_id=self.transaction_id,
            )
            enqueue_semantic_record(
                self.db,
                transaction_id=self.transaction_id,
                agent_id=presence.agent_id,
                source_table="presence_assertions",
                source_id=presence.presence_assertion_id,
                target_template_code=TEMPLATE_CODES["presence_assertion"],
                name=f"presence-assertion:{presence.presence_assertion_id}",
                lifecycle_state="present",
                properties={
                    "agent_id": presence.agent_id,
                    "presence_assertion_id": presence.presence_assertion_id,
                    "hypothesis_id": presence.hypothesis_id,
                    "person_id": presence.person_id,
                    "space_id": presence.space_id or "",
                    "location_id": presence.location_id or "",
                    "confidence": presence.confidence,
                    "recognition_decision_id": decision.decision_id,
                },
            )

        decision_ref = GraphObjectRef(key="decision")
        objects = (GraphObjectWrite("decision", TEMPLATE_CODES["event_sensor"],
            f"recognition-decision:{decision.decision_id}",
            {"decision": decision.decision.value, "reason": decision.reason,
             "decided_at": decision.decided_at.isoformat(), "consent_id": decision.consent_id or ""},
            decision.decision.value),)
        links = [
            GraphLinkWrite(decision_ref, GraphSourceRef("recognition_observations", observation.observation_id,
                                                       TEMPLATE_CODES["recognition_observation"]), "BASED_ON"),
            GraphLinkWrite(decision_ref, GraphSourceRef("recognition_hypotheses", hypothesis.hypothesis_id,
                                                       TEMPLATE_CODES["recognition_hypothesis"]), "REVIEWS"),
            GraphLinkWrite(decision_ref, GraphObjectRef(semantic_id=self._reviewer_principal_euid), "AUTHENTICATED_BY"),
        ]
        if decision.decision == ReviewDecision.ACCEPTED and hypothesis.candidate_person_id:
            links.append(GraphLinkWrite(decision_ref,
                GraphSourceRef("people", hypothesis.candidate_person_id, TEMPLATE_CODES["person"]), "ASSOCIATES_ACTOR"))
        enqueue_semantic_graph(self.db, transaction_id=self.transaction_id, agent_id=observation.agent_id,
            source_table="recognition_decisions", source_id=decision.decision_id,
            objects=objects, links=tuple(links), primary_key="decision")

    def persist_worker_heartbeat(
        self,
        heartbeat: RecognitionWorkerHeartbeat,
        *,
        authenticated_device_id: str,
        allowed_agent_ids: Sequence[str],
    ) -> WorkerHeartbeatReceipt:
        payload = heartbeat.as_payload()
        allowed = {_text(value) for value in allowed_agent_ids if _text(value)}
        if self.agent_id not in allowed:
            raise RecognitionConflictError("worker capability does not authorize its authenticated agent")
        if heartbeat.last_event_id:
            event_rows = self.db.query(
                """
                SELECT agent_id::text AS agent_id
                FROM events
                WHERE event_id = :event_id::uuid
                LIMIT 1
                """,
                {"event_id": heartbeat.last_event_id},
                transaction_id=self.transaction_id,
            )
            if not event_rows or _text(event_rows[0].get("agent_id")) not in allowed:
                raise RecognitionConflictError("heartbeat last_event_id is outside the worker agent allowlist")
        worker_rows = self.db.query(
            """
            SELECT recognition_worker_id::text AS recognition_worker_id
            FROM recognition_workers
            WHERE worker_key = :worker_key
            FOR UPDATE
            """,
            {"worker_key": heartbeat.worker_id},
            transaction_id=self.transaction_id,
        )
        if worker_rows:
            ownership_rows = self.db.query(
                """
                SELECT DISTINCT agent_id::text AS agent_id
                FROM semantic_outbox
                WHERE payload #>> '{external_reference,source_table}' = 'recognition_worker_heartbeats'
                  AND payload #>> '{properties,worker_key}' = :worker_key
                """,
                {"worker_key": heartbeat.worker_id},
                transaction_id=self.transaction_id,
            )
            owners = {_text(row.get("agent_id")) for row in ownership_rows if _text(row.get("agent_id"))}
            if owners != {self.agent_id}:
                raise RecognitionConflictError("persisted recognition worker lacks exactly one matching semantic owner")
        recognition_worker_id = _text(worker_rows[0].get("recognition_worker_id")) if worker_rows else str(uuid.uuid4())
        lifecycle_state = "stopped" if heartbeat.state == "stopped" else "active"
        self.db.execute(
            """
            INSERT INTO recognition_workers(
                recognition_worker_id, worker_key, worker_version, host_id,
                voice_model_id, voice_model_version, face_model_id, face_model_version,
                lifecycle_state, health_state, started_at, last_heartbeat_at
            ) VALUES(
                :recognition_worker_id::uuid, :worker_key, :worker_version, :host_id,
                :voice_model_id, :voice_model_version, :face_model_id, :face_model_version,
                :lifecycle_state, :health_state, :started_at::timestamptz, :observed_at::timestamptz
            )
            ON CONFLICT (worker_key) DO UPDATE
            SET worker_version = EXCLUDED.worker_version,
                host_id = EXCLUDED.host_id,
                voice_model_id = EXCLUDED.voice_model_id,
                voice_model_version = EXCLUDED.voice_model_version,
                face_model_id = EXCLUDED.face_model_id,
                face_model_version = EXCLUDED.face_model_version,
                lifecycle_state = EXCLUDED.lifecycle_state,
                health_state = EXCLUDED.health_state,
                started_at = EXCLUDED.started_at,
                last_heartbeat_at = EXCLUDED.last_heartbeat_at
            """,
            {
                "recognition_worker_id": recognition_worker_id,
                "worker_key": heartbeat.worker_id,
                "worker_version": heartbeat.worker_version,
                "host_id": heartbeat.host_id,
                "voice_model_id": heartbeat.voice_model_id,
                "voice_model_version": heartbeat.voice_model_version,
                "face_model_id": heartbeat.face_model_id,
                "face_model_version": heartbeat.face_model_version,
                "lifecycle_state": lifecycle_state,
                "health_state": heartbeat.state,
                "started_at": heartbeat.started_at.isoformat(),
                "observed_at": heartbeat.observed_at.isoformat(),
            },
            transaction_id=self.transaction_id,
        )
        existing_rows = self.db.query(
            """
            SELECT recognition_worker_heartbeat_id::text AS heartbeat_id,
                   received_at::text AS received_at,
                   worker_version, host_id, voice_model_id, voice_model_version,
                   face_model_id, face_model_version, health_state,
                   processed_messages, failed_messages, last_event_id::text AS last_event_id,
                   last_error, worker_started_at::text AS worker_started_at
            FROM recognition_worker_heartbeats
            WHERE recognition_worker_id = :recognition_worker_id::uuid
              AND observed_at = :observed_at::timestamptz
            LIMIT 1
            """,
            {
                "recognition_worker_id": recognition_worker_id,
                "observed_at": heartbeat.observed_at.isoformat(),
            },
            transaction_id=self.transaction_id,
        )
        if existing_rows:
            row = existing_rows[0]
            persisted = {
                "worker_version": _text(row.get("worker_version")),
                "host_id": _text(row.get("host_id")),
                "voice_model_id": _text(row.get("voice_model_id")),
                "voice_model_version": _text(row.get("voice_model_version")),
                "face_model_id": _text(row.get("face_model_id")),
                "face_model_version": _text(row.get("face_model_version")),
                "health_state": _text(row.get("health_state")),
                "processed_messages": int(row.get("processed_messages")),
                "failed_messages": int(row.get("failed_messages")),
                "last_event_id": _optional_text(row.get("last_event_id")),
                "last_error": _optional_text(row.get("last_error")),
                "worker_started_at": _datetime(row.get("worker_started_at"), "worker_started_at"),
            }
            expected = {
                "worker_version": heartbeat.worker_version,
                "host_id": heartbeat.host_id,
                "voice_model_id": heartbeat.voice_model_id,
                "voice_model_version": heartbeat.voice_model_version,
                "face_model_id": heartbeat.face_model_id,
                "face_model_version": heartbeat.face_model_version,
                "health_state": heartbeat.state,
                "processed_messages": heartbeat.processed_messages,
                "failed_messages": heartbeat.failed_messages,
                "last_event_id": heartbeat.last_event_id,
                "last_error": heartbeat.last_error,
                "worker_started_at": heartbeat.started_at,
            }
            if persisted != expected:
                raise RecognitionConflictError("worker heartbeat replay conflicts with persisted evidence")
            return WorkerHeartbeatReceipt(
                worker_id=recognition_worker_id,
                heartbeat_id=_text(row.get("heartbeat_id")),
                received_at=_text(row.get("received_at")),
                replayed=True,
            )

        heartbeat_id = str(uuid.uuid4())
        inserted = self.db.query(
            """
            INSERT INTO recognition_worker_heartbeats(
                recognition_worker_heartbeat_id, recognition_worker_id, worker_version, host_id,
                voice_model_id, voice_model_version, face_model_id, face_model_version,
                health_state, processed_messages, failed_messages, last_event_id, last_error,
                worker_started_at, observed_at
            ) VALUES(
                :heartbeat_id::uuid, :recognition_worker_id::uuid, :worker_version, :host_id,
                :voice_model_id, :voice_model_version, :face_model_id, :face_model_version,
                :health_state, :processed_messages, :failed_messages,
                NULLIF(CAST(:last_event_id AS text), '')::uuid, NULLIF(CAST(:last_error AS text), ''),
                :worker_started_at::timestamptz, :observed_at::timestamptz
            )
            RETURNING received_at::text AS received_at
            """,
            {
                "heartbeat_id": heartbeat_id,
                "recognition_worker_id": recognition_worker_id,
                "worker_version": heartbeat.worker_version,
                "host_id": heartbeat.host_id,
                "voice_model_id": heartbeat.voice_model_id,
                "voice_model_version": heartbeat.voice_model_version,
                "face_model_id": heartbeat.face_model_id,
                "face_model_version": heartbeat.face_model_version,
                "health_state": heartbeat.state,
                "processed_messages": heartbeat.processed_messages,
                "failed_messages": heartbeat.failed_messages,
                "last_event_id": heartbeat.last_event_id or "",
                "last_error": heartbeat.last_error or "",
                "worker_started_at": heartbeat.started_at.isoformat(),
                "observed_at": heartbeat.observed_at.isoformat(),
            },
            transaction_id=self.transaction_id,
        )
        if len(inserted) != 1:
            raise RecognitionPersistenceError("worker heartbeat insert did not return a receipt")
        enqueue_semantic_record(
            self.db,
            transaction_id=self.transaction_id,
            agent_id=self.agent_id,
            source_table="recognition_worker_heartbeats",
            source_id=heartbeat_id,
            target_template_code=TEMPLATE_CODES["event_sensor"],
            name=f"recognition-worker-heartbeat:{heartbeat.worker_id}:{heartbeat_id}",
            lifecycle_state=heartbeat.state,
            properties={
                "agent_id": self.agent_id,
                "recognition_worker_id": recognition_worker_id,
                "recognition_worker_heartbeat_id": heartbeat_id,
                "worker_key": heartbeat.worker_id,
                "authenticated_device_id": authenticated_device_id,
                "worker_version": heartbeat.worker_version,
                "host_id": heartbeat.host_id,
                "health_state": heartbeat.state,
                "processed_messages": heartbeat.processed_messages,
                "failed_messages": heartbeat.failed_messages,
                "last_event_id": heartbeat.last_event_id or "",
                "schema": payload["schema"],
            },
        )
        return WorkerHeartbeatReceipt(
            worker_id=recognition_worker_id,
            heartbeat_id=heartbeat_id,
            received_at=_text(inserted[0].get("received_at")),
            replayed=False,
        )


def get_recognition_hypothesis_detail(db: RdsData, *, hypothesis_id: str) -> dict[str, Any] | None:
    rows = db.query(
        """
        SELECT rh.identity_hypothesis_id::text AS hypothesis_id,
               rh.recognition_observation_id::text AS observation_id,
               rh.kind, rh.candidate_person_id::text AS candidate_person_id,
               rh.consent_id::text AS proposed_consent_id,
               rh.confidence, rh.distance, rh.decision, rh.rationale,
               rh.requested_projection, rh.created_at::text AS created_at,
               rh.decided_at::text AS decided_at,
               ro.agent_id::text AS agent_id, ro.space_id::text AS space_id,
               ro.location_id::text AS location_id, ro.session_id::text AS session_id,
               ro.device_id::text AS source_device_id, ro.source_event_id::text AS source_event_id,
               ro.artifact_id::text AS artifact_id, ro.modality, ro.lifecycle_state AS observation_state,
               ro.model_id, ro.model_version, ro.embedding_sha256,
               rd.recognition_decision_id::text AS decision_id,
               rd.reviewer_actor_type, rd.reviewer_actor_id, rd.reviewer_auth_subject,
               rd.consent_id::text AS decision_consent_id, rd.reason AS decision_reason,
               bp.biometric_projection_id::text AS projection_id,
               pa.presence_assertion_id::text AS presence_assertion_id,
               sos.semantic_outbox_id::text AS semantic_outbox_id,
               sos.status AS semantic_status
        FROM recognition_hypotheses rh
        JOIN recognition_observations ro
          ON ro.recognition_observation_id = rh.recognition_observation_id
        LEFT JOIN recognition_decisions rd ON rd.identity_hypothesis_id = rh.identity_hypothesis_id
        LEFT JOIN biometric_projections bp ON bp.recognition_decision_id = rd.recognition_decision_id
        LEFT JOIN presence_assertions pa ON pa.identity_hypothesis_id = rh.identity_hypothesis_id
                                           AND pa.status = 'present'
        LEFT JOIN semantic_sync_status sss
          ON sss.agent_id = ro.agent_id
         AND sss.source_table = 'recognition_decisions'
         AND sss.source_id = rd.recognition_decision_id
        LEFT JOIN semantic_outbox sos ON sos.semantic_sync_id = sss.semantic_sync_id
        WHERE rh.identity_hypothesis_id = :hypothesis_id::uuid
        LIMIT 1
        """,
        {"hypothesis_id": hypothesis_id},
    )
    return dict(rows[0]) if rows else None


__all__ = [
    "ActorType",
    "AuthenticatedReviewer",
    "HypothesisKind",
    "RdsRecognitionRepository",
    "RecognitionConflictError",
    "RecognitionNotFoundError",
    "RecognitionPersistenceError",
    "RecognitionWorkerHeartbeat",
    "ReviewDecision",
    "get_recognition_hypothesis_detail",
]
