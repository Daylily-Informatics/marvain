"""Greenfield semantic lifecycle helpers for Marvain domain objects."""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from typing import Any

from agent_hub.semantic_tapdb import TEMPLATE_CODES, SemanticObject, TapdbSemanticStore


class LifecycleError(ValueError):
    pass


@dataclass(frozen=True)
class MemoryLifecycleRecord:
    evidence: SemanticObject
    candidate: SemanticObject
    committed: SemanticObject
    recall_projection: dict[str, Any]


@dataclass(frozen=True)
class RecognitionLifecycleRecord:
    artifact: SemanticObject
    observation: SemanticObject
    hypothesis: SemanticObject
    presence_assertion: SemanticObject | None


@dataclass(frozen=True)
class ActionLifecycleRecord:
    proposal: SemanticObject
    approval: SemanticObject | None = None
    execution: SemanticObject | None = None
    result: SemanticObject | None = None


def _require_text(value: Any, field: str) -> str:
    text = str(value or "").strip()
    if not text:
        raise LifecycleError(f"{field} is required")
    return text


class MarvainSemanticLifecycle:
    """High-level semantic object graph recorder.

    The service records canonical TapDB semantic objects and lineage. Fast SQL
    projections remain separate and rebuildable from these records plus source
    events/artifacts.
    """

    def __init__(self, store: TapdbSemanticStore) -> None:
        self.store = store

    def record_event_evidence(
        self,
        *,
        event_id: str,
        agent_id: str,
        space_id: str,
        session_id: str | None,
        device_id: str | None,
        person_id: str | None,
        event_type: str,
        text: str | None = None,
    ) -> SemanticObject:
        template = (
            TEMPLATE_CODES["event_transcript"] if event_type == "transcript_chunk" else TEMPLATE_CODES["event_sensor"]
        )
        return self.store.create_object(
            template_code=template,
            name=f"event:{_require_text(event_id, 'event_id')}",
            lifecycle_state="recorded",
            properties={
                "event_id": event_id,
                "agent_id": _require_text(agent_id, "agent_id"),
                "space_id": _require_text(space_id, "space_id"),
                "session_id": session_id or "",
                "device_id": device_id or "",
                "person_id": person_id or "",
                "event_type": event_type,
                "text": text or "",
            },
        )

    def commit_memory_from_evidence(
        self,
        *,
        evidence: SemanticObject,
        agent_id: str,
        content: str,
        tier: str,
        participants: list[str] | None = None,
        subject_person_id: str | None = None,
        confidence: float = 1.0,
    ) -> MemoryLifecycleRecord:
        source_event_id = str(evidence.properties.get("event_id") or "").strip()
        if not source_event_id:
            raise LifecycleError("memory requires source event evidence")
        content_n = _require_text(content, "content")
        candidate_id = str(uuid.uuid4())
        memory_id = str(uuid.uuid4())
        candidate = self.store.create_object(
            template_code=TEMPLATE_CODES["memory_candidate"],
            name=f"memory-candidate:{candidate_id}",
            lifecycle_state="candidate",
            properties={
                "memory_candidate_id": candidate_id,
                "agent_id": _require_text(agent_id, "agent_id"),
                "source_event_id": source_event_id,
                "content": content_n,
                "tier": tier,
                "participants": participants or [],
                "subject_person_id": subject_person_id or "",
                "confidence": float(confidence),
            },
        )
        self.store.link_objects(
            parent_semantic_id=evidence.semantic_id,
            child_semantic_id=candidate.semantic_id,
            relationship_type="DERIVED_FROM",
        )
        committed = self.store.create_object(
            template_code=TEMPLATE_CODES["memory_committed"],
            name=f"memory:{memory_id}",
            lifecycle_state="committed",
            properties={
                "memory_id": memory_id,
                "memory_candidate_id": candidate_id,
                "agent_id": agent_id,
                "content": content_n,
                "tier": tier,
                "participants": participants or [],
                "subject_person_id": subject_person_id or "",
            },
        )
        self.store.link_objects(
            parent_semantic_id=candidate.semantic_id,
            child_semantic_id=committed.semantic_id,
            relationship_type="COMMITTED_AS",
        )
        if subject_person_id:
            person = self.store.create_object(
                template_code=TEMPLATE_CODES["person"],
                name=f"person:{subject_person_id}",
                lifecycle_state="active",
                properties={"person_id": subject_person_id, "agent_id": agent_id},
            )
            self.store.link_objects(
                parent_semantic_id=committed.semantic_id,
                child_semantic_id=person.semantic_id,
                relationship_type="ABOUT_PERSON",
            )
        recall_projection = {
            "memory_id": memory_id,
            "tapdb_euid": committed.semantic_id,
            "source_event_id": source_event_id,
            "explanation": f"Memory was committed from source event {source_event_id}.",
        }
        return MemoryLifecycleRecord(
            evidence=evidence, candidate=candidate, committed=committed, recall_projection=recall_projection
        )

    def tombstone_memory(
        self,
        *,
        committed_memory: SemanticObject,
        agent_id: str,
        reason: str,
    ) -> SemanticObject:
        memory_id = _require_text(committed_memory.properties.get("memory_id"), "memory_id")
        tombstone = self.store.create_object(
            template_code=TEMPLATE_CODES["memory_tombstone"],
            name=f"memory-tombstone:{memory_id}",
            lifecycle_state="tombstoned",
            properties={
                "memory_tombstone_id": str(uuid.uuid4()),
                "memory_id": memory_id,
                "agent_id": _require_text(agent_id, "agent_id"),
                "reason": reason,
            },
        )
        self.store.link_objects(
            parent_semantic_id=committed_memory.semantic_id,
            child_semantic_id=tombstone.semantic_id,
            relationship_type="TOMBSTONED_BY",
        )
        return tombstone

    def record_recognition_path(
        self,
        *,
        agent_id: str,
        space_id: str,
        device_id: str,
        artifact_ref: dict[str, Any],
        modality: str,
        candidate_person_id: str | None,
        consent_id: str | None,
        confidence: float,
        matched: bool,
    ) -> RecognitionLifecycleRecord:
        artifact_id = str(artifact_ref.get("artifact_id") or uuid.uuid4())
        artifact = self.store.create_object(
            template_code=TEMPLATE_CODES["artifact_reference"],
            name=f"artifact:{artifact_id}",
            lifecycle_state="available",
            properties={
                "artifact_id": artifact_id,
                "agent_id": _require_text(agent_id, "agent_id"),
                "bucket": str(artifact_ref.get("bucket") or ""),
                "key": str(artifact_ref.get("key") or ""),
                "media_type": str(artifact_ref.get("media_type") or modality),
            },
        )
        observation_id = str(uuid.uuid4())
        observation = self.store.create_object(
            template_code=TEMPLATE_CODES["recognition_observation"],
            name=f"recognition-observation:{observation_id}",
            lifecycle_state="observed",
            properties={
                "recognition_observation_id": observation_id,
                "agent_id": agent_id,
                "space_id": _require_text(space_id, "space_id"),
                "device_id": _require_text(device_id, "device_id"),
                "artifact_id": artifact_id,
                "modality": _require_text(modality, "modality"),
            },
        )
        self.store.link_objects(
            parent_semantic_id=artifact.semantic_id,
            child_semantic_id=observation.semantic_id,
            relationship_type="DERIVED_FROM",
        )
        if matched and not candidate_person_id:
            raise LifecycleError("matched recognition requires candidate_person_id")
        hypothesis = self.store.create_object(
            template_code=TEMPLATE_CODES["recognition_hypothesis"],
            name=f"identity-hypothesis:{uuid.uuid4()}",
            lifecycle_state="accepted" if matched else "no_match",
            properties={
                "identity_hypothesis_id": str(uuid.uuid4()),
                "recognition_observation_id": observation_id,
                "candidate_person_id": candidate_person_id or "",
                "consent_id": consent_id or "",
                "confidence": float(confidence),
            },
        )
        self.store.link_objects(
            parent_semantic_id=observation.semantic_id,
            child_semantic_id=hypothesis.semantic_id,
            relationship_type="BASED_ON",
        )
        presence = None
        if matched:
            presence = self.store.create_object(
                template_code=TEMPLATE_CODES["presence_assertion"],
                name=f"presence:{uuid.uuid4()}",
                lifecycle_state="asserted",
                properties={
                    "presence_assertion_id": str(uuid.uuid4()),
                    "agent_id": agent_id,
                    "space_id": space_id,
                    "person_id": candidate_person_id,
                    "confidence": float(confidence),
                },
            )
            self.store.link_objects(
                parent_semantic_id=hypothesis.semantic_id,
                child_semantic_id=presence.semantic_id,
                relationship_type="BASED_ON",
            )
        return RecognitionLifecycleRecord(
            artifact=artifact, observation=observation, hypothesis=hypothesis, presence_assertion=presence
        )

    def record_action_proposal(
        self,
        *,
        action_id: str,
        agent_id: str,
        space_id: str | None,
        kind: str,
        source_event: SemanticObject | None = None,
        target_device_id: str | None = None,
    ) -> ActionLifecycleRecord:
        proposal = self.store.create_object(
            template_code=TEMPLATE_CODES["action_proposal"],
            name=f"action-proposal:{_require_text(action_id, 'action_id')}",
            lifecycle_state="proposed",
            properties={
                "action_id": action_id,
                "agent_id": _require_text(agent_id, "agent_id"),
                "space_id": space_id or "",
                "kind": _require_text(kind, "kind"),
                "target_device_id": target_device_id or "",
            },
        )
        if source_event is not None:
            self.store.link_objects(
                parent_semantic_id=source_event.semantic_id,
                child_semantic_id=proposal.semantic_id,
                relationship_type="CAUSED_BY",
            )
        return ActionLifecycleRecord(proposal=proposal)

    def record_action_approval(
        self, record: ActionLifecycleRecord, *, approval_source: str, approved_by: str | None
    ) -> ActionLifecycleRecord:
        action_id = _require_text(record.proposal.properties.get("action_id"), "action_id")
        approval = self.store.create_object(
            template_code=TEMPLATE_CODES["action_approval"],
            name=f"action-approval:{action_id}",
            lifecycle_state="approved",
            properties={
                "action_approval_id": str(uuid.uuid4()),
                "action_id": action_id,
                "approval_source": _require_text(approval_source, "approval_source"),
                "approved_by": approved_by or "",
            },
        )
        self.store.link_objects(
            parent_semantic_id=record.proposal.semantic_id,
            child_semantic_id=approval.semantic_id,
            relationship_type="APPROVED_BY",
        )
        return ActionLifecycleRecord(
            proposal=record.proposal, approval=approval, execution=record.execution, result=record.result
        )

    def record_action_execution(
        self,
        record: ActionLifecycleRecord,
        *,
        target_device_id: str | None,
        correlation_id: str | None,
        state: str,
    ) -> ActionLifecycleRecord:
        action_id = _require_text(record.proposal.properties.get("action_id"), "action_id")
        execution = self.store.create_object(
            template_code=TEMPLATE_CODES["action_execution"],
            name=f"action-execution:{action_id}",
            lifecycle_state=_require_text(state, "state"),
            properties={
                "action_execution_id": str(uuid.uuid4()),
                "action_id": action_id,
                "target_device_id": target_device_id or "",
                "correlation_id": correlation_id or "",
            },
        )
        self.store.link_objects(
            parent_semantic_id=(record.approval or record.proposal).semantic_id,
            child_semantic_id=execution.semantic_id,
            relationship_type="DISPATCHED_AS",
        )
        return ActionLifecycleRecord(
            proposal=record.proposal, approval=record.approval, execution=execution, result=record.result
        )

    def record_action_result(
        self, record: ActionLifecycleRecord, *, status: str, error: str | None = None
    ) -> ActionLifecycleRecord:
        if record.execution is None:
            raise LifecycleError("action result requires execution")
        action_id = _require_text(record.proposal.properties.get("action_id"), "action_id")
        result = self.store.create_object(
            template_code=TEMPLATE_CODES["action_result"],
            name=f"action-result:{action_id}",
            lifecycle_state="failed" if error else "recorded",
            properties={
                "action_result_id": str(uuid.uuid4()),
                "action_id": action_id,
                "status": _require_text(status, "status"),
                "error": error or "",
            },
        )
        self.store.link_objects(
            parent_semantic_id=record.execution.semantic_id,
            child_semantic_id=result.semantic_id,
            relationship_type="FULFILLS",
        )
        return ActionLifecycleRecord(
            proposal=record.proposal, approval=record.approval, execution=record.execution, result=result
        )
