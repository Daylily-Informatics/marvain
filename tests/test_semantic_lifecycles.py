from __future__ import annotations

import pytest
from agent_hub.semantic_lifecycle import LifecycleError, MarvainSemanticLifecycle
from fakes.semantic_tapdb import InMemoryTapdbSemanticStore


def test_memory_lifecycle_records_evidence_candidate_commit_recall_and_tombstone() -> None:
    store = InMemoryTapdbSemanticStore()
    lifecycle = MarvainSemanticLifecycle(store)

    event = lifecycle.record_event_evidence(
        event_id="event-1",
        agent_id="agent-1",
        space_id="space-1",
        session_id="session-1",
        device_id="device-1",
        person_id="person-1",
        event_type="transcript_chunk",
        text="Major likes direct status reports.",
    )
    record = lifecycle.commit_memory_from_evidence(
        evidence=event,
        agent_id="agent-1",
        content="Major likes direct status reports.",
        tier="semantic",
        participants=["person:person-1"],
        subject_person_id="person-1",
    )
    tombstone = lifecycle.tombstone_memory(committed_memory=record.committed, agent_id="agent-1", reason="user deleted")
    graph = store.graph_for(record.committed.semantic_id)

    assert record.evidence.properties["event_id"] == "event-1"
    assert record.candidate.lifecycle_state == "candidate"
    assert record.committed.lifecycle_state == "committed"
    assert record.recall_projection["source_event_id"] == "event-1"
    assert "source event event-1" in record.recall_projection["explanation"]
    assert tombstone.lifecycle_state == "tombstoned"
    assert {edge["relationship_type"] for edge in graph["edges"]} >= {"COMMITTED_AS", "TOMBSTONED_BY"}


def test_memory_lifecycle_rejects_memory_without_source_event_evidence() -> None:
    store = InMemoryTapdbSemanticStore()
    lifecycle = MarvainSemanticLifecycle(store)
    evidence = store.create_object(
        template_code="MVN/event/transcript/1.0/",
        name="bad-evidence",
        lifecycle_state="recorded",
        properties={},
    )

    with pytest.raises(LifecycleError, match="source event evidence"):
        lifecycle.commit_memory_from_evidence(
            evidence=evidence,
            agent_id="agent-1",
            content="No source",
            tier="semantic",
        )


def test_recognition_lifecycle_keeps_unknown_observation_without_presence_identity() -> None:
    store = InMemoryTapdbSemanticStore()
    lifecycle = MarvainSemanticLifecycle(store)

    record = lifecycle.record_recognition_path(
        agent_id="agent-1",
        space_id="space-1",
        device_id="device-1",
        artifact_ref={"bucket": "b", "key": "recognition/x.wav", "media_type": "audio/wav"},
        modality="voice",
        candidate_person_id=None,
        consent_id=None,
        confidence=0.1,
        matched=False,
    )

    assert record.observation.lifecycle_state == "observed"
    assert record.hypothesis.lifecycle_state == "no_match"
    assert record.hypothesis.properties["candidate_person_id"] == ""
    assert record.presence_assertion is None


def test_action_lifecycle_records_proposal_approval_execution_result_lineage() -> None:
    store = InMemoryTapdbSemanticStore()
    lifecycle = MarvainSemanticLifecycle(store)
    event = lifecycle.record_event_evidence(
        event_id="event-1",
        agent_id="agent-1",
        space_id="space-1",
        session_id="session-1",
        device_id="device-1",
        person_id=None,
        event_type="sensor",
    )

    action = lifecycle.record_action_proposal(
        action_id="action-1",
        agent_id="agent-1",
        space_id="space-1",
        kind="device_command",
        source_event=event,
        target_device_id="device-1",
    )
    action = lifecycle.record_action_approval(action, approval_source="manual", approved_by="user-1")
    action = lifecycle.record_action_execution(
        action,
        target_device_id="device-1",
        correlation_id="corr-1",
        state="awaiting_device_result",
    )
    action = lifecycle.record_action_result(action, status="executed")

    graph = store.graph_for(action.proposal.semantic_id)
    relationships = {edge["relationship_type"] for edge in graph["edges"]}
    assert {"CAUSED_BY", "APPROVED_BY", "DISPATCHED_AS", "FULFILLS"} <= relationships
    assert action.result is not None
