"""Tests for canonical memory taxonomy and provenance classes."""

from __future__ import annotations

import pytest
from agent_hub.memory_classifier import (
    DeterministicMemoryClassifier,
    MemoryClassifierUnavailable,
    classify_memory_event,
    memory_classifier_from_environment,
)
from agent_hub.memory_taxonomy import (
    MEMORY_KIND_DESCRIPTIONS,
    MEMORY_KIND_LABELS,
    MEMORY_KIND_VALUES,
    MEMORY_PROVENANCE_DESCRIPTIONS,
    MEMORY_PROVENANCE_LABELS,
    MEMORY_PROVENANCE_VALUES,
    classify_memory_kinds,
    classify_memory_provenance_class,
    memory_kind_options,
    memory_provenance_options,
    normalize_memory_kind,
    normalize_memory_provenance_class,
)

EXPECTED_MEMORY_KINDS = (
    "episodic",
    "semantic",
    "procedural",
    "preference",
    "relationship",
    "location",
    "device",
    "policy",
)

EXPECTED_PROVENANCE_CLASSES = (
    "external_interaction",
    "self_reflection",
    "cross_agent_interaction",
    "system_observation",
)


def test_memory_kind_taxonomy_keeps_existing_kinds() -> None:
    assert MEMORY_KIND_VALUES == EXPECTED_MEMORY_KINDS
    assert set(MEMORY_KIND_LABELS) == set(EXPECTED_MEMORY_KINDS)
    assert set(MEMORY_KIND_DESCRIPTIONS) == set(EXPECTED_MEMORY_KINDS)
    assert [item["value"] for item in memory_kind_options()] == list(EXPECTED_MEMORY_KINDS)

    for kind in EXPECTED_MEMORY_KINDS:
        assert normalize_memory_kind(kind) == kind
        assert MEMORY_KIND_LABELS[kind]
        assert MEMORY_KIND_DESCRIPTIONS[kind]


def test_memory_kind_classifier_covers_every_kind() -> None:
    text = (
        "Remember that the kitchen device camera routine means I prefer privacy consent for my colleague relationship."
    )

    assert set(classify_memory_kinds(text)) == set(EXPECTED_MEMORY_KINDS)


def test_memory_provenance_taxonomy_covers_required_classes() -> None:
    assert MEMORY_PROVENANCE_VALUES == EXPECTED_PROVENANCE_CLASSES
    assert set(MEMORY_PROVENANCE_LABELS) == set(EXPECTED_PROVENANCE_CLASSES)
    assert set(MEMORY_PROVENANCE_DESCRIPTIONS) == set(EXPECTED_PROVENANCE_CLASSES)
    assert [item["value"] for item in memory_provenance_options()] == list(EXPECTED_PROVENANCE_CLASSES)

    for provenance_class in EXPECTED_PROVENANCE_CLASSES:
        assert normalize_memory_provenance_class(provenance_class) == provenance_class
        assert MEMORY_PROVENANCE_LABELS[provenance_class]
        assert MEMORY_PROVENANCE_DESCRIPTIONS[provenance_class]


@pytest.mark.parametrize(
    ("text", "kwargs", "expected"),
    (
        ("User said to remember the kitchen note", {"actor_type": "user"}, "external_interaction"),
        ("I noticed this pattern during reflection", {"actor_type": "agent"}, "self_reflection"),
        ("Other agent shared a handoff summary", {"interacting_agent_id": "agent-2"}, "cross_agent_interaction"),
        ("Heartbeat telemetry changed routing state", {"actor_type": "system"}, "system_observation"),
    ),
)
def test_memory_provenance_classifier_covers_every_class(text: str, kwargs: dict[str, str], expected: str) -> None:
    assert classify_memory_provenance_class(text, **kwargs) == expected


def test_memory_provenance_normalizer_rejects_unknown_class() -> None:
    with pytest.raises(ValueError, match="invalid memory provenance class"):
        normalize_memory_provenance_class("legacy_source")


def test_deterministic_memory_classifier_is_explicit_test_provider() -> None:
    classifications = DeterministicMemoryClassifier().classify(
        text="Remember that the office camera policy means I prefer privacy.",
        modality="text",
        source_evidence_id="event-1",
        actor_type="user",
        source="unit-test",
    )

    assert {item.kind for item in classifications} >= {
        "episodic",
        "semantic",
        "preference",
        "location",
        "device",
        "policy",
    }
    assert {item.source_evidence_id for item in classifications} == {"event-1"}
    assert {item.provenance_class for item in classifications} == {"external_interaction"}
    assert all(item.model_provider_id == "deterministic-test" for item in classifications)


def test_production_memory_classifier_hard_fails_when_unconfigured(monkeypatch) -> None:
    monkeypatch.delenv("MARVAIN_MEMORY_CLASSIFIER_PROVIDER", raising=False)
    monkeypatch.delenv("MARVAIN_MEMORY_CLASSIFIER_MODEL", raising=False)
    monkeypatch.setenv("ENVIRONMENT", "prod")

    with pytest.raises(MemoryClassifierUnavailable, match="classification_unavailable"):
        memory_classifier_from_environment()


def test_test_environment_uses_deterministic_classifier(monkeypatch) -> None:
    monkeypatch.delenv("MARVAIN_MEMORY_CLASSIFIER_PROVIDER", raising=False)
    monkeypatch.setenv("ENVIRONMENT", "test")

    classifications = classify_memory_event(
        text="Remember that the device routine matters.",
        modality="text",
        source_evidence_id="event-2",
    )

    assert {item.kind for item in classifications} >= {"episodic", "semantic", "device", "procedural"}
