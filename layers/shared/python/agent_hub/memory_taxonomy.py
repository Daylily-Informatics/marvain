"""Canonical Marvain memory taxonomy."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final


@dataclass(frozen=True)
class MemoryKind:
    value: str
    label: str
    description: str


@dataclass(frozen=True)
class MemoryProvenanceClass:
    value: str
    label: str
    description: str


MEMORY_KINDS: Final[tuple[MemoryKind, ...]] = (
    MemoryKind("episodic", "Episodic", "Time-bound events, observations, and transcripts."),
    MemoryKind("semantic", "Semantic", "Stable facts and learned knowledge."),
    MemoryKind("procedural", "Procedural", "How-to instructions, routines, and action recipes."),
    MemoryKind("preference", "Preference", "User likes, dislikes, defaults, and choices."),
    MemoryKind("relationship", "Relationship", "Connections among people, agents, devices, and roles."),
    MemoryKind("location", "Location", "Location and space-specific facts or observations."),
    MemoryKind("device", "Device", "Device capabilities, state, routing, and behavior."),
    MemoryKind("policy", "Policy/Audit", "Consent, privacy, governance, and audit-supporting notes."),
)

MEMORY_KIND_VALUES: Final[tuple[str, ...]] = tuple(item.value for item in MEMORY_KINDS)
MEMORY_KIND_LABELS: Final[dict[str, str]] = {item.value: item.label for item in MEMORY_KINDS}
MEMORY_KIND_DESCRIPTIONS: Final[dict[str, str]] = {item.value: item.description for item in MEMORY_KINDS}

MEMORY_PROVENANCE_CLASSES: Final[tuple[MemoryProvenanceClass, ...]] = (
    MemoryProvenanceClass(
        "external_interaction",
        "External Interaction",
        "Memory provoked by a user, device, integration, or external participant.",
    ),
    MemoryProvenanceClass(
        "self_reflection",
        "Self Reflection",
        "Memory initiated by the agent's own reflection, synthesis, or self-directed learning.",
    ),
    MemoryProvenanceClass(
        "cross_agent_interaction",
        "Cross-Agent Interaction",
        "Memory formed during an interaction with another agent.",
    ),
    MemoryProvenanceClass(
        "system_observation",
        "System Observation",
        "Memory derived from system state, telemetry, routing, or lifecycle observations.",
    ),
)
MEMORY_PROVENANCE_VALUES: Final[tuple[str, ...]] = tuple(item.value for item in MEMORY_PROVENANCE_CLASSES)
MEMORY_PROVENANCE_LABELS: Final[dict[str, str]] = {item.value: item.label for item in MEMORY_PROVENANCE_CLASSES}
MEMORY_PROVENANCE_DESCRIPTIONS: Final[dict[str, str]] = {
    item.value: item.description for item in MEMORY_PROVENANCE_CLASSES
}


def normalize_memory_kind(value: object, *, default: str = "episodic") -> str:
    """Normalize and validate a memory kind."""
    text = str(value or default).strip().lower()
    if text not in MEMORY_KIND_VALUES:
        allowed = ", ".join(MEMORY_KIND_VALUES)
        raise ValueError(f"invalid memory kind {text!r}; expected one of: {allowed}")
    return text


def normalize_memory_provenance_class(value: object, *, default: str = "external_interaction") -> str:
    """Normalize and validate a memory provenance class."""
    text = str(value or default).strip().lower()
    if text not in MEMORY_PROVENANCE_VALUES:
        allowed = ", ".join(MEMORY_PROVENANCE_VALUES)
        raise ValueError(f"invalid memory provenance class {text!r}; expected one of: {allowed}")
    return text


def memory_kind_options() -> list[dict[str, str]]:
    """Return UI/API option dictionaries for all canonical memory kinds."""
    return [{"value": item.value, "label": item.label, "description": item.description} for item in MEMORY_KINDS]


def memory_provenance_options() -> list[dict[str, str]]:
    """Return UI/API option dictionaries for all canonical memory provenance classes."""
    return [
        {"value": item.value, "label": item.label, "description": item.description}
        for item in MEMORY_PROVENANCE_CLASSES
    ]


def classify_memory_provenance_class(
    text: str,
    *,
    actor_type: str | None = None,
    source: str | None = None,
    interacting_agent_id: str | None = None,
) -> str:
    """Classify how a memory was initiated."""
    actor = str(actor_type or "").strip().lower()
    source_text = f"{text} {source or ''}".lower()
    if interacting_agent_id or actor == "agent_peer" or "other agent" in source_text:
        return "cross_agent_interaction"
    if actor in {"agent", "self"} or any(
        token in source_text for token in ("self-reflection", "self reflection", "i noticed", "i learned")
    ):
        return "self_reflection"
    if actor in {"system", "worker", "device"} or any(
        token in source_text for token in ("heartbeat", "telemetry", "routing", "observability", "system")
    ):
        return "system_observation"
    return "external_interaction"


def classify_memory_kinds(text: str, *, modality: str = "text") -> list[str]:
    """Classify a source utterance into one or more memory kinds.

    This deterministic classifier is intentionally conservative. It is used for
    capture policy and tests, not as a semantic substitute for model-assisted
    memory review.
    """
    normalized = f"{text} {modality}".lower()
    kinds: list[str] = ["episodic"]
    rules: tuple[tuple[str, tuple[str, ...]], ...] = (
        ("semantic", ("fact", "remember that", "is called", "means", "learned")),
        ("procedural", ("how to", "steps", "procedure", "when you", "routine")),
        ("preference", ("prefer", "like", "dislike", "favorite", "default")),
        ("relationship", ("my wife", "my husband", "my partner", "friend", "colleague", "relationship")),
        ("location", ("kitchen", "office", "studio", "space", "room", "location")),
        ("device", ("device", "camera", "microphone", "sensor", "satellite", "laptop")),
        ("policy", ("consent", "privacy", "policy", "audit", "permission", "allowed")),
    )
    for kind, needles in rules:
        if any(needle in normalized for needle in needles) and kind not in kinds:
            kinds.append(kind)
    return kinds
