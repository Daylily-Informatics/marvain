"""Canonical Marvain memory taxonomy."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final


@dataclass(frozen=True)
class MemoryKind:
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


def normalize_memory_kind(value: object, *, default: str = "episodic") -> str:
    """Normalize and validate a memory kind."""
    text = str(value or default).strip().lower()
    if text not in MEMORY_KIND_VALUES:
        allowed = ", ".join(MEMORY_KIND_VALUES)
        raise ValueError(f"invalid memory kind {text!r}; expected one of: {allowed}")
    return text


def memory_kind_options() -> list[dict[str, str]]:
    """Return UI/API option dictionaries for all canonical memory kinds."""
    return [{"value": item.value, "label": item.label, "description": item.description} for item in MEMORY_KINDS]


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
