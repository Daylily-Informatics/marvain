"""Memory auto-capture classification providers."""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from typing import Protocol

from agent_hub.memory_taxonomy import (
    MEMORY_KIND_VALUES,
    classify_memory_kinds,
    classify_memory_provenance_class,
    normalize_memory_kind,
    normalize_memory_provenance_class,
)


class MemoryClassifierUnavailable(RuntimeError):
    """Raised when production memory classification is not configured."""


@dataclass(frozen=True)
class MemoryClassification:
    kind: str
    provenance_class: str
    confidence: float
    rationale: str
    source_evidence_id: str
    model_provider_id: str

    def as_metadata(self) -> dict[str, object]:
        return {
            "kind": self.kind,
            "provenance_class": self.provenance_class,
            "confidence": self.confidence,
            "rationale": self.rationale,
            "source_evidence_id": self.source_evidence_id,
            "model_provider_id": self.model_provider_id,
        }


class MemoryClassifierProvider(Protocol):
    provider_id: str

    def classify(
        self,
        *,
        text: str,
        modality: str,
        source_evidence_id: str,
        actor_type: str | None = None,
        source: str | None = None,
        interacting_agent_id: str | None = None,
    ) -> list[MemoryClassification]: ...


class DeterministicMemoryClassifier:
    """Explicit test/smoke classifier backed by the canonical taxonomy rules."""

    provider_id = "deterministic-test"

    def classify(
        self,
        *,
        text: str,
        modality: str,
        source_evidence_id: str,
        actor_type: str | None = None,
        source: str | None = None,
        interacting_agent_id: str | None = None,
    ) -> list[MemoryClassification]:
        provenance_class = classify_memory_provenance_class(
            text,
            actor_type=actor_type,
            source=source,
            interacting_agent_id=interacting_agent_id,
        )
        return [
            MemoryClassification(
                kind=kind,
                provenance_class=provenance_class,
                confidence=1.0,
                rationale="Deterministic test/smoke taxonomy rule selected this memory kind.",
                source_evidence_id=source_evidence_id,
                model_provider_id=self.provider_id,
            )
            for kind in classify_memory_kinds(text, modality=modality)
        ]


class OpenAIMemoryClassifier:
    provider_id = "openai"

    def __init__(self, *, model: str) -> None:
        self.model = model

    def classify(
        self,
        *,
        text: str,
        modality: str,
        source_evidence_id: str,
        actor_type: str | None = None,
        source: str | None = None,
        interacting_agent_id: str | None = None,
    ) -> list[MemoryClassification]:
        try:
            from openai import OpenAI
        except Exception as exc:  # pragma: no cover - dependency contract covers import in real env
            raise MemoryClassifierUnavailable("classification_unavailable: openai package is unavailable") from exc

        prompt = {
            "task": "Classify a Marvain memory capture event.",
            "allowed_memory_kinds": list(MEMORY_KIND_VALUES),
            "allowed_provenance_classes": [
                "external_interaction",
                "self_reflection",
                "cross_agent_interaction",
                "system_observation",
            ],
            "required_output": {
                "items": [
                    {
                        "kind": "one allowed memory kind",
                        "provenance_class": "one allowed provenance class",
                        "confidence": "0.0 to 1.0",
                        "rationale": "short reason grounded in source text",
                    }
                ]
            },
            "event": {
                "text": text,
                "modality": modality,
                "source_evidence_id": source_evidence_id,
                "actor_type": actor_type,
                "source": source,
                "interacting_agent_id": interacting_agent_id,
            },
        }
        client = OpenAI()
        response = client.responses.create(
            model=self.model,
            input=[
                {
                    "role": "system",
                    "content": "Return only JSON. Do not invent memory kinds or provenance classes.",
                },
                {"role": "user", "content": json.dumps(prompt, sort_keys=True)},
            ],
        )
        raw = str(getattr(response, "output_text", "") or "").strip()
        try:
            payload = json.loads(raw)
            items = payload["items"]
        except Exception as exc:
            raise MemoryClassifierUnavailable(
                "classification_unavailable: model returned invalid classifier JSON"
            ) from exc
        if not isinstance(items, list) or not items:
            raise MemoryClassifierUnavailable("classification_unavailable: model returned no memory classifications")
        classifications: list[MemoryClassification] = []
        for item in items:
            if not isinstance(item, dict):
                raise MemoryClassifierUnavailable("classification_unavailable: classifier item is not an object")
            classifications.append(
                MemoryClassification(
                    kind=normalize_memory_kind(item.get("kind")),
                    provenance_class=normalize_memory_provenance_class(item.get("provenance_class")),
                    confidence=max(0.0, min(1.0, float(item.get("confidence", 0.0)))),
                    rationale=str(item.get("rationale") or "").strip(),
                    source_evidence_id=source_evidence_id,
                    model_provider_id=f"openai:{self.model}",
                )
            )
        return classifications


def memory_classifier_from_environment() -> MemoryClassifierProvider:
    provider = str(os.getenv("MARVAIN_MEMORY_CLASSIFIER_PROVIDER") or "").strip().lower()
    if provider in {"deterministic", "test", "smoke"}:
        return DeterministicMemoryClassifier()
    if not provider and str(os.getenv("ENVIRONMENT") or "").strip().lower() == "test":
        return DeterministicMemoryClassifier()
    if provider == "openai":
        model = str(os.getenv("MARVAIN_MEMORY_CLASSIFIER_MODEL") or "").strip()
        if not model:
            raise MemoryClassifierUnavailable(
                "classification_unavailable: set MARVAIN_MEMORY_CLASSIFIER_MODEL for OpenAI classification"
            )
        return OpenAIMemoryClassifier(model=model)
    raise MemoryClassifierUnavailable(
        "classification_unavailable: set MARVAIN_MEMORY_CLASSIFIER_PROVIDER=openai "
        "or use deterministic only in explicit test/smoke mode"
    )


def classify_memory_event(
    *,
    text: str,
    modality: str,
    source_evidence_id: str,
    actor_type: str | None = None,
    source: str | None = None,
    interacting_agent_id: str | None = None,
    provider: MemoryClassifierProvider | None = None,
) -> list[MemoryClassification]:
    selected_provider = provider or memory_classifier_from_environment()
    return selected_provider.classify(
        text=text,
        modality=modality,
        source_evidence_id=source_evidence_id,
        actor_type=actor_type,
        source=source,
        interacting_agent_id=interacting_agent_id,
    )
