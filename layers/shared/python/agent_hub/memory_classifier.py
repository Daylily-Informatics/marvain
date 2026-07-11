"""Memory auto-capture classification providers and failure contracts."""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass, replace
from enum import StrEnum
from typing import Protocol, Self

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator

from agent_hub.memory_taxonomy import (
    MEMORY_KIND_VALUES,
    MEMORY_PROVENANCE_VALUES,
    MemoryKindName,
    MemoryProvenanceClassName,
    classify_memory_kinds,
    classify_memory_provenance_class,
    normalize_memory_kind,
    normalize_memory_provenance_class,
)

MEMORY_CLASSIFIER_FAILURE_CONTRACT = "memory_classifier_failure_v1"


class MemoryClassifierFailureCode(StrEnum):
    INVALID_REQUEST = "invalid_request"
    PROVIDER_NOT_CONFIGURED = "provider_not_configured"
    DEPENDENCY_UNAVAILABLE = "dependency_unavailable"
    PROVIDER_REQUEST_FAILED = "provider_request_failed"
    INVALID_OUTPUT = "invalid_output"
    EMPTY_OUTPUT = "empty_output"
    PROVIDER_CONTRACT_ERROR = "provider_contract_error"


@dataclass(frozen=True)
class MemoryClassifierFailure:
    """Serializable failure value for a classification attempt."""

    code: MemoryClassifierFailureCode
    message: str
    provider_id: str
    model_provider_id: str | None
    source_evidence_id: str | None
    retryable: bool
    details: tuple[tuple[str, str], ...] = ()

    def __post_init__(self) -> None:
        if not self.message.strip():
            raise ValueError("classifier failure message is required")
        if not self.provider_id.strip():
            raise ValueError("classifier failure provider_id is required")
        if self.model_provider_id is not None and not self.model_provider_id.strip():
            raise ValueError("classifier failure model_provider_id cannot be blank")
        if self.source_evidence_id is not None and not self.source_evidence_id.strip():
            raise ValueError("classifier failure source_evidence_id cannot be blank")
        detail_names = [name for name, _ in self.details]
        if any(not name.strip() for name in detail_names):
            raise ValueError("classifier failure detail names cannot be blank")
        if len(detail_names) != len(set(detail_names)):
            raise ValueError("classifier failure detail names must be unique")

    def as_record(self) -> dict[str, object]:
        """Return the durable record shape expected by service integrations."""

        return {
            "contract": MEMORY_CLASSIFIER_FAILURE_CONTRACT,
            "status": "classification_failed",
            "failure_code": self.code.value,
            "message": self.message,
            "provider_id": self.provider_id,
            "model_provider_id": self.model_provider_id,
            "source_evidence_id": self.source_evidence_id,
            "retryable": self.retryable,
            "details": dict(self.details),
        }


class MemoryClassifierUnavailable(RuntimeError):
    """Raised with an explicit failure record when classification cannot complete."""

    def __init__(self, failure: MemoryClassifierFailure) -> None:
        self.failure = failure
        super().__init__(f"classification_unavailable: {failure.code.value}: {failure.message}")


@dataclass(frozen=True)
class MemoryClassification:
    kind: str
    provenance_class: str
    confidence: float
    rationale: str
    evidence_quote: str
    source_evidence_id: str
    model_provider_id: str

    def __post_init__(self) -> None:
        kind = normalize_memory_kind(_require_text(self.kind, "kind"))
        provenance_class = normalize_memory_provenance_class(_require_text(self.provenance_class, "provenance_class"))
        if isinstance(self.confidence, bool) or not isinstance(self.confidence, int | float):
            raise ValueError("confidence must be a number from 0.0 to 1.0")
        confidence = float(self.confidence)
        if not 0.0 <= confidence <= 1.0:
            raise ValueError("confidence must be from 0.0 to 1.0")
        object.__setattr__(self, "kind", kind)
        object.__setattr__(self, "provenance_class", provenance_class)
        object.__setattr__(self, "confidence", confidence)
        object.__setattr__(self, "rationale", _require_text(self.rationale, "rationale"))
        object.__setattr__(self, "evidence_quote", _require_text(self.evidence_quote, "evidence_quote"))
        object.__setattr__(
            self,
            "source_evidence_id",
            _require_text(self.source_evidence_id, "source_evidence_id"),
        )
        object.__setattr__(
            self,
            "model_provider_id",
            _require_text(self.model_provider_id, "model_provider_id"),
        )

    def as_metadata(self) -> dict[str, object]:
        return {
            "kind": self.kind,
            "provenance_class": self.provenance_class,
            "confidence": self.confidence,
            "rationale": self.rationale,
            "evidence_quote": self.evidence_quote,
            "source_evidence_id": self.source_evidence_id,
            "model_provider_id": self.model_provider_id,
        }


@dataclass(frozen=True)
class MemoryClassificationResult:
    """Success-or-failure result with no implicit classifier fallback."""

    classifications: tuple[MemoryClassification, ...] = ()
    failure: MemoryClassifierFailure | None = None

    def __post_init__(self) -> None:
        if bool(self.classifications) == bool(self.failure):
            raise ValueError("classification result must contain classifications or one failure")

    @property
    def succeeded(self) -> bool:
        return self.failure is None


class MemoryClassifierOutputItem(BaseModel):
    """Strict provider output item used for both JSON Schema and local validation."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    kind: MemoryKindName
    provenance_class: MemoryProvenanceClassName
    confidence: float = Field(ge=0.0, le=1.0, allow_inf_nan=False)
    rationale: str = Field(min_length=1, max_length=1000)
    evidence_quote: str = Field(min_length=1, max_length=240)

    @field_validator("rationale", "evidence_quote")
    @classmethod
    def reject_blank_text(cls, value: str) -> str:
        normalized = value.strip()
        if not normalized:
            raise ValueError("value cannot be blank")
        return normalized


class MemoryClassifierOutput(BaseModel):
    """Strict, schema-constrained output from a model classifier."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    items: tuple[MemoryClassifierOutputItem, ...] = Field(min_length=1, max_length=len(MEMORY_KIND_VALUES))

    @model_validator(mode="after")
    def reject_duplicate_kinds(self) -> Self:
        kinds = [item.kind for item in self.items]
        if len(kinds) != len(set(kinds)):
            raise ValueError("classifier output contains duplicate memory kinds")
        return self


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


def _require_text(value: object, field: str) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{field} must be a string")
    text = value.strip()
    if not text:
        raise ValueError(f"{field} is required")
    return text


def _failure(
    code: MemoryClassifierFailureCode,
    *,
    message: str,
    provider_id: str,
    model_provider_id: str | None = None,
    source_evidence_id: str | None = None,
    retryable: bool,
    details: tuple[tuple[str, str], ...] = (),
) -> MemoryClassifierFailure:
    return MemoryClassifierFailure(
        code=code,
        message=message,
        provider_id=provider_id,
        model_provider_id=model_provider_id,
        source_evidence_id=source_evidence_id,
        retryable=retryable,
        details=details,
    )


def _raise_failure(*args, **kwargs) -> None:
    raise MemoryClassifierUnavailable(_failure(*args, **kwargs))


def _grounding_quote(text: str) -> str:
    return _require_text(text, "text")[:240]


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
        evidence_quote = _grounding_quote(text)
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
                evidence_quote=evidence_quote,
                source_evidence_id=source_evidence_id,
                model_provider_id=self.provider_id,
            )
            for kind in classify_memory_kinds(text, modality=modality)
        ]


class OpenAIMemoryClassifier:
    provider_id = "openai"

    def __init__(self, *, model: str) -> None:
        self.model = _require_text(model, "model")

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
        text = _require_text(text, "text")
        source_evidence_id = _require_text(source_evidence_id, "source_evidence_id")
        model_provider_id = f"openai:{self.model}"
        try:
            from openai import OpenAI
        except Exception as exc:  # pragma: no cover - dependency contract covers import in real env
            _raise_failure(
                MemoryClassifierFailureCode.DEPENDENCY_UNAVAILABLE,
                message="openai package is unavailable",
                provider_id=self.provider_id,
                model_provider_id=model_provider_id,
                source_evidence_id=source_evidence_id,
                retryable=False,
                details=(("exception_type", type(exc).__name__),),
            )

        prompt = {
            "task": "Classify a Marvain memory capture event.",
            "allowed_memory_kinds": list(MEMORY_KIND_VALUES),
            "allowed_provenance_classes": list(MEMORY_PROVENANCE_VALUES),
            "grounding_requirement": "evidence_quote must be an exact contiguous quote from event.text",
            "event": {
                "text": text,
                "modality": modality,
                "source_evidence_id": source_evidence_id,
                "actor_type": actor_type,
                "source": source,
                "interacting_agent_id": interacting_agent_id,
            },
        }
        try:
            client = OpenAI()
            response = client.responses.create(
                model=self.model,
                input=[
                    {
                        "role": "system",
                        "content": (
                            "Classify only from the supplied event. Do not invent memory kinds, "
                            "provenance classes, or evidence quotes."
                        ),
                    },
                    {"role": "user", "content": json.dumps(prompt, sort_keys=True)},
                ],
                text={
                    "format": {
                        "type": "json_schema",
                        "name": "marvain_memory_classification",
                        "description": "Evidence-grounded Marvain memory classifications.",
                        "strict": True,
                        "schema": MemoryClassifierOutput.model_json_schema(),
                    }
                },
            )
        except MemoryClassifierUnavailable:
            raise
        except Exception as exc:
            _raise_failure(
                MemoryClassifierFailureCode.PROVIDER_REQUEST_FAILED,
                message="OpenAI classifier request failed",
                provider_id=self.provider_id,
                model_provider_id=model_provider_id,
                source_evidence_id=source_evidence_id,
                retryable=True,
                details=(("exception_type", type(exc).__name__),),
            )

        raw = str(getattr(response, "output_text", "") or "").strip()
        try:
            payload = MemoryClassifierOutput.model_validate_json(raw)
        except ValidationError as exc:
            _raise_failure(
                MemoryClassifierFailureCode.INVALID_OUTPUT,
                message="model returned classifier output that violates the required schema",
                provider_id=self.provider_id,
                model_provider_id=model_provider_id,
                source_evidence_id=source_evidence_id,
                retryable=False,
                details=(
                    ("raw_output_sha256", hashlib.sha256(raw.encode("utf-8")).hexdigest()),
                    (
                        "validation_errors",
                        json.dumps(
                            exc.errors(include_input=False, include_url=False),
                            default=str,
                            sort_keys=True,
                        )[:4000],
                    ),
                ),
            )

        classifications: list[MemoryClassification] = []
        source_text = text.casefold()
        for item in payload.items:
            if item.evidence_quote.casefold() not in source_text:
                _raise_failure(
                    MemoryClassifierFailureCode.INVALID_OUTPUT,
                    message="model returned an evidence quote that is not grounded in the source text",
                    provider_id=self.provider_id,
                    model_provider_id=model_provider_id,
                    source_evidence_id=source_evidence_id,
                    retryable=False,
                    details=(("memory_kind", item.kind),),
                )
            classifications.append(
                MemoryClassification(
                    kind=item.kind,
                    provenance_class=item.provenance_class,
                    confidence=item.confidence,
                    rationale=item.rationale,
                    evidence_quote=item.evidence_quote,
                    source_evidence_id=source_evidence_id,
                    model_provider_id=model_provider_id,
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
            _raise_failure(
                MemoryClassifierFailureCode.PROVIDER_NOT_CONFIGURED,
                message="set MARVAIN_MEMORY_CLASSIFIER_MODEL for OpenAI classification",
                provider_id="openai",
                retryable=False,
            )
        return OpenAIMemoryClassifier(model=model)
    _raise_failure(
        MemoryClassifierFailureCode.PROVIDER_NOT_CONFIGURED,
        message=("set MARVAIN_MEMORY_CLASSIFIER_PROVIDER=openai or use deterministic only in explicit test/smoke mode"),
        provider_id=provider or "unconfigured",
        retryable=False,
    )


def _with_source_evidence(
    failure: MemoryClassifierFailure,
    source_evidence_id: str,
) -> MemoryClassifierFailure:
    if failure.source_evidence_id is not None:
        return failure
    return replace(failure, source_evidence_id=source_evidence_id)


def classify_memory_event_result(
    *,
    text: str,
    modality: str,
    source_evidence_id: str,
    actor_type: str | None = None,
    source: str | None = None,
    interacting_agent_id: str | None = None,
    provider: MemoryClassifierProvider | None = None,
) -> MemoryClassificationResult:
    """Classify an event and return an explicit success-or-failure record."""

    for field, value in (("text", text), ("modality", modality), ("source_evidence_id", source_evidence_id)):
        try:
            _require_text(value, field)
        except ValueError as exc:
            return MemoryClassificationResult(
                failure=_failure(
                    MemoryClassifierFailureCode.INVALID_REQUEST,
                    message=str(exc),
                    provider_id="request_validation",
                    source_evidence_id=source_evidence_id.strip()
                    if isinstance(source_evidence_id, str) and source_evidence_id.strip()
                    else None,
                    retryable=False,
                )
            )

    try:
        selected_provider = provider or memory_classifier_from_environment()
    except MemoryClassifierUnavailable as exc:
        return MemoryClassificationResult(
            failure=_with_source_evidence(exc.failure, source_evidence_id),
        )

    try:
        provider_id = _require_text(selected_provider.provider_id, "provider_id")
    except (AttributeError, ValueError) as exc:
        return MemoryClassificationResult(
            failure=_failure(
                MemoryClassifierFailureCode.PROVIDER_CONTRACT_ERROR,
                message="classifier provider does not declare a valid provider_id",
                provider_id="invalid_provider",
                source_evidence_id=source_evidence_id,
                retryable=False,
                details=(("exception_type", type(exc).__name__),),
            )
        )

    try:
        classifications = selected_provider.classify(
            text=text,
            modality=modality,
            source_evidence_id=source_evidence_id,
            actor_type=actor_type,
            source=source,
            interacting_agent_id=interacting_agent_id,
        )
    except MemoryClassifierUnavailable as exc:
        return MemoryClassificationResult(
            failure=_with_source_evidence(exc.failure, source_evidence_id),
        )
    except Exception as exc:
        return MemoryClassificationResult(
            failure=_failure(
                MemoryClassifierFailureCode.PROVIDER_CONTRACT_ERROR,
                message="classifier provider raised an uncontracted exception",
                provider_id=provider_id,
                source_evidence_id=source_evidence_id,
                retryable=False,
                details=(("exception_type", type(exc).__name__),),
            )
        )

    if not isinstance(classifications, list):
        return MemoryClassificationResult(
            failure=_failure(
                MemoryClassifierFailureCode.PROVIDER_CONTRACT_ERROR,
                message="classifier provider must return a list",
                provider_id=provider_id,
                source_evidence_id=source_evidence_id,
                retryable=False,
            )
        )
    if not classifications:
        return MemoryClassificationResult(
            failure=_failure(
                MemoryClassifierFailureCode.EMPTY_OUTPUT,
                message="classifier provider returned no memory classifications",
                provider_id=provider_id,
                source_evidence_id=source_evidence_id,
                retryable=False,
            )
        )
    if any(not isinstance(item, MemoryClassification) for item in classifications):
        return MemoryClassificationResult(
            failure=_failure(
                MemoryClassifierFailureCode.PROVIDER_CONTRACT_ERROR,
                message="classifier provider returned an invalid classification value",
                provider_id=provider_id,
                source_evidence_id=source_evidence_id,
                retryable=False,
            )
        )
    return MemoryClassificationResult(classifications=tuple(classifications))


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
    result = classify_memory_event_result(
        text=text,
        modality=modality,
        source_evidence_id=source_evidence_id,
        actor_type=actor_type,
        source=source,
        interacting_agent_id=interacting_agent_id,
        provider=provider,
    )
    if result.failure is not None:
        raise MemoryClassifierUnavailable(result.failure)
    return list(result.classifications)
