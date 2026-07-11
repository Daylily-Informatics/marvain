"""Focused contracts for model-assisted memory classification."""

from __future__ import annotations

import json
import sys
from types import ModuleType, SimpleNamespace

import pytest
from agent_hub.memory_classifier import (
    MemoryClassifierFailureCode,
    MemoryClassifierUnavailable,
    OpenAIMemoryClassifier,
    classify_memory_event_result,
)
from agent_hub.memory_taxonomy import MEMORY_KIND_VALUES, MEMORY_PROVENANCE_VALUES


def _install_fake_openai(monkeypatch, *, output: dict | None = None, error: Exception | None = None) -> dict:
    captured: dict = {}

    class FakeResponses:
        def create(self, **kwargs):
            captured.update(kwargs)
            if error is not None:
                raise error
            return SimpleNamespace(output_text=json.dumps(output))

    class FakeOpenAI:
        def __init__(self):
            self.responses = FakeResponses()

    module = ModuleType("openai")
    module.OpenAI = FakeOpenAI
    monkeypatch.setitem(sys.modules, "openai", module)
    return captured


def _valid_item(**overrides) -> dict:
    item = {
        "kind": "preference",
        "provenance_class": "external_interaction",
        "confidence": 0.92,
        "rationale": "The user states a durable communication preference.",
        "evidence_quote": "prefers concise status reports",
    }
    item.update(overrides)
    return item


def test_openai_classifier_requests_strict_schema_and_validates_grounded_output(monkeypatch) -> None:
    captured = _install_fake_openai(monkeypatch, output={"items": [_valid_item()]})

    classifications = OpenAIMemoryClassifier(model="gpt-test").classify(
        text="Major prefers concise status reports during incidents.",
        modality="text",
        source_evidence_id="event-1",
        actor_type="user",
        source="live_session_chat",
    )

    assert len(classifications) == 1
    assert classifications[0].kind == "preference"
    assert classifications[0].evidence_quote == "prefers concise status reports"
    assert classifications[0].model_provider_id == "openai:gpt-test"

    response_format = captured["text"]["format"]
    assert response_format["type"] == "json_schema"
    assert response_format["strict"] is True
    schema = response_format["schema"]
    assert schema["additionalProperties"] is False
    item_ref = schema["properties"]["items"]["items"]["$ref"]
    item_schema = schema["$defs"][item_ref.rsplit("/", 1)[-1]]
    assert item_schema["additionalProperties"] is False
    assert item_schema["properties"]["kind"]["enum"] == list(MEMORY_KIND_VALUES)
    assert item_schema["properties"]["provenance_class"]["enum"] == list(MEMORY_PROVENANCE_VALUES)


@pytest.mark.parametrize(
    "item",
    (
        _valid_item(kind="legacy_kind"),
        _valid_item(confidence=1.25),
        _valid_item(rationale="   "),
        _valid_item(unexpected="not allowed"),
    ),
)
def test_openai_classifier_rejects_output_outside_schema(monkeypatch, item: dict) -> None:
    _install_fake_openai(monkeypatch, output={"items": [item]})

    with pytest.raises(MemoryClassifierUnavailable) as raised:
        OpenAIMemoryClassifier(model="gpt-test").classify(
            text="Major prefers concise status reports during incidents.",
            modality="text",
            source_evidence_id="event-2",
        )

    failure = raised.value.failure
    assert failure.code is MemoryClassifierFailureCode.INVALID_OUTPUT
    assert failure.retryable is False
    assert failure.source_evidence_id == "event-2"
    record = failure.as_record()
    assert record["contract"] == "memory_classifier_failure_v1"
    assert record["status"] == "classification_failed"
    assert record["failure_code"] == "invalid_output"


def test_openai_classifier_rejects_ungrounded_evidence_quote(monkeypatch) -> None:
    _install_fake_openai(
        monkeypatch,
        output={"items": [_valid_item(evidence_quote="invented source evidence")]},
    )

    with pytest.raises(MemoryClassifierUnavailable) as raised:
        OpenAIMemoryClassifier(model="gpt-test").classify(
            text="Major prefers concise status reports during incidents.",
            modality="text",
            source_evidence_id="event-3",
        )

    assert raised.value.failure.code is MemoryClassifierFailureCode.INVALID_OUTPUT
    assert "not grounded" in raised.value.failure.message


def test_openai_classifier_records_retryable_provider_failure_without_fallback(monkeypatch) -> None:
    _install_fake_openai(monkeypatch, error=TimeoutError("provider timeout"))

    result = classify_memory_event_result(
        text="Major prefers concise status reports during incidents.",
        modality="text",
        source_evidence_id="event-4",
        provider=OpenAIMemoryClassifier(model="gpt-test"),
    )

    assert result.succeeded is False
    assert result.classifications == ()
    assert result.failure is not None
    assert result.failure.code is MemoryClassifierFailureCode.PROVIDER_REQUEST_FAILED
    assert result.failure.retryable is True
    assert result.failure.as_record()["details"] == {"exception_type": "TimeoutError"}


def test_classifier_result_records_empty_provider_output() -> None:
    class EmptyProvider:
        provider_id = "empty-test"

        def classify(self, **kwargs):
            return []

    result = classify_memory_event_result(
        text="Remember this event.",
        modality="text",
        source_evidence_id="event-5",
        provider=EmptyProvider(),
    )

    assert result.failure is not None
    assert result.failure.code is MemoryClassifierFailureCode.EMPTY_OUTPUT
    assert result.failure.provider_id == "empty-test"
    assert result.failure.source_evidence_id == "event-5"
