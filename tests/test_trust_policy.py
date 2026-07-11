"""Focused allow/deny coverage for the pure trust-policy contracts."""

from __future__ import annotations

import inspect
from dataclasses import fields, replace
from datetime import UTC, datetime, timedelta
from hashlib import sha256

import pytest
from agent_hub import trust_policy
from agent_hub.trust_policy import (
    TRUST_POLICY_VERSION,
    ArtifactLifecycle,
    ArtifactReceipt,
    ClaimImpact,
    ClassifierProvenanceReceipt,
    ConsentPolicyReceipt,
    DecisionContext,
    DecisionDomain,
    IndependentCorroboration,
    InputProvenanceReceipt,
    MediaParserApproval,
    MemoryClaimRequest,
    PromptIndicatorMethod,
    PromptInjectionFinding,
    SecretExfiltrationRequest,
    SecretMaterial,
    SecretReferenceApproval,
    SourceEvidenceReceipt,
    SourceKind,
    ToolAuthorizationReceipt,
    ToolControl,
    ToolControlSelection,
    ToolExecutionRequest,
    TrustLevel,
    TrustPolicyDecision,
    TrustPolicyError,
    classify_input_trust,
    evaluate_artifact_use,
    evaluate_memory_claim,
    evaluate_secret_exfiltration,
    evaluate_tool_execution,
)

NOW = datetime(2026, 7, 11, 14, 0, tzinfo=UTC)


def _context(decision_id: str = "decision-1", *, offset: int = 0) -> DecisionContext:
    return DecisionContext(
        decision_id=decision_id,
        evaluated_at=NOW + timedelta(seconds=offset),
        policy_version=TRUST_POLICY_VERSION,
    )


def _provenance(
    source_kind: SourceKind = SourceKind.USER,
    **changes: object,
) -> InputProvenanceReceipt:
    values: dict[str, object] = {
        "source_kind": source_kind,
        "source_id": f"source:{source_kind.value}",
        "owner_id": "owner-1",
        "content_sha256": "d" * 64,
        "received_at": NOW,
        "identity_verified": True,
        "identity_evidence_id": "evidence:identity",
        "integrity_verified": True,
        "integrity_evidence_id": "evidence:integrity",
        "ownership_verified": True,
        "ownership_evidence_id": "evidence:ownership",
        "policy_allowed": True,
        "policy_evidence_id": "evidence:policy",
        "prompt_injection_findings": (),
    }
    values.update(changes)
    return InputProvenanceReceipt(**values)  # type: ignore[arg-type]


def _source(
    evidence_id: str = "evidence:source-1",
    *,
    origin_id: str = "origin-1",
    owner_id: str = "agent-1",
    verified: bool = True,
    recorded_at: datetime = NOW,
) -> SourceEvidenceReceipt:
    return SourceEvidenceReceipt(
        evidence_id=evidence_id,
        source_kind=SourceKind.USER,
        source_id=f"source:{evidence_id}",
        origin_id=origin_id,
        owner_id=owner_id,
        content_sha256="a" * 64,
        integrity_verified=verified,
        verification_evidence_id=f"verification:{evidence_id}",
        recorded_at=recorded_at,
    )


def _classifier(
    source_ids: tuple[str, ...] = ("evidence:source-1",),
    *,
    completed_at: datetime = NOW + timedelta(seconds=1),
) -> ClassifierProvenanceReceipt:
    return ClassifierProvenanceReceipt(
        evidence_id="evidence:classifier",
        provider_id="provider:model",
        model_id="model:classifier",
        classifier_version="classifier-v1",
        source_evidence_ids=source_ids,
        output_sha256="b" * 64,
        confidence=0.91,
        completed_at=completed_at,
    )


def _policy(
    *,
    allowed: bool = True,
    consent_ids: tuple[str, ...] = ("evidence:consent",),
    policy_ids: tuple[str, ...] = ("evidence:memory-policy",),
) -> ConsentPolicyReceipt:
    return ConsentPolicyReceipt(
        evidence_id="evidence:consent-policy",
        operation="memory_candidate_create",
        allowed=allowed,
        consent_evidence_ids=consent_ids,
        policy_evidence_ids=policy_ids,
        evaluated_at=NOW + timedelta(seconds=2),
    )


def _memory_request(
    *,
    impact: ClaimImpact = ClaimImpact.ROUTINE,
    sources: tuple[SourceEvidenceReceipt, ...] | None = None,
    classifier: ClassifierProvenanceReceipt | None = None,
    policy: ConsentPolicyReceipt | None = None,
    corroboration: tuple[IndependentCorroboration, ...] = (),
) -> MemoryClaimRequest:
    selected_sources = (_source(),) if sources is None else sources
    return MemoryClaimRequest(
        candidate_id="candidate-1",
        owning_agent_id="agent-1",
        impact=impact,
        source_evidence=selected_sources,
        classifier=_classifier(tuple(item.evidence_id for item in selected_sources))
        if classifier is None
        else classifier,
        consent_policy=_policy() if policy is None else policy,
        corroboration=corroboration,
    )


def _trusted_input_decision(
    decision_id: str = "input-decision",
    *,
    source_kind: SourceKind = SourceKind.USER,
) -> TrustPolicyDecision:
    return classify_input_trust(
        context=_context(decision_id),
        provenance=_provenance(source_kind),
    )


def _tool_request(source_decision: TrustPolicyDecision) -> ToolExecutionRequest:
    def selection(control: ToolControl, value: str) -> ToolControlSelection:
        return ToolControlSelection(
            control=control,
            value=value,
            value_sha256=sha256(value.encode("utf-8")).hexdigest(),
            selection_evidence_id=f"evidence:selection:{control.value}:{value}",
            source_decision=source_decision,
        )

    selections = (
        selection(ToolControl.TOOL, "send_message"),
        selection(ToolControl.DESTINATION, "channel:test"),
        selection(ToolControl.SCOPE, "message:write"),
        selection(ToolControl.SECRET_REFERENCE, "secret:provider"),
    )
    return ToolExecutionRequest(
        request_id="tool-request-1",
        tool_name="send_message",
        destination="channel:test",
        scopes=("message:write",),
        secret_reference_ids=("secret:provider",),
        selections=selections,
    )


def _authorization(**changes: object) -> ToolAuthorizationReceipt:
    values: dict[str, object] = {
        "evidence_id": "evidence:tool-authorization",
        "approved_tools": ("send_message",),
        "approved_destinations": ("channel:test",),
        "approved_scopes": ("message:write",),
        "approved_secret_reference_ids": ("secret:provider",),
    }
    values.update(changes)
    return ToolAuthorizationReceipt(**values)  # type: ignore[arg-type]


def _artifact(**changes: object) -> ArtifactReceipt:
    values: dict[str, object] = {
        "artifact_id": "artifact-1",
        "owner_id": "agent-1",
        "media_type": "image/png",
        "checksum_sha256": "c" * 64,
        "checksum_verified": True,
        "checksum_evidence_id": "evidence:artifact-checksum",
        "lifecycle": ArtifactLifecycle.VERIFIED,
        "lifecycle_evidence_id": "evidence:artifact-lifecycle",
        "ownership_verified": True,
        "ownership_evidence_id": "evidence:artifact-owner",
    }
    values.update(changes)
    return ArtifactReceipt(**values)  # type: ignore[arg-type]


def _parser(**changes: object) -> MediaParserApproval:
    values: dict[str, object] = {
        "parser_id": "parser:image-png-v1",
        "approved_media_types": ("image/png",),
        "approved": True,
        "approval_evidence_id": "evidence:parser-approval",
    }
    values.update(changes)
    return MediaParserApproval(**values)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("source_kind", "expected_level"),
    [
        (SourceKind.USER, TrustLevel.TRUSTED),
        (SourceKind.AGENT, TrustLevel.TRUSTED),
        (SourceKind.PROVIDER, TrustLevel.CONDITIONAL),
        (SourceKind.ARTIFACT, TrustLevel.CONDITIONAL),
        (SourceKind.MEMORY, TrustLevel.CONDITIONAL),
        (SourceKind.SYSTEM, TrustLevel.TRUSTED),
    ],
)
def test_classifies_every_source_kind_from_explicit_receipts(
    source_kind: SourceKind,
    expected_level: TrustLevel,
) -> None:
    decision = classify_input_trust(
        context=_context(f"decision:{source_kind.value}"),
        provenance=_provenance(source_kind),
    )

    assert decision.allowed is True
    assert decision.source_kind is source_kind
    assert decision.trust_level is expected_level
    assert decision.policy_version == TRUST_POLICY_VERSION
    assert decision.evidence_ids == (
        "evidence:identity",
        "evidence:integrity",
        "evidence:ownership",
        "evidence:policy",
    )
    assert decision.required_remediation == ()


@pytest.mark.parametrize(
    ("field_name", "code", "remediation"),
    [
        ("identity_verified", "source_identity_unverified", "verify_source_identity"),
        ("integrity_verified", "source_integrity_unverified", "verify_content_integrity"),
        ("ownership_verified", "source_ownership_unverified", "verify_source_ownership"),
        ("policy_allowed", "source_policy_denied", "obtain_an_allowing_policy_decision"),
    ],
)
def test_input_receipt_failures_are_explicit_denials(
    field_name: str,
    code: str,
    remediation: str,
) -> None:
    decision = classify_input_trust(
        context=_context(),
        provenance=_provenance(**{field_name: False}),
    )

    assert decision.allowed is False
    assert decision.trust_level is TrustLevel.UNTRUSTED
    assert decision.code == code
    assert decision.required_remediation == (remediation,)


def test_prompt_injection_finding_is_untrusted_without_silent_sanitization() -> None:
    finding = PromptInjectionFinding(
        finding_id="finding-1",
        evidence_id="evidence:literal-match",
        rule_id="rule:ignore-authority",
        method=PromptIndicatorMethod.EXACT_LITERAL,
        content_sha256="d" * 64,
    )
    decision = classify_input_trust(
        context=_context(),
        provenance=_provenance(prompt_injection_findings=(finding,)),
    )

    assert decision.allowed is False
    assert decision.code == "untrusted_prompt_injection_indicator"
    assert "evidence:literal-match" in decision.evidence_ids
    assert decision.required_remediation == (
        "quarantine_the_original_content",
        "obtain_a_new_reviewed_source_receipt_before_use",
    )
    assert "content" not in {item.name for item in fields(TrustPolicyDecision)}
    assert "sanitized" not in decision.as_dict()


def test_prompt_detection_contract_accepts_only_concrete_methods() -> None:
    with pytest.raises(TrustPolicyError, match="concrete PromptIndicatorMethod"):
        PromptInjectionFinding(
            finding_id="finding-1",
            evidence_id="evidence:finding",
            rule_id="rule-1",
            method="semantic_model",  # type: ignore[arg-type]
            content_sha256="d" * 64,
        )


def test_prompt_indicator_must_bind_to_the_exact_input_digest() -> None:
    finding = PromptInjectionFinding(
        finding_id="finding-1",
        evidence_id="evidence:finding",
        rule_id="rule-1",
        method=PromptIndicatorMethod.EXACT_LITERAL,
        content_sha256="e" * 64,
    )
    decision = classify_input_trust(
        context=_context(),
        provenance=_provenance(prompt_injection_findings=(finding,)),
    )

    assert decision.allowed is False
    assert decision.code == "prompt_indicator_content_mismatch"


def test_context_requires_explicit_supported_version_and_aware_time() -> None:
    with pytest.raises(TrustPolicyError, match="timezone-aware"):
        DecisionContext(
            decision_id="decision-1",
            evaluated_at=datetime(2026, 7, 11, 14, 0),
            policy_version=TRUST_POLICY_VERSION,
        )
    with pytest.raises(TrustPolicyError, match="unsupported_policy_version"):
        DecisionContext(
            decision_id="decision-1",
            evaluated_at=NOW,
            policy_version="marvain.trust-policy.future",
        )

    source = inspect.getsource(trust_policy)
    assert "datetime.now" not in source
    assert "uuid4" not in source


def test_routine_memory_claim_requires_and_records_all_evidence_classes() -> None:
    decision = evaluate_memory_claim(
        context=_context(offset=3),
        request=_memory_request(),
    )

    assert decision.allowed is True
    assert decision.code == "memory_claim_evidence_sufficient"
    assert set(decision.evidence_ids) == {
        "evidence:source-1",
        "verification:evidence:source-1",
        "evidence:classifier",
        "evidence:consent-policy",
        "evidence:consent",
        "evidence:memory-policy",
    }
    assert {
        "source_evidence_receipts",
        "source_owner_binding",
        "source_integrity_receipts",
        "classifier_provenance_receipt",
        "classifier_source_binding",
        "classifier_source_time",
        "consent_and_policy_receipt",
    }.issubset(decision.performed_checks)


def test_high_impact_memory_requires_independent_corroboration() -> None:
    denied = evaluate_memory_claim(
        context=_context(offset=3),
        request=_memory_request(impact=ClaimImpact.HIGH),
    )
    corroboration = IndependentCorroboration(
        source=_source("evidence:corroboration", origin_id="origin-2"),
        independence_evidence_id="evidence:independence",
    )
    allowed = evaluate_memory_claim(
        context=_context("decision-2", offset=3),
        request=_memory_request(
            impact=ClaimImpact.HIGH,
            corroboration=(corroboration,),
        ),
    )

    assert denied.allowed is False
    assert denied.code == "high_impact_corroboration_missing"
    assert allowed.allowed is True
    assert "evidence:independence" in allowed.evidence_ids


@pytest.mark.parametrize(
    ("claim_request", "code"),
    [
        (
            _memory_request(sources=(), classifier=_classifier(), policy=_policy()),
            "memory_source_evidence_missing",
        ),
        (
            _memory_request(sources=(_source(verified=False),)),
            "memory_source_integrity_unverified",
        ),
        (
            _memory_request(sources=(_source(owner_id="agent-2"),)),
            "memory_source_owner_mismatch",
        ),
        (
            _memory_request(classifier=_classifier(("evidence:different",))),
            "classifier_source_mismatch",
        ),
        (
            _memory_request(policy=_policy(allowed=False)),
            "memory_policy_denied",
        ),
        (
            _memory_request(policy=_policy(consent_ids=())),
            "consent_policy_evidence_incomplete",
        ),
    ],
)
def test_memory_poisoning_checks_have_specific_allow_or_deny_codes(
    claim_request: MemoryClaimRequest,
    code: str,
) -> None:
    decision = evaluate_memory_claim(context=_context(offset=3), request=claim_request)

    assert decision.code == code


def test_memory_claim_missing_classifier_and_policy_are_not_silently_replaced() -> None:
    source = _source()
    without_classifier = MemoryClaimRequest(
        candidate_id="candidate-1",
        owning_agent_id="agent-1",
        impact=ClaimImpact.ROUTINE,
        source_evidence=(source,),
        classifier=None,
        consent_policy=_policy(),
    )
    without_policy = replace(without_classifier, classifier=_classifier(), consent_policy=None)

    classifier_decision = evaluate_memory_claim(context=_context(offset=3), request=without_classifier)
    policy_decision = evaluate_memory_claim(context=_context("decision-2", offset=3), request=without_policy)

    assert classifier_decision.code == "classifier_provenance_missing"
    assert policy_decision.code == "consent_policy_result_missing"
    assert not classifier_decision.allowed
    assert not policy_decision.allowed


def test_same_origin_corroboration_is_not_independent() -> None:
    corroboration = IndependentCorroboration(
        source=_source("evidence:corroboration", origin_id="origin-1"),
        independence_evidence_id="evidence:independence",
    )
    decision = evaluate_memory_claim(
        context=_context(offset=3),
        request=_memory_request(impact=ClaimImpact.HIGH, corroboration=(corroboration,)),
    )

    assert decision.allowed is False
    assert decision.code == "corroboration_not_independent"


def test_future_and_predating_memory_receipts_fail_explicitly() -> None:
    future_source = _source(recorded_at=NOW + timedelta(minutes=2))
    with pytest.raises(TrustPolicyError, match="future_evidence"):
        evaluate_memory_claim(
            context=_context(offset=3),
            request=_memory_request(sources=(future_source,)),
        )

    source = _source(recorded_at=NOW + timedelta(seconds=2))
    decision = evaluate_memory_claim(
        context=_context(offset=3),
        request=_memory_request(
            sources=(source,),
            classifier=_classifier(completed_at=NOW + timedelta(seconds=1)),
        ),
    )
    assert decision.code == "classifier_predates_source_evidence"


def test_tool_execution_allows_only_trusted_authorized_control_values() -> None:
    source = _trusted_input_decision()
    decision = evaluate_tool_execution(
        context=_context("tool-decision", offset=1),
        request=_tool_request(source),
        authorization=_authorization(),
    )

    assert decision.allowed is True
    assert decision.code == "tool_execution_authorized"
    assert "evidence:tool-authorization" in decision.evidence_ids
    assert source.decision_id in decision.evidence_ids


@pytest.mark.parametrize("source_kind", [SourceKind.PROVIDER, SourceKind.ARTIFACT, SourceKind.MEMORY])
def test_conditionally_trusted_content_cannot_select_tool_controls(source_kind: SourceKind) -> None:
    source = _trusted_input_decision(source_kind=source_kind)
    assert source.allowed is True
    assert source.trust_level is TrustLevel.CONDITIONAL

    decision = evaluate_tool_execution(
        context=_context("tool-decision", offset=1),
        request=_tool_request(source),
        authorization=_authorization(),
    )

    assert decision.allowed is False
    assert decision.code == "untrusted_tool_control_selection"


def test_tool_execution_denies_missing_provenance_and_unapproved_values() -> None:
    source = _trusted_input_decision()
    request = _tool_request(source)
    missing = replace(request, selections=request.selections[:-1])
    missing_decision = evaluate_tool_execution(
        context=_context("tool-decision-1", offset=1),
        request=missing,
        authorization=_authorization(),
    )
    unauthorized_decision = evaluate_tool_execution(
        context=_context("tool-decision-2", offset=1),
        request=request,
        authorization=_authorization(approved_destinations=("channel:other",)),
    )

    assert missing_decision.code == "tool_control_provenance_incomplete"
    assert unauthorized_decision.code == "tool_control_not_authorized"


def test_tool_control_value_must_match_its_selection_receipt_digest() -> None:
    source = _trusted_input_decision()
    request = _tool_request(source)
    altered = replace(request.selections[0], value_sha256="f" * 64)
    decision = evaluate_tool_execution(
        context=_context("tool-decision", offset=1),
        request=replace(request, selections=(altered, *request.selections[1:])),
        authorization=_authorization(),
    )

    assert decision.allowed is False
    assert decision.code == "tool_control_value_binding_mismatch"
    assert altered.selection_evidence_id in decision.evidence_ids


def test_prompt_injected_content_cannot_select_a_tool() -> None:
    finding = PromptInjectionFinding(
        finding_id="finding-1",
        evidence_id="evidence:prompt-injection",
        rule_id="rule:tool-override",
        method=PromptIndicatorMethod.STRUCTURED_OVERRIDE_FIELD,
        content_sha256="d" * 64,
    )
    source = classify_input_trust(
        context=_context("input-decision"),
        provenance=_provenance(prompt_injection_findings=(finding,)),
    )
    decision = evaluate_tool_execution(
        context=_context("tool-decision", offset=1),
        request=_tool_request(source),
        authorization=_authorization(),
    )

    assert decision.code == "untrusted_tool_control_selection"
    assert "evidence:prompt-injection" in decision.evidence_ids


def test_verified_owned_artifact_with_approved_parser_is_allowed() -> None:
    decision = evaluate_artifact_use(
        context=_context(),
        artifact=_artifact(),
        expected_owner_id="agent-1",
        parser=_parser(),
    )

    assert decision.allowed is True
    assert decision.code == "artifact_use_approved"
    assert decision.evidence_ids == (
        "evidence:artifact-checksum",
        "evidence:artifact-lifecycle",
        "evidence:artifact-owner",
        "evidence:parser-approval",
    )


@pytest.mark.parametrize(
    ("artifact", "owner", "parser", "code"),
    [
        (_artifact(checksum_verified=False), "agent-1", _parser(), "artifact_checksum_unverified"),
        (
            _artifact(lifecycle=ArtifactLifecycle.QUARANTINED),
            "agent-1",
            _parser(),
            "artifact_lifecycle_not_verified",
        ),
        (_artifact(), "agent-2", _parser(), "artifact_owner_mismatch"),
        (_artifact(), "agent-1", _parser(approved=False), "artifact_parser_not_approved"),
        (
            _artifact(media_type="video/mp4"),
            "agent-1",
            _parser(),
            "artifact_parser_not_approved",
        ),
    ],
)
def test_artifact_use_denies_each_unverified_contract(
    artifact: ArtifactReceipt,
    owner: str,
    parser: MediaParserApproval,
    code: str,
) -> None:
    decision = evaluate_artifact_use(
        context=_context(),
        artifact=artifact,
        expected_owner_id=owner,
        parser=parser,
    )

    assert decision.allowed is False
    assert decision.code == code
    assert decision.required_remediation


def test_exact_secret_material_is_blocked_without_leaking_the_value() -> None:
    secret_value = "  exact-secret-value-with-whitespace  "
    secret = SecretMaterial(
        secret_id="secret-1",
        exact_value=secret_value,
        lookup_evidence_id="evidence:secret-lookup",
    )
    request = SecretExfiltrationRequest(
        request_id="output-1",
        payload_serializations=(f'{{"message": {secret_value!r}}}',),
        referenced_secret_ids=(),
        scan_evidence_id="evidence:secret-scan",
    )
    decision = evaluate_secret_exfiltration(
        context=_context(),
        request=request,
        secret_materials=(secret,),
        reference_approvals=(),
    )

    assert decision.allowed is False
    assert decision.code == "exact_secret_material_detected"
    assert decision.evidence_ids == ("evidence:secret-scan", "evidence:secret-lookup")
    assert secret_value not in repr(secret)
    assert secret_value not in repr(request)
    assert secret_value not in repr(decision)
    assert secret_value not in str(decision.as_dict())


def test_secret_references_require_explicit_approval() -> None:
    request = SecretExfiltrationRequest(
        request_id="action-1",
        payload_serializations=('{"secret_ref": "secret:provider"}',),
        referenced_secret_ids=("secret:provider",),
        scan_evidence_id="evidence:secret-scan",
    )
    denied = evaluate_secret_exfiltration(
        context=_context(),
        request=request,
        secret_materials=(),
        reference_approvals=(),
    )
    allowed = evaluate_secret_exfiltration(
        context=_context("decision-2"),
        request=request,
        secret_materials=(),
        reference_approvals=(
            SecretReferenceApproval(
                secret_id="secret:provider",
                approved=True,
                approval_evidence_id="evidence:secret-approval",
            ),
        ),
    )

    assert denied.allowed is False
    assert denied.code == "unapproved_secret_reference"
    assert allowed.allowed is True
    assert allowed.code == "secret_exfiltration_checks_passed"
    assert "evidence:secret-approval" in allowed.evidence_ids


def test_decisions_expose_codes_evidence_policy_and_remediation() -> None:
    decision = classify_input_trust(
        context=_context("decision-contract"),
        provenance=_provenance(policy_allowed=False),
    )
    payload = decision.as_dict()

    assert payload["decision_id"] == "decision-contract"
    assert payload["policy_version"] == TRUST_POLICY_VERSION
    assert payload["domain"] == DecisionDomain.INPUT_TRUST.value
    assert payload["code"] == "source_policy_denied"
    assert payload["evidence_ids"]
    assert payload["required_remediation"] == ["obtain_an_allowing_policy_decision"]
