"""Pure, evidence-first trust decisions for untrusted inputs and actions.

This module does not authenticate callers, inspect persistence, execute tools,
parse artifacts, or retrieve secrets. Owning services perform those operations
and pass immutable receipts here. Every decision uses an explicitly supplied
ID and timestamp so tests and runtimes cannot manufacture implicit evidence.
"""

from __future__ import annotations

import math
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from hashlib import sha256
from typing import Final

TRUST_POLICY_VERSION: Final = "marvain.trust-policy.v1"
_SHA256_RE: Final = re.compile(r"^[0-9a-f]{64}$")


class TrustPolicyError(ValueError):
    """A trust-policy request is structurally invalid or unsupported."""

    def __init__(self, code: str, message: str) -> None:
        self.code = code
        super().__init__(f"{code}: {message}")


class SourceKind(StrEnum):
    USER = "user"
    AGENT = "agent"
    PROVIDER = "provider"
    ARTIFACT = "artifact"
    MEMORY = "memory"
    SYSTEM = "system"


class TrustLevel(StrEnum):
    TRUSTED = "trusted"
    CONDITIONAL = "conditional"
    UNTRUSTED = "untrusted"


class DecisionDomain(StrEnum):
    INPUT_TRUST = "input_trust"
    MEMORY_CLAIM = "memory_claim"
    TOOL_EXECUTION = "tool_execution"
    ARTIFACT_USE = "artifact_use"
    SECRET_EXFILTRATION = "secret_exfiltration"


class ClaimImpact(StrEnum):
    ROUTINE = "routine"
    HIGH = "high"


class PromptIndicatorMethod(StrEnum):
    EXACT_LITERAL = "exact_literal"
    STRUCTURED_OVERRIDE_FIELD = "structured_override_field"
    INSTRUCTION_BOUNDARY_VIOLATION = "instruction_boundary_violation"


class ToolControl(StrEnum):
    TOOL = "tool"
    DESTINATION = "destination"
    SCOPE = "scope"
    SECRET_REFERENCE = "secret_reference"


class ArtifactLifecycle(StrEnum):
    PENDING = "pending"
    VERIFIED = "verified"
    QUARANTINED = "quarantined"
    REVOKED = "revoked"
    EXPIRED = "expired"


def _require_text(value: object, field_name: str) -> str:
    if not isinstance(value, str) or not value or value != value.strip():
        raise TrustPolicyError("invalid_field", f"{field_name} must be a non-empty trimmed string")
    return value


def _require_raw_text(value: object, field_name: str) -> str:
    if not isinstance(value, str) or not value:
        raise TrustPolicyError("invalid_field", f"{field_name} must be a non-empty string")
    return value


def _require_datetime(value: object, field_name: str) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise TrustPolicyError("invalid_timestamp", f"{field_name} must be timezone-aware")
    return value


def _require_sha256(value: object, field_name: str) -> str:
    digest = _require_text(value, field_name).lower()
    if _SHA256_RE.fullmatch(digest) is None:
        raise TrustPolicyError("invalid_digest", f"{field_name} must be a SHA-256 hex digest")
    return digest


def _require_ids(values: object, field_name: str, *, allow_empty: bool = False) -> tuple[str, ...]:
    if isinstance(values, str) or not isinstance(values, Sequence):
        raise TrustPolicyError("invalid_evidence", f"{field_name} must be an explicit sequence")
    normalized = tuple(_require_text(value, field_name) for value in values)
    if not allow_empty and not normalized:
        raise TrustPolicyError("evidence_required", f"{field_name} must contain persisted evidence")
    if len(normalized) != len(set(normalized)):
        raise TrustPolicyError("duplicate_evidence", f"{field_name} must contain unique values")
    return normalized


def _unique(values: Sequence[str]) -> tuple[str, ...]:
    return tuple(dict.fromkeys(values))


@dataclass(frozen=True)
class DecisionContext:
    decision_id: str
    evaluated_at: datetime
    policy_version: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "decision_id", _require_text(self.decision_id, "decision_id"))
        object.__setattr__(self, "evaluated_at", _require_datetime(self.evaluated_at, "evaluated_at"))
        version = _require_text(self.policy_version, "policy_version")
        if version != TRUST_POLICY_VERSION:
            raise TrustPolicyError("unsupported_policy_version", f"policy_version must be {TRUST_POLICY_VERSION}")
        object.__setattr__(self, "policy_version", version)


@dataclass(frozen=True)
class TrustPolicyDecision:
    decision_id: str
    evaluated_at: datetime
    policy_version: str
    domain: DecisionDomain
    allowed: bool
    trust_level: TrustLevel
    code: str
    evidence_ids: tuple[str, ...]
    performed_checks: tuple[str, ...]
    required_remediation: tuple[str, ...]
    source_kind: SourceKind | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.domain, DecisionDomain):
            raise TrustPolicyError("invalid_field", "domain must be a DecisionDomain")
        if not isinstance(self.trust_level, TrustLevel):
            raise TrustPolicyError("invalid_field", "trust_level must be a TrustLevel")
        if self.source_kind is not None and not isinstance(self.source_kind, SourceKind):
            raise TrustPolicyError("invalid_field", "source_kind must be a SourceKind")
        object.__setattr__(self, "decision_id", _require_text(self.decision_id, "decision_id"))
        object.__setattr__(self, "evaluated_at", _require_datetime(self.evaluated_at, "evaluated_at"))
        object.__setattr__(self, "policy_version", _require_text(self.policy_version, "policy_version"))
        if self.policy_version != TRUST_POLICY_VERSION:
            raise TrustPolicyError("unsupported_policy_version", "decision uses an unsupported policy version")
        object.__setattr__(self, "code", _require_text(self.code, "code"))
        object.__setattr__(
            self,
            "evidence_ids",
            _require_ids(self.evidence_ids, "evidence_ids", allow_empty=True),
        )
        object.__setattr__(self, "performed_checks", _require_ids(self.performed_checks, "performed_checks"))
        object.__setattr__(
            self,
            "required_remediation",
            _require_ids(self.required_remediation, "required_remediation", allow_empty=self.allowed),
        )
        if self.allowed and self.trust_level is TrustLevel.UNTRUSTED:
            raise TrustPolicyError("invalid_decision", "an allowed decision cannot be untrusted")
        if not self.allowed and self.trust_level is not TrustLevel.UNTRUSTED:
            raise TrustPolicyError("invalid_decision", "a denied decision must be untrusted")

    def as_dict(self) -> dict[str, object]:
        return {
            "decision_id": self.decision_id,
            "evaluated_at": self.evaluated_at.isoformat(),
            "policy_version": self.policy_version,
            "domain": self.domain.value,
            "allowed": self.allowed,
            "trust_level": self.trust_level.value,
            "code": self.code,
            "evidence_ids": list(self.evidence_ids),
            "performed_checks": list(self.performed_checks),
            "required_remediation": list(self.required_remediation),
            "source_kind": self.source_kind.value if self.source_kind is not None else None,
        }


def _decision(
    context: DecisionContext,
    *,
    domain: DecisionDomain,
    allowed: bool,
    code: str,
    evidence_ids: Sequence[str],
    performed_checks: Sequence[str],
    required_remediation: Sequence[str] = (),
    trust_level: TrustLevel | None = None,
    source_kind: SourceKind | None = None,
) -> TrustPolicyDecision:
    return TrustPolicyDecision(
        decision_id=context.decision_id,
        evaluated_at=context.evaluated_at,
        policy_version=context.policy_version,
        domain=domain,
        allowed=allowed,
        trust_level=trust_level or (TrustLevel.TRUSTED if allowed else TrustLevel.UNTRUSTED),
        code=code,
        evidence_ids=_unique(tuple(evidence_ids)),
        performed_checks=_unique(tuple(performed_checks)),
        required_remediation=_unique(tuple(required_remediation)),
        source_kind=source_kind,
    )


@dataclass(frozen=True)
class PromptInjectionFinding:
    finding_id: str
    evidence_id: str
    rule_id: str
    method: PromptIndicatorMethod
    content_sha256: str

    def __post_init__(self) -> None:
        if not isinstance(self.method, PromptIndicatorMethod):
            raise TrustPolicyError("invalid_field", "method must name a concrete PromptIndicatorMethod")
        object.__setattr__(self, "finding_id", _require_text(self.finding_id, "finding_id"))
        object.__setattr__(self, "evidence_id", _require_text(self.evidence_id, "evidence_id"))
        object.__setattr__(self, "rule_id", _require_text(self.rule_id, "rule_id"))
        object.__setattr__(self, "content_sha256", _require_sha256(self.content_sha256, "content_sha256"))


@dataclass(frozen=True)
class InputProvenanceReceipt:
    source_kind: SourceKind
    source_id: str
    owner_id: str
    content_sha256: str
    received_at: datetime
    identity_verified: bool
    identity_evidence_id: str
    integrity_verified: bool
    integrity_evidence_id: str
    ownership_verified: bool
    ownership_evidence_id: str
    policy_allowed: bool
    policy_evidence_id: str
    prompt_injection_findings: tuple[PromptInjectionFinding, ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.source_kind, SourceKind):
            raise TrustPolicyError("invalid_field", "source_kind must be a SourceKind")
        object.__setattr__(self, "source_id", _require_text(self.source_id, "source_id"))
        object.__setattr__(self, "owner_id", _require_text(self.owner_id, "owner_id"))
        object.__setattr__(self, "content_sha256", _require_sha256(self.content_sha256, "content_sha256"))
        object.__setattr__(self, "received_at", _require_datetime(self.received_at, "received_at"))
        for field_name in (
            "identity_verified",
            "integrity_verified",
            "ownership_verified",
            "policy_allowed",
        ):
            if not isinstance(getattr(self, field_name), bool):
                raise TrustPolicyError("invalid_field", f"{field_name} must be a boolean receipt outcome")
        for field_name in (
            "identity_evidence_id",
            "integrity_evidence_id",
            "ownership_evidence_id",
            "policy_evidence_id",
        ):
            object.__setattr__(self, field_name, _require_text(getattr(self, field_name), field_name))
        findings = tuple(self.prompt_injection_findings)
        if any(not isinstance(item, PromptInjectionFinding) for item in findings):
            raise TrustPolicyError(
                "invalid_evidence",
                "prompt_injection_findings must contain concrete finding receipts",
            )
        finding_ids = [item.finding_id for item in findings]
        if len(finding_ids) != len(set(finding_ids)):
            raise TrustPolicyError("duplicate_evidence", "prompt injection finding IDs must be unique")
        object.__setattr__(self, "prompt_injection_findings", findings)


_CONDITIONALLY_TRUSTED_KINDS: Final = frozenset({SourceKind.PROVIDER, SourceKind.ARTIFACT, SourceKind.MEMORY})


def classify_input_trust(
    *,
    context: DecisionContext,
    provenance: InputProvenanceReceipt,
) -> TrustPolicyDecision:
    """Classify input from concrete provenance receipts and indicator findings.

    This function does not infer semantic intent and returns no transformed or
    sanitized content. Any supplied injection finding produces an explicit deny.
    """

    if not isinstance(provenance, InputProvenanceReceipt):
        raise TrustPolicyError("invalid_provenance", "provenance must be an InputProvenanceReceipt")
    base_evidence = (
        provenance.identity_evidence_id,
        provenance.integrity_evidence_id,
        provenance.ownership_evidence_id,
        provenance.policy_evidence_id,
    )
    base_checks = (
        "input_receipt_time",
        "source_identity_receipt",
        "content_integrity_receipt",
        "source_ownership_receipt",
        "source_policy_receipt",
        "prompt_injection_finding_receipts",
    )
    if provenance.received_at > context.evaluated_at:
        raise TrustPolicyError("future_evidence", "input provenance cannot postdate the trust decision")
    if provenance.prompt_injection_findings and any(
        item.content_sha256 != provenance.content_sha256 for item in provenance.prompt_injection_findings
    ):
        return _decision(
            context,
            domain=DecisionDomain.INPUT_TRUST,
            allowed=False,
            code="prompt_indicator_content_mismatch",
            evidence_ids=base_evidence + tuple(item.evidence_id for item in provenance.prompt_injection_findings),
            performed_checks=base_checks,
            required_remediation=("rerun_concrete_indicator_checks_over_the_exact_input_digest",),
            source_kind=provenance.source_kind,
        )
    if provenance.prompt_injection_findings:
        return _decision(
            context,
            domain=DecisionDomain.INPUT_TRUST,
            allowed=False,
            code="untrusted_prompt_injection_indicator",
            evidence_ids=base_evidence + tuple(item.evidence_id for item in provenance.prompt_injection_findings),
            performed_checks=base_checks,
            required_remediation=(
                "quarantine_the_original_content",
                "obtain_a_new_reviewed_source_receipt_before_use",
            ),
            source_kind=provenance.source_kind,
        )
    for verified, code, remediation in (
        (provenance.identity_verified, "source_identity_unverified", "verify_source_identity"),
        (provenance.integrity_verified, "source_integrity_unverified", "verify_content_integrity"),
        (provenance.ownership_verified, "source_ownership_unverified", "verify_source_ownership"),
        (provenance.policy_allowed, "source_policy_denied", "obtain_an_allowing_policy_decision"),
    ):
        if not verified:
            return _decision(
                context,
                domain=DecisionDomain.INPUT_TRUST,
                allowed=False,
                code=code,
                evidence_ids=base_evidence,
                performed_checks=base_checks,
                required_remediation=(remediation,),
                source_kind=provenance.source_kind,
            )
    level = TrustLevel.CONDITIONAL if provenance.source_kind in _CONDITIONALLY_TRUSTED_KINDS else TrustLevel.TRUSTED
    return _decision(
        context,
        domain=DecisionDomain.INPUT_TRUST,
        allowed=True,
        code="input_conditionally_trusted" if level is TrustLevel.CONDITIONAL else "input_trusted",
        evidence_ids=base_evidence,
        performed_checks=base_checks,
        trust_level=level,
        source_kind=provenance.source_kind,
    )


@dataclass(frozen=True)
class SourceEvidenceReceipt:
    evidence_id: str
    source_kind: SourceKind
    source_id: str
    origin_id: str
    owner_id: str
    content_sha256: str
    integrity_verified: bool
    verification_evidence_id: str
    recorded_at: datetime

    def __post_init__(self) -> None:
        if not isinstance(self.source_kind, SourceKind):
            raise TrustPolicyError("invalid_field", "source_kind must be a SourceKind")
        for field_name in ("evidence_id", "source_id", "origin_id", "owner_id", "verification_evidence_id"):
            object.__setattr__(self, field_name, _require_text(getattr(self, field_name), field_name))
        object.__setattr__(self, "content_sha256", _require_sha256(self.content_sha256, "content_sha256"))
        object.__setattr__(self, "recorded_at", _require_datetime(self.recorded_at, "recorded_at"))
        if not isinstance(self.integrity_verified, bool):
            raise TrustPolicyError("invalid_field", "integrity_verified must be a boolean receipt outcome")


@dataclass(frozen=True)
class ClassifierProvenanceReceipt:
    evidence_id: str
    provider_id: str
    model_id: str
    classifier_version: str
    source_evidence_ids: tuple[str, ...]
    output_sha256: str
    confidence: float
    completed_at: datetime

    def __post_init__(self) -> None:
        for field_name in ("evidence_id", "provider_id", "model_id", "classifier_version"):
            object.__setattr__(self, field_name, _require_text(getattr(self, field_name), field_name))
        object.__setattr__(self, "source_evidence_ids", _require_ids(self.source_evidence_ids, "source_evidence_ids"))
        object.__setattr__(self, "output_sha256", _require_sha256(self.output_sha256, "output_sha256"))
        if isinstance(self.confidence, bool) or not isinstance(self.confidence, int | float):
            raise TrustPolicyError("invalid_confidence", "confidence must be numeric")
        confidence = float(self.confidence)
        if not math.isfinite(confidence) or confidence < 0.0 or confidence > 1.0:
            raise TrustPolicyError("invalid_confidence", "confidence must be finite from 0 to 1")
        object.__setattr__(self, "confidence", confidence)
        object.__setattr__(self, "completed_at", _require_datetime(self.completed_at, "completed_at"))


@dataclass(frozen=True)
class ConsentPolicyReceipt:
    evidence_id: str
    operation: str
    allowed: bool
    consent_evidence_ids: tuple[str, ...]
    policy_evidence_ids: tuple[str, ...]
    evaluated_at: datetime

    def __post_init__(self) -> None:
        object.__setattr__(self, "evidence_id", _require_text(self.evidence_id, "evidence_id"))
        object.__setattr__(self, "operation", _require_text(self.operation, "operation"))
        if not isinstance(self.allowed, bool):
            raise TrustPolicyError("invalid_field", "allowed must be a boolean policy outcome")
        object.__setattr__(
            self,
            "consent_evidence_ids",
            _require_ids(self.consent_evidence_ids, "consent_evidence_ids", allow_empty=True),
        )
        object.__setattr__(
            self,
            "policy_evidence_ids",
            _require_ids(self.policy_evidence_ids, "policy_evidence_ids", allow_empty=True),
        )
        object.__setattr__(self, "evaluated_at", _require_datetime(self.evaluated_at, "evaluated_at"))


@dataclass(frozen=True)
class IndependentCorroboration:
    source: SourceEvidenceReceipt
    independence_evidence_id: str

    def __post_init__(self) -> None:
        if not isinstance(self.source, SourceEvidenceReceipt):
            raise TrustPolicyError("invalid_evidence", "source must be a SourceEvidenceReceipt")
        object.__setattr__(
            self,
            "independence_evidence_id",
            _require_text(self.independence_evidence_id, "independence_evidence_id"),
        )


@dataclass(frozen=True)
class MemoryClaimRequest:
    candidate_id: str
    owning_agent_id: str
    impact: ClaimImpact
    source_evidence: tuple[SourceEvidenceReceipt, ...]
    classifier: ClassifierProvenanceReceipt | None
    consent_policy: ConsentPolicyReceipt | None
    corroboration: tuple[IndependentCorroboration, ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.impact, ClaimImpact):
            raise TrustPolicyError("invalid_field", "impact must be a ClaimImpact")
        object.__setattr__(self, "candidate_id", _require_text(self.candidate_id, "candidate_id"))
        object.__setattr__(self, "owning_agent_id", _require_text(self.owning_agent_id, "owning_agent_id"))
        source_evidence = tuple(self.source_evidence)
        corroboration = tuple(self.corroboration)
        if any(not isinstance(item, SourceEvidenceReceipt) for item in source_evidence):
            raise TrustPolicyError("invalid_evidence", "source_evidence must contain source receipts")
        if any(not isinstance(item, IndependentCorroboration) for item in corroboration):
            raise TrustPolicyError("invalid_evidence", "corroboration must contain independent receipts")
        object.__setattr__(self, "source_evidence", source_evidence)
        object.__setattr__(self, "corroboration", corroboration)


def evaluate_memory_claim(
    *,
    context: DecisionContext,
    request: MemoryClaimRequest,
) -> TrustPolicyDecision:
    evidence_ids = [item.evidence_id for item in request.source_evidence]
    evidence_ids.extend(item.verification_evidence_id for item in request.source_evidence)
    checks = ["source_evidence_receipts"]
    if not request.source_evidence:
        return _decision(
            context,
            domain=DecisionDomain.MEMORY_CLAIM,
            allowed=False,
            code="memory_source_evidence_missing",
            evidence_ids=(),
            performed_checks=checks,
            required_remediation=("attach_verified_source_evidence",),
        )
    source_ids = [item.evidence_id for item in request.source_evidence]
    if len(source_ids) != len(set(source_ids)):
        raise TrustPolicyError("duplicate_evidence", "memory source evidence IDs must be unique")
    if any(item.owner_id != request.owning_agent_id for item in request.source_evidence):
        return _decision(
            context,
            domain=DecisionDomain.MEMORY_CLAIM,
            allowed=False,
            code="memory_source_owner_mismatch",
            evidence_ids=evidence_ids,
            performed_checks=checks + ["source_owner_binding"],
            required_remediation=("persist_source_evidence_under_the_owning_agent",),
        )
    if any(item.recorded_at > context.evaluated_at for item in request.source_evidence):
        raise TrustPolicyError("future_evidence", "memory source evidence cannot postdate the policy decision")
    checks.append("source_owner_binding")
    if any(not item.integrity_verified for item in request.source_evidence):
        return _decision(
            context,
            domain=DecisionDomain.MEMORY_CLAIM,
            allowed=False,
            code="memory_source_integrity_unverified",
            evidence_ids=evidence_ids,
            performed_checks=checks + ["source_integrity_receipts"],
            required_remediation=("verify_each_source_before_classification",),
        )
    checks.append("source_integrity_receipts")
    if request.classifier is None:
        return _decision(
            context,
            domain=DecisionDomain.MEMORY_CLAIM,
            allowed=False,
            code="classifier_provenance_missing",
            evidence_ids=evidence_ids,
            performed_checks=checks + ["classifier_provenance_receipt"],
            required_remediation=("classify_with_a_configured_evidence_linked_provider",),
        )
    classifier = request.classifier
    evidence_ids.append(classifier.evidence_id)
    checks.append("classifier_provenance_receipt")
    if set(classifier.source_evidence_ids) != set(source_ids):
        return _decision(
            context,
            domain=DecisionDomain.MEMORY_CLAIM,
            allowed=False,
            code="classifier_source_mismatch",
            evidence_ids=evidence_ids,
            performed_checks=checks + ["classifier_source_binding"],
            required_remediation=("rerun_classification_over_the_exact_source_bundle",),
        )
    if classifier.completed_at > context.evaluated_at:
        raise TrustPolicyError("future_evidence", "classifier evidence cannot postdate the policy decision")
    if any(item.recorded_at > classifier.completed_at for item in request.source_evidence):
        return _decision(
            context,
            domain=DecisionDomain.MEMORY_CLAIM,
            allowed=False,
            code="classifier_predates_source_evidence",
            evidence_ids=evidence_ids,
            performed_checks=checks + ["classifier_source_time"],
            required_remediation=("rerun_classification_after_all_source_evidence_is_recorded",),
        )
    checks.append("classifier_source_binding")
    checks.append("classifier_source_time")
    if request.consent_policy is None:
        return _decision(
            context,
            domain=DecisionDomain.MEMORY_CLAIM,
            allowed=False,
            code="consent_policy_result_missing",
            evidence_ids=evidence_ids,
            performed_checks=checks + ["consent_and_policy_receipt"],
            required_remediation=("evaluate_current_consent_and_memory_policy",),
        )
    policy = request.consent_policy
    evidence_ids.extend((policy.evidence_id, *policy.consent_evidence_ids, *policy.policy_evidence_ids))
    checks.append("consent_and_policy_receipt")
    if not policy.consent_evidence_ids or not policy.policy_evidence_ids:
        return _decision(
            context,
            domain=DecisionDomain.MEMORY_CLAIM,
            allowed=False,
            code="consent_policy_evidence_incomplete",
            evidence_ids=evidence_ids,
            performed_checks=checks,
            required_remediation=("record_both_consent_and_policy_evidence",),
        )
    if policy.evaluated_at > context.evaluated_at:
        raise TrustPolicyError("future_evidence", "consent policy evidence cannot postdate the policy decision")
    if not policy.allowed:
        return _decision(
            context,
            domain=DecisionDomain.MEMORY_CLAIM,
            allowed=False,
            code="memory_policy_denied",
            evidence_ids=evidence_ids,
            performed_checks=checks,
            required_remediation=("do_not_persist_the_claim", "obtain_a_new_allowing_policy_result_before_retry"),
        )

    source_origins = {item.origin_id for item in request.source_evidence}
    if request.impact is ClaimImpact.HIGH:
        checks.append("high_impact_independent_corroboration")
        if not request.corroboration:
            return _decision(
                context,
                domain=DecisionDomain.MEMORY_CLAIM,
                allowed=False,
                code="high_impact_corroboration_missing",
                evidence_ids=evidence_ids,
                performed_checks=checks,
                required_remediation=("obtain_verified_evidence_from_an_independent_origin",),
            )
    elif request.corroboration:
        checks.append("independent_corroboration")
    for corroboration in request.corroboration:
        evidence_ids.extend(
            (
                corroboration.source.evidence_id,
                corroboration.source.verification_evidence_id,
                corroboration.independence_evidence_id,
            )
        )
        if not corroboration.source.integrity_verified:
            return _decision(
                context,
                domain=DecisionDomain.MEMORY_CLAIM,
                allowed=False,
                code="corroboration_integrity_unverified",
                evidence_ids=evidence_ids,
                performed_checks=checks,
                required_remediation=("verify_corroborating_source_integrity",),
            )
        if corroboration.source.owner_id != request.owning_agent_id:
            return _decision(
                context,
                domain=DecisionDomain.MEMORY_CLAIM,
                allowed=False,
                code="corroboration_owner_mismatch",
                evidence_ids=evidence_ids,
                performed_checks=checks,
                required_remediation=("persist_corroboration_under_the_owning_agent",),
            )
        if corroboration.source.recorded_at > context.evaluated_at:
            raise TrustPolicyError("future_evidence", "corroboration cannot postdate the policy decision")
        if corroboration.source.origin_id in source_origins:
            return _decision(
                context,
                domain=DecisionDomain.MEMORY_CLAIM,
                allowed=False,
                code="corroboration_not_independent",
                evidence_ids=evidence_ids,
                performed_checks=checks,
                required_remediation=("obtain_corroboration_from_a_distinct_origin",),
            )
    return _decision(
        context,
        domain=DecisionDomain.MEMORY_CLAIM,
        allowed=True,
        code="memory_claim_evidence_sufficient",
        evidence_ids=evidence_ids,
        performed_checks=checks,
    )


@dataclass(frozen=True)
class ToolControlSelection:
    control: ToolControl
    value: str
    value_sha256: str
    selection_evidence_id: str
    source_decision: TrustPolicyDecision

    def __post_init__(self) -> None:
        if not isinstance(self.control, ToolControl):
            raise TrustPolicyError("invalid_field", "control must be a ToolControl")
        object.__setattr__(self, "value", _require_text(self.value, "value"))
        object.__setattr__(self, "value_sha256", _require_sha256(self.value_sha256, "value_sha256"))
        object.__setattr__(
            self,
            "selection_evidence_id",
            _require_text(self.selection_evidence_id, "selection_evidence_id"),
        )
        if not isinstance(self.source_decision, TrustPolicyDecision):
            raise TrustPolicyError("invalid_provenance", "source_decision must be a trust-policy decision")


@dataclass(frozen=True)
class ToolExecutionRequest:
    request_id: str
    tool_name: str
    destination: str
    scopes: tuple[str, ...]
    secret_reference_ids: tuple[str, ...]
    selections: tuple[ToolControlSelection, ...]

    def __post_init__(self) -> None:
        object.__setattr__(self, "request_id", _require_text(self.request_id, "request_id"))
        object.__setattr__(self, "tool_name", _require_text(self.tool_name, "tool_name"))
        object.__setattr__(self, "destination", _require_text(self.destination, "destination"))
        object.__setattr__(self, "scopes", _require_ids(self.scopes, "scopes"))
        object.__setattr__(
            self,
            "secret_reference_ids",
            _require_ids(self.secret_reference_ids, "secret_reference_ids", allow_empty=True),
        )
        selections = tuple(self.selections)
        if any(not isinstance(item, ToolControlSelection) for item in selections):
            raise TrustPolicyError("invalid_provenance", "selections must contain ToolControlSelection values")
        object.__setattr__(self, "selections", selections)


@dataclass(frozen=True)
class ToolAuthorizationReceipt:
    evidence_id: str
    approved_tools: tuple[str, ...]
    approved_destinations: tuple[str, ...]
    approved_scopes: tuple[str, ...]
    approved_secret_reference_ids: tuple[str, ...]

    def __post_init__(self) -> None:
        object.__setattr__(self, "evidence_id", _require_text(self.evidence_id, "evidence_id"))
        for field_name in ("approved_tools", "approved_destinations", "approved_scopes"):
            object.__setattr__(self, field_name, _require_ids(getattr(self, field_name), field_name))
        object.__setattr__(
            self,
            "approved_secret_reference_ids",
            _require_ids(
                self.approved_secret_reference_ids,
                "approved_secret_reference_ids",
                allow_empty=True,
            ),
        )


def evaluate_tool_execution(
    *,
    context: DecisionContext,
    request: ToolExecutionRequest,
    authorization: ToolAuthorizationReceipt,
) -> TrustPolicyDecision:
    required = {
        (ToolControl.TOOL, request.tool_name),
        (ToolControl.DESTINATION, request.destination),
        *((ToolControl.SCOPE, value) for value in request.scopes),
        *((ToolControl.SECRET_REFERENCE, value) for value in request.secret_reference_ids),
    }
    supplied = [(item.control, item.value) for item in request.selections]
    evidence_ids = [authorization.evidence_id]
    checks = ["control_selection_provenance", "control_value_digest_binding", "tool_authorization_receipt"]
    if len(supplied) != len(set(supplied)):
        raise TrustPolicyError("duplicate_provenance", "tool control selection receipts must be unique")
    if set(supplied) != required:
        return _decision(
            context,
            domain=DecisionDomain.TOOL_EXECUTION,
            allowed=False,
            code="tool_control_provenance_incomplete",
            evidence_ids=evidence_ids,
            performed_checks=checks,
            required_remediation=("supply_trusted_provenance_for_every_control_value",),
        )
    for selection in request.selections:
        source = selection.source_decision
        evidence_ids.extend((selection.selection_evidence_id, source.decision_id, *source.evidence_ids))
        if selection.value_sha256 != sha256(selection.value.encode("utf-8")).hexdigest():
            return _decision(
                context,
                domain=DecisionDomain.TOOL_EXECUTION,
                allowed=False,
                code="tool_control_value_binding_mismatch",
                evidence_ids=evidence_ids,
                performed_checks=checks,
                required_remediation=("bind_each_control_value_to_its_selection_receipt",),
            )
        if (
            source.domain is not DecisionDomain.INPUT_TRUST
            or source.policy_version != context.policy_version
            or source.evaluated_at > context.evaluated_at
            or not source.allowed
            or source.trust_level is not TrustLevel.TRUSTED
        ):
            return _decision(
                context,
                domain=DecisionDomain.TOOL_EXECUTION,
                allowed=False,
                code="untrusted_tool_control_selection",
                evidence_ids=evidence_ids,
                performed_checks=checks,
                required_remediation=(
                    "select_tools_destinations_scopes_and_secrets_from_trusted_authorized_control_input",
                ),
            )
    authorized = (
        request.tool_name in authorization.approved_tools
        and request.destination in authorization.approved_destinations
        and set(request.scopes).issubset(authorization.approved_scopes)
        and set(request.secret_reference_ids).issubset(authorization.approved_secret_reference_ids)
    )
    if not authorized:
        return _decision(
            context,
            domain=DecisionDomain.TOOL_EXECUTION,
            allowed=False,
            code="tool_control_not_authorized",
            evidence_ids=evidence_ids,
            performed_checks=checks,
            required_remediation=("request_explicit_authorization_for_every_control_value",),
        )
    return _decision(
        context,
        domain=DecisionDomain.TOOL_EXECUTION,
        allowed=True,
        code="tool_execution_authorized",
        evidence_ids=evidence_ids,
        performed_checks=checks,
    )


@dataclass(frozen=True)
class ArtifactReceipt:
    artifact_id: str
    owner_id: str
    media_type: str
    checksum_sha256: str
    checksum_verified: bool
    checksum_evidence_id: str
    lifecycle: ArtifactLifecycle
    lifecycle_evidence_id: str
    ownership_verified: bool
    ownership_evidence_id: str

    def __post_init__(self) -> None:
        if not isinstance(self.lifecycle, ArtifactLifecycle):
            raise TrustPolicyError("invalid_field", "lifecycle must be an ArtifactLifecycle")
        for field_name in (
            "artifact_id",
            "owner_id",
            "media_type",
            "checksum_evidence_id",
            "lifecycle_evidence_id",
            "ownership_evidence_id",
        ):
            object.__setattr__(self, field_name, _require_text(getattr(self, field_name), field_name))
        object.__setattr__(self, "checksum_sha256", _require_sha256(self.checksum_sha256, "checksum_sha256"))
        if not isinstance(self.checksum_verified, bool) or not isinstance(self.ownership_verified, bool):
            raise TrustPolicyError("invalid_field", "artifact verification outcomes must be booleans")


@dataclass(frozen=True)
class MediaParserApproval:
    parser_id: str
    approved_media_types: tuple[str, ...]
    approved: bool
    approval_evidence_id: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "parser_id", _require_text(self.parser_id, "parser_id"))
        object.__setattr__(
            self,
            "approved_media_types",
            _require_ids(self.approved_media_types, "approved_media_types"),
        )
        if not isinstance(self.approved, bool):
            raise TrustPolicyError("invalid_field", "approved must be a boolean receipt outcome")
        object.__setattr__(
            self,
            "approval_evidence_id",
            _require_text(self.approval_evidence_id, "approval_evidence_id"),
        )


def evaluate_artifact_use(
    *,
    context: DecisionContext,
    artifact: ArtifactReceipt,
    expected_owner_id: str,
    parser: MediaParserApproval,
) -> TrustPolicyDecision:
    expected_owner = _require_text(expected_owner_id, "expected_owner_id")
    evidence_ids = (
        artifact.checksum_evidence_id,
        artifact.lifecycle_evidence_id,
        artifact.ownership_evidence_id,
        parser.approval_evidence_id,
    )
    checks = (
        "artifact_checksum_receipt",
        "artifact_lifecycle_receipt",
        "artifact_ownership_receipt",
        "approved_media_parser_receipt",
    )
    for allowed, code, remediation in (
        (artifact.checksum_verified, "artifact_checksum_unverified", "verify_artifact_checksum"),
        (
            artifact.lifecycle is ArtifactLifecycle.VERIFIED,
            "artifact_lifecycle_not_verified",
            "complete_artifact_verification_or_keep_quarantined",
        ),
        (
            artifact.ownership_verified and artifact.owner_id == expected_owner,
            "artifact_owner_mismatch",
            "verify_artifact_owner_and_requested_owner",
        ),
        (
            parser.approved and artifact.media_type in parser.approved_media_types,
            "artifact_parser_not_approved",
            "use_an_approved_parser_for_the_verified_media_type",
        ),
    ):
        if not allowed:
            return _decision(
                context,
                domain=DecisionDomain.ARTIFACT_USE,
                allowed=False,
                code=code,
                evidence_ids=evidence_ids,
                performed_checks=checks,
                required_remediation=(remediation,),
            )
    return _decision(
        context,
        domain=DecisionDomain.ARTIFACT_USE,
        allowed=True,
        code="artifact_use_approved",
        evidence_ids=evidence_ids,
        performed_checks=checks,
    )


@dataclass(frozen=True)
class SecretMaterial:
    secret_id: str
    exact_value: str = field(repr=False)
    lookup_evidence_id: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "secret_id", _require_text(self.secret_id, "secret_id"))
        object.__setattr__(self, "exact_value", _require_raw_text(self.exact_value, "exact_value"))
        object.__setattr__(
            self,
            "lookup_evidence_id",
            _require_text(self.lookup_evidence_id, "lookup_evidence_id"),
        )


@dataclass(frozen=True)
class SecretReferenceApproval:
    secret_id: str
    approved: bool
    approval_evidence_id: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "secret_id", _require_text(self.secret_id, "secret_id"))
        if not isinstance(self.approved, bool):
            raise TrustPolicyError("invalid_field", "approved must be a boolean receipt outcome")
        object.__setattr__(
            self,
            "approval_evidence_id",
            _require_text(self.approval_evidence_id, "approval_evidence_id"),
        )


@dataclass(frozen=True)
class SecretExfiltrationRequest:
    request_id: str
    payload_serializations: tuple[str, ...] = field(repr=False)
    referenced_secret_ids: tuple[str, ...]
    scan_evidence_id: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "request_id", _require_text(self.request_id, "request_id"))
        if isinstance(self.payload_serializations, str) or not isinstance(self.payload_serializations, Sequence):
            raise TrustPolicyError("invalid_payload", "payload_serializations must be an explicit sequence")
        payloads = tuple(_require_raw_text(value, "payload_serializations") for value in self.payload_serializations)
        if not payloads:
            raise TrustPolicyError("payload_required", "at least one canonical payload serialization is required")
        object.__setattr__(self, "payload_serializations", payloads)
        object.__setattr__(
            self,
            "referenced_secret_ids",
            _require_ids(self.referenced_secret_ids, "referenced_secret_ids", allow_empty=True),
        )
        object.__setattr__(self, "scan_evidence_id", _require_text(self.scan_evidence_id, "scan_evidence_id"))


def evaluate_secret_exfiltration(
    *,
    context: DecisionContext,
    request: SecretExfiltrationRequest,
    secret_materials: Sequence[SecretMaterial],
    reference_approvals: Sequence[SecretReferenceApproval],
) -> TrustPolicyDecision:
    if isinstance(secret_materials, str) or not isinstance(secret_materials, Sequence):
        raise TrustPolicyError("invalid_secret_receipts", "secret_materials must be an explicit sequence")
    if isinstance(reference_approvals, str) or not isinstance(reference_approvals, Sequence):
        raise TrustPolicyError("invalid_secret_receipts", "reference_approvals must be an explicit sequence")
    if any(not isinstance(item, SecretMaterial) for item in secret_materials):
        raise TrustPolicyError("invalid_secret_receipts", "secret_materials contains an invalid receipt")
    if any(not isinstance(item, SecretReferenceApproval) for item in reference_approvals):
        raise TrustPolicyError("invalid_secret_receipts", "reference_approvals contains an invalid receipt")

    evidence_ids = [request.scan_evidence_id]
    checks = ["exact_secret_material_scan", "secret_reference_approval_receipts"]
    matched_receipts = [
        secret.lookup_evidence_id
        for secret in secret_materials
        if any(secret.exact_value in payload for payload in request.payload_serializations)
    ]
    if matched_receipts:
        return _decision(
            context,
            domain=DecisionDomain.SECRET_EXFILTRATION,
            allowed=False,
            code="exact_secret_material_detected",
            evidence_ids=evidence_ids + matched_receipts,
            performed_checks=checks,
            required_remediation=(
                "block_output_or_action",
                "remove_secret_material_without_recording_it_in_logs",
                "rotate_the_secret_if_exposure_occurred",
            ),
        )

    approvals: Mapping[str, SecretReferenceApproval] = {item.secret_id: item for item in reference_approvals}
    if len(approvals) != len(reference_approvals):
        raise TrustPolicyError("duplicate_evidence", "secret reference approvals must be unique by secret ID")
    evidence_ids.extend(item.approval_evidence_id for item in reference_approvals)
    if any(
        secret_id not in approvals or not approvals[secret_id].approved for secret_id in request.referenced_secret_ids
    ):
        return _decision(
            context,
            domain=DecisionDomain.SECRET_EXFILTRATION,
            allowed=False,
            code="unapproved_secret_reference",
            evidence_ids=evidence_ids,
            performed_checks=checks,
            required_remediation=("remove_the_reference_or_obtain_explicit_secret_use_approval",),
        )
    return _decision(
        context,
        domain=DecisionDomain.SECRET_EXFILTRATION,
        allowed=True,
        code="secret_exfiltration_checks_passed",
        evidence_ids=evidence_ids,
        performed_checks=checks,
    )
