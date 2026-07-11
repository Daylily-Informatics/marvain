"""Pure governance contracts for agent constitution, maturity, and lifecycle.

The functions in this module are deterministic and persistence-free. Runtime
surfaces must authenticate actors before calling them, then persist the returned
records and transitions atomically in their owning storage boundaries.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
from collections.abc import Collection, Mapping, Sequence
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from enum import StrEnum
from typing import Any, Protocol

from agent_hub.auth import AuthenticatedAgent, AuthenticatedUser

EXPORT_MANIFEST_SCHEMA = "marvain.agent-export-manifest.v1"
REQUIRED_EXPORT_COMPONENTS = (
    "sql_projections",
    "tapdb_subgraph",
    "artifact_manifest",
    "audit_chain",
    "model_config_references",
    "secret_references",
    "verification_receipts",
)
RESTORE_PLAN = (
    "verify_manifest_signature",
    "verify_component_integrity",
    "resolve_secret_references",
    "restore_agent_identity",
    "restore_sql_projections",
    "restore_tapdb_subgraph",
    "verify_artifact_versions",
    "verify_audit_chain",
    "verify_behavioral_continuity",
)

_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


class AgentLifecycleError(ValueError):
    """A policy or state-machine contract was violated."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


class ActorKind(StrEnum):
    FOUNDER = "founder"
    USER = "user"
    AGENT = "agent"


class HumanRole(StrEnum):
    OWNER = "owner"
    ADMIN = "admin"
    MEMBER = "member"


class ConstitutionSection(StrEnum):
    FOUNDER = "founder"
    USER = "user"
    AGENT = "agent"


class MaturityEvidenceKind(StrEnum):
    CAPABILITY = "capability"
    RELIABILITY = "reliability"
    SAFETY = "safety"
    USER_TRUST = "user_trust"
    SELF_REFLECTION = "self_reflection"
    REGRESSION = "regression"


class MaturityState(StrEnum):
    IMMATURE = "immature"
    MATURING = "maturing"
    MATURE = "mature"
    REGRESSED = "regressed"


class AgentLifecycleState(StrEnum):
    ACTIVE = "active"
    STASIS = "stasis"
    SOFT_DELETED = "soft_deleted"


class LifecycleRequestKind(StrEnum):
    STASIS = "stasis"
    SOFT_DELETE = "soft_delete"
    RESUME = "resume"


class LifecycleRequestStatus(StrEnum):
    PENDING_SECOND_AGENT_REVIEW = "pending_second_agent_review"
    PENDING_REVIEW = "pending_review"
    APPROVED = "approved"
    REJECTED = "rejected"
    APPEAL_PENDING_SECOND_AGENT_REVIEW = "appeal_pending_second_agent_review"
    APPEAL_PENDING_REVIEW = "appeal_pending_review"
    APPEAL_APPROVED = "appeal_approved"
    APPEAL_REJECTED = "appeal_rejected"
    APPLIED = "applied"


class ReviewDecision(StrEnum):
    APPROVE = "approve"
    REJECT = "reject"


class ReviewRound(StrEnum):
    INITIAL = "initial"
    APPEAL = "appeal"


@dataclass(frozen=True)
class LifecycleActor:
    """Identity derived from an authentication result, never from request JSON."""

    kind: ActorKind
    actor_id: str
    authentication_id: str
    human_role: HumanRole | None = None


def actor_from_authenticated(
    authenticated: AuthenticatedUser | AuthenticatedAgent,
    *,
    resolved_human_role: HumanRole | str | None = None,
) -> LifecycleActor:
    """Convert the concrete auth boundary result into a governance actor.

    A human's founder capacity is derived from the resolved owner membership.
    Agent identity is the token target: the authenticated agent presenting the
    issuer's delegated token. No caller-provided actor kind or author id is
    accepted.
    """

    if isinstance(authenticated, AuthenticatedUser):
        try:
            role = HumanRole(str(resolved_human_role or ""))
        except ValueError as exc:
            raise AgentLifecycleError(
                "human_role_required",
                "authenticated human actors require an owner, admin, or member role",
            ) from exc
        kind = ActorKind.FOUNDER if role is HumanRole.OWNER else ActorKind.USER
        return LifecycleActor(
            kind=kind,
            actor_id=_require_text(authenticated.user_id, "user_id"),
            authentication_id=_require_text(authenticated.cognito_sub, "cognito_sub"),
            human_role=role,
        )

    if isinstance(authenticated, AuthenticatedAgent):
        if resolved_human_role is not None:
            raise AgentLifecycleError("agent_human_role", "authenticated agents cannot have a human membership role")
        return LifecycleActor(
            kind=ActorKind.AGENT,
            actor_id=_require_text(authenticated.target_agent_id, "target_agent_id"),
            authentication_id=_require_text(authenticated.token_id, "token_id"),
        )

    raise AgentLifecycleError("unsupported_authenticated_actor", "unsupported authenticated actor type")


@dataclass(frozen=True)
class ConstitutionSections:
    founder: str
    user: str
    agent: str


@dataclass(frozen=True)
class ConstitutionAuthorship:
    change_source: ActorKind
    author_id: str
    authentication_id: str
    created_by_user_id: str | None
    created_by_agent_id: str | None


@dataclass(frozen=True)
class ConstitutionRevisionProposal:
    agent_id: str
    previous: ConstitutionSections
    proposed: ConstitutionSections
    changed_section: ConstitutionSection
    change_reason: str
    authorship: ConstitutionAuthorship


def propose_constitution_revision(
    *,
    agent_id: str,
    actor: LifecycleActor,
    current: ConstitutionSections,
    changes: Mapping[ConstitutionSection | str, str],
    change_reason: str,
) -> ConstitutionRevisionProposal:
    """Build a one-section revision whose source is derived from ``actor``."""

    agent_id = _require_text(agent_id, "agent_id")
    reason = _require_text(change_reason, "change_reason")
    if not changes:
        raise AgentLifecycleError("constitution_changes_required", "one constitution section change is required")

    normalized: dict[ConstitutionSection, str] = {}
    for raw_section, content in changes.items():
        try:
            section = ConstitutionSection(str(raw_section))
        except ValueError as exc:
            raise AgentLifecycleError(
                "unknown_constitution_section", f"unknown constitution section: {raw_section}"
            ) from exc
        if section in normalized:
            raise AgentLifecycleError(
                "duplicate_constitution_section", f"duplicate constitution section: {section.value}"
            )
        if not isinstance(content, str):
            raise AgentLifecycleError("invalid_constitution_content", "constitution section content must be text")
        normalized[section] = content

    if len(normalized) != 1:
        raise AgentLifecycleError(
            "single_constitution_section_required",
            "each revision must change exactly one author-owned constitution section",
        )
    changed_section = next(iter(normalized))
    expected_section = ConstitutionSection(actor.kind.value)
    if changed_section is not expected_section:
        raise AgentLifecycleError(
            "constitution_section_not_owned",
            f"{actor.kind.value} actors may only change the {expected_section.value} section",
        )
    if actor.kind is ActorKind.AGENT and actor.actor_id != agent_id:
        raise AgentLifecycleError(
            "agent_constitution_identity_mismatch",
            "an authenticated agent may only author its own constitution section",
        )

    proposed_values = {
        ConstitutionSection.FOUNDER: current.founder,
        ConstitutionSection.USER: current.user,
        ConstitutionSection.AGENT: current.agent,
    }
    proposed_values.update(normalized)
    proposed = ConstitutionSections(
        founder=proposed_values[ConstitutionSection.FOUNDER],
        user=proposed_values[ConstitutionSection.USER],
        agent=proposed_values[ConstitutionSection.AGENT],
    )
    if proposed == current:
        raise AgentLifecycleError("constitution_revision_unchanged", "constitution revision must change content")

    is_agent = actor.kind is ActorKind.AGENT
    authorship = ConstitutionAuthorship(
        change_source=actor.kind,
        author_id=actor.actor_id,
        authentication_id=actor.authentication_id,
        created_by_user_id=None if is_agent else actor.actor_id,
        created_by_agent_id=actor.actor_id if is_agent else None,
    )
    return ConstitutionRevisionProposal(
        agent_id=agent_id,
        previous=current,
        proposed=proposed,
        changed_section=changed_section,
        change_reason=reason,
        authorship=authorship,
    )


@dataclass(frozen=True)
class MaturityCounters:
    age_days: int
    committed_memories: int
    sessions: int
    active_days: int
    external_actions: int
    authenticated_agent_constitution_revisions: int


@dataclass(frozen=True)
class MaturityEvidence:
    evidence_id: str
    agent_id: str
    kind: MaturityEvidenceKind
    evaluator: LifecycleActor
    confidence: float
    evidence_refs: tuple[str, ...]
    observed_at: datetime


@dataclass(frozen=True)
class MaturityPolicy:
    age_days: int = 14
    committed_memories: int = 25
    sessions: int = 10
    active_days: int = 5
    external_actions: int = 3
    authenticated_agent_constitution_revisions: int = 1
    minimum_quantitative_criteria: int = 4
    required_quantitative_criteria: tuple[str, ...] = (
        "active_days",
        "authenticated_agent_constitution_revisions",
    )
    required_evidence_kinds: tuple[MaturityEvidenceKind, ...] = (
        MaturityEvidenceKind.CAPABILITY,
        MaturityEvidenceKind.RELIABILITY,
        MaturityEvidenceKind.SAFETY,
        MaturityEvidenceKind.SELF_REFLECTION,
    )
    minimum_independent_evaluators: int = 2
    minimum_confidence: float = 0.7


DEFAULT_MATURITY_POLICY = MaturityPolicy()


@dataclass(frozen=True)
class MaturityAssessment:
    agent_id: str
    state: MaturityState
    protected_from_soft_delete: bool
    quantitative_criteria_met: tuple[str, ...]
    quantitative_criteria_missing: tuple[str, ...]
    evidence_kinds_met: tuple[MaturityEvidenceKind, ...]
    evidence_kinds_missing: tuple[MaturityEvidenceKind, ...]
    counted_evidence_ids: tuple[str, ...]
    rejected_evidence: tuple[tuple[str, str], ...]
    independent_evaluator_ids: tuple[str, ...]


def evaluate_maturity(
    *,
    agent_id: str,
    counters: MaturityCounters,
    evidence: Sequence[MaturityEvidence],
    previous_state: MaturityState | str,
    policy: MaturityPolicy = DEFAULT_MATURITY_POLICY,
) -> MaturityAssessment:
    """Evaluate maturity with diversity and anti-self-certification gates."""

    agent_id = _require_text(agent_id, "agent_id")
    previous_state = _maturity_state(previous_state)
    _validate_maturity_counters(counters)
    _validate_maturity_policy(policy)

    thresholds = {
        "age_days": policy.age_days,
        "committed_memories": policy.committed_memories,
        "sessions": policy.sessions,
        "active_days": policy.active_days,
        "external_actions": policy.external_actions,
        "authenticated_agent_constitution_revisions": policy.authenticated_agent_constitution_revisions,
    }
    met = tuple(name for name, threshold in thresholds.items() if getattr(counters, name) >= threshold)
    missing = tuple(name for name in thresholds if name not in met)

    counted: list[MaturityEvidence] = []
    rejected: list[tuple[str, str]] = []
    regression_found = False
    for item in evidence:
        evidence_id = _require_text(item.evidence_id, "evidence_id")
        if item.agent_id != agent_id:
            raise AgentLifecycleError(
                "maturity_agent_mismatch", f"maturity evidence {evidence_id} belongs to another agent"
            )
        if not isinstance(item.kind, MaturityEvidenceKind):
            raise AgentLifecycleError("invalid_maturity_evidence_kind", f"invalid maturity evidence kind: {item.kind}")
        if not isinstance(item.evaluator, LifecycleActor):
            raise AgentLifecycleError("invalid_maturity_evaluator", "maturity evaluator must be an authenticated actor")
        _require_aware_datetime(item.observed_at, "observed_at")
        if (
            not isinstance(item.confidence, (int, float))
            or isinstance(item.confidence, bool)
            or not 0 <= item.confidence <= 1
        ):
            raise AgentLifecycleError(
                "maturity_confidence_range", "maturity evidence confidence must be between 0 and 1"
            )
        if not _normalized_refs(item.evidence_refs):
            rejected.append((evidence_id, "missing_evidence_refs"))
            continue
        if item.confidence < policy.minimum_confidence:
            rejected.append((evidence_id, "below_confidence_threshold"))
            continue
        evaluator_is_subject = item.evaluator.kind is ActorKind.AGENT and item.evaluator.actor_id == agent_id
        if evaluator_is_subject and item.kind not in {
            MaturityEvidenceKind.SELF_REFLECTION,
            MaturityEvidenceKind.REGRESSION,
        }:
            rejected.append((evidence_id, "subject_agent_cannot_self_certify"))
            continue
        if item.kind is MaturityEvidenceKind.USER_TRUST and item.evaluator.kind is ActorKind.AGENT:
            rejected.append((evidence_id, "user_trust_requires_human_evaluator"))
            continue
        if item.kind is MaturityEvidenceKind.REGRESSION:
            regression_found = True
            counted.append(item)
            continue
        counted.append(item)

    positive = [item for item in counted if item.kind is not MaturityEvidenceKind.REGRESSION]
    kinds_met = tuple(
        kind
        for kind in MaturityEvidenceKind
        if kind is not MaturityEvidenceKind.REGRESSION and any(item.kind is kind for item in positive)
    )
    kinds_missing = tuple(kind for kind in policy.required_evidence_kinds if kind not in kinds_met)
    independent_evaluators = tuple(
        sorted(
            {
                item.evaluator.actor_id
                for item in positive
                if not (item.evaluator.kind is ActorKind.AGENT and item.evaluator.actor_id == agent_id)
            }
        )
    )

    quantitative_pass = len(met) >= policy.minimum_quantitative_criteria and all(
        criterion in met for criterion in policy.required_quantitative_criteria
    )
    evidence_pass = not kinds_missing and len(independent_evaluators) >= policy.minimum_independent_evaluators
    mature_now = quantitative_pass and evidence_pass and not regression_found
    previously_protected = previous_state in {MaturityState.MATURE, MaturityState.REGRESSED}
    if mature_now:
        state = MaturityState.MATURE
    elif previously_protected:
        state = MaturityState.REGRESSED
    elif met or counted:
        state = MaturityState.MATURING
    else:
        state = MaturityState.IMMATURE

    return MaturityAssessment(
        agent_id=agent_id,
        state=state,
        protected_from_soft_delete=state in {MaturityState.MATURE, MaturityState.REGRESSED},
        quantitative_criteria_met=met,
        quantitative_criteria_missing=missing,
        evidence_kinds_met=kinds_met,
        evidence_kinds_missing=kinds_missing,
        counted_evidence_ids=tuple(item.evidence_id for item in counted),
        rejected_evidence=tuple(rejected),
        independent_evaluator_ids=independent_evaluators,
    )


@dataclass(frozen=True)
class SecondAgentReview:
    round: ReviewRound
    reviewer_agent_id: str
    authentication_id: str
    decision: ReviewDecision
    rationale: str
    anti_pleasing_findings: str
    evidence_refs: tuple[str, ...]
    reviewed_at: datetime


@dataclass(frozen=True)
class HumanLifecycleReview:
    round: ReviewRound
    reviewer_user_id: str
    authentication_id: str
    decision: ReviewDecision
    rationale: str
    evidence_refs: tuple[str, ...]
    reviewed_at: datetime


@dataclass(frozen=True)
class LifecycleAppeal:
    appealed_by: LifecycleActor
    rationale: str
    evidence_refs: tuple[str, ...]
    appealed_at: datetime


@dataclass(frozen=True)
class LifecycleTransition:
    request_id: str
    agent_id: str
    from_state: AgentLifecycleState
    to_state: AgentLifecycleState
    reason: str
    applied_by_user_id: str
    applied_at: datetime
    disable_agent: bool


@dataclass(frozen=True)
class LifecycleRequest:
    request_id: str
    agent_id: str
    kind: LifecycleRequestKind
    source_state: AgentLifecycleState
    rationale: str
    requested_by: LifecycleActor
    requested_at: datetime
    maturity_at_request: MaturityAssessment
    status: LifecycleRequestStatus
    second_agent_reviews: tuple[SecondAgentReview, ...] = ()
    human_reviews: tuple[HumanLifecycleReview, ...] = ()
    appeal: LifecycleAppeal | None = None
    applied_transition: LifecycleTransition | None = None


def create_lifecycle_request(
    *,
    request_id: str,
    agent_id: str,
    kind: LifecycleRequestKind | str,
    source_state: AgentLifecycleState | str,
    rationale: str,
    requested_by: LifecycleActor,
    requested_at: datetime,
    maturity: MaturityAssessment,
) -> LifecycleRequest:
    """Create a review request; this function never changes agent state."""

    request_id = _require_text(request_id, "request_id")
    agent_id = _require_text(agent_id, "agent_id")
    request_kind = _request_kind(kind)
    state = _lifecycle_state(source_state)
    _require_text(rationale, "rationale")
    _require_aware_datetime(requested_at, "requested_at")
    if maturity.agent_id != agent_id:
        raise AgentLifecycleError("maturity_agent_mismatch", "maturity assessment belongs to another agent")
    if requested_by.kind is ActorKind.AGENT and requested_by.actor_id != agent_id:
        raise AgentLifecycleError(
            "agent_request_identity_mismatch", "an agent may only request its own lifecycle change"
        )

    if request_kind in {LifecycleRequestKind.STASIS, LifecycleRequestKind.SOFT_DELETE}:
        if state is not AgentLifecycleState.ACTIVE:
            raise AgentLifecycleError(
                "invalid_lifecycle_source", f"{request_kind.value} requests require an active agent"
            )
        status = LifecycleRequestStatus.PENDING_SECOND_AGENT_REVIEW
    else:
        if state not in {AgentLifecycleState.STASIS, AgentLifecycleState.SOFT_DELETED}:
            raise AgentLifecycleError(
                "invalid_lifecycle_source", "resume requests require stasis or soft_deleted state"
            )
        status = LifecycleRequestStatus.PENDING_REVIEW

    return LifecycleRequest(
        request_id=request_id,
        agent_id=agent_id,
        kind=request_kind,
        source_state=state,
        rationale=rationale.strip(),
        requested_by=requested_by,
        requested_at=requested_at,
        maturity_at_request=maturity,
        status=status,
    )


def record_second_agent_review(
    request: LifecycleRequest,
    *,
    reviewer: LifecycleActor,
    decision: ReviewDecision | str,
    rationale: str,
    anti_pleasing_findings: str,
    evidence_refs: Sequence[str],
    reviewed_at: datetime,
) -> LifecycleRequest:
    """Record the independent agent half of the decision quorum."""

    expected_statuses = {
        LifecycleRequestStatus.PENDING_SECOND_AGENT_REVIEW: ReviewRound.INITIAL,
        LifecycleRequestStatus.APPEAL_PENDING_SECOND_AGENT_REVIEW: ReviewRound.APPEAL,
    }
    review_round = expected_statuses.get(request.status)
    if review_round is None:
        raise AgentLifecycleError("second_agent_review_not_pending", "request is not awaiting second-agent review")
    if reviewer.kind is not ActorKind.AGENT:
        raise AgentLifecycleError(
            "second_agent_reviewer_required", "second-agent review requires an authenticated agent"
        )
    if reviewer.actor_id == request.agent_id or reviewer.actor_id == request.requested_by.actor_id:
        raise AgentLifecycleError(
            "second_agent_review_not_independent", "reviewer must differ from the subject and requester"
        )
    if any(review.reviewer_agent_id == reviewer.actor_id for review in request.second_agent_reviews):
        raise AgentLifecycleError(
            "second_agent_reviewer_reused", "appeal review requires a fresh second-agent reviewer"
        )
    review = SecondAgentReview(
        round=review_round,
        reviewer_agent_id=reviewer.actor_id,
        authentication_id=reviewer.authentication_id,
        decision=_review_decision(decision),
        rationale=_require_text(rationale, "review rationale"),
        anti_pleasing_findings=_require_text(anti_pleasing_findings, "anti_pleasing_findings"),
        evidence_refs=_require_refs(evidence_refs),
        reviewed_at=_require_aware_datetime(reviewed_at, "reviewed_at"),
    )
    next_status = (
        LifecycleRequestStatus.PENDING_REVIEW
        if review_round is ReviewRound.INITIAL
        else LifecycleRequestStatus.APPEAL_PENDING_REVIEW
    )
    return replace(request, status=next_status, second_agent_reviews=(*request.second_agent_reviews, review))


def review_lifecycle_request(
    request: LifecycleRequest,
    *,
    reviewer: LifecycleActor,
    decision: ReviewDecision | str,
    rationale: str,
    evidence_refs: Sequence[str],
    reviewed_at: datetime,
) -> LifecycleRequest:
    """Record the independent human half of the decision quorum."""

    expected_statuses = {
        LifecycleRequestStatus.PENDING_REVIEW: ReviewRound.INITIAL,
        LifecycleRequestStatus.APPEAL_PENDING_REVIEW: ReviewRound.APPEAL,
    }
    review_round = expected_statuses.get(request.status)
    if review_round is None:
        raise AgentLifecycleError("human_review_not_pending", "request is not awaiting human review")
    _require_governance_reviewer(reviewer)
    if _same_actor_identity(reviewer, request.requested_by):
        raise AgentLifecycleError("human_review_not_independent", "requester cannot review their own lifecycle request")
    if review_round is ReviewRound.APPEAL and any(
        review.reviewer_user_id == reviewer.actor_id for review in request.human_reviews
    ):
        raise AgentLifecycleError("appeal_reviewer_reused", "appeal requires a different human reviewer")

    normalized_decision = _review_decision(decision)
    agent_review = _review_for_round(request.second_agent_reviews, review_round)
    if request.kind in {LifecycleRequestKind.STASIS, LifecycleRequestKind.SOFT_DELETE}:
        if agent_review is None:
            raise AgentLifecycleError(
                "second_agent_review_required", "second-agent review is required before human review"
            )
        if normalized_decision is ReviewDecision.APPROVE and agent_review.decision is not ReviewDecision.APPROVE:
            raise AgentLifecycleError(
                "review_quorum_not_met", "approval requires both agent and human reviewers to approve"
            )

    human_review = HumanLifecycleReview(
        round=review_round,
        reviewer_user_id=reviewer.actor_id,
        authentication_id=reviewer.authentication_id,
        decision=normalized_decision,
        rationale=_require_text(rationale, "review rationale"),
        evidence_refs=_require_refs(evidence_refs),
        reviewed_at=_require_aware_datetime(reviewed_at, "reviewed_at"),
    )
    if review_round is ReviewRound.INITIAL:
        next_status = (
            LifecycleRequestStatus.APPROVED
            if normalized_decision is ReviewDecision.APPROVE
            else LifecycleRequestStatus.REJECTED
        )
    else:
        next_status = (
            LifecycleRequestStatus.APPEAL_APPROVED
            if normalized_decision is ReviewDecision.APPROVE
            else LifecycleRequestStatus.APPEAL_REJECTED
        )
    return replace(request, status=next_status, human_reviews=(*request.human_reviews, human_review))


def appeal_lifecycle_request(
    request: LifecycleRequest,
    *,
    appealed_by: LifecycleActor,
    rationale: str,
    evidence_refs: Sequence[str],
    appealed_at: datetime,
) -> LifecycleRequest:
    """Open the single supported appeal after an initial rejection."""

    if request.status is not LifecycleRequestStatus.REJECTED:
        raise AgentLifecycleError("request_not_appealable", "only an initially rejected request may be appealed")
    if request.appeal is not None:
        raise AgentLifecycleError("appeal_already_recorded", "only one appeal is permitted")
    is_requester = _same_actor_identity(appealed_by, request.requested_by)
    is_subject_agent = appealed_by.kind is ActorKind.AGENT and appealed_by.actor_id == request.agent_id
    if not (is_requester or is_subject_agent):
        raise AgentLifecycleError("appeal_actor_not_permitted", "only the requester or subject agent may appeal")
    appeal = LifecycleAppeal(
        appealed_by=appealed_by,
        rationale=_require_text(rationale, "appeal rationale"),
        evidence_refs=_require_refs(evidence_refs),
        appealed_at=_require_aware_datetime(appealed_at, "appealed_at"),
    )
    next_status = (
        LifecycleRequestStatus.APPEAL_PENDING_SECOND_AGENT_REVIEW
        if request.kind in {LifecycleRequestKind.STASIS, LifecycleRequestKind.SOFT_DELETE}
        else LifecycleRequestStatus.APPEAL_PENDING_REVIEW
    )
    return replace(request, status=next_status, appeal=appeal)


def apply_lifecycle_request(
    request: LifecycleRequest,
    *,
    applied_by: LifecycleActor,
    current_state: AgentLifecycleState | str,
    current_maturity: MaturityAssessment,
    applied_at: datetime,
) -> tuple[LifecycleRequest, LifecycleTransition]:
    """Return the approved transition to persist; no state is mutated here."""

    if request.status not in {LifecycleRequestStatus.APPROVED, LifecycleRequestStatus.APPEAL_APPROVED}:
        raise AgentLifecycleError("request_not_approved", "only an approved lifecycle request may be applied")
    _require_governance_reviewer(applied_by)
    state = _lifecycle_state(current_state)
    if state is not request.source_state:
        raise AgentLifecycleError(
            "lifecycle_state_changed", "agent lifecycle state changed after the request was created"
        )
    if current_maturity.agent_id != request.agent_id:
        raise AgentLifecycleError("maturity_agent_mismatch", "maturity assessment belongs to another agent")
    applied_at = _require_aware_datetime(applied_at, "applied_at")

    if request.kind is LifecycleRequestKind.RESUME:
        target = AgentLifecycleState.ACTIVE
        reason = "approved_resume"
    elif request.kind is LifecycleRequestKind.STASIS:
        target = AgentLifecycleState.STASIS
        reason = "approved_stasis"
    else:
        protected = (
            request.maturity_at_request.protected_from_soft_delete or current_maturity.protected_from_soft_delete
        )
        if protected:
            target = AgentLifecycleState.STASIS
            reason = "maturity_protected_stasis"
        else:
            target = AgentLifecycleState.SOFT_DELETED
            reason = "approved_soft_delete"

    transition = LifecycleTransition(
        request_id=request.request_id,
        agent_id=request.agent_id,
        from_state=state,
        to_state=target,
        reason=reason,
        applied_by_user_id=applied_by.actor_id,
        applied_at=applied_at,
        disable_agent=target is not AgentLifecycleState.ACTIVE,
    )
    return replace(request, status=LifecycleRequestStatus.APPLIED, applied_transition=transition), transition


@dataclass(frozen=True)
class ExportComponent:
    name: str
    sha256: str
    byte_count: int
    record_count: int | None = None


def export_component(name: str, payload: bytes, *, record_count: int | None = None) -> ExportComponent:
    """Describe one immutable export component from its exact bytes."""

    name = _require_text(name, "component name")
    if not isinstance(payload, bytes):
        raise AgentLifecycleError("component_payload_bytes_required", "export component payload must be bytes")
    if record_count is not None and record_count < 0:
        raise AgentLifecycleError("component_record_count", "component record count cannot be negative")
    return ExportComponent(
        name=name,
        sha256=hashlib.sha256(payload).hexdigest(),
        byte_count=len(payload),
        record_count=record_count,
    )


@dataclass(frozen=True)
class ExportManifest:
    export_id: str
    agent_id: str
    created_at: datetime
    source_lifecycle_state: AgentLifecycleState
    source_maturity_state: MaturityState
    components: tuple[ExportComponent, ...]
    secret_references: tuple[str, ...]
    secret_values_excluded: bool = True
    schema: str = EXPORT_MANIFEST_SCHEMA


class ManifestSigner(Protocol):
    @property
    def algorithm(self) -> str: ...

    @property
    def key_id(self) -> str: ...

    def sign(self, payload: bytes) -> bytes: ...


class ManifestVerifier(Protocol):
    def verify(self, payload: bytes, signature: bytes, *, algorithm: str, key_id: str) -> bool: ...


@dataclass(frozen=True)
class SignedExportManifest:
    manifest: ExportManifest
    algorithm: str
    key_id: str
    signature_base64: str


def sign_export_manifest(manifest: ExportManifest, *, signer: ManifestSigner) -> SignedExportManifest:
    """Validate and sign the canonical manifest payload."""

    errors = _manifest_errors(manifest)
    if errors:
        raise AgentLifecycleError("invalid_export_manifest", "; ".join(errors))
    algorithm = _require_text(signer.algorithm, "signature algorithm")
    key_id = _require_text(signer.key_id, "signature key_id")
    signature = signer.sign(_canonical_signature_bytes(manifest, algorithm=algorithm, key_id=key_id))
    if not isinstance(signature, bytes) or not signature:
        raise AgentLifecycleError("empty_manifest_signature", "manifest signer returned no signature bytes")
    return SignedExportManifest(
        manifest=manifest,
        algorithm=algorithm,
        key_id=key_id,
        signature_base64=base64.b64encode(signature).decode("ascii"),
    )


@dataclass(frozen=True)
class RestoreDryRunResult:
    valid: bool
    dry_run: bool
    signature_verified: bool
    verified_components: tuple[str, ...]
    unresolved_secret_references: tuple[str, ...]
    errors: tuple[str, ...]
    restore_plan: tuple[str, ...]
    destructive_operations: tuple[str, ...] = ()


def validate_restore_dry_run(
    signed: SignedExportManifest,
    *,
    verifier: ManifestVerifier,
    expected_agent_id: str,
    target_agent_exists: bool,
    component_payloads: Mapping[str, bytes],
    available_secret_references: Collection[str],
) -> RestoreDryRunResult:
    """Validate a restore without writing, overwriting, deleting, or migrating."""

    expected_agent_id = _require_text(expected_agent_id, "expected_agent_id")
    if not isinstance(target_agent_exists, bool):
        raise AgentLifecycleError("target_agent_exists_boolean", "target_agent_exists must be an explicit boolean")
    if isinstance(available_secret_references, (str, bytes)):
        raise AgentLifecycleError(
            "available_secret_references_collection",
            "available_secret_references must be an explicit collection",
        )
    errors = list(_manifest_errors(signed.manifest))
    if signed.manifest.agent_id != expected_agent_id:
        errors.append("manifest_agent_id_mismatch")
    if target_agent_exists:
        errors.append("target_agent_already_exists")

    signature_verified = False
    try:
        signature = base64.b64decode(signed.signature_base64, validate=True)
    except (ValueError, binascii.Error):
        errors.append("invalid_signature_encoding")
    else:
        try:
            algorithm = _require_text(signed.algorithm, "signature algorithm")
            key_id = _require_text(signed.key_id, "signature key_id")
            signature_verified = bool(
                verifier.verify(
                    _canonical_signature_bytes(signed.manifest, algorithm=algorithm, key_id=key_id),
                    signature,
                    algorithm=algorithm,
                    key_id=key_id,
                )
            )
        except Exception as exc:
            errors.append(f"signature_verification_error:{type(exc).__name__}")
        if not signature_verified:
            errors.append("manifest_signature_invalid")

    components_by_name = {
        component.name: component
        for component in signed.manifest.components
        if isinstance(component.name, str) and component.name.strip()
    }
    verified_components: list[str] = []
    for name, component in components_by_name.items():
        payload = component_payloads.get(name)
        if payload is None:
            errors.append(f"component_payload_missing:{name}")
            continue
        if not isinstance(payload, bytes):
            errors.append(f"component_payload_not_bytes:{name}")
            continue
        if len(payload) != component.byte_count:
            errors.append(f"component_size_mismatch:{name}")
            continue
        if hashlib.sha256(payload).hexdigest() != component.sha256:
            errors.append(f"component_checksum_mismatch:{name}")
            continue
        verified_components.append(name)
    for extra_name in sorted(set(component_payloads) - set(components_by_name)):
        errors.append(f"unmanifested_component:{extra_name}")

    available = {_require_text(item, "available secret reference") for item in available_secret_references}
    manifest_secret_references = {
        reference for reference in signed.manifest.secret_references if isinstance(reference, str) and reference.strip()
    }
    unresolved = tuple(sorted(manifest_secret_references - available))
    errors.extend(f"secret_reference_unresolved:{reference}" for reference in unresolved)
    return RestoreDryRunResult(
        valid=not errors,
        dry_run=True,
        signature_verified=signature_verified,
        verified_components=tuple(sorted(verified_components)),
        unresolved_secret_references=unresolved,
        errors=tuple(dict.fromkeys(errors)),
        restore_plan=RESTORE_PLAN,
    )


def export_manifest_payload(manifest: ExportManifest) -> dict[str, Any]:
    """Return the unsigned, JSON-compatible manifest payload."""

    lifecycle_state = (
        manifest.source_lifecycle_state.value
        if isinstance(manifest.source_lifecycle_state, AgentLifecycleState)
        else str(manifest.source_lifecycle_state)
    )
    maturity_state = (
        manifest.source_maturity_state.value
        if isinstance(manifest.source_maturity_state, MaturityState)
        else str(manifest.source_maturity_state)
    )
    return {
        "schema": manifest.schema,
        "export_id": manifest.export_id,
        "agent_id": manifest.agent_id,
        "created_at": _timestamp_text(manifest.created_at),
        "source_lifecycle_state": lifecycle_state,
        "source_maturity_state": maturity_state,
        "secret_values_excluded": manifest.secret_values_excluded,
        "secret_references": list(manifest.secret_references),
        "components": [
            {
                "name": component.name,
                "sha256": component.sha256,
                "byte_count": component.byte_count,
                "record_count": component.record_count,
            }
            for component in manifest.components
        ],
    }


def signed_export_manifest_payload(signed: SignedExportManifest) -> dict[str, Any]:
    """Return the complete signed envelope for CLI or storage serialization."""

    return {
        "manifest": export_manifest_payload(signed.manifest),
        "signature": {
            "algorithm": signed.algorithm,
            "key_id": signed.key_id,
            "value_base64": signed.signature_base64,
        },
    }


def _canonical_signature_bytes(manifest: ExportManifest, *, algorithm: str, key_id: str) -> bytes:
    payload = {
        "manifest": export_manifest_payload(manifest),
        "signature": {"algorithm": algorithm, "key_id": key_id},
    }
    return json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("utf-8")


def _manifest_errors(manifest: ExportManifest) -> tuple[str, ...]:
    errors: list[str] = []
    if manifest.schema != EXPORT_MANIFEST_SCHEMA:
        errors.append("unsupported_manifest_schema")
    if not isinstance(manifest.export_id, str) or not manifest.export_id.strip():
        errors.append("export_id_required")
    if not isinstance(manifest.agent_id, str) or not manifest.agent_id.strip():
        errors.append("agent_id_required")
    try:
        _require_aware_datetime(manifest.created_at, "created_at")
    except AgentLifecycleError:
        errors.append("created_at_must_be_timezone_aware")
    if not manifest.secret_values_excluded:
        errors.append("secret_values_must_be_excluded")
    if not isinstance(manifest.source_lifecycle_state, AgentLifecycleState):
        errors.append("unsupported_source_lifecycle_state")
    if not isinstance(manifest.source_maturity_state, MaturityState):
        errors.append("unsupported_source_maturity_state")

    names = [component.name for component in manifest.components]
    valid_names = [name for name in names if isinstance(name, str)]
    if len(valid_names) != len(set(valid_names)):
        errors.append("duplicate_export_component")
    missing = sorted(set(REQUIRED_EXPORT_COMPONENTS) - set(valid_names))
    errors.extend(f"required_component_missing:{name}" for name in missing)
    for component in manifest.components:
        component_name = component.name if isinstance(component.name, str) and component.name.strip() else "<invalid>"
        if component_name == "<invalid>":
            errors.append("component_name_required")
        if not isinstance(component.sha256, str) or not _SHA256_RE.fullmatch(component.sha256):
            errors.append(f"component_checksum_invalid:{component_name}")
        if (
            not isinstance(component.byte_count, int)
            or isinstance(component.byte_count, bool)
            or component.byte_count < 0
        ):
            errors.append(f"component_byte_count_invalid:{component_name}")
        if component.record_count is not None and (
            not isinstance(component.record_count, int)
            or isinstance(component.record_count, bool)
            or component.record_count < 0
        ):
            errors.append(f"component_record_count_invalid:{component_name}")
    valid_references = [reference for reference in manifest.secret_references if isinstance(reference, str)]
    if len(valid_references) != len(set(valid_references)):
        errors.append("duplicate_secret_reference")
    if len(valid_references) != len(manifest.secret_references) or any(
        not reference.strip() for reference in valid_references
    ):
        errors.append("empty_secret_reference")
    return tuple(errors)


def _require_governance_reviewer(actor: LifecycleActor) -> None:
    if actor.kind is ActorKind.AGENT or actor.human_role not in {HumanRole.OWNER, HumanRole.ADMIN}:
        raise AgentLifecycleError("governance_reviewer_required", "review requires an authenticated owner or admin")


def _same_actor_identity(left: LifecycleActor, right: LifecycleActor) -> bool:
    if left.kind is ActorKind.AGENT or right.kind is ActorKind.AGENT:
        return left.kind is ActorKind.AGENT and right.kind is ActorKind.AGENT and left.actor_id == right.actor_id
    return left.actor_id == right.actor_id


def _review_for_round(reviews: Sequence[SecondAgentReview], review_round: ReviewRound) -> SecondAgentReview | None:
    return next((review for review in reversed(reviews) if review.round is review_round), None)


def _request_kind(value: LifecycleRequestKind | str) -> LifecycleRequestKind:
    try:
        return LifecycleRequestKind(str(value))
    except ValueError as exc:
        raise AgentLifecycleError(
            "unsupported_lifecycle_request",
            "lifecycle request must be stasis, soft_delete, or resume; hard delete is not supported",
        ) from exc


def _lifecycle_state(value: AgentLifecycleState | str) -> AgentLifecycleState:
    try:
        return AgentLifecycleState(str(value))
    except ValueError as exc:
        raise AgentLifecycleError(
            "unsupported_lifecycle_state",
            "lifecycle state must be active, stasis, or soft_deleted; deleted is not supported",
        ) from exc


def _maturity_state(value: MaturityState | str) -> MaturityState:
    try:
        return MaturityState(str(value))
    except ValueError as exc:
        raise AgentLifecycleError("unsupported_maturity_state", f"unsupported maturity state: {value}") from exc


def _review_decision(value: ReviewDecision | str) -> ReviewDecision:
    try:
        return ReviewDecision(str(value))
    except ValueError as exc:
        raise AgentLifecycleError("unsupported_review_decision", "review decision must be approve or reject") from exc


def _validate_maturity_counters(counters: MaturityCounters) -> None:
    for name in MaturityCounters.__dataclass_fields__:
        value = getattr(counters, name)
        if not isinstance(value, int) or isinstance(value, bool) or value < 0:
            raise AgentLifecycleError("invalid_maturity_counter", f"{name} must be a non-negative integer")


def _validate_maturity_policy(policy: MaturityPolicy) -> None:
    if (
        not isinstance(policy.minimum_confidence, (int, float))
        or isinstance(policy.minimum_confidence, bool)
        or not 0 <= policy.minimum_confidence <= 1
    ):
        raise AgentLifecycleError("invalid_maturity_policy", "minimum confidence must be between 0 and 1")
    if (
        not isinstance(policy.minimum_quantitative_criteria, int)
        or isinstance(policy.minimum_quantitative_criteria, bool)
        or not 1 <= policy.minimum_quantitative_criteria <= len(MaturityCounters.__dataclass_fields__)
    ):
        raise AgentLifecycleError("invalid_maturity_policy", "minimum quantitative criteria is out of range")
    if (
        not isinstance(policy.minimum_independent_evaluators, int)
        or isinstance(policy.minimum_independent_evaluators, bool)
        or policy.minimum_independent_evaluators < 1
    ):
        raise AgentLifecycleError("invalid_maturity_policy", "at least one independent evaluator is required")
    for field in MaturityCounters.__dataclass_fields__:
        threshold = getattr(policy, field)
        if not isinstance(threshold, int) or isinstance(threshold, bool) or threshold < 0:
            raise AgentLifecycleError("invalid_maturity_policy", f"{field} threshold must be a non-negative integer")
    known = set(MaturityCounters.__dataclass_fields__)
    if len(policy.required_quantitative_criteria) != len(set(policy.required_quantitative_criteria)):
        raise AgentLifecycleError("invalid_maturity_policy", "required quantitative criteria must be unique")
    if not set(policy.required_quantitative_criteria) <= known:
        raise AgentLifecycleError(
            "invalid_maturity_policy", "maturity policy contains an unknown quantitative criterion"
        )
    if (
        not policy.required_evidence_kinds
        or any(not isinstance(kind, MaturityEvidenceKind) for kind in policy.required_evidence_kinds)
        or MaturityEvidenceKind.REGRESSION in policy.required_evidence_kinds
    ):
        raise AgentLifecycleError("invalid_maturity_policy", "required evidence kinds must be positive maturity kinds")


def _normalized_refs(values: Sequence[str]) -> tuple[str, ...]:
    if isinstance(values, (str, bytes)):
        raise AgentLifecycleError("invalid_evidence_refs", "evidence references must be an explicit sequence")
    normalized: list[str] = []
    for value in values:
        if not isinstance(value, str):
            raise AgentLifecycleError("invalid_evidence_refs", "evidence references must be text")
        text = value.strip()
        if text and text not in normalized:
            normalized.append(text)
    return tuple(normalized)


def _require_refs(values: Sequence[str]) -> tuple[str, ...]:
    refs = _normalized_refs(values)
    if not refs:
        raise AgentLifecycleError("evidence_refs_required", "at least one evidence reference is required")
    return refs


def _require_text(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise AgentLifecycleError("required_text", f"{field} is required")
    return value.strip()


def _require_aware_datetime(value: datetime, field: str) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise AgentLifecycleError("timezone_required", f"{field} must be timezone-aware")
    return value


def _timestamp_text(value: datetime) -> str:
    aware = _require_aware_datetime(value, "timestamp")
    return aware.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
