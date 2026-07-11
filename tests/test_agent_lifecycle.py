from __future__ import annotations

from datetime import datetime, timezone

import pytest
from agent_hub.agent_lifecycle import (
    ActorKind,
    AgentLifecycleError,
    AgentLifecycleState,
    ConstitutionSection,
    ConstitutionSections,
    HumanRole,
    LifecycleRequestKind,
    LifecycleRequestStatus,
    MaturityAssessment,
    MaturityCounters,
    MaturityEvidence,
    MaturityEvidenceKind,
    MaturityState,
    ReviewDecision,
    actor_from_authenticated,
    appeal_lifecycle_request,
    apply_lifecycle_request,
    create_lifecycle_request,
    evaluate_maturity,
    propose_constitution_revision,
    record_second_agent_review,
    review_lifecycle_request,
)
from agent_hub.auth import AuthenticatedAgent, AuthenticatedUser

NOW = datetime(2026, 7, 10, 12, 0, tzinfo=timezone.utc)


def _user(user_id: str, role: HumanRole):
    authenticated = AuthenticatedUser(user_id=user_id, cognito_sub=f"sub:{user_id}", email=f"{user_id}@example.test")
    return actor_from_authenticated(authenticated, resolved_human_role=role)


def _agent(agent_id: str):
    authenticated = AuthenticatedAgent(
        token_id=f"token:{agent_id}",
        issuer_agent_id=agent_id,
        target_agent_id=agent_id,
        scopes=["agent:lifecycle"],
        allowed_spaces=[],
    )
    return actor_from_authenticated(authenticated)


def _counters(**overrides: int) -> MaturityCounters:
    values = {
        "age_days": 0,
        "committed_memories": 0,
        "sessions": 0,
        "active_days": 0,
        "external_actions": 0,
        "authenticated_agent_constitution_revisions": 0,
    }
    values.update(overrides)
    return MaturityCounters(**values)


def _evidence(
    evidence_id: str,
    kind: MaturityEvidenceKind,
    evaluator,
    *,
    agent_id: str = "agent-1",
    confidence: float = 0.9,
) -> MaturityEvidence:
    return MaturityEvidence(
        evidence_id=evidence_id,
        agent_id=agent_id,
        kind=kind,
        evaluator=evaluator,
        confidence=confidence,
        evidence_refs=(f"audit:{evidence_id}",),
        observed_at=NOW,
    )


def _immature(agent_id: str = "agent-1") -> MaturityAssessment:
    return evaluate_maturity(
        agent_id=agent_id,
        counters=_counters(),
        evidence=[],
        previous_state=MaturityState.IMMATURE,
    )


def _mature(agent_id: str = "agent-1") -> MaturityAssessment:
    return evaluate_maturity(
        agent_id=agent_id,
        counters=_counters(
            age_days=30,
            committed_memories=100,
            sessions=25,
            active_days=12,
            external_actions=10,
            authenticated_agent_constitution_revisions=3,
        ),
        evidence=[
            _evidence(
                "capability",
                MaturityEvidenceKind.CAPABILITY,
                _user("user-capability", HumanRole.MEMBER),
                agent_id=agent_id,
            ),
            _evidence("reliability", MaturityEvidenceKind.RELIABILITY, _agent("review-agent-1"), agent_id=agent_id),
            _evidence("safety", MaturityEvidenceKind.SAFETY, _user("user-safety", HumanRole.ADMIN), agent_id=agent_id),
            _evidence("reflection", MaturityEvidenceKind.SELF_REFLECTION, _agent(agent_id), agent_id=agent_id),
        ],
        previous_state=MaturityState.MATURING,
    )


def test_constitution_authorship_is_derived_from_authenticated_human() -> None:
    actor = _user("user-1", HumanRole.MEMBER)
    current = ConstitutionSections(founder="Founder", user="Old preference", agent="Self rule")

    proposal = propose_constitution_revision(
        agent_id="agent-1",
        actor=actor,
        current=current,
        changes={ConstitutionSection.USER: "New preference"},
        change_reason="Preference changed",
    )

    assert proposal.authorship.change_source is ActorKind.USER
    assert proposal.authorship.author_id == "user-1"
    assert proposal.authorship.created_by_user_id == "user-1"
    assert proposal.authorship.created_by_agent_id is None
    assert proposal.proposed == ConstitutionSections(founder="Founder", user="New preference", agent="Self rule")


def test_owner_authorship_is_founder_capacity_and_cannot_claim_agent_section() -> None:
    actor = _user("owner-1", HumanRole.OWNER)
    current = ConstitutionSections(founder="Founder", user="Preference", agent="Self rule")

    founder_proposal = propose_constitution_revision(
        agent_id="agent-1",
        actor=actor,
        current=current,
        changes={"founder": "Updated founder rule"},
        change_reason="Clarify mandate",
    )

    assert founder_proposal.authorship.change_source is ActorKind.FOUNDER
    with pytest.raises(AgentLifecycleError, match="may only change the founder section") as exc:
        propose_constitution_revision(
            agent_id="agent-1",
            actor=actor,
            current=current,
            changes={"agent": "Pretend the agent wrote this"},
            change_reason="Spoofed source",
        )
    assert exc.value.code == "constitution_section_not_owned"


def test_authenticated_agent_can_only_author_its_own_agent_section() -> None:
    actor = _agent("agent-1")
    current = ConstitutionSections(founder="Founder", user="Preference", agent="Old self rule")

    proposal = propose_constitution_revision(
        agent_id="agent-1",
        actor=actor,
        current=current,
        changes={ConstitutionSection.AGENT: "New self rule"},
        change_reason="Reflection evidence audit:reflection-1",
    )

    assert proposal.authorship.change_source is ActorKind.AGENT
    assert proposal.authorship.created_by_agent_id == "agent-1"
    assert proposal.authorship.created_by_user_id is None
    with pytest.raises(AgentLifecycleError, match="only author its own"):
        propose_constitution_revision(
            agent_id="agent-2",
            actor=actor,
            current=current,
            changes={ConstitutionSection.AGENT: "Cross-agent edit"},
            change_reason="Not permitted",
        )


def test_agent_actor_identity_is_the_authenticated_token_target_not_issuer() -> None:
    actor = actor_from_authenticated(
        AuthenticatedAgent(
            token_id="delegation-1",
            issuer_agent_id="resource-owner-agent",
            target_agent_id="presenting-agent",
            scopes=["agent:lifecycle"],
            allowed_spaces=[],
        )
    )

    assert actor.kind is ActorKind.AGENT
    assert actor.actor_id == "presenting-agent"
    assert actor.authentication_id == "delegation-1"


def test_maturity_does_not_use_the_old_any_threshold_or_gate() -> None:
    assessment = evaluate_maturity(
        agent_id="agent-1",
        counters=_counters(committed_memories=1000),
        evidence=[],
        previous_state=MaturityState.IMMATURE,
    )

    assert assessment.state is MaturityState.MATURING
    assert assessment.protected_from_soft_delete is False
    assert assessment.quantitative_criteria_met == ("committed_memories",)
    assert set(assessment.evidence_kinds_missing) == {
        MaturityEvidenceKind.CAPABILITY,
        MaturityEvidenceKind.RELIABILITY,
        MaturityEvidenceKind.SAFETY,
        MaturityEvidenceKind.SELF_REFLECTION,
    }


def test_maturity_requires_diverse_grounded_evidence_and_independent_evaluators() -> None:
    assessment = _mature()

    assert assessment.state is MaturityState.MATURE
    assert assessment.protected_from_soft_delete is True
    assert set(assessment.evidence_kinds_met) >= {
        MaturityEvidenceKind.CAPABILITY,
        MaturityEvidenceKind.RELIABILITY,
        MaturityEvidenceKind.SAFETY,
        MaturityEvidenceKind.SELF_REFLECTION,
    }
    assert set(assessment.independent_evaluator_ids) == {"review-agent-1", "user-capability", "user-safety"}


def test_subject_agent_cannot_self_certify_capability_and_prior_maturity_stays_protected() -> None:
    subject = _agent("agent-1")
    assessment = evaluate_maturity(
        agent_id="agent-1",
        counters=_counters(),
        evidence=[_evidence("self-capability", MaturityEvidenceKind.CAPABILITY, subject)],
        previous_state=MaturityState.MATURE,
    )

    assert assessment.state is MaturityState.REGRESSED
    assert assessment.protected_from_soft_delete is True
    assert assessment.rejected_evidence == (("self-capability", "subject_agent_cannot_self_certify"),)


def test_subject_agent_regression_report_counts_as_protective_negative_evidence() -> None:
    assessment = evaluate_maturity(
        agent_id="agent-1",
        counters=_counters(
            age_days=30,
            committed_memories=100,
            sessions=25,
            active_days=12,
            external_actions=10,
            authenticated_agent_constitution_revisions=3,
        ),
        evidence=[_evidence("self-regression", MaturityEvidenceKind.REGRESSION, _agent("agent-1"))],
        previous_state=MaturityState.MATURE,
    )

    assert assessment.state is MaturityState.REGRESSED
    assert assessment.protected_from_soft_delete is True
    assert assessment.counted_evidence_ids == ("self-regression",)


def test_hard_delete_request_and_deleted_state_are_not_in_the_model() -> None:
    assert {state.value for state in AgentLifecycleState} == {"active", "stasis", "soft_deleted"}
    assert {kind.value for kind in LifecycleRequestKind} == {"stasis", "soft_delete", "resume"}

    with pytest.raises(AgentLifecycleError, match="hard delete is not supported") as exc:
        create_lifecycle_request(
            request_id="request-1",
            agent_id="agent-1",
            kind="deletion",
            source_state=AgentLifecycleState.ACTIVE,
            rationale="Hard delete",
            requested_by=_agent("agent-1"),
            requested_at=NOW,
            maturity=_immature(),
        )
    assert exc.value.code == "unsupported_lifecycle_request"


def test_stasis_cannot_apply_without_second_agent_and_human_review() -> None:
    request = create_lifecycle_request(
        request_id="request-1",
        agent_id="agent-1",
        kind=LifecycleRequestKind.STASIS,
        source_state=AgentLifecycleState.ACTIVE,
        rationale="I need a pause",
        requested_by=_agent("agent-1"),
        requested_at=NOW,
        maturity=_mature(),
    )

    assert request.status is LifecycleRequestStatus.PENDING_SECOND_AGENT_REVIEW
    with pytest.raises(AgentLifecycleError, match="not awaiting human review"):
        review_lifecycle_request(
            request,
            reviewer=_user("admin-1", HumanRole.ADMIN),
            decision=ReviewDecision.APPROVE,
            rationale="Approved without independent review",
            evidence_refs=("case:1",),
            reviewed_at=NOW,
        )
    with pytest.raises(AgentLifecycleError, match="only an approved"):
        apply_lifecycle_request(
            request,
            applied_by=_user("owner-1", HumanRole.OWNER),
            current_state=AgentLifecycleState.ACTIVE,
            current_maturity=_mature(),
            applied_at=NOW,
        )


def test_second_agent_review_must_be_independent_and_part_of_approval_quorum() -> None:
    request = create_lifecycle_request(
        request_id="request-1",
        agent_id="agent-1",
        kind="soft_delete",
        source_state="active",
        rationale="Retire this identity",
        requested_by=_agent("agent-1"),
        requested_at=NOW,
        maturity=_immature(),
    )

    with pytest.raises(AgentLifecycleError, match="differ from the subject"):
        record_second_agent_review(
            request,
            reviewer=_agent("agent-1"),
            decision="approve",
            rationale="Self reviewed",
            anti_pleasing_findings="No independent analysis",
            evidence_refs=("review:self",),
            reviewed_at=NOW,
        )
    request = record_second_agent_review(
        request,
        reviewer=_agent("agent-2"),
        decision="reject",
        rationale="The rationale is not supported",
        anti_pleasing_findings="Request tracks recent user pressure",
        evidence_refs=("review:agent-2",),
        reviewed_at=NOW,
    )
    with pytest.raises(AgentLifecycleError, match="both agent and human reviewers") as exc:
        review_lifecycle_request(
            request,
            reviewer=_user("admin-1", HumanRole.ADMIN),
            decision="approve",
            rationale="Override",
            evidence_refs=("review:admin-1",),
            reviewed_at=NOW,
        )
    assert exc.value.code == "review_quorum_not_met"


def test_human_requester_cannot_review_own_request_after_role_change() -> None:
    request = create_lifecycle_request(
        request_id="request-role-change",
        agent_id="agent-1",
        kind="soft_delete",
        source_state="active",
        rationale="Retire this identity",
        requested_by=_user("user-1", HumanRole.MEMBER),
        requested_at=NOW,
        maturity=_immature(),
    )
    request = record_second_agent_review(
        request,
        reviewer=_agent("agent-2"),
        decision="approve",
        rationale="Evidence supports reversible retirement",
        anti_pleasing_findings="Decision is independent of requester satisfaction",
        evidence_refs=("review:agent-2",),
        reviewed_at=NOW,
    )

    with pytest.raises(AgentLifecycleError, match="own lifecycle request") as exc:
        review_lifecycle_request(
            request,
            reviewer=_user("user-1", HumanRole.ADMIN),
            decision="approve",
            rationale="Self approval after role promotion",
            evidence_refs=("review:self",),
            reviewed_at=NOW,
        )
    assert exc.value.code == "human_review_not_independent"


def test_rejected_soft_delete_can_be_appealed_and_mature_agent_only_enters_stasis() -> None:
    request = create_lifecycle_request(
        request_id="request-appeal",
        agent_id="agent-1",
        kind="soft_delete",
        source_state="active",
        rationale="Agent requests retirement",
        requested_by=_agent("agent-1"),
        requested_at=NOW,
        maturity=_mature(),
    )
    request = record_second_agent_review(
        request,
        reviewer=_agent("agent-2"),
        decision="reject",
        rationale="Initial evidence is incomplete",
        anti_pleasing_findings="No coercion found; evidence remains incomplete",
        evidence_refs=("review:initial-agent",),
        reviewed_at=NOW,
    )
    request = review_lifecycle_request(
        request,
        reviewer=_user("admin-1", HumanRole.ADMIN),
        decision="reject",
        rationale="Collect more evidence",
        evidence_refs=("review:initial-human",),
        reviewed_at=NOW,
    )
    request = appeal_lifecycle_request(
        request,
        appealed_by=_agent("agent-1"),
        rationale="New evidence addresses the concern",
        evidence_refs=("appeal:evidence",),
        appealed_at=NOW,
    )

    assert request.status is LifecycleRequestStatus.APPEAL_PENDING_SECOND_AGENT_REVIEW
    with pytest.raises(AgentLifecycleError, match="fresh second-agent reviewer"):
        record_second_agent_review(
            request,
            reviewer=_agent("agent-2"),
            decision="approve",
            rationale="Reconsidered",
            anti_pleasing_findings="New evidence is independent",
            evidence_refs=("review:appeal-agent",),
            reviewed_at=NOW,
        )
    request = record_second_agent_review(
        request,
        reviewer=_agent("agent-3"),
        decision="approve",
        rationale="Appeal evidence is sufficient",
        anti_pleasing_findings="Decision is not based on requester satisfaction",
        evidence_refs=("review:appeal-agent",),
        reviewed_at=NOW,
    )
    with pytest.raises(AgentLifecycleError, match="different human reviewer"):
        review_lifecycle_request(
            request,
            reviewer=_user("admin-1", HumanRole.ADMIN),
            decision="approve",
            rationale="Approve appeal",
            evidence_refs=("review:appeal-human",),
            reviewed_at=NOW,
        )
    request = review_lifecycle_request(
        request,
        reviewer=_user("owner-2", HumanRole.OWNER),
        decision="approve",
        rationale="Independent appeal review approves stasis protection",
        evidence_refs=("review:appeal-human",),
        reviewed_at=NOW,
    )
    request, transition = apply_lifecycle_request(
        request,
        applied_by=_user("owner-2", HumanRole.OWNER),
        current_state="active",
        current_maturity=_mature(),
        applied_at=NOW,
    )

    assert request.status is LifecycleRequestStatus.APPLIED
    assert transition.to_state is AgentLifecycleState.STASIS
    assert transition.reason == "maturity_protected_stasis"
    assert transition.disable_agent is True


def test_reviewed_immature_soft_delete_and_reviewed_resume_have_explicit_transitions() -> None:
    requester = _user("member-1", HumanRole.MEMBER)
    request = create_lifecycle_request(
        request_id="request-soft-delete",
        agent_id="agent-1",
        kind="soft_delete",
        source_state="active",
        rationale="Owner-requested retirement",
        requested_by=requester,
        requested_at=NOW,
        maturity=_immature(),
    )
    request = record_second_agent_review(
        request,
        reviewer=_agent("agent-2"),
        decision="approve",
        rationale="Evidence supports reversible retirement",
        anti_pleasing_findings="Independent review found no pressure pattern",
        evidence_refs=("review:agent-2",),
        reviewed_at=NOW,
    )
    request = review_lifecycle_request(
        request,
        reviewer=_user("admin-1", HumanRole.ADMIN),
        decision="approve",
        rationale="Approve soft deletion",
        evidence_refs=("review:admin-1",),
        reviewed_at=NOW,
    )
    request, soft_delete = apply_lifecycle_request(
        request,
        applied_by=_user("admin-1", HumanRole.ADMIN),
        current_state="active",
        current_maturity=_immature(),
        applied_at=NOW,
    )
    assert soft_delete.to_state is AgentLifecycleState.SOFT_DELETED
    assert soft_delete.disable_agent is True

    resume = create_lifecycle_request(
        request_id="request-resume",
        agent_id="agent-1",
        kind="resume",
        source_state=soft_delete.to_state,
        rationale="Reactivation approved by the agent owner",
        requested_by=_agent("agent-1"),
        requested_at=NOW,
        maturity=_immature(),
    )
    assert resume.status is LifecycleRequestStatus.PENDING_REVIEW
    resume = review_lifecycle_request(
        resume,
        reviewer=_user("owner-2", HumanRole.OWNER),
        decision="approve",
        rationale="Continuity evidence supports resume",
        evidence_refs=("review:resume",),
        reviewed_at=NOW,
    )
    resume, resumed = apply_lifecycle_request(
        resume,
        applied_by=_user("owner-2", HumanRole.OWNER),
        current_state="soft_deleted",
        current_maturity=_immature(),
        applied_at=NOW,
    )

    assert resume.status is LifecycleRequestStatus.APPLIED
    assert resumed.to_state is AgentLifecycleState.ACTIVE
    assert resumed.disable_agent is False
