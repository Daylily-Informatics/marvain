"""Decide Daylily workflow outcomes from explicit evidence on one Linear issue."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum


def _require_text(value: str, field: str) -> None:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field} is required")


def _require_time(value: datetime, field: str) -> None:
    if not isinstance(value, datetime) or value.utcoffset() is None:
        raise ValueError(f"{field} must include a timezone")


@dataclass(frozen=True)
class LinearIssueKey:
    workspace_id: str
    issue_id: str

    def __post_init__(self) -> None:
        _require_text(self.workspace_id, "workspace_id")
        _require_text(self.issue_id, "issue_id")


class ExecutionState(StrEnum):
    TRIAGE = "triage"
    BACKLOG = "backlog"
    TODO = "todo"
    ACTIVE = "active"
    WAITING = "waiting"
    BLOCKED = "blocked"
    IN_REVIEW = "in_review"
    DONE = "done"
    ABANDONED = "abandoned"
    DUPLICATE = "duplicate"


class AttentionReason(StrEnum):
    NEEDS_DECISION = "needs_decision"
    NEEDS_APPROVAL = "needs_approval"
    REVIEW_RESULT = "review_result"
    NEEDS_RECONCILIATION = "needs_reconciliation"


@dataclass(frozen=True)
class Attention:
    reason: AttentionReason
    owner_id: str

    def __post_init__(self) -> None:
        _require_text(self.owner_id, "attention owner")


@dataclass(frozen=True)
class NextMove:
    action: str
    owner_id: str

    def __post_init__(self) -> None:
        _require_text(self.action, "next action")
        _require_text(self.owner_id, "next action owner")


class DeliveryState(StrEnum):
    UNKNOWN = "unknown"
    PENDING = "pending"
    DELIVERED = "delivered"


@dataclass(frozen=True)
class DeliveryReceipt:
    receipt_id: str
    delivered_at: datetime
    destination: str
    recipient_id: str
    result_url: str

    def __post_init__(self) -> None:
        _require_time(self.delivered_at, "delivered_at")
        for field in ("receipt_id", "destination", "recipient_id", "result_url"):
            _require_text(getattr(self, field), field)


class AcknowledgmentState(StrEnum):
    UNKNOWN = "unknown"
    ACKNOWLEDGED = "acknowledged"
    REVIEW_COMPLETED = "review_completed"
    DISMISSED = "dismissed"


@dataclass(frozen=True)
class Acknowledgment:
    state: AcknowledgmentState
    evidence_id: str
    reviewer_id: str
    occurred_at: datetime
    decision: str | None = None

    def __post_init__(self) -> None:
        if self.state not in {
            AcknowledgmentState.ACKNOWLEDGED,
            AcknowledgmentState.REVIEW_COMPLETED,
            AcknowledgmentState.DISMISSED,
        }:
            raise ValueError("An acknowledgment requires an explicit acknowledgment or review outcome")
        _require_text(self.evidence_id, "acknowledgment evidence")
        _require_text(self.reviewer_id, "reviewer_id")
        _require_time(self.occurred_at, "acknowledgment occurred_at")


@dataclass(frozen=True)
class PostReviewChange:
    """Dated scope change kept separately from the original handoff goals."""

    evidence_id: str
    decided_at: datetime
    change: str

    def __post_init__(self) -> None:
        _require_text(self.evidence_id, "review change evidence")
        _require_text(self.change, "review change")
        _require_time(self.decided_at, "decided_at")


class ReportSeriesState(StrEnum):
    ACTIVE = "active"
    PAUSED = "paused"
    RETIRED = "retired"


@dataclass(frozen=True)
class ReportSeries:
    """The ongoing provider issue. Its editions own their execution and checkpoints."""

    issue: LinearIssueKey
    state: ReportSeriesState


@dataclass(frozen=True)
class ReportEdition:
    """Stable source identity for a dated or event-driven edition of a series."""

    series_issue: LinearIssueKey
    coverage_period: str | None = None
    source_event_id: str | None = None

    def __post_init__(self) -> None:
        if (self.coverage_period is None) == (self.source_event_id is None):
            raise ValueError("An edition requires exactly one coverage period or source event")
        if self.coverage_period is not None:
            _require_text(self.coverage_period, "coverage_period")
        if self.source_event_id is not None:
            _require_text(self.source_event_id, "source_event_id")


@dataclass(frozen=True)
class WorkSnapshot:
    """A transient projection of explicit facts on one canonical Linear issue."""

    issue: LinearIssueKey
    execution: ExecutionState
    next_move: NextMove | None = None
    attention: tuple[Attention, ...] = ()
    delivery_state: DeliveryState = DeliveryState.UNKNOWN
    delivery_receipt: DeliveryReceipt | None = None
    acknowledgment: Acknowledgment | None = None
    edition: ReportEdition | None = None
    delivery_deadline: datetime | None = None
    delivery_risk: str | None = None
    post_review_changes: tuple[PostReviewChange, ...] = ()

    def __post_init__(self) -> None:
        if (self.delivery_state == DeliveryState.DELIVERED) != (self.delivery_receipt is not None):
            raise ValueError("Delivered requires an owning delivery receipt")
        if self.delivery_deadline is not None:
            _require_time(self.delivery_deadline, "delivery_deadline")
        if self.edition is not None:
            series = self.edition.series_issue
            if series == self.issue or series.workspace_id != self.issue.workspace_id:
                raise ValueError("An edition needs a distinct issue in its series workspace")

    @property
    def acknowledgment_state(self) -> AcknowledgmentState:
        if self.acknowledgment is None:
            return AcknowledgmentState.UNKNOWN
        return self.acknowledgment.state

    @property
    def is_active_work(self) -> bool:
        return self.execution in {ExecutionState.TODO, ExecutionState.ACTIVE, ExecutionState.IN_REVIEW}

    @property
    def is_result_to_review(self) -> bool:
        return any(item.reason == AttentionReason.REVIEW_RESULT for item in self.attention)


@dataclass(frozen=True)
class AgreedCheckpoint:
    issue: LinearIssueKey
    agreement_id: str
    agreed_at: datetime
    due_at: datetime
    owner_id: str
    expected_update: str

    def __post_init__(self) -> None:
        _require_time(self.agreed_at, "agreed_at")
        _require_time(self.due_at, "due_at")
        if self.due_at < self.agreed_at:
            raise ValueError("A checkpoint cannot be due before it was agreed")
        for field in ("agreement_id", "owner_id", "expected_update"):
            _require_text(getattr(self, field), field)


@dataclass(frozen=True)
class SubstantiveUpdate:
    """An owning source's material update. Routine pings, syncs and edits do not qualify."""

    issue: LinearIssueKey
    evidence_id: str
    occurred_at: datetime
    detail: str

    def __post_init__(self) -> None:
        _require_text(self.evidence_id, "substantive update evidence")
        _require_text(self.detail, "substantive update detail")
        _require_time(self.occurred_at, "substantive update occurred_at")


@dataclass(frozen=True)
class StallEpisode:
    checkpoint: AgreedCheckpoint
    detected_at: datetime

    def __post_init__(self) -> None:
        _require_time(self.detected_at, "stall detected_at")
        if self.detected_at < self.checkpoint.due_at:
            raise ValueError("A stall cannot begin before its agreed checkpoint")

    @property
    def key(self) -> tuple[LinearIssueKey, str]:
        return self.checkpoint.issue, self.checkpoint.agreement_id


class CheckpointState(StrEnum):
    NOT_APPLICABLE = "not_applicable"
    MISSING = "missing"
    PENDING = "pending"
    MISSED = "missed"


@dataclass(frozen=True)
class CheckpointAssessment:
    state: CheckpointState
    progress: SubstantiveUpdate | None
    stall: StallEpisode | None = None
    stall_started: bool = False


_STALL_ELIGIBLE = {
    ExecutionState.ACTIVE,
    ExecutionState.WAITING,
    ExecutionState.BLOCKED,
    ExecutionState.IN_REVIEW,
}


def assess_checkpoint(
    work: WorkSnapshot,
    *,
    as_of: datetime,
    checkpoint: AgreedCheckpoint | None = None,
    progress: SubstantiveUpdate | None = None,
    existing_stall: StallEpisode | None = None,
) -> CheckpointAssessment:
    """Use the current agreement, latest material update and any open stall from the owning issue.

    The owning integration records a new stall under `StallEpisode.key` and
    supplies that episode on later checks. This function performs no writes.
    """
    _require_time(as_of, "as_of")
    if checkpoint is not None and (checkpoint.issue != work.issue or checkpoint.agreed_at > as_of):
        raise ValueError("Checkpoint does not belong to this issue as of the assessment")
    if progress is not None and (progress.issue != work.issue or progress.occurred_at > as_of):
        raise ValueError("Progress does not belong to this issue as of the assessment")
    if existing_stall is not None and (
        existing_stall.checkpoint.issue != work.issue or existing_stall.detected_at > as_of
    ):
        raise ValueError("Stall does not belong to this issue as of the assessment")

    if work.execution not in _STALL_ELIGIBLE:
        return CheckpointAssessment(CheckpointState.NOT_APPLICABLE, progress)
    if checkpoint is None or (progress is not None and progress.occurred_at > checkpoint.agreed_at):
        return CheckpointAssessment(CheckpointState.MISSING, progress, existing_stall)
    if as_of < checkpoint.due_at:
        return CheckpointAssessment(CheckpointState.PENDING, progress, existing_stall)
    if existing_stall is not None:
        return CheckpointAssessment(CheckpointState.MISSED, progress, existing_stall)
    return CheckpointAssessment(CheckpointState.MISSED, progress, StallEpisode(checkpoint, as_of), stall_started=True)


class StallExit(StrEnum):
    RENEW = "renew"
    DEFER = "defer"
    DROP = "drop"


@dataclass(frozen=True)
class StallResolution:
    episode: StallEpisode
    execution: ExecutionState
    decided_at: datetime
    evidence_id: str
    reason: str
    checkpoint: AgreedCheckpoint | None


def resolve_stall(
    episode: StallEpisode,
    *,
    decision: StallExit,
    decided_at: datetime,
    evidence_id: str,
    reason: str,
    checkpoint: AgreedCheckpoint | None = None,
) -> StallResolution:
    """Apply an explicit domain decision. The owning integration chooses any native mapping."""
    _require_time(decided_at, "decided_at")
    _require_text(evidence_id, "stall resolution evidence")
    _require_text(reason, "stall resolution reason")
    if decided_at < episode.detected_at:
        raise ValueError("A stall cannot be resolved before detection")

    if decision == StallExit.RENEW:
        if checkpoint is None or (
            checkpoint.issue != episode.checkpoint.issue
            or checkpoint.agreement_id == episode.checkpoint.agreement_id
            or not episode.checkpoint.due_at <= checkpoint.agreed_at <= decided_at < checkpoint.due_at
        ):
            raise ValueError("Returning to active work requires a new agreed checkpoint on this issue")
        execution = ExecutionState.ACTIVE
    elif decision in (StallExit.DEFER, StallExit.DROP):
        if checkpoint is not None:
            raise ValueError("Deferral and abandonment do not create an active checkpoint")
        execution = ExecutionState.BACKLOG if decision == StallExit.DEFER else ExecutionState.ABANDONED
    else:
        raise ValueError("Unknown supported stall decision; use renewal, deferral or abandonment")
    return StallResolution(episode, execution, decided_at, evidence_id, reason, checkpoint)
