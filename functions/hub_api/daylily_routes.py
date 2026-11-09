"""Receive an intentional Daylily issue result from a configured reporter."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC
from typing import Annotated, Protocol
from uuid import NAMESPACE_URL, UUID, uuid5

from fastapi import APIRouter, HTTPException, Request, status
from pydantic import AwareDatetime, BaseModel, ConfigDict, StringConstraints

from agent_hub.daylily_work.handoff import (
    CommitmentIntent,
    DaylilyLinearBinding,
    DaylilyWorkBridge,
    LinearIssueOperation,
    LinearIssueReceipt,
)
from agent_hub.memory_service import MemoryAccessPolicy
from agent_hub.rds_data import RdsData
from agent_hub.semantic_outbox import SemanticOutboxError, enqueue_semantic_graph

_EVENT_TYPE = "semantic.operation.received"
_NonEmptyText = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1)]

_INSERT_RECEIPT = """
INSERT INTO events(event_id, agent_id, space_id, session_id, type, payload)
VALUES (CAST(:event_id AS uuid), CAST(:agent_id AS uuid), CAST(:space_id AS uuid),
        CAST(:session_id AS uuid), :event_type, CAST(:payload AS jsonb))
ON CONFLICT (event_id) DO UPDATE SET event_id = events.event_id
WHERE events.agent_id = EXCLUDED.agent_id
  AND events.space_id = EXCLUDED.space_id
  AND events.session_id = EXCLUDED.session_id
  AND events.type = EXCLUDED.type
  AND events.payload = EXCLUDED.payload
RETURNING event_id::text AS event_id
"""


@dataclass(frozen=True)
class AuthorizedDaylilyIntake:
    """Canonical scope and policy resolved for this request by the hub."""

    binding: DaylilyLinearBinding
    agent_id: str
    space_id: str
    session_id: str
    scene_euid: str
    reporter_principal_euid: str
    requester_principal_euid: str
    access_policy: MemoryAccessPolicy
    delegation_euid: str | None = None
    recipient_principal_euid: str | None = None


class AuthorizeDaylilyIntake(Protocol):
    def __call__(
        self, request: Request, *, initiating_evidence_euid: str, episode_euid: str
    ) -> AuthorizedDaylilyIntake:
        """Authorize the configured reporter and resolve evidence and episode lineage."""
        ...


class DaylilyCommitmentIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    initiating_evidence_euid: _NonEmptyText
    episode_euid: _NonEmptyText
    operation_id: UUID
    operation: LinearIssueOperation
    issue_id: UUID
    issue_url: _NonEmptyText
    completed_at: AwareDatetime
    original_completion_goal: _NonEmptyText
    original_delivery_goal: _NonEmptyText
    selected_issue_id: UUID | None = None


class DaylilyCommitmentAccepted(BaseModel):
    operation_id: UUID
    event_id: UUID
    semantic_sync_id: UUID
    issue_id: UUID
    issue_url: str


def build_daylily_router(
    *, get_db: Callable[[], RdsData], authorize: AuthorizeDaylilyIntake
) -> APIRouter:
    router = APIRouter()

    @router.post(
        "/v1/daylily/commitments",
        status_code=status.HTTP_202_ACCEPTED,
        response_model=DaylilyCommitmentAccepted,
    )
    def record_commitment(body: DaylilyCommitmentIn, request: Request) -> DaylilyCommitmentAccepted:
        scope = authorize(
            request,
            initiating_evidence_euid=body.initiating_evidence_euid,
            episode_euid=body.episode_euid,
        )
        completed_at = body.completed_at.astimezone(UTC)
        operation_id = str(body.operation_id)
        issue_id = str(body.issue_id)
        selected_issue_id = str(body.selected_issue_id) if body.selected_issue_id is not None else None
        try:
            intent = CommitmentIntent(
                operation_id=operation_id,
                scene_euid=scope.scene_euid,
                episode_euid=body.episode_euid,
                initiating_evidence_euid=body.initiating_evidence_euid,
                requester_principal_euid=scope.requester_principal_euid,
                reporter_principal_euid=scope.reporter_principal_euid,
                original_completion_goal=body.original_completion_goal,
                original_delivery_goal=body.original_delivery_goal,
                access_policy=scope.access_policy,
                operation=body.operation,
                selected_issue_id=selected_issue_id,
                delegation_euid=scope.delegation_euid,
                recipient_principal_euid=scope.recipient_principal_euid,
            )
            receipt = LinearIssueReceipt(
                binding=scope.binding,
                operation_id=operation_id,
                operation=body.operation,
                issue_id=issue_id,
                issue_url=body.issue_url,
                completed_at=completed_at,
            )
            graph = DaylilyWorkBridge(binding=scope.binding).commitment_graph(intent=intent, receipt=receipt)
        except PermissionError as exc:
            raise HTTPException(status_code=403, detail=str(exc)) from exc
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc

        # The generic event feed can show this opaque marker. The graph outbox
        # carries the goals and provider receipt in the same transaction.
        event_id = str(uuid5(NAMESPACE_URL, f"marvain/daylily/commitment/{scope.agent_id}/{operation_id}"))

        db = get_db()
        tx = db.begin()
        try:
            rows = db.query(
                _INSERT_RECEIPT,
                {
                    "event_id": event_id,
                    "agent_id": scope.agent_id,
                    "space_id": scope.space_id,
                    "session_id": scope.session_id,
                    "event_type": _EVENT_TYPE,
                    "payload": {"operation_id": operation_id},
                },
                transaction_id=tx,
            )
            if not rows:
                raise HTTPException(status_code=409, detail="This operation already belongs to a different scope")
            persisted_event_id = rows[0]["event_id"]
            try:
                queued = enqueue_semantic_graph(
                    db,
                    transaction_id=tx,
                    agent_id=scope.agent_id,
                    source_table="events",
                    source_id=persisted_event_id,
                    objects=graph.objects,
                    links=graph.links,
                    primary_key="handoff",
                )
            except SemanticOutboxError as exc:
                if str(exc).startswith("semantic outbox conflict:"):
                    raise HTTPException(status_code=409, detail="This operation already has different handoff data") from exc
                raise
            db.commit(tx)
        except Exception:
            db.rollback(tx)
            raise

        return DaylilyCommitmentAccepted(
            operation_id=body.operation_id,
            event_id=persisted_event_id,
            semantic_sync_id=queued.semantic_sync_id,
            issue_id=body.issue_id,
            issue_url=body.issue_url,
        )

    return router
