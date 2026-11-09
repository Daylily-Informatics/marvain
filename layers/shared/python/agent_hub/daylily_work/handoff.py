"""Translate an intentional request and a trusted Linear receipt into TapDB lineage."""

from __future__ import annotations

import json
import uuid
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum

from agent_hub.dot_bridge.events import HandoffReadyEvent
from agent_hub.memory_service import MemoryAccessPolicy, MemoryLayer, MemoryPurpose
from agent_hub.semantic_tapdb import TEMPLATE_CODES, GraphLinkWrite, GraphObjectRef, GraphObjectWrite

_LINEAR_REFERENCE_TEMPLATE = "reference/external_identifier/tapdb_object/1.0/"


def _require_text(field: str, value: str | None) -> None:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field} is required")


@dataclass(frozen=True)
class DaylilyLinearBinding:
    """Explicit connector, provider account, and destination selected by the server."""

    connection_id: str
    account_id: str
    workspace_id: str
    team_id: str
    project_id: str | None

    def __post_init__(self) -> None:
        for field in ("connection_id", "account_id", "workspace_id", "team_id"):
            _require_text(field, getattr(self, field))
        if self.project_id is not None:
            _require_text("project_id", self.project_id)


class LinearIssueOperation(StrEnum):
    ISSUE_CREATED = "issue_created"
    EXISTING_ISSUE_LINKED = "existing_issue_linked"


@dataclass(frozen=True)
class LinearIssueReceipt:
    """Normalize only the trusted connector's successful issue result for this operation.

    For an existing issue, the connector resolves the explicitly selected issue and
    supplies its identity. This operation does not imply a Linear mutation.
    """

    binding: DaylilyLinearBinding
    operation_id: str
    operation: LinearIssueOperation
    issue_id: str
    issue_url: str
    completed_at: datetime

    def __post_init__(self) -> None:
        for field in ("operation_id", "issue_id", "issue_url"):
            _require_text(field, getattr(self, field))
        if self.operation not in (LinearIssueOperation.ISSUE_CREATED, LinearIssueOperation.EXISTING_ISSUE_LINKED):
            raise ValueError("A commitment requires a successful issue create or explicit issue link receipt")
        if not isinstance(self.completed_at, datetime) or self.completed_at.utcoffset() is None:
            raise ValueError("Linear receipt completion time must include a timezone")


@dataclass(frozen=True)
class CommitmentIntent:
    """Authorized request resolved by the caller from persisted scope and identity.

    An observation or a comment is insufficient. The request must explicitly
    authorize this operation, including the chosen destination and permitted text.
    """

    operation_id: str
    scene_euid: str
    episode_euid: str
    request_euid: str
    requester_principal_euid: str
    original_completion_goal: str
    original_delivery_goal: str
    access_policy: MemoryAccessPolicy
    operation: LinearIssueOperation
    selected_issue_id: str | None = None
    delegation_euid: str | None = None
    recipient_principal_euid: str | None = None

    def __post_init__(self) -> None:
        for field in (
            "operation_id",
            "scene_euid",
            "episode_euid",
            "request_euid",
            "requester_principal_euid",
            "original_completion_goal",
            "original_delivery_goal",
        ):
            _require_text(field, getattr(self, field))
        for field in ("delegation_euid", "recipient_principal_euid"):
            value = getattr(self, field)
            if value is not None:
                _require_text(field, value)
        if self.operation == LinearIssueOperation.EXISTING_ISSUE_LINKED:
            _require_text("selected_issue_id", self.selected_issue_id)
        elif self.operation != LinearIssueOperation.ISSUE_CREATED or self.selected_issue_id is not None:
            raise ValueError("A new issue commitment requires an explicit create operation without an existing issue")


@dataclass(frozen=True)
class CommitmentGraph:
    """Graph data for the owning writer, anchored to the same durable operation on retry."""

    objects: tuple[GraphObjectWrite, ...]
    links: tuple[GraphLinkWrite, ...]
    operation_id: str
    scene_euid: str
    recipient_principal_euid: str | None
    event_id: str

    def ready_event(self, *, handoff_euid: str, committed_at: datetime) -> HandoffReadyEvent | None:
        """Build the pointer after the owning writer returns its persisted handoff EUID."""
        if self.recipient_principal_euid is None:
            return None
        return HandoffReadyEvent(
            event_id=self.event_id,
            occurred_at=committed_at,
            handoff_euid=handoff_euid,
            scene_euid=self.scene_euid,
            recipient_principal_euid=self.recipient_principal_euid,
        )


class DaylilyWorkBridge:
    def __init__(self, *, binding: DaylilyLinearBinding) -> None:
        self.binding = binding

    def commitment_graph(self, *, intent: CommitmentIntent, receipt: LinearIssueReceipt) -> CommitmentGraph:
        """Prepare one handoff and its typed Linear reference for transactional graph persistence."""
        if receipt.binding != self.binding:
            raise PermissionError("Linear receipt does not match the configured Daylily destination")
        if receipt.operation_id != intent.operation_id or receipt.operation != intent.operation:
            raise ValueError("Linear receipt does not match the intentional handoff operation")
        if intent.selected_issue_id is not None and receipt.issue_id != intent.selected_issue_id:
            raise ValueError("Linear receipt does not match the explicitly selected issue")

        policy = intent.access_policy
        recipient = intent.recipient_principal_euid
        if recipient is not None and not policy.permits(
            authenticated_principal_id=recipient,
            purpose=MemoryPurpose.DETAIL,
            layer=MemoryLayer.EPISODE,
            at=receipt.completed_at,
        ):
            raise PermissionError("The handoff recipient is outside its authorized audience")

        event_key = json.dumps([self.binding.workspace_id, intent.request_euid, intent.operation_id])
        event_id = str(uuid.uuid5(uuid.NAMESPACE_URL, f"marvain/daylily/handoff-ready/{event_key}"))
        handoff = GraphObjectRef(key="handoff")
        linear_issue = GraphObjectRef(key="linear_issue")
        objects = (
            GraphObjectWrite(
                key="handoff",
                template_code=TEMPLATE_CODES["work_handoff"],
                name=f"daylily-handoff:{event_id}",
                properties={
                    "operation_id": intent.operation_id,
                    "operation": str(receipt.operation),
                    "original_completion_goal": intent.original_completion_goal,
                    "original_delivery_goal": intent.original_delivery_goal,
                    "linear_completed_at": receipt.completed_at.isoformat(),
                    "access_policy": policy.as_properties(),
                },
                lifecycle_state="recorded",
            ),
            GraphObjectWrite(
                key="linear_issue",
                template_code=_LINEAR_REFERENCE_TEMPLATE,
                name=f"linear-issue:{self.binding.workspace_id}:{receipt.issue_id}",
                properties={
                    "root_euid": receipt.issue_id,
                    "external_identifier": {
                        "system": "linear",
                        "target_euid": receipt.issue_id,
                        "href": receipt.issue_url,
                        "base_url": None,
                        "graph_data_path": None,
                        "object_detail_path_template": None,
                        "auth_mode": "none",
                    },
                    "connection_id": self.binding.connection_id,
                    "account_id": self.binding.account_id,
                    "workspace_id": self.binding.workspace_id,
                    "team_id": self.binding.team_id,
                    "project_id": self.binding.project_id,
                },
                lifecycle_state="active",
            ),
        )
        links = [
            GraphLinkWrite(handoff, linear_issue, "has_external_reference"),
            GraphLinkWrite(GraphObjectRef(semantic_id=intent.episode_euid), handoff, "INITIATES"),
            GraphLinkWrite(handoff, GraphObjectRef(semantic_id=intent.request_euid), "DERIVED_FROM"),
            GraphLinkWrite(handoff, GraphObjectRef(semantic_id=intent.scene_euid), "IN_SCENE"),
            GraphLinkWrite(handoff, GraphObjectRef(semantic_id=intent.requester_principal_euid), "AUTHENTICATED_BY"),
            GraphLinkWrite(handoff, GraphObjectRef(semantic_id=policy.owner_principal_id), "OWNER_PRINCIPAL"),
        ]
        links.extend(
            GraphLinkWrite(handoff, GraphObjectRef(semantic_id=reader), "READER_PRINCIPAL")
            for reader in sorted(policy.reader_principal_ids)
        )
        if intent.delegation_euid is not None:
            links.append(GraphLinkWrite(handoff, GraphObjectRef(semantic_id=intent.delegation_euid), "AUTHORIZED_BY"))
        if recipient is not None:
            links.append(GraphLinkWrite(handoff, GraphObjectRef(semantic_id=recipient), "ADDRESSED_TO"))
        return CommitmentGraph(
            objects=objects,
            links=tuple(links),
            operation_id=intent.operation_id,
            scene_euid=intent.scene_euid,
            recipient_principal_euid=recipient,
            event_id=event_id,
        )
