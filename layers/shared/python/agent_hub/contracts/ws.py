from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field


class WsEnvelope(BaseModel):
    """Canonical outbound event envelope for GUI/device subscribers."""

    type: str
    agent_id: str
    space_id: str | None = None
    payload: dict[str, Any] = Field(default_factory=dict)


class CmdRunAction(BaseModel):
    """Hub -> device command payload."""

    type: Literal["cmd.run_action"] = "cmd.run_action"
    action_id: str
    correlation_id: str
    kind: str
    payload: dict[str, Any] = Field(default_factory=dict)
    sent_at: int | None = None
    from_connection_id: str | None = None


class DeviceActionAck(BaseModel):
    """Device -> hub acknowledgement that a command was accepted."""

    action: Literal["device_action_ack"] = "device_action_ack"
    action_id: str
    correlation_id: str
    device_id: str
    received_at: int | None = None


class DeviceActionResult(BaseModel):
    """Device -> hub command completion result."""

    action: Literal["device_action_result"] = "device_action_result"
    action_id: str
    correlation_id: str
    device_id: str
    kind: str
    status: Literal["success", "error", "unsupported"]
    result: dict[str, Any] | None = None
    error: str | None = None
    completed_at: int | None = None


def _model_dump(model: BaseModel) -> dict[str, Any]:
    if hasattr(model, "model_dump"):
        return model.model_dump()
    return model.dict()  # pragma: no cover - pydantic v1 fallback


def build_ws_envelope(*, event_type: str, agent_id: str, space_id: str | None, payload: dict[str, Any]) -> dict[str, Any]:
    return _model_dump(
        WsEnvelope(
            type=event_type,
            agent_id=agent_id,
            space_id=space_id,
            payload=payload,
        )
    )
