from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field, ValidationError


class SendMessagePayload(BaseModel):
    recipient_type: Literal["space", "connection", "user"]
    recipient_id: str
    message_type: str = "notification"
    content: Any


class SlackPostMessagePayload(BaseModel):
    channel_id: str
    text: str
    thread_ts: str | None = None


class TwilioSendSmsPayload(BaseModel):
    to: str
    body: str


class CreateMemoryPayload(BaseModel):
    tier: Literal["episodic", "semantic"] = "semantic"
    content: str
    participants: list[str] = Field(default_factory=list)
    provenance: dict[str, Any] = Field(default_factory=dict)
    retention: dict[str, Any] = Field(default_factory=dict)


class HttpRequestPayload(BaseModel):
    method: str = "GET"
    url: str
    headers: dict[str, Any] = Field(default_factory=dict)
    body: Any | None = None
    timeout: int = 10


class DeviceCommandPayload(BaseModel):
    device_id: str
    command: str = "run_action"
    data: dict[str, Any] = Field(default_factory=dict)
    correlation_id: str | None = None
    timeout_seconds: int | None = None


class HostProcessPayload(BaseModel):
    operation: Literal["launch_satellite", "launch_agent_worker", "stop_agent_worker", "restart_agent_worker"]
    args: dict[str, Any] = Field(default_factory=dict)


class ShellCommandPayload(BaseModel):
    device_id: str
    command: str
    timeout: int = 30
    working_dir: str | None = None
    correlation_id: str | None = None
    timeout_seconds: int | None = None


TOOL_PAYLOAD_MODELS: dict[str, type[BaseModel]] = {
    "send_message": SendMessagePayload,
    "slack_post_message": SlackPostMessagePayload,
    "twilio_send_sms": TwilioSendSmsPayload,
    "create_memory": CreateMemoryPayload,
    "http_request": HttpRequestPayload,
    "device_command": DeviceCommandPayload,
    "host_process": HostProcessPayload,
    "shell_command": ShellCommandPayload,
}


def _model_dump(model: BaseModel) -> dict[str, Any]:
    return model.model_dump()


def _model_schema(model_type: type[BaseModel]) -> dict[str, Any]:
    return model_type.model_json_schema()


def validate_tool_payload(kind: str, payload: dict[str, Any]) -> dict[str, Any]:
    model = TOOL_PAYLOAD_MODELS.get(str(kind))
    if not model:
        return payload
    try:
        return _model_dump(model(**(payload or {})))
    except ValidationError as exc:
        raise ValueError(f"invalid_payload:{kind}: {exc}") from exc


def dump_json_schemas() -> dict[str, dict[str, Any]]:
    out: dict[str, dict[str, Any]] = {}
    for kind, model in TOOL_PAYLOAD_MODELS.items():
        out[kind] = _model_schema(model)
    return out
