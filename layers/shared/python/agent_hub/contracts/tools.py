from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field, ValidationError


class SendMessagePayload(BaseModel):
    recipient_type: Literal["space", "connection", "user"]
    recipient_id: str
    message_type: str = "notification"
    content: Any


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


class ShellCommandPayload(BaseModel):
    device_id: str
    command: str
    timeout: int = 30
    working_dir: str | None = None


TOOL_PAYLOAD_MODELS: dict[str, type[BaseModel]] = {
    "send_message": SendMessagePayload,
    "create_memory": CreateMemoryPayload,
    "http_request": HttpRequestPayload,
    "device_command": DeviceCommandPayload,
    "shell_command": ShellCommandPayload,
}


def _model_dump(model: BaseModel) -> dict[str, Any]:
    if hasattr(model, "model_dump"):
        return model.model_dump()
    return model.dict()  # pragma: no cover - pydantic v1 fallback


def _model_schema(model_type: type[BaseModel]) -> dict[str, Any]:
    if hasattr(model_type, "model_json_schema"):
        return model_type.model_json_schema()
    return model_type.schema()  # pragma: no cover - pydantic v1 fallback


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
