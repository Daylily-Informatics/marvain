"""Tests for shared typed contracts."""

from __future__ import annotations

import pytest

from agent_hub.contracts import CmdRunAction, build_ws_envelope, dump_json_schemas, validate_tool_payload


def test_dump_json_schemas_contains_all_tool_contracts():
    schemas = dump_json_schemas()
    assert set(schemas.keys()) == {
        "send_message",
        "create_memory",
        "http_request",
        "device_command",
        "shell_command",
    }


def test_validate_tool_payload_accepts_known_payload():
    payload = validate_tool_payload(
        "device_command",
        {
            "device_id": "00000000-0000-0000-0000-000000000001",
            "command": "run_action",
            "data": {"kind": "device_status"},
        },
    )
    assert payload["command"] == "run_action"
    assert payload["data"]["kind"] == "device_status"


def test_validate_tool_payload_rejects_invalid_payload():
    with pytest.raises(ValueError, match="invalid_payload:device_command"):
        validate_tool_payload("device_command", {"command": "run_action"})


def test_cmd_run_action_and_envelope_contract_shape():
    cmd = CmdRunAction(
        action_id="00000000-0000-0000-0000-000000000010",
        correlation_id="00000000-0000-0000-0000-000000000011",
        kind="device_status",
        payload={"verbose": True},
        sent_at=1,
    )
    dump = cmd.model_dump() if hasattr(cmd, "model_dump") else cmd.dict()
    assert dump["type"] == "cmd.run_action"
    assert dump["kind"] == "device_status"

    event = build_ws_envelope(
        event_type="actions.updated",
        agent_id="00000000-0000-0000-0000-000000000020",
        space_id="00000000-0000-0000-0000-000000000021",
        payload={"action_id": "a1", "status": "awaiting_device_result"},
    )
    assert event["type"] == "actions.updated"
    assert event["payload"]["status"] == "awaiting_device_result"
