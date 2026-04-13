"""Tests for shared typed contracts."""

from __future__ import annotations

import pytest

from agent_hub.contracts import CmdRunAction, build_ws_envelope, dump_json_schemas, validate_tool_payload


def test_dump_json_schemas_contains_all_tool_contracts():
    schemas = dump_json_schemas()
    assert set(schemas.keys()) == {
        "send_message",
        "slack_post_message",
        "twilio_send_sms",
        "create_memory",
        "http_request",
        "device_command",
        "host_process",
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


def test_validate_tool_payload_accepts_slack_post_message():
    payload = validate_tool_payload(
        "slack_post_message",
        {
            "channel_id": "C123",
            "text": "hello",
            "thread_ts": "1712345678.000100",
        },
    )
    assert payload["channel_id"] == "C123"
    assert payload["text"] == "hello"
    assert payload["thread_ts"] == "1712345678.000100"


def test_validate_tool_payload_accepts_twilio_send_sms():
    payload = validate_tool_payload(
        "twilio_send_sms",
        {
            "to": "+15551230001",
            "body": "hello",
        },
    )
    assert payload["to"] == "+15551230001"
    assert payload["body"] == "hello"


def test_validate_tool_payload_rejects_invalid_payload():
    with pytest.raises(ValueError, match="invalid_payload:device_command"):
        validate_tool_payload("device_command", {"command": "run_action"})


def test_validate_tool_payload_rejects_invalid_slack_post_message():
    with pytest.raises(ValueError, match="invalid_payload:slack_post_message"):
        validate_tool_payload("slack_post_message", {"text": "hello"})


def test_validate_tool_payload_rejects_invalid_twilio_send_sms():
    with pytest.raises(ValueError, match="invalid_payload:twilio_send_sms"):
        validate_tool_payload("twilio_send_sms", {"body": "hello"})


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
