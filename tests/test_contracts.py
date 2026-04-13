"""Tests for shared typed contracts."""

from __future__ import annotations

import pytest

from agent_hub.contracts import (
    CmdRunAction,
    TOOL_REQUIRED_SCOPES,
    build_ws_envelope,
    dump_json_schemas,
    validate_tool_payload,
)


def test_dump_json_schemas_contains_all_tool_contracts():
    schemas = dump_json_schemas()
    assert set(schemas.keys()) == {
        "send_message",
        "slack_post_message",
        "twilio_send_sms",
        "gmail_create_draft",
        "gmail_send_message",
        "github_issue_comment",
        "linear_comment_create",
        "set_message_status",
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
            "integration_account_id": "00000000-0000-0000-0000-000000000030",
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
            "integration_account_id": "00000000-0000-0000-0000-000000000031",
            "to": "+15551230001",
            "body": "hello",
        },
    )
    assert payload["to"] == "+15551230001"
    assert payload["body"] == "hello"


@pytest.mark.parametrize(
    ("kind", "payload", "expected_key"),
    [
        (
            "gmail_create_draft",
            {
                "integration_account_id": "00000000-0000-0000-0000-000000000032",
                "to": ["to@example.com"],
                "cc": ["cc@example.com"],
                "bcc": [],
                "subject": "draft subject",
                "body_text": "draft body",
            },
            "subject",
        ),
        (
            "gmail_send_message",
            {
                "integration_account_id": "00000000-0000-0000-0000-000000000033",
                "to": ["to@example.com"],
                "cc": [],
                "bcc": [],
                "subject": "send subject",
                "body_text": "send body",
                "draft_id": "draft-1",
            },
            "draft_id",
        ),
        (
            "github_issue_comment",
            {
                "integration_account_id": "00000000-0000-0000-0000-000000000034",
                "repository": "octo/repo",
                "issue_number": 7,
                "body": "comment body",
            },
            "issue_number",
        ),
        (
            "linear_comment_create",
            {
                "integration_account_id": "00000000-0000-0000-0000-000000000035",
                "issue_id": "LIN-123",
                "body": "comment body",
            },
            "issue_id",
        ),
        (
            "set_message_status",
            {
                "integration_message_id": "00000000-0000-0000-0000-000000000036",
                "status": "triaged",
                "reason": "handled",
            },
            "status",
        ),
    ],
)
def test_validate_tool_payload_accepts_new_connector_payloads(kind, payload, expected_key):
    normalized = validate_tool_payload(kind, payload)
    assert normalized[expected_key] == payload[expected_key]
    if kind != "set_message_status":
        assert normalized["integration_account_id"] == payload["integration_account_id"]


def test_tool_required_scopes_cover_connector_actions():
    assert TOOL_REQUIRED_SCOPES["set_message_status"] == ["message:triage"]
    assert TOOL_REQUIRED_SCOPES["gmail_create_draft"] == ["gmail:message:write"]
    assert TOOL_REQUIRED_SCOPES["github_issue_comment"] == ["github:issue:write"]
    assert TOOL_REQUIRED_SCOPES["linear_comment_create"] == ["linear:comment:write"]


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
