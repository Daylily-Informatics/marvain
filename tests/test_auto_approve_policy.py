"""Unit tests for auto-approve policy evaluator."""

from __future__ import annotations

from datetime import UTC, datetime
from unittest.mock import MagicMock

from agent_hub.auto_approve_policy import evaluate_auto_approve


def test_policy_matches_kind_scopes_and_time_window():
    db = MagicMock()
    db.query.return_value = [
        {
            "policy_id": "00000000-0000-0000-0000-000000000101",
            "action_kind": "device_command",
            "required_scopes": '["devices:write"]',
            "time_window": '{"timezone":"UTC","days":[1],"start":"09:00","end":"17:00"}',
        }
    ]

    decision = evaluate_auto_approve(
        db,
        agent_id="00000000-0000-0000-0000-000000000001",
        action_kind="device_command",
        action_required_scopes=["devices:write", "devices:read"],
        now_utc=datetime(2026, 3, 3, 12, 0, tzinfo=UTC),  # Tuesday
    )

    assert decision.matched is True
    assert decision.policy_id == "00000000-0000-0000-0000-000000000101"
    assert decision.reason == "matched"


def test_policy_no_match_when_required_scopes_missing():
    db = MagicMock()
    db.query.return_value = [
        {
            "policy_id": "00000000-0000-0000-0000-000000000102",
            "action_kind": "shell_command",
            "required_scopes": '["devices:write","shell:execute"]',
            "time_window": "{}",
        }
    ]

    decision = evaluate_auto_approve(
        db,
        agent_id="00000000-0000-0000-0000-000000000001",
        action_kind="shell_command",
        action_required_scopes=["devices:write"],
        now_utc=datetime(2026, 3, 3, 12, 0, tzinfo=UTC),
    )

    assert decision.matched is False
    assert decision.policy_id is None
    assert decision.reason == "no_policy_match"


def test_policy_matches_with_overnight_window():
    db = MagicMock()
    db.query.return_value = [
        {
            "policy_id": "00000000-0000-0000-0000-000000000103",
            "action_kind": "*",
            "required_scopes": "[]",
            "time_window": '{"timezone":"UTC","start":"22:00","end":"02:00"}',
        }
    ]

    decision = evaluate_auto_approve(
        db,
        agent_id="00000000-0000-0000-0000-000000000001",
        action_kind="send_message",
        action_required_scopes=[],
        now_utc=datetime(2026, 3, 3, 1, 15, tzinfo=UTC),
    )

    assert decision.matched is True
    assert decision.reason == "matched"


def test_policy_table_unavailable_is_non_fatal():
    db = MagicMock()
    db.query.side_effect = RuntimeError("relation does not exist")

    decision = evaluate_auto_approve(
        db,
        agent_id="00000000-0000-0000-0000-000000000001",
        action_kind="send_message",
        action_required_scopes=[],
    )

    assert decision.matched is False
    assert decision.policy_id is None
    assert decision.reason == "policy_table_unavailable"
