"""Tests for the retention sweeper."""

from __future__ import annotations

import importlib.util
import os
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

os.environ.setdefault("DB_RESOURCE_ARN", "arn:aws:rds:us-east-1:123:cluster:test")
os.environ.setdefault("DB_SECRET_ARN", "arn:aws:secretsmanager:us-east-1:123:secret:test")
os.environ.setdefault("DB_NAME", "testdb")


def _load_module():
    module_name = "retention_sweeper_handler"
    if module_name in sys.modules:
        return sys.modules[module_name]

    root = Path(__file__).resolve().parents[1]
    module_path = root / "functions" / "retention_sweeper" / "handler.py"
    spec = importlib.util.spec_from_file_location(module_name, module_path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


def test_retention_sweeper_redacts_expired_messages_and_audits():
    sweeper = _load_module()
    mock_db = MagicMock()
    mock_db.query.side_effect = [
        [
            {
                "integration_message_id": "msg-1",
                "agent_id": "agent-1",
                "integration_account_id": "acct-1",
                "provider": "slack",
                "direction": "inbound",
                "channel_type": "dm",
                "object_type": "message",
                "external_thread_id": "thread-1",
                "external_message_id": "prov-1",
                "dedupe_key": "slack:1",
                "retention_until": "2026-04-12T00:00:00+00:00",
            }
        ],
        [
            {
                "integration_message_id": "msg-1",
                "agent_id": "agent-1",
                "integration_account_id": "acct-1",
                "provider": "slack",
                "direction": "inbound",
                "channel_type": "dm",
                "object_type": "message",
                "external_thread_id": "thread-1",
                "external_message_id": "prov-1",
                "dedupe_key": "slack:1",
                "retention_until": "2026-04-12T00:00:00+00:00",
                "redacted_at": "2026-04-12T01:00:00+00:00",
            }
        ],
    ]

    with (
        patch.object(sweeper, "_db", mock_db),
        patch.object(sweeper, "_cfg", MagicMock(audit_bucket="audit-bucket")),
        patch.object(sweeper, "append_audit_entry") as mock_audit,
    ):
        out = sweeper.handler({}, None)

    assert out == {"redacted": 1}
    assert mock_db.query.call_count == 2

    update_sql = mock_db.query.call_args_list[1].args[0]
    update_params = mock_db.query.call_args_list[1].args[1]
    assert "UPDATE integration_messages" in update_sql
    assert "subject = NULL" in update_sql
    assert "body_text = ''" in update_sql
    assert "payload = '{}'::jsonb" in update_sql
    assert update_params["integration_message_id"] == "msg-1"

    mock_audit.assert_called_once()
    audit_kwargs = mock_audit.call_args.kwargs
    assert audit_kwargs["bucket"] == "audit-bucket"
    assert audit_kwargs["entry_type"] == "integration_message_redacted"
    assert audit_kwargs["agent_id"] == "agent-1"
    assert audit_kwargs["entry"]["integration_message_id"] == "msg-1"
    assert audit_kwargs["entry"]["dedupe_key"] == "slack:1"


def test_retention_sweeper_no_expired_messages_noops():
    sweeper = _load_module()
    mock_db = MagicMock()
    mock_db.query.return_value = []

    with (
        patch.object(sweeper, "_db", mock_db),
        patch.object(sweeper, "_cfg", MagicMock(audit_bucket=None)),
        patch.object(sweeper, "append_audit_entry") as mock_audit,
    ):
        out = sweeper.handler({}, None)

    assert out == {"redacted": 0}
    mock_db.query.assert_called_once()
    mock_audit.assert_not_called()
