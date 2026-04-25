"""Unit tests for action timeout sweeper."""

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
    module_name = "action_timeout_sweeper_handler"
    if module_name in sys.modules:
        return sys.modules[module_name]

    root = Path(__file__).resolve().parents[1]
    module_path = root / "functions" / "action_timeout_sweeper" / "handler.py"
    spec = importlib.util.spec_from_file_location(module_name, module_path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


def test_timeout_sweeper_marks_actions_and_broadcasts_updates():
    sweeper = _load_module()
    mock_db = MagicMock()
    mock_db.query.return_value = [
        {
            "action_id": "00000000-0000-0000-0000-000000000201",
            "agent_id": "00000000-0000-0000-0000-000000000001",
            "space_id": "00000000-0000-0000-0000-000000000002",
            "kind": "device_command",
        },
        {
            "action_id": "00000000-0000-0000-0000-000000000202",
            "agent_id": "00000000-0000-0000-0000-000000000001",
            "space_id": None,
            "kind": "shell_command",
        },
    ]

    with (
        patch.object(sweeper, "_db", mock_db),
        patch.object(sweeper, "broadcast_event") as mock_broadcast,
        patch.object(sweeper, "emit_count") as mock_emit_count,
    ):
        out = sweeper.handler({}, None)

    assert out["timed_out"] == 2
    assert mock_db.execute.call_count == 2
    assert mock_broadcast.call_count == 2
    assert mock_emit_count.call_count == 2

    for call in mock_broadcast.call_args_list:
        kwargs = call.kwargs
        assert kwargs["event_type"] == "actions.updated"
        assert kwargs["payload"]["status"] == "device_timeout"
        assert kwargs["payload"]["error"] == "device_timeout"


def test_timeout_sweeper_no_overdue_actions_noops():
    sweeper = _load_module()
    mock_db = MagicMock()
    mock_db.query.return_value = []

    with (
        patch.object(sweeper, "_db", mock_db),
        patch.object(sweeper, "broadcast_event") as mock_broadcast,
        patch.object(sweeper, "emit_count") as mock_emit_count,
    ):
        out = sweeper.handler({}, None)

    assert out["timed_out"] == 0
    mock_db.execute.assert_not_called()
    mock_broadcast.assert_not_called()
    mock_emit_count.assert_not_called()
