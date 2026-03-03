"""Tests for EMF metrics helper."""

from __future__ import annotations

import json
import logging
from unittest.mock import patch

from agent_hub.metrics import emit_count, emit_ms


def _extract_payload(caplog) -> dict:
    record = caplog.records[-1]
    return json.loads(record.getMessage())


def test_emit_count_logs_emf_payload(caplog):
    caplog.set_level(logging.INFO, logger="agent_hub.metrics")
    with patch("agent_hub.metrics.time.time", return_value=1700000000.0):
        emit_count("BroadcastDelivered", dimensions={"Type": "actions.updated"})

    payload = _extract_payload(caplog)
    assert payload["BroadcastDelivered"] == 1.0
    assert payload["Type"] == "actions.updated"
    assert payload["_aws"]["CloudWatchMetrics"][0]["Metrics"][0]["Unit"] == "Count"


def test_emit_ms_logs_millisecond_metric(caplog):
    caplog.set_level(logging.INFO, logger="agent_hub.metrics")
    with patch("agent_hub.metrics.time.time", return_value=1700000000.0):
        emit_ms("CommandResultLatencyMs", value_ms=123.45, dimensions={"ActionKind": "device_command"})

    payload = _extract_payload(caplog)
    assert payload["CommandResultLatencyMs"] == 123.45
    assert payload["ActionKind"] == "device_command"
    assert payload["_aws"]["CloudWatchMetrics"][0]["Metrics"][0]["Unit"] == "Milliseconds"
