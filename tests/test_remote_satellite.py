"""Tests for remote satellite daemon action execution.

These tests verify the device-local action handlers in the remote satellite daemon.
"""
from __future__ import annotations

import asyncio
import importlib.util
import platform
import sys
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

# Directory containing the remote satellite code
_REMOTE_SAT_DIR = Path(__file__).parent.parent / "apps" / "remote_satellite"


def _load_remote_satellite_daemon():
    """Load the daemon module without polluting sys.path permanently.

    Uses a context-manager pattern to temporarily add the remote_satellite
    directory to sys.path, load the module, then restore sys.path.
    """
    original_path = sys.path.copy()
    remote_sat_str = str(_REMOTE_SAT_DIR)

    try:
        # Temporarily add to path for hub_client import resolution
        if remote_sat_str not in sys.path:
            sys.path.insert(0, remote_sat_str)

        # Load the daemon module with a unique name to avoid conflicts
        daemon_path = _REMOTE_SAT_DIR / "daemon.py"
        spec = importlib.util.spec_from_file_location(
            "remote_satellite_daemon", daemon_path
        )
        module = importlib.util.module_from_spec(spec)

        # Register under unique name before exec to handle any self-imports
        sys.modules["remote_satellite_daemon"] = module
        spec.loader.exec_module(module)

        return module
    finally:
        # Restore original sys.path
        sys.path[:] = original_path


# Load module once at import time, but clean up sys.path
_daemon_module = _load_remote_satellite_daemon()

# Extract the functions/objects we need for tests
handle_command = _daemon_module.handle_command
get_device_config = _daemon_module.get_device_config
_device_config = _daemon_module._device_config


def _run_async(coro) -> Any:
    """Helper to run async function in sync context."""
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


class TestDeviceActions:
    """Tests for device action handlers."""

    def test_handle_ping_action(self):
        """ping action should return device info."""
        msg = {"type": "cmd.run_action", "kind": "ping", "payload": {}}
        result = _run_async(handle_command(msg))

        assert result is not None
        assert result["action"] == "action_result"
        assert result["kind"] == "ping"
        assert result["status"] == "success"
        assert "result" in result
        assert result["result"]["status"] == "ok"
        assert result["result"]["platform"] == platform.system()
        assert result["result"]["hostname"] == platform.node()

    def test_handle_status_action(self):
        """status action should return system status."""
        msg = {"type": "cmd.run_action", "kind": "status", "payload": {}}
        result = _run_async(handle_command(msg))

        assert result is not None
        assert result["action"] == "action_result"
        assert result["kind"] == "status"
        assert result["status"] == "success"
        assert "result" in result
        assert "disk_total_gb" in result["result"]
        assert "disk_free_gb" in result["result"]
        assert "disk_used_percent" in result["result"]
        assert "python_version" in result["result"]

    def test_handle_echo_action(self):
        """echo action should echo back payload."""
        test_payload = {"message": "hello", "count": 42}
        msg = {"type": "cmd.run_action", "kind": "echo", "payload": test_payload}
        result = _run_async(handle_command(msg))

        assert result is not None
        assert result["action"] == "action_result"
        assert result["kind"] == "echo"
        assert result["status"] == "success"
        assert result["result"]["echoed"] == test_payload

    def test_handle_unsupported_action(self):
        """Unsupported action should return unsupported status."""
        msg = {"type": "cmd.run_action", "kind": "unknown_action", "payload": {}}
        result = _run_async(handle_command(msg))

        assert result is not None
        assert result["action"] == "action_result"
        assert result["kind"] == "unknown_action"
        assert result["status"] == "unsupported"
        assert "not supported" in result["message"].lower()
        assert "ping" in result["message"]  # Should list available actions


class TestConfigCommand:
    """Tests for config command handling."""

    def test_handle_config_command(self):
        """config command should store configuration."""
        msg = {
            "type": "cmd.config",
            "config": {"log_level": "DEBUG", "heartbeat_interval": 30}
        }
        result = _run_async(handle_command(msg))

        assert result is not None
        assert result["action"] == "config_ack"
        assert result["status"] == "applied"
        assert "log_level" in result["config_keys"]
        assert "heartbeat_interval" in result["config_keys"]

        # Verify config was stored
        config = get_device_config()
        assert config["log_level"] == "DEBUG"
        assert config["heartbeat_interval"] == 30

    def test_config_merges_with_existing(self):
        """config command should merge with existing config."""
        # Reset config state
        _device_config.clear()

        # First config
        msg1 = {"type": "cmd.config", "config": {"key1": "value1"}}
        _run_async(handle_command(msg1))

        # Second config
        msg2 = {"type": "cmd.config", "config": {"key2": "value2"}}
        _run_async(handle_command(msg2))

        config = get_device_config()
        assert config["key1"] == "value1"
        assert config["key2"] == "value2"


class TestUnknownMessageType:
    """Tests for unknown message types."""

    def test_unknown_message_type_returns_none(self):
        """Unknown message types should return None."""
        msg = {"type": "unknown.message", "data": "test"}
        result = _run_async(handle_command(msg))

        assert result is None

