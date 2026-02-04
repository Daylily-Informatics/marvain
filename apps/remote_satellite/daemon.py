#!/usr/bin/env python3
"""Marvain Remote Satellite Daemon.

A lightweight daemon that runs on remote devices (Raspberry Pi, etc.) and connects
to the Marvain Hub via WebSocket. It reports heartbeats, responds to pings, and
can execute device-local tools when commanded by the Hub.

Usage:
    python daemon.py --hub-ws-url wss://example.com/ws --device-token TOKEN

Or via installed CLI:
    marvain-remote-satellite --hub-ws-url wss://example.com/ws --device-token TOKEN
"""

from __future__ import annotations

import asyncio
import logging
import os
import signal
import sys
from typing import Any

import click
import yaml

from hub_client import HubClient, HubClientConfig

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)
logger = logging.getLogger("marvain-satellite")


# -----------------------------------------------------------------------------
# Device Action Registry
# -----------------------------------------------------------------------------

import platform
import time as time_module


def _action_ping(payload: dict[str, Any]) -> dict[str, Any]:
    """Respond to ping with basic device info."""
    return {
        "status": "ok",
        "timestamp": time_module.time(),
        "platform": platform.system(),
        "hostname": platform.node(),
    }


def _action_status(payload: dict[str, Any]) -> dict[str, Any]:
    """Return device status information."""
    import shutil

    disk = shutil.disk_usage("/")
    return {
        "platform": platform.system(),
        "platform_version": platform.version(),
        "hostname": platform.node(),
        "python_version": platform.python_version(),
        "uptime_seconds": time_module.time(),  # Placeholder - real uptime requires OS-specific calls
        "disk_total_gb": round(disk.total / (1024**3), 2),
        "disk_free_gb": round(disk.free / (1024**3), 2),
        "disk_used_percent": round((disk.used / disk.total) * 100, 1),
    }


def _action_echo(payload: dict[str, Any]) -> dict[str, Any]:
    """Echo back the payload for testing."""
    return {"echoed": payload, "timestamp": time_module.time()}


# Registry of supported device actions
DEVICE_ACTIONS: dict[str, Any] = {
    "ping": _action_ping,
    "status": _action_status,
    "echo": _action_echo,
}


# -----------------------------------------------------------------------------
# Configuration State
# -----------------------------------------------------------------------------

_device_config: dict[str, Any] = {}


def get_device_config() -> dict[str, Any]:
    """Get the current device configuration."""
    return _device_config.copy()


# -----------------------------------------------------------------------------
# Command Handler
# -----------------------------------------------------------------------------


async def handle_command(msg: dict[str, Any]) -> dict[str, Any] | None:
    """Handle incoming device commands.

    Supports:
    - cmd.run_action: Execute device-local actions (ping, status, echo, etc.)
    - cmd.config: Apply configuration updates

    Add custom device-specific functionality by extending DEVICE_ACTIONS.
    """
    global _device_config
    msg_type = msg.get("type", "")

    if msg_type == "cmd.run_action":
        kind = msg.get("kind", "")
        payload = msg.get("payload", {})
        logger.info("Received run_action command: kind=%s", kind)

        if kind in DEVICE_ACTIONS:
            try:
                handler = DEVICE_ACTIONS[kind]
                result = handler(payload)
                return {
                    "action": "action_result",
                    "kind": kind,
                    "status": "success",
                    "result": result,
                }
            except Exception as e:
                logger.exception("Error executing action %s", kind)
                return {
                    "action": "action_result",
                    "kind": kind,
                    "status": "error",
                    "error": str(e),
                }
        else:
            return {
                "action": "action_result",
                "kind": kind,
                "status": "unsupported",
                "message": f"Action kind '{kind}' not supported. Supported: {list(DEVICE_ACTIONS.keys())}",
            }

    elif msg_type == "cmd.config":
        config_data = msg.get("config", {})
        logger.info("Received config update: %s", config_data)

        # Merge new config with existing config
        _device_config.update(config_data)

        return {
            "action": "config_ack",
            "status": "applied",
            "config_keys": list(config_data.keys()),
        }

    return None


def load_config_file(path: str) -> dict[str, Any]:
    """Load configuration from YAML file."""
    if os.path.exists(path):
        with open(path) as f:
            return yaml.safe_load(f) or {}
    return {}


@click.command()
@click.option(
    "--hub-ws-url",
    envvar="MARVAIN_HUB_WS_URL",
    required=True,
    help="WebSocket URL of the Marvain Hub (e.g., wss://api.example.com/ws)",
)
@click.option(
    "--hub-rest-url",
    envvar="MARVAIN_HUB_REST_URL",
    default=None,
    help="REST API URL of the Marvain Hub (optional, for heartbeat endpoint)",
)
@click.option(
    "--device-token",
    envvar="MARVAIN_DEVICE_TOKEN",
    required=True,
    help="Device authentication token from the Hub",
)
@click.option(
    "--heartbeat-interval",
    envvar="MARVAIN_HEARTBEAT_INTERVAL",
    default=20,
    type=int,
    help="Heartbeat interval in seconds (default: 20)",
)
@click.option(
    "--config-file",
    envvar="MARVAIN_CONFIG_FILE",
    default=None,
    type=click.Path(exists=False),
    help="Path to YAML configuration file",
)
@click.option("--debug", is_flag=True, help="Enable debug logging")
def main(
    hub_ws_url: str,
    hub_rest_url: str | None,
    device_token: str,
    heartbeat_interval: int,
    config_file: str | None,
    debug: bool,
) -> None:
    """Marvain Remote Satellite Daemon.

    Connects to a Marvain Hub and acts as a remote device, sending heartbeats
    and responding to commands.
    """
    if debug:
        logging.getLogger().setLevel(logging.DEBUG)

    # Load config file if provided (overrides CLI args)
    if config_file:
        file_config = load_config_file(config_file)
        hub_ws_url = file_config.get("hub_ws_url", hub_ws_url)
        hub_rest_url = file_config.get("hub_rest_url", hub_rest_url)
        device_token = file_config.get("device_token", device_token)
        heartbeat_interval = file_config.get("heartbeat_interval", heartbeat_interval)

    logger.info("Starting Marvain Remote Satellite Daemon")
    logger.info("Hub WebSocket URL: %s", hub_ws_url)
    logger.info("Heartbeat interval: %d seconds", heartbeat_interval)

    config = HubClientConfig(
        ws_url=hub_ws_url,
        rest_url=hub_rest_url,
        device_token=device_token,
        heartbeat_interval=heartbeat_interval,
    )

    client = HubClient(config, on_command=handle_command)

    # Handle shutdown gracefully
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    def shutdown_handler(sig: signal.Signals) -> None:
        logger.info("Received signal %s, shutting down...", sig.name)
        loop.create_task(client.stop())

    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, shutdown_handler, sig)

    try:
        loop.run_until_complete(client.run())
    finally:
        loop.close()
        logger.info("Satellite daemon stopped")


if __name__ == "__main__":
    main()

