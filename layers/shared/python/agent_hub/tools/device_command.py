"""Device command tool - send commands to devices via WebSocket.

This tool sends a command message to a specific device connected to the agent.
The device must be online and have a WebSocket connection to receive the command.
"""

from __future__ import annotations

import json
import logging
import os
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from agent_hub.tools.registry import ToolContext, ToolRegistry, ToolResult

logger = logging.getLogger(__name__)

# DynamoDB table name for WebSocket connections
_WS_TABLE_NAME = os.getenv("WS_CONNECTIONS_TABLE", "")


def _get_dynamodb():
    """Lazy import boto3 to avoid import errors in tests."""
    import boto3

    return boto3.resource("dynamodb")


def _get_connections_for_device(device_id: str) -> list[str]:
    """Get all WebSocket connection IDs for a device."""
    if not _WS_TABLE_NAME:
        return []

    table = _get_dynamodb().Table(_WS_TABLE_NAME)

    # Query by device_id using GSI (assumes device_id_index exists)
    # If no GSI, we'd need a scan which is expensive
    try:
        response = table.query(
            IndexName="device_id_index",
            KeyConditionExpression="device_id = :did",
            ExpressionAttributeValues={":did": device_id},
        )
        return [item["connection_id"] for item in response.get("Items", [])]
    except Exception as e:
        logger.warning("Failed to query connections for device %s: %s", device_id, e)
        return []


def _send_to_connection(connection_id: str, message: dict[str, Any], endpoint_url: str) -> bool:
    """Send a message to a WebSocket connection."""
    import boto3

    try:
        client = boto3.client("apigatewaymanagementapi", endpoint_url=endpoint_url)
        client.post_to_connection(
            ConnectionId=connection_id,
            Data=json.dumps(message).encode("utf-8"),
        )
        return True
    except Exception as e:
        logger.warning("Failed to send to connection %s: %s", connection_id, e)
        return False


def device_command_handler(payload: dict[str, Any], ctx: "ToolContext") -> "ToolResult":
    """Execute a device command.

    Payload:
        device_id: str - Target device ID
        command: str - Command type (e.g., "run_action", "config", "ping")
        data: dict - Command-specific data

    Returns:
        ToolResult with ok=True if command was sent, ok=False if device not found or offline
    """
    from agent_hub.tools.registry import ToolResult

    device_id = payload.get("device_id")
    command = payload.get("command", "run_action")
    data = payload.get("data", {})

    if not device_id:
        return ToolResult(ok=False, error="missing_device_id")

    # Verify device belongs to this agent
    rows = ctx.db.query(
        """
        SELECT device_id::TEXT, agent_id::TEXT, name
        FROM devices
        WHERE device_id = :device_id::uuid
          AND agent_id = :agent_id::uuid
          AND revoked_at IS NULL
        """,
        {"device_id": device_id, "agent_id": ctx.agent_id},
    )

    if not rows:
        return ToolResult(ok=False, error="device_not_found_or_not_owned")

    device = rows[0]

    # Get WebSocket connections for this device
    connection_ids = _get_connections_for_device(device_id)

    if not connection_ids:
        return ToolResult(ok=False, error="device_not_connected")

    # Build the command message
    message = {
        "type": f"cmd.{command}",
        "action_id": ctx.action_id,
        "device_id": device_id,
        "payload": data,
    }

    # Get WebSocket endpoint URL
    ws_endpoint = os.getenv("WS_API_ENDPOINT", "")
    if not ws_endpoint:
        return ToolResult(ok=False, error="ws_endpoint_not_configured")

    # Send to all connections (device might have multiple)
    sent = 0
    for conn_id in connection_ids:
        if _send_to_connection(conn_id, message, ws_endpoint):
            sent += 1

    if sent == 0:
        return ToolResult(ok=False, error="failed_to_send_to_any_connection")

    return ToolResult(
        ok=True,
        data={
            "device_id": device_id,
            "device_name": device.get("name", ""),
            "command": command,
            "connections_sent": sent,
        },
    )


# Tool registration data
TOOL_NAME = "device_command"
TOOL_SCOPES = ["devices:write"]
TOOL_DESCRIPTION = "Send a command to a connected device"


def register(registry: "ToolRegistry") -> None:
    """Register the device_command tool with the registry."""
    registry.register(
        TOOL_NAME,
        required_scopes=TOOL_SCOPES,
        handler=device_command_handler,
        description=TOOL_DESCRIPTION,
    )
