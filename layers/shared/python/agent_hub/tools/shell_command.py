"""shell_command tool - Execute read-only shell commands on devices.

This tool allows the agent to execute safe, read-only shell commands
on remote devices via the device command system.

Note: This tool doesn't execute commands directly on the Hub - it sends
commands to remote satellite devices which have their own safety restrictions.
"""
from __future__ import annotations

import logging
from typing import Any

from .registry import ToolRegistry, ToolResult, ToolContext

logger = logging.getLogger(__name__)

TOOL_NAME = "shell_command"
REQUIRED_SCOPES = ["shell:execute"]

# Safe read-only commands that are allowed
SAFE_COMMANDS = {
    "ls", "cat", "head", "tail", "grep", "find", "wc", "du", "df",
    "ps", "top", "uptime", "uname", "hostname", "whoami", "id",
    "pwd", "echo", "date", "which", "whereis", "file", "stat",
    "env", "printenv", "ifconfig", "ip", "netstat", "ss",
    "free", "vmstat", "iostat", "lscpu", "lsblk", "lsusb",
    "ping", "nslookup", "dig", "host", "traceroute",
}


def _handler(payload: dict[str, Any], ctx: ToolContext) -> ToolResult:
    """Execute the shell_command tool.
    
    This sends a shell command to a remote device for execution.
    The device's daemon has its own safety restrictions.
    
    Payload:
        device_id: str - Target device ID
        command: str - The shell command to execute
        timeout: int - Maximum execution time in seconds (default: 30)
        working_dir: str - Optional working directory
    """
    device_id = payload.get("device_id")
    command = payload.get("command", "").strip()
    timeout = payload.get("timeout", 30)
    working_dir = payload.get("working_dir")
    
    if not device_id:
        return ToolResult(ok=False, error="missing_device_id")
    
    if not command:
        return ToolResult(ok=False, error="missing_command")
    
    # Check if command is in safe list (first word only)
    parts = command.split()
    base_cmd = parts[0].split("/")[-1] if parts else ""
    
    if base_cmd not in SAFE_COMMANDS:
        return ToolResult(
            ok=False,
            error=f"command_not_allowed: {base_cmd}",
            data={"safe_commands": sorted(SAFE_COMMANDS)},
        )
    
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
    
    # Use device_command tool to send the shell command
    from .device_command import device_command_handler
    
    device_payload = {
        "device_id": device_id,
        "command": "run_action",
        "data": {
            "kind": "shell_command",
            "payload": {
                "command": command,
                "timeout": timeout,
                "working_dir": working_dir,
            },
        },
    }
    
    result = device_command_handler(device_payload, ctx)
    
    if not result.ok:
        return result
    
    # Enhance result with command info
    result.data["command"] = command
    result.data["device_name"] = device.get("name", "")
    
    return result


def register(registry: ToolRegistry) -> None:
    """Register the shell_command tool with the registry."""
    registry.register(
        TOOL_NAME,
        required_scopes=REQUIRED_SCOPES,
        handler=_handler,
        description="Execute read-only shell commands on remote devices",
    )

