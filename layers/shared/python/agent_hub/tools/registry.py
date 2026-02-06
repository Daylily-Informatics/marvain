"""Tool registry for marvain action execution.

Tools are functions that can be invoked by the tool_runner when an action is approved.
Each tool:
1. Declares required scopes
2. Validates input payload
3. Executes the action
4. Returns a structured result
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Callable

if TYPE_CHECKING:
    from agent_hub.rds_data import RdsData

logger = logging.getLogger(__name__)


@dataclass
class ToolResult:
    """Result from tool execution."""

    ok: bool
    data: dict[str, Any] = field(default_factory=dict)
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        result = {"ok": self.ok}
        if self.ok:
            result["data"] = self.data
        else:
            result["error"] = self.error or "unknown_error"
        return result


@dataclass
class ToolSpec:
    """Specification for a registered tool."""

    name: str
    required_scopes: list[str]
    handler: Callable[[dict[str, Any], "ToolContext"], ToolResult]
    description: str = ""


@dataclass
class ToolContext:
    """Context passed to tool handlers during execution."""

    db: "RdsData"
    agent_id: str
    space_id: str | None
    action_id: str
    device_scopes: list[str] = field(default_factory=list)
    # For send_message: WebSocket broadcast function
    broadcast_fn: Callable[[str, dict], None] | None = None
    # For http_request: config for allowed hosts
    allowed_http_hosts: list[str] = field(default_factory=list)


class ToolRegistry:
    """Registry of available tools."""

    def __init__(self) -> None:
        self._tools: dict[str, ToolSpec] = {}

    def register(
        self,
        name: str,
        *,
        required_scopes: list[str],
        handler: Callable[[dict[str, Any], ToolContext], ToolResult],
        description: str = "",
    ) -> None:
        """Register a tool with the registry."""
        self._tools[name] = ToolSpec(
            name=name,
            required_scopes=required_scopes,
            handler=handler,
            description=description,
        )
        logger.debug("Registered tool: %s", name)

    def get(self, name: str) -> ToolSpec | None:
        """Get a tool by name."""
        return self._tools.get(name)

    def list_tools(self) -> list[str]:
        """List all registered tool names."""
        return list(self._tools.keys())

    def check_scopes(self, name: str, granted_scopes: list[str]) -> bool:
        """Check if granted scopes satisfy tool requirements.

        Returns True if all required scopes are in granted_scopes.
        """
        tool = self._tools.get(name)
        if not tool:
            return False

        granted_set = set(granted_scopes)
        for required in tool.required_scopes:
            if required not in granted_set:
                return False
        return True

    def execute(self, name: str, payload: dict[str, Any], ctx: ToolContext) -> ToolResult:
        """Execute a tool by name with payload and context."""
        tool = self._tools.get(name)
        if not tool:
            return ToolResult(ok=False, error=f"unknown_tool: {name}")

        # Check scopes
        if not self.check_scopes(name, ctx.device_scopes):
            missing = set(tool.required_scopes) - set(ctx.device_scopes)
            return ToolResult(ok=False, error=f"missing_scopes: {', '.join(missing)}")

        try:
            return tool.handler(payload, ctx)
        except Exception as e:
            logger.exception("Tool %s failed", name)
            return ToolResult(ok=False, error=f"execution_error: {str(e)}")


# Global registry instance
_registry: ToolRegistry | None = None


def get_registry() -> ToolRegistry:
    """Get the global tool registry, initializing if needed."""
    global _registry
    if _registry is None:
        _registry = ToolRegistry()
        _register_default_tools(_registry)
    return _registry


def _register_default_tools(registry: ToolRegistry) -> None:
    """Register the default set of tools."""
    from . import create_memory, device_command, http_request, send_message, shell_command

    send_message.register(registry)
    create_memory.register(registry)
    http_request.register(registry)
    device_command.register(registry)
    shell_command.register(registry)


def execute_tool(name: str, payload: dict[str, Any], ctx: ToolContext) -> ToolResult:
    """Execute a tool by name using the global registry."""
    return get_registry().execute(name, payload, ctx)
