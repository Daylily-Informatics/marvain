"""host_process tool registration.

This action kind is reserved for local GUI/CLI execution and should never be
sent to the Lambda tool runner. We still register it so ActionService can
validate and persist host-process actions through the same lifecycle.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from agent_hub.tools.registry import ToolContext, ToolRegistry, ToolResult


def _handler(payload: dict, ctx: "ToolContext") -> "ToolResult":
    from agent_hub.tools.registry import ToolResult

    return ToolResult(ok=False, error="host_process_requires_local_executor")


def register(registry: "ToolRegistry") -> None:
    registry.register(
        "host_process",
        required_scopes=["devices:launch"],
        handler=_handler,
        description="Local-only host process lifecycle action",
    )
