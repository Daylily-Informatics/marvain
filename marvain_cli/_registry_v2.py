from __future__ import annotations

import inspect
from collections.abc import Callable, Sequence
from typing import Any

from cli_core_yo.registry import CommandRegistry
from cli_core_yo.spec import CommandPolicy

EXEMPT = CommandPolicy(runtime_guard="exempt")
EXEMPT_JSON = CommandPolicy(supports_json=True, runtime_guard="exempt")
EXEMPT_MUTATING = CommandPolicy(mutates_state=True, runtime_guard="exempt")
EXEMPT_MUTATING_DRY_RUN = CommandPolicy(
    mutates_state=True,
    supports_dry_run=True,
    runtime_guard="exempt",
)
EXEMPT_MUTATING_INTERACTIVE_DRY_RUN = CommandPolicy(
    mutates_state=True,
    supports_dry_run=True,
    runtime_guard="exempt",
    interactive=True,
)
EXEMPT_LONG_RUNNING_DRY_RUN = CommandPolicy(
    mutates_state=True,
    supports_dry_run=True,
    runtime_guard="exempt",
    long_running=True,
)

CommandDef = tuple[str, Callable[..., Any], CommandPolicy]


def help_text(callback: Callable[..., Any]) -> str:
    return inspect.getdoc(callback) or ""


def register_group_commands(
    registry: CommandRegistry,
    group_path: str,
    group_help: str,
    commands: Sequence[CommandDef],
) -> None:
    if "/" in group_path:
        parent = registry._resolve_parent(group_path)  # type: ignore[attr-defined]
        if parent is None:
            raise ValueError(f"Unable to create command group {group_path!r}")
        if group_help and parent.help_text and parent.help_text != group_help:
            raise ValueError(f"Conflicting help text for command group {group_path!r}")
        if group_help and not parent.help_text:
            parent.help_text = group_help
    else:
        registry.add_group(group_path, help_text=group_help)
    for name, callback, policy in commands:
        registry.add_command(
            group_path,
            name,
            callback,
            help_text=help_text(callback),
            policy=policy,
        )
