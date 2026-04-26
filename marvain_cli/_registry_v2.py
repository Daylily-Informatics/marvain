from __future__ import annotations

import inspect
from collections.abc import Callable, Sequence
from typing import Any

from cli_core_yo.registry import CommandRegistry
from cli_core_yo.spec import CommandPolicy

MARVAIN_RUNTIME_TAG = "marvain-runtime"
MARVAIN_AWS_TAG = "marvain-aws"
MARVAIN_SAM_TAG = "marvain-sam"

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
REQUIRED = CommandPolicy(runtime_guard="required", prereq_tags={MARVAIN_RUNTIME_TAG})
REQUIRED_JSON = CommandPolicy(
    supports_json=True,
    runtime_guard="required",
    prereq_tags={MARVAIN_RUNTIME_TAG},
)
REQUIRED_MUTATING_DRY_RUN = CommandPolicy(
    mutates_state=True,
    supports_dry_run=True,
    runtime_guard="required",
    prereq_tags={MARVAIN_RUNTIME_TAG},
)
REQUIRED_MUTATING_INTERACTIVE_DRY_RUN = CommandPolicy(
    mutates_state=True,
    supports_dry_run=True,
    runtime_guard="required",
    prereq_tags={MARVAIN_RUNTIME_TAG},
    interactive=True,
)
REQUIRED_LONG_RUNNING_DRY_RUN = CommandPolicy(
    mutates_state=True,
    supports_dry_run=True,
    runtime_guard="required",
    prereq_tags={MARVAIN_RUNTIME_TAG},
    long_running=True,
)

CommandDef = tuple[str, Callable[..., Any], CommandPolicy]


def required_policy(
    *,
    supports_json: bool = False,
    mutates_state: bool = False,
    supports_dry_run: bool = False,
    interactive: bool = False,
    long_running: bool = False,
    prereq_tags: set[str] | None = None,
) -> CommandPolicy:
    tags = {MARVAIN_RUNTIME_TAG}
    if prereq_tags:
        tags.update(prereq_tags)
    return CommandPolicy(
        supports_json=supports_json,
        mutates_state=mutates_state,
        supports_dry_run=supports_dry_run,
        runtime_guard="required",
        interactive=interactive,
        long_running=long_running,
        prereq_tags=tags,
    )


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


def register_root_command(
    registry: CommandRegistry,
    name: str,
    callback: Callable[..., Any],
    policy: CommandPolicy,
) -> None:
    registry.add_command(
        None,
        name,
        callback,
        help_text=help_text(callback),
        policy=policy,
    )
