from __future__ import annotations

import os

from agent_hub.memberships import check_agent_permission
from agent_hub.rds_data import RdsData

_DEFAULT_TOOL_RUNNER_SCOPES = [
    "devices:write",
    "http:request",
    "memory:write",
    "message:send",
    "shell:execute",
]

_SCOPE_ALIASES = {
    "read_events": "events:read",
    "read_memories": "memories:read",
    "read_spaces": "spaces:read",
    "write_events": "events:write",
    "write_memories": "memories:write",
}


def normalize_scope(scope: str) -> str:
    raw = str(scope or "").strip()
    if not raw:
        return ""
    return _SCOPE_ALIASES.get(raw, raw)


def normalize_scopes(scopes: list[str] | tuple[str, ...] | set[str] | None) -> list[str]:
    normalized = {normalize_scope(scope) for scope in (scopes or [])}
    normalized.discard("")
    return sorted(normalized)


def get_tool_runner_scopes() -> list[str]:
    configured = [item.strip() for item in os.getenv("TOOL_RUNNER_SCOPES", "").split(",") if item.strip()]
    if configured:
        return normalize_scopes(configured)
    return normalize_scopes(_DEFAULT_TOOL_RUNNER_SCOPES)


def user_has_agent_access(db: RdsData, *, user_id: str, agent_id: str, required_role: str = "member") -> bool:
    return check_agent_permission(db, agent_id=agent_id, user_id=user_id, required_role=required_role)
