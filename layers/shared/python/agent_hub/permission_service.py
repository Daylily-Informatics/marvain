from __future__ import annotations

import os

from agent_hub.auth import (
    AuthenticatedAgent,
    AuthStateError,
    check_agent_space_access,
    check_agent_target_access,
)
from agent_hub.memberships import check_agent_permission
from agent_hub.policy import PolicyCheckEvidence, PolicyDecision
from agent_hub.rds_data import RdsData

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
    raw = os.getenv("TOOL_RUNNER_SCOPES")
    if raw is None:
        raise RuntimeError("TOOL_RUNNER_SCOPES is required")
    configured = [item.strip() for item in raw.split(",") if item.strip()]
    if not configured:
        raise RuntimeError("TOOL_RUNNER_SCOPES must contain at least one scope")
    return normalize_scopes(configured)


def _explicit_scopes(scopes: list[str], *, field_name: str) -> list[str]:
    if not isinstance(scopes, list):
        raise ValueError(f"{field_name} must be an explicit list")
    normalized: list[str] = []
    seen: set[str] = set()
    for scope in scopes:
        if not isinstance(scope, str) or not scope or scope != scope.strip():
            raise ValueError(f"{field_name} entries must be non-empty strings")
        if scope in seen:
            raise ValueError(f"{field_name} entries must be unique")
        seen.add(scope)
        normalized.append(scope)
    return normalized


def _authenticated_agent_scopes(scopes: list[str]) -> list[str]:
    try:
        return _explicit_scopes(scopes, field_name="agent.scopes")
    except ValueError as exc:
        raise AuthStateError(f"Malformed authenticated agent: {exc}") from exc


def evaluate_agent_token_access(
    agent: AuthenticatedAgent,
    *,
    operation: str,
    target_agent_id: str,
    required_scopes: list[str],
    space_id: str | None,
) -> PolicyDecision:
    """Evaluate target, scope, and optional space authorization for an agent token."""

    if not isinstance(operation, str) or not operation or operation != operation.strip():
        raise ValueError("operation must be a non-empty string")
    required = _explicit_scopes(required_scopes, field_name="required_scopes")

    evidence: list[PolicyCheckEvidence] = []
    target_allowed = check_agent_target_access(agent, target_agent_id)
    target_evidence = PolicyCheckEvidence(
        check="agent_token_target",
        allowed=target_allowed,
        fields={
            "target_agent_id": target_agent_id,
            "token_target_agent_id": agent.target_agent_id,
        },
    )
    evidence.append(target_evidence)
    if not target_allowed:
        return PolicyDecision(operation, False, "target_agent_mismatch", tuple(evidence))

    granted = _authenticated_agent_scopes(agent.scopes)
    missing = [scope for scope in required if scope not in granted]
    scope_evidence = PolicyCheckEvidence(
        check="agent_token_scopes",
        allowed=not missing,
        fields={
            "required_scopes": required,
            "granted_scopes": granted,
            "missing_scopes": missing,
        },
    )
    evidence.append(scope_evidence)
    if missing:
        return PolicyDecision(operation, False, "missing_required_scopes", tuple(evidence))

    if space_id is not None:
        space_allowed = check_agent_space_access(agent, space_id)
        space_evidence = PolicyCheckEvidence(
            check="agent_token_space",
            allowed=space_allowed,
            fields={
                "space_id": space_id,
                "allowed_spaces": list(agent.allowed_spaces),
            },
        )
        evidence.append(space_evidence)
        if not space_allowed:
            return PolicyDecision(operation, False, "space_not_allowed", tuple(evidence))

    return PolicyDecision(operation, True, "allowed", tuple(evidence))


def user_has_agent_access(db: RdsData, *, user_id: str, agent_id: str, required_role: str = "member") -> bool:
    return check_agent_permission(db, agent_id=agent_id, user_id=user_id, required_role=required_role)
