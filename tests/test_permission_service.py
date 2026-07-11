from __future__ import annotations

import pytest
from agent_hub.auth import AuthenticatedAgent
from agent_hub.permission_service import evaluate_agent_token_access, get_tool_runner_scopes


def test_tool_runner_scopes_require_explicit_configuration(monkeypatch):
    monkeypatch.delenv("TOOL_RUNNER_SCOPES", raising=False)

    with pytest.raises(RuntimeError, match="TOOL_RUNNER_SCOPES is required"):
        get_tool_runner_scopes()


def test_tool_runner_scopes_normalize_explicit_configuration(monkeypatch):
    monkeypatch.setenv("TOOL_RUNNER_SCOPES", "write_events, message:send,write_events")

    assert get_tool_runner_scopes() == ["events:write", "message:send"]


def _agent(*, target_agent_id: str = "agent-target", allowed_spaces=None, scopes=None) -> AuthenticatedAgent:
    return AuthenticatedAgent(
        token_id="token-id",
        issuer_agent_id="agent-issuer",
        target_agent_id=target_agent_id,
        scopes=["read_memories"] if scopes is None else scopes,
        allowed_spaces=["space-allowed"] if allowed_spaces is None else allowed_spaces,
    )


def test_agent_token_access_short_circuits_after_target_denial() -> None:
    decision = evaluate_agent_token_access(
        _agent(),
        operation="delegate_memory_read",
        target_agent_id="agent-other",
        required_scopes=["read_memories"],
        space_id="space-allowed",
    )

    assert decision.allowed is False
    assert decision.reason == "target_agent_mismatch"
    assert [item.check for item in decision.evidence] == ["agent_token_target"]


def test_agent_token_access_short_circuits_before_space_when_scope_missing() -> None:
    decision = evaluate_agent_token_access(
        _agent(scopes=[]),
        operation="delegate_memory_read",
        target_agent_id="agent-target",
        required_scopes=["read_memories"],
        space_id="space-allowed",
    )

    assert decision.allowed is False
    assert decision.reason == "missing_required_scopes"
    assert [item.check for item in decision.evidence] == ["agent_token_target", "agent_token_scopes"]


def test_agent_token_access_enforces_explicit_allowed_spaces() -> None:
    denied = evaluate_agent_token_access(
        _agent(allowed_spaces=[]),
        operation="delegate_memory_read",
        target_agent_id="agent-target",
        required_scopes=["read_memories"],
        space_id="space-allowed",
    )
    allowed = evaluate_agent_token_access(
        _agent(),
        operation="delegate_memory_read",
        target_agent_id="agent-target",
        required_scopes=["read_memories"],
        space_id="space-allowed",
    )

    assert denied.allowed is False
    assert denied.reason == "space_not_allowed"
    assert allowed.allowed is True
    assert [item.check for item in allowed.evidence] == [
        "agent_token_target",
        "agent_token_scopes",
        "agent_token_space",
    ]
