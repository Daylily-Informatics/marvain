from __future__ import annotations

from agent_hub.permission_service import get_tool_runner_scopes


def test_default_tool_runner_scopes_do_not_include_http_request_or_shell_execute(monkeypatch):
    monkeypatch.delenv("TOOL_RUNNER_SCOPES", raising=False)

    scopes = get_tool_runner_scopes()

    assert "http:request" not in scopes
    assert "shell:execute" not in scopes
    assert "devices:write" in scopes
    assert "message:send" in scopes
