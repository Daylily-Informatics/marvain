from __future__ import annotations

from unittest.mock import MagicMock

import pytest
from agent_hub.auth import (
    AuthenticatedDevice,
    AuthStateError,
    create_agent_token,
    has_scope,
    require_scopes,
)


def _device(scopes: list[str]) -> AuthenticatedDevice:
    return AuthenticatedDevice(
        device_id="device-1",
        agent_id="agent-1",
        scopes=scopes,
        capabilities={"kind": "satellite"},
    )


def test_device_scope_checks_require_exact_explicit_grants() -> None:
    device = _device(["events:read", "artifacts:write"])

    assert has_scope(device, "events:read") is True
    assert has_scope(device, "events:write") is False
    require_scopes(device, ["events:read", "artifacts:write"])


@pytest.mark.parametrize(
    "checker", [lambda device: has_scope(device, "events:read"), lambda device: require_scopes(device, ["events:read"])]
)
def test_persisted_wildcard_scope_fails_as_malformed_state(checker) -> None:
    with pytest.raises(AuthStateError, match="must contain explicit values"):
        checker(_device(["*"]))


def test_agent_token_creation_rejects_wildcard_scope_or_space_before_database_write() -> None:
    db = MagicMock()

    with pytest.raises(ValueError, match="must contain explicit values"):
        create_agent_token(
            db,
            issuer_agent_id="agent-1",
            target_agent_id="agent-2",
            scopes=["*"],
            allowed_spaces=["space-1"],
        )
    with pytest.raises(ValueError, match="must contain explicit values"):
        create_agent_token(
            db,
            issuer_agent_id="agent-1",
            target_agent_id="agent-2",
            scopes=["events:read"],
            allowed_spaces=["*"],
        )

    db.query.assert_not_called()
