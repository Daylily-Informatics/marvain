from __future__ import annotations

from unittest import mock

import pytest
from agent_hub.auth import (
    AuthenticatedAgent,
    AuthStateError,
    authenticate_agent_token,
    authenticate_device,
    check_agent_space_access,
    check_agent_target_access,
    create_agent_token,
)

ISSUER_AGENT_ID = "00000000-0000-0000-0000-000000000101"
TARGET_AGENT_ID = "00000000-0000-0000-0000-000000000102"
OTHER_AGENT_ID = "00000000-0000-0000-0000-000000000103"
SPACE_ID = "00000000-0000-0000-0000-000000000201"


def _agent_token_row(**overrides):
    row = {
        "token_id": "00000000-0000-0000-0000-000000000301",
        "issuer_agent_id": ISSUER_AGENT_ID,
        "target_agent_id": TARGET_AGENT_ID,
        "scopes_json": '["read_memories"]',
        "allowed_spaces_json": f'["{SPACE_ID}"]',
    }
    row.update(overrides)
    return row


def test_malformed_device_scopes_fail_instead_of_becoming_empty() -> None:
    db = mock.Mock()
    db.query.return_value = [
        {
            "device_id": "00000000-0000-0000-0000-000000000401",
            "agent_id": ISSUER_AGENT_ID,
            "scopes_json": "not-json",
            "capabilities_json": "{}",
        }
    ]

    with pytest.raises(AuthStateError, match="scopes contains invalid JSON"):
        authenticate_device(db, "device-token")


def test_malformed_device_capabilities_fail_instead_of_becoming_empty() -> None:
    db = mock.Mock()
    db.query.return_value = [
        {
            "device_id": "00000000-0000-0000-0000-000000000401",
            "agent_id": ISSUER_AGENT_ID,
            "scopes_json": "[]",
            "capabilities_json": "[]",
        }
    ]

    with pytest.raises(AuthStateError, match="capabilities must be a JSON object"):
        authenticate_device(db, "device-token")


def test_agent_token_authentication_requires_matching_target_identity() -> None:
    db = mock.Mock()
    db.query.return_value = [_agent_token_row()]

    result = authenticate_agent_token(db, "agent-token", target_agent_id=OTHER_AGENT_ID)

    assert result is None
    db.execute.assert_not_called()


def test_agent_token_authentication_rejects_null_allowed_spaces() -> None:
    db = mock.Mock()
    db.query.return_value = [_agent_token_row(allowed_spaces_json=None)]

    with pytest.raises(AuthStateError, match="allowed_spaces must contain JSON"):
        authenticate_agent_token(db, "agent-token", target_agent_id=TARGET_AGENT_ID)
    db.execute.assert_not_called()


def test_agent_token_authentication_preserves_empty_space_list_as_deny_all() -> None:
    db = mock.Mock()
    db.query.return_value = [_agent_token_row(allowed_spaces_json="[]")]

    authenticated = authenticate_agent_token(db, "agent-token", target_agent_id=TARGET_AGENT_ID)

    assert authenticated is not None
    assert authenticated.target_agent_id == TARGET_AGENT_ID
    assert authenticated.allowed_spaces == []
    assert check_agent_space_access(authenticated, SPACE_ID) is False
    db.execute.assert_called_once()


def test_create_agent_token_persists_explicit_empty_spaces(monkeypatch) -> None:
    db = mock.Mock()
    db.query.return_value = [{"token_id": "00000000-0000-0000-0000-000000000301"}]
    monkeypatch.setattr("agent_hub.auth.generate_agent_token", lambda: "plaintext-token")

    token_id, plaintext = create_agent_token(
        db,
        issuer_agent_id=ISSUER_AGENT_ID,
        target_agent_id=TARGET_AGENT_ID,
        scopes=[],
        allowed_spaces=[],
    )

    assert token_id == "00000000-0000-0000-0000-000000000301"
    assert plaintext == "plaintext-token"
    params = db.query.call_args.args[1]
    assert params["target_agent_id"] == TARGET_AGENT_ID
    assert params["scopes"] == "[]"
    assert params["allowed_spaces"] == "[]"


def test_create_agent_token_requires_explicit_target_and_spaces() -> None:
    db = mock.Mock()

    with pytest.raises(ValueError, match="target_agent_id"):
        create_agent_token(
            db,
            issuer_agent_id=ISSUER_AGENT_ID,
            target_agent_id=None,  # type: ignore[arg-type]
            scopes=[],
            allowed_spaces=[],
        )
    with pytest.raises(ValueError, match="allowed_spaces must be an explicit list"):
        create_agent_token(
            db,
            issuer_agent_id=ISSUER_AGENT_ID,
            target_agent_id=TARGET_AGENT_ID,
            scopes=[],
            allowed_spaces=None,  # type: ignore[arg-type]
        )
    db.query.assert_not_called()


def test_runtime_agent_checks_fail_on_malformed_state() -> None:
    malformed_target = AuthenticatedAgent(
        token_id="token-id",
        issuer_agent_id=ISSUER_AGENT_ID,
        target_agent_id=None,  # type: ignore[arg-type]
        scopes=[],
        allowed_spaces=[],
    )
    malformed_spaces = AuthenticatedAgent(
        token_id="token-id",
        issuer_agent_id=ISSUER_AGENT_ID,
        target_agent_id=TARGET_AGENT_ID,
        scopes=[],
        allowed_spaces=None,  # type: ignore[arg-type]
    )

    with pytest.raises(AuthStateError, match="target_agent_id"):
        check_agent_target_access(malformed_target, TARGET_AGENT_ID)
    with pytest.raises(AuthStateError, match="allowed_spaces"):
        check_agent_space_access(malformed_spaces, SPACE_ID)
