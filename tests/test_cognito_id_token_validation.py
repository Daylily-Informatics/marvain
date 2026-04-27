from __future__ import annotations

import asyncio
from typing import Any

import pytest
from agent_hub import cognito
from agent_hub.config import HubConfig
from jose import jwt


def _cfg(*, client_id: str = "client-123") -> HubConfig:
    return HubConfig(
        stage="test",
        db_resource_arn="arn:aws:rds:us-east-1:123456789012:cluster:test",
        db_secret_arn="arn:aws:secretsmanager:us-east-1:123456789012:secret:test",
        db_name="agenthub",
        transcript_queue_url=None,
        action_queue_url=None,
        tapdb_writer_queue_url=None,
        integration_queue_url=None,
        audit_bucket=None,
        artifact_bucket=None,
        admin_secret_arn=None,
        openai_secret_arn=None,
        planner_model=None,
        cognito_region="us-east-1",
        cognito_user_pool_id="us-east-1_test",
        cognito_user_pool_client_id=client_id,
        cognito_user_pool_client_secret=None,
        cognito_domain="marvain-test.auth.us-east-1.amazoncognito.com",
        cognito_redirect_uri="https://localhost:8084/auth/callback",
        cognito_group_role_map=None,
        cognito_identity_provider=None,
        session_secret_key="test-secret",
        session_secret_arn=None,
        livekit_url=None,
        livekit_secret_arn=None,
        ws_api_url=None,
        max_spaces_per_agent=10,
    )


def test_id_token_signature_verification_disables_python_jose_audience_check(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict[str, Any] = {}

    class _Cache:
        def get_key(self, kid: str) -> dict[str, str]:
            assert kid == "kid-1"
            return {"kty": "RSA", "kid": kid}

    def fake_decode(*args: Any, **kwargs: Any) -> dict[str, Any]:
        captured.update(kwargs)
        return {"sub": "sub-1", "email": "user@example.com", "aud": "client-123"}

    monkeypatch.setattr(cognito, "_get_daylily_jwks_cache", lambda cfg: _Cache())
    monkeypatch.setattr(jwt, "get_unverified_header", lambda token: {"kid": "kid-1"})
    monkeypatch.setattr(jwt, "decode", fake_decode)

    claims = cognito._verify_id_token_with_jwks(_cfg(), "id-token")

    assert claims["aud"] == "client-123"
    assert captured["issuer"] == "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_test"
    assert captured["options"]["verify_signature"] is True
    assert captured["options"]["verify_exp"] is True
    assert captured["options"]["verify_iss"] is True
    assert captured["options"]["verify_aud"] is False
    assert captured["options"]["verify_at_hash"] is False


def test_validate_id_token_accepts_cognito_id_token_aud_claim(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        cognito,
        "_verify_id_token_with_jwks",
        lambda cfg, token: {"sub": "sub-1", "email": "user@example.com", "aud": "client-123"},
    )

    claims = asyncio.run(cognito.validate_id_token(_cfg(), "id-token"))

    assert claims["sub"] == "sub-1"


def test_validate_id_token_rejects_wrong_audience(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        cognito,
        "_verify_id_token_with_jwks",
        lambda cfg, token: {"sub": "sub-1", "email": "user@example.com", "aud": "other-client"},
    )

    with pytest.raises(cognito.CognitoAuthError, match="invalid audience"):
        asyncio.run(cognito.validate_id_token(_cfg(), "id-token"))
