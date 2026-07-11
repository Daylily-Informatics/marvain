from __future__ import annotations

import sys
from pathlib import Path
from unittest import mock

import pytest
from daylily_auth_cognito.browser.session import CONFIG_STATE_KEY, CognitoWebSessionConfig
from fastapi import FastAPI
from starlette.requests import Request

_SHARED = Path(__file__).resolve().parents[1] / "layers" / "shared" / "python"
if str(_SHARED) not in sys.path:
    sys.path.insert(0, str(_SHARED))

from agent_hub.auth import AuthenticatedUser  # noqa: E402
from agent_hub.browser_session_auth import (  # noqa: E402
    BrowserSessionAuthenticationError,
    BrowserSessionConfigurationError,
    resolve_browser_session_user,
)

SERVER_INSTANCE_ID = "marvain-test"


def _session_config(*, server_instance_id: str = SERVER_INSTANCE_ID) -> CognitoWebSessionConfig:
    return CognitoWebSessionConfig(
        domain="auth.example.test",
        client_id="browser-client",
        redirect_uri="https://marvain.example.test/auth/callback",
        logout_uri="https://marvain.example.test/logged-out",
        session_secret_key="test-session-signing-secret",
        session_cookie_name="marvain_session",
        server_instance_id=server_instance_id,
    )


def _request(
    session: dict[str, object],
    *,
    config: CognitoWebSessionConfig | None = None,
    authorization: str | None = None,
) -> tuple[Request, CognitoWebSessionConfig]:
    app = FastAPI()
    registered_config = config or _session_config()
    app.state.__dict__[CONFIG_STATE_KEY] = registered_config
    headers = []
    if authorization is not None:
        headers.append((b"authorization", authorization.encode("ascii")))
    scope = {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": "GET",
        "scheme": "https",
        "path": "/v1/me",
        "raw_path": b"/v1/me",
        "query_string": b"",
        "root_path": "",
        "headers": headers,
        "client": ("127.0.0.1", 12345),
        "server": ("marvain.example.test", 443),
        "app": app,
        "session": session,
    }
    return Request(scope), registered_config


def _principal_session(**overrides: object) -> dict[str, object]:
    session: dict[str, object] = {
        "user_sub": "cognito-sub-1",
        "email": "user@example.test",
        "server_instance_id": SERVER_INSTANCE_ID,
        "app_context": {"user_id": "user-1"},
    }
    session.update(overrides)
    return session


def _resolve(
    request: Request,
    config: CognitoWebSessionConfig,
    *,
    ensure_user=None,
) -> AuthenticatedUser:
    return resolve_browser_session_user(
        request,
        registered_session_config=config,
        expected_server_instance_id=SERVER_INSTANCE_ID,
        ensure_user=ensure_user,
    )


def test_resolves_valid_registered_session_principal() -> None:
    request, config = _request(_principal_session())

    user = _resolve(request, config)

    assert user == AuthenticatedUser(
        user_id="user-1",
        cognito_sub="cognito-sub-1",
        email="user@example.test",
    )


def test_missing_session_fails_even_when_bearer_header_is_present() -> None:
    request, config = _request({}, authorization="Bearer must-not-be-read")
    ensure_user = mock.Mock()

    with pytest.raises(BrowserSessionAuthenticationError) as error:
        _resolve(request, config, ensure_user=ensure_user)

    assert error.value.code == "browser_session_missing"
    ensure_user.assert_not_called()


def test_malformed_session_state_is_rejected_and_cleared() -> None:
    request, config = _request(_principal_session(app_context=["not", "a", "mapping"]))

    with pytest.raises(BrowserSessionAuthenticationError) as error:
        _resolve(request, config)

    assert error.value.code == "browser_session_malformed"
    assert "user_sub" not in request.session


@pytest.mark.parametrize(
    ("field", "value"),
    [("user_sub", "  "), ("email", " user@example.test")],
)
def test_malformed_identity_fields_are_rejected(field: str, value: str) -> None:
    request, config = _request(_principal_session(**{field: value}))

    with pytest.raises(BrowserSessionAuthenticationError) as error:
        _resolve(request, config)

    assert error.value.code == "browser_session_malformed"


@pytest.mark.parametrize("token_key", ["access_token", "refreshToken", "nested-id-token"])
def test_token_like_app_context_keys_are_rejected_without_exposing_values(token_key: str) -> None:
    secret_value = "secret-value-that-must-not-appear"
    request, config = _request(
        _principal_session(
            app_context={"user_id": "user-1", "profile": [{token_key: secret_value}]},
        )
    )

    with pytest.raises(BrowserSessionAuthenticationError) as error:
        _resolve(request, config)

    assert error.value.code == "browser_session_token_material"
    assert secret_value not in str(error.value)
    assert request.session == {}


def test_top_level_oauth_token_state_is_rejected_and_cleared() -> None:
    request, config = _request(_principal_session(access_token="must-not-survive"))

    with pytest.raises(BrowserSessionAuthenticationError) as error:
        _resolve(request, config)

    assert error.value.code == "browser_session_token_material"
    assert request.session == {}


def test_principal_server_instance_mismatch_is_rejected() -> None:
    request, config = _request(_principal_session(server_instance_id="other-server"))

    with pytest.raises(BrowserSessionAuthenticationError) as error:
        _resolve(request, config)

    assert error.value.code == "browser_session_rejected"
    assert "user_sub" not in request.session


def test_supplied_config_must_be_the_registered_config_for_expected_instance() -> None:
    request, _ = _request(_principal_session())
    unregistered = _session_config()

    with pytest.raises(BrowserSessionConfigurationError) as error:
        _resolve(request, unregistered)

    assert error.value.code == "browser_session_config_unregistered"


def test_missing_user_id_requires_explicit_ensure_callback_and_persists_only_identity() -> None:
    request, config = _request(_principal_session(app_context={"tenant": "test-tenant"}))
    ensure_user = mock.Mock(return_value="ensured-user-1")

    first = _resolve(request, config, ensure_user=ensure_user)
    second = _resolve(request, config, ensure_user=ensure_user)

    assert first.user_id == "ensured-user-1"
    assert second == first
    ensure_user.assert_called_once_with(cognito_sub="cognito-sub-1", email="user@example.test")
    assert request.session["app_context"] == {
        "tenant": "test-tenant",
        "user_id": "ensured-user-1",
    }


def test_missing_user_id_without_ensure_callback_fails_hard() -> None:
    request, config = _request(_principal_session(app_context={}))

    with pytest.raises(BrowserSessionAuthenticationError) as error:
        _resolve(request, config)

    assert error.value.code == "browser_session_user_unresolved"


def test_ensure_callback_failure_does_not_modify_session() -> None:
    request, config = _request(_principal_session(app_context={"tenant": "test-tenant"}))
    original_context = dict(request.session["app_context"])

    with pytest.raises(BrowserSessionAuthenticationError) as error:
        _resolve(request, config, ensure_user=mock.Mock(side_effect=RuntimeError("database unavailable")))

    assert error.value.code == "browser_session_user_ensure_failed"
    assert request.session["app_context"] == original_context
