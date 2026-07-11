from __future__ import annotations

import importlib.util
import os
import sys
from pathlib import Path
from unittest import mock

import pytest
from daylily_auth_cognito.browser.session import CONFIG_STATE_KEY, CognitoWebSessionConfig
from starlette.requests import Request

ROOT = Path(__file__).resolve().parents[1]


def _load_api_module():
    for path in (ROOT / "layers/shared/python", ROOT / "functions/hub_api"):
        if str(path) not in sys.path:
            sys.path.insert(0, str(path))
    os.environ.setdefault("AWS_DEFAULT_REGION", "us-east-1")
    os.environ.setdefault("DB_RESOURCE_ARN", "arn:aws:rds:us-east-1:123:cluster:test")
    os.environ.setdefault("DB_SECRET_ARN", "arn:aws:secretsmanager:us-east-1:123:secret:test")
    os.environ.setdefault("DB_NAME", "test")
    os.environ.setdefault("STAGE", "test")
    os.environ.setdefault("SESSION_SECRET_KEY", "api-auth-mode-test-secret")
    spec = importlib.util.spec_from_file_location("hub_api_auth_mode_tests", ROOT / "functions/hub_api/api_app.py")
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    with mock.patch("boto3.client", return_value=mock.Mock()):
        spec.loader.exec_module(module)
    return module


def _session_config() -> CognitoWebSessionConfig:
    return CognitoWebSessionConfig(
        domain="auth.example.test",
        client_id="client-1",
        redirect_uri="https://marvain.example.test/auth/callback",
        logout_uri="https://marvain.example.test/logged-out",
        session_secret_key="api-auth-mode-test-secret",
        session_cookie_name="marvain_session",
        server_instance_id="marvain-test",
    )


def _request(module, *, authorization: str | None = None) -> Request:
    headers = [] if authorization is None else [(b"authorization", authorization.encode("ascii"))]
    return Request(
        {
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
            "app": module.api_app,
            "session": {},
        }
    )


def test_bearer_header_selects_only_bearer_authentication(monkeypatch) -> None:
    module = _load_api_module()
    expected = module.AuthenticatedUser(user_id="user-1", cognito_sub="sub-1", email="user@example.test")
    bearer = mock.Mock(return_value=expected)
    browser = mock.Mock(side_effect=AssertionError("browser auth must not run"))
    monkeypatch.setattr(module, "authenticate_user_access_token", bearer)
    monkeypatch.setattr(module, "resolve_browser_session_user", browser)
    monkeypatch.setattr(module, "_get_db", lambda: object())

    assert module.get_user(_request(module, authorization="Bearer access-token")) == expected
    bearer.assert_called_once_with(mock.ANY, "access-token")
    browser.assert_not_called()


def test_invalid_bearer_never_retries_browser_session(monkeypatch) -> None:
    module = _load_api_module()
    browser = mock.Mock(side_effect=AssertionError("browser auth must not run"))
    monkeypatch.setattr(module, "authenticate_user_access_token", mock.Mock(side_effect=PermissionError("invalid")))
    monkeypatch.setattr(module, "resolve_browser_session_user", browser)
    monkeypatch.setattr(module, "_get_db", lambda: object())

    with pytest.raises(module.HTTPException) as exc_info:
        module.get_user(_request(module, authorization="Bearer invalid"))

    assert exc_info.value.status_code == 401
    browser.assert_not_called()


def test_absent_bearer_selects_only_registered_browser_session(monkeypatch) -> None:
    module = _load_api_module()
    config = _session_config()
    module.api_app.state.__dict__[CONFIG_STATE_KEY] = config
    expected = module.AuthenticatedUser(user_id="user-1", cognito_sub="sub-1", email="user@example.test")
    browser = mock.Mock(return_value=expected)
    bearer = mock.Mock(side_effect=AssertionError("bearer auth must not run"))
    monkeypatch.setattr(module, "resolve_browser_session_user", browser)
    monkeypatch.setattr(module, "authenticate_user_access_token", bearer)

    assert module.get_user(_request(module)) == expected
    bearer.assert_not_called()
    call = browser.call_args
    assert call.kwargs["registered_session_config"] is config
    assert call.kwargs["expected_server_instance_id"] == "marvain-test"
    assert callable(call.kwargs["ensure_user"])


def test_missing_browser_config_and_invalid_session_fail_without_bearer_retry(monkeypatch) -> None:
    module = _load_api_module()
    module.api_app.state.__dict__.pop(CONFIG_STATE_KEY, None)
    bearer = mock.Mock(side_effect=AssertionError("bearer auth must not run"))
    monkeypatch.setattr(module, "authenticate_user_access_token", bearer)

    with pytest.raises(module.HTTPException) as missing_config:
        module.get_user(_request(module))
    assert missing_config.value.status_code == 500

    module.api_app.state.__dict__[CONFIG_STATE_KEY] = _session_config()
    monkeypatch.setattr(
        module,
        "resolve_browser_session_user",
        mock.Mock(side_effect=module.BrowserSessionAuthenticationError("browser_session_missing", "missing")),
    )
    with pytest.raises(module.HTTPException) as invalid_session:
        module.get_user(_request(module))
    assert invalid_session.value.status_code == 401
    bearer.assert_not_called()
