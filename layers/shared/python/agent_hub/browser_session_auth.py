"""Strict browser-session authentication for canonical Marvain APIs."""

from __future__ import annotations

import re
from collections.abc import Callable, Mapping, Sequence
from dataclasses import replace
from typing import Any

from daylily_auth_cognito.browser.session import (
    CONFIG_STATE_KEY,
    CognitoWebSessionConfig,
    load_session_principal,
)
from starlette.requests import Request

from agent_hub.auth import AuthenticatedUser
from agent_hub.auth_policy import require_allowed_human_email
from agent_hub.config import load_config

EnsureUser = Callable[..., str]


class BrowserSessionConfigurationError(RuntimeError):
    """The server has not registered the required browser-session contract."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


class BrowserSessionAuthenticationError(PermissionError):
    """The request does not carry an acceptable browser-session principal."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


def _clean_required_string(value: Any, *, field: str) -> str:
    if not isinstance(value, str) or not value or value != value.strip():
        raise BrowserSessionAuthenticationError(
            "browser_session_malformed",
            f"Browser session principal contains malformed {field}",
        )
    return value


def _normalized_key(value: Any) -> str:
    return re.sub(r"[^a-z0-9]+", "_", str(value).strip().lower()).strip("_")


def _reject_token_like_keys(value: Any, *, path: str = "app_context") -> None:
    if isinstance(value, Mapping):
        for raw_key, nested in value.items():
            key = _normalized_key(raw_key)
            if "token" in key:
                raise BrowserSessionAuthenticationError(
                    "browser_session_token_material",
                    f"Browser session {path} contains a token-like key",
                )
            _reject_token_like_keys(nested, path=f"{path}.{key or '<empty>'}")
        return
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        for index, nested in enumerate(value):
            _reject_token_like_keys(nested, path=f"{path}[{index}]")


def _validate_registered_config(
    request: Request,
    *,
    registered_session_config: CognitoWebSessionConfig,
    expected_server_instance_id: str,
) -> None:
    expected = expected_server_instance_id.strip()
    if not expected or expected != expected_server_instance_id:
        raise BrowserSessionConfigurationError(
            "browser_session_server_instance_unconfigured",
            "Expected browser-session server instance is not configured",
        )
    if not isinstance(registered_session_config, CognitoWebSessionConfig):
        raise BrowserSessionConfigurationError(
            "browser_session_config_invalid",
            "Browser-session configuration has the wrong type",
        )

    state = getattr(getattr(request, "app", None), "state", None)
    registered = None if state is None else state.__dict__.get(CONFIG_STATE_KEY)
    if registered is not registered_session_config:
        raise BrowserSessionConfigurationError(
            "browser_session_config_unregistered",
            "The supplied browser-session configuration is not registered on the request app",
        )
    if registered_session_config.server_instance_id != expected:
        raise BrowserSessionConfigurationError(
            "browser_session_server_instance_unconfigured",
            "Registered browser-session configuration does not match the expected server instance",
        )


def resolve_browser_session_user(
    request: Request,
    *,
    registered_session_config: CognitoWebSessionConfig,
    expected_server_instance_id: str,
    ensure_user: EnsureUser | None = None,
) -> AuthenticatedUser:
    """Resolve a signed browser session to a canonical Marvain user.

    The caller must first register ``registered_session_config`` on the request
    app through the daylily-auth-cognito browser-session setup path. Its
    ``server_instance_id`` must equal ``expected_server_instance_id``. This
    boundary intentionally does not inspect bearer authorization headers.

    ``ensure_user`` is required only when the signed principal has no Marvain
    ``app_context.user_id``. It is called with keyword arguments
    ``cognito_sub`` and ``email`` and must return the persisted Marvain user ID.
    """

    _validate_registered_config(
        request,
        registered_session_config=registered_session_config,
        expected_server_instance_id=expected_server_instance_id,
    )

    try:
        principal = load_session_principal(request)
    except AssertionError as exc:
        raise BrowserSessionConfigurationError(
            "browser_session_middleware_missing",
            "SessionMiddleware did not provide request session state",
        ) from exc
    except RuntimeError as exc:
        raise BrowserSessionConfigurationError(
            "browser_session_config_unregistered",
            "Shared browser-session configuration is not registered",
        ) from exc

    if principal is None:
        reason = getattr(request.state, "cognito_auth_reason", None)
        if reason == "invalid_session":
            code = "browser_session_malformed"
            message = "Browser session state is malformed"
        elif reason:
            code = "browser_session_rejected"
            message = "Browser session principal was rejected"
        else:
            code = "browser_session_missing"
            message = "Browser session principal is missing"
        raise BrowserSessionAuthenticationError(code, message)

    try:
        _reject_token_like_keys(request.session, path="session")
    except BrowserSessionAuthenticationError:
        request.session.clear()
        request.state.cognito_session_principal = None
        raise

    user_sub = _clean_required_string(principal.user_sub, field="user_sub")
    email = _clean_required_string(principal.email, field="email")
    app_context = principal.app_context
    if not isinstance(app_context, Mapping):
        raise BrowserSessionAuthenticationError(
            "browser_session_malformed",
            "Browser session app_context must be a mapping",
        )
    _reject_token_like_keys(app_context)

    try:
        require_allowed_human_email(
            email=email,
            email_verified=app_context.get("email_verified"),
            allowed_domains=load_config().auth_allowed_email_domains,
        )
    except PermissionError as exc:
        raise BrowserSessionAuthenticationError(
            "browser_session_email_not_allowed", "A verified email in an allowed domain is required"
        ) from exc
    except RuntimeError as exc:
        raise BrowserSessionConfigurationError(
            "browser_session_email_policy_unconfigured", "Human email-domain policy is not configured"
        ) from exc

    if "user_id" in app_context:
        user_id = _clean_required_string(app_context["user_id"], field="app_context.user_id")
    else:
        if ensure_user is None:
            raise BrowserSessionAuthenticationError(
                "browser_session_user_unresolved",
                "Browser session principal has no Marvain user ID",
            )
        try:
            ensured_user_id = ensure_user(cognito_sub=user_sub, email=email)
        except Exception as exc:
            raise BrowserSessionAuthenticationError(
                "browser_session_user_ensure_failed",
                "Marvain user resolution failed",
            ) from exc
        user_id = _clean_required_string(ensured_user_id, field="ensured user_id")
        updated_context = dict(app_context)
        updated_context["user_id"] = user_id
        _reject_token_like_keys(updated_context)
        request.session["app_context"] = updated_context
        request.state.cognito_session_principal = replace(principal, app_context=updated_context)

    return AuthenticatedUser(user_id=user_id, cognito_sub=user_sub, email=email)
