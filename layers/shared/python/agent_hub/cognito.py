"""Marvain - AWS Cognito OIDC Authentication.

Provides OIDC login redirect URL builder, callback token exchange,
JWT validation with cached JWKs, and Cognito group-to-role mapping.

Adapted from lsmc-hub patterns.
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass
from functools import lru_cache
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from agent_hub.config import HubConfig

logger = logging.getLogger(__name__)

class CognitoAuthError(Exception):
    """Raised when Cognito authentication fails."""

    pass


@dataclass
class CognitoUserInfo:
    """User information extracted from Cognito tokens."""

    sub: str  # Cognito subject (unique user ID)
    email: str
    name: str | None
    cognito_groups: list[str]  # Raw Cognito group names
    roles: list[str]  # Mapped application roles
    email_verified: bool = False

    @property
    def display_name(self) -> str:
        """Return display name, falling back to email."""
        return self.name or self.email or self.sub


@lru_cache(maxsize=16)
def _configured_verifier(region: str, user_pool_id: str, app_client_id: str):
    """Reuse the owning library's verifier and its JWKS cache per pool/client."""
    from daylily_auth_cognito import CognitoTokenVerifier

    return CognitoTokenVerifier(region=region, user_pool_id=user_pool_id, app_client_id=app_client_id)


def _token_verifier(cfg: HubConfig):
    region = str(cfg.cognito_region or "").strip()
    user_pool_id = str(cfg.cognito_user_pool_id or "").strip()
    app_client_id = str(cfg.cognito_user_pool_client_id or "").strip()
    if not region or not user_pool_id or not app_client_id:
        raise CognitoAuthError("Cognito token verifier is not fully configured")
    return _configured_verifier(region, user_pool_id, app_client_id)


def _domain(cfg: HubConfig) -> str:
    return str(cfg.cognito_domain or "").strip()


def build_login_url(cfg: HubConfig, state: str | None = None) -> str:
    """Build the Cognito OIDC authorization URL for login redirect.

    Args:
        cfg: Hub configuration
        state: Optional state parameter for CSRF protection

    Returns:
        Full authorization URL to redirect the user to

    Raises:
        CognitoAuthError: If Cognito is not configured
    """
    if not cfg.cognito_domain or not cfg.cognito_user_pool_client_id or not cfg.cognito_redirect_uri:
        raise CognitoAuthError("Cognito is not fully configured")

    from daylily_auth_cognito.browser.oauth import build_authorization_url

    identity_provider = str(getattr(cfg, "cognito_identity_provider", "") or "").strip()
    return build_authorization_url(
        domain=_domain(cfg),
        client_id=cfg.cognito_user_pool_client_id,
        redirect_uri=cfg.cognito_redirect_uri,
        response_type="code",
        scope="openid email profile aws.cognito.signin.user.admin",
        state=state,
        identity_provider=identity_provider or None,
    )


def build_logout_url(cfg: HubConfig, redirect_uri: str | None = None) -> str:
    """Build the Cognito logout URL.

    Args:
        cfg: Hub configuration
        redirect_uri: URL to redirect to after logout

    Returns:
        Full logout URL

    Raises:
        CognitoAuthError: If Cognito is not configured
    """
    if not cfg.cognito_domain or not cfg.cognito_user_pool_client_id:
        raise CognitoAuthError("Cognito is not fully configured")

    # Default to /logged-out page (must be registered in Cognito LogoutURLs)
    logout_target = redirect_uri
    if not logout_target and cfg.cognito_redirect_uri:
        # Replace /auth/callback with /logged-out
        logout_target = cfg.cognito_redirect_uri.replace("/auth/callback", "/logged-out")

    from daylily_auth_cognito.browser.oauth import build_logout_url as build_cognito_logout_url

    return build_cognito_logout_url(
        domain=_domain(cfg),
        client_id=cfg.cognito_user_pool_client_id,
        logout_uri=logout_target or "",
    )


async def exchange_code_for_tokens(cfg: HubConfig, code: str) -> dict[str, Any]:
    """Exchange authorization code for tokens.

    Args:
        cfg: Hub configuration
        code: The authorization code from the callback

    Returns:
        Token response containing access_token, id_token, refresh_token

    Raises:
        CognitoAuthError: If token exchange fails
    """
    if not cfg.cognito_domain or not cfg.cognito_user_pool_client_id or not cfg.cognito_redirect_uri:
        raise CognitoAuthError("Cognito is not fully configured")

    from daylily_auth_cognito.browser.oauth import exchange_authorization_code_async

    try:
        return await exchange_authorization_code_async(
            domain=_domain(cfg),
            client_id=cfg.cognito_user_pool_client_id,
            code=code,
            redirect_uri=cfg.cognito_redirect_uri,
            client_secret=cfg.cognito_user_pool_client_secret,
        )
    except Exception as exc:
        raise CognitoAuthError(f"Token exchange failed: {exc}") from exc


async def validate_id_token(
    cfg: HubConfig, id_token: str, *, access_token: str | None = None,
) -> dict[str, Any]:
    """Validate a Cognito ID token and return its claims.

    Args:
        cfg: Hub configuration
        id_token: The JWT ID token to validate

    Returns:
        Token claims (sub, email, name, etc.)

    Raises:
        CognitoAuthError: If token validation fails
    """
    if not cfg.cognito_user_pool_id or not cfg.cognito_issuer or not cfg.cognito_user_pool_client_id:
        raise CognitoAuthError("Cognito is not fully configured")

    try:
        verifier = _token_verifier(cfg)
        return await asyncio.to_thread(verifier.verify_id_token, id_token, access_token=access_token)
    except CognitoAuthError:
        raise
    except Exception as exc:
        raise CognitoAuthError("ID token validation failed") from exc


def extract_cognito_groups(claims: dict[str, Any]) -> list[str]:
    """Extract Cognito User Pool groups from token claims."""
    groups = claims.get("cognito:groups", [])
    if isinstance(groups, list):
        return groups
    return []


async def get_user_info_from_tokens(cfg: HubConfig, id_token: str, access_token: str | None = None) -> CognitoUserInfo:
    """Extract complete user information from Cognito tokens.

    Validates the ID token, extracts user claims, maps Cognito groups
    to application roles, and returns a structured user info object.

    Args:
        cfg: Hub configuration
        id_token: The JWT ID token from Cognito
        access_token: Access token from the same authorization-code exchange

    Returns:
        CognitoUserInfo with all extracted user data

    Raises:
        CognitoAuthError: If token validation fails
    """
    id_claims = await validate_id_token(cfg, id_token, access_token=access_token)
    if access_token:
        try:
            access_claims = await asyncio.to_thread(_token_verifier(cfg).verify_token, access_token)
        except Exception as exc:
            raise CognitoAuthError("Access token validation failed") from exc
        if str(access_claims.get("sub") or "") != str(id_claims.get("sub") or ""):
            raise CognitoAuthError("Token validation failed: access token subject mismatch")

    # Extract basic user info
    sub = id_claims.get("sub", "")
    email = id_claims.get("email", "")
    name = id_claims.get("name") or id_claims.get("cognito:username")
    email_verified = id_claims.get("email_verified", False)
    from agent_hub.auth_policy import require_allowed_human_email

    try:
        email = require_allowed_human_email(email=email, email_verified=email_verified,
                                            allowed_domains=cfg.auth_allowed_email_domains)
    except PermissionError as exc:
        raise CognitoAuthError("A verified email in an allowed domain is required") from exc

    # Extract Cognito groups
    cognito_groups = extract_cognito_groups(id_claims)

    # Map Cognito groups to application roles
    group_role_mapping = cfg.get_cognito_group_role_mapping()
    roles: list[str] = []
    for group in cognito_groups:
        if group in group_role_mapping:
            roles.extend(group_role_mapping[group])

    # Deduplicate roles
    roles = list(dict.fromkeys(roles))

    logger.info(f"Cognito login for {email} ({sub}), groups={cognito_groups}, roles={roles}")

    return CognitoUserInfo(
        sub=sub,
        email=email,
        name=name,
        cognito_groups=cognito_groups,
        roles=roles,
        email_verified=email_verified,
    )
