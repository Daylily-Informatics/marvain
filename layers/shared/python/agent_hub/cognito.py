"""Marvain - AWS Cognito OIDC Authentication.

Provides OIDC login redirect URL builder, callback token exchange,
JWT validation with cached JWKs, and Cognito group-to-role mapping.

Adapted from lsmc-hub patterns.
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any
from urllib.parse import urlencode

if TYPE_CHECKING:
    from agent_hub.config import HubConfig

logger = logging.getLogger(__name__)

_daylily_jwks_cache: Any | None = None
_daylily_jwks_cache_key: tuple[str, str] | None = None


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


def _get_daylily_jwks_cache(cfg: HubConfig):
    """Get a reusable daylily-cognito JWKS cache for the configured pool."""
    global _daylily_jwks_cache, _daylily_jwks_cache_key

    region = str(cfg.cognito_region or "").strip()
    pool_id = str(cfg.cognito_user_pool_id or "").strip()
    cache_key = (region, pool_id)

    if _daylily_jwks_cache is None or _daylily_jwks_cache_key != cache_key:
        from daylily_cognito.jwks import JWKSCache

        _daylily_jwks_cache = JWKSCache(region, pool_id)
        _daylily_jwks_cache_key = cache_key

    return _daylily_jwks_cache


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
    if not cfg.cognito_authorize_url or not cfg.cognito_user_pool_client_id or not cfg.cognito_redirect_uri:
        raise CognitoAuthError("Cognito is not fully configured")

    params = {
        "client_id": cfg.cognito_user_pool_client_id,
        "response_type": "code",
        "scope": "openid email profile aws.cognito.signin.user.admin",
        "redirect_uri": cfg.cognito_redirect_uri,
    }
    if state:
        params["state"] = state

    return f"{cfg.cognito_authorize_url}?{urlencode(params)}"


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
    if not cfg.cognito_logout_url or not cfg.cognito_user_pool_client_id:
        raise CognitoAuthError("Cognito is not fully configured")

    # Default to /logged-out page (must be registered in Cognito LogoutURLs)
    logout_target = redirect_uri
    if not logout_target and cfg.cognito_redirect_uri:
        # Replace /auth/callback with /logged-out
        logout_target = cfg.cognito_redirect_uri.replace("/auth/callback", "/logged-out")

    params = {
        "client_id": cfg.cognito_user_pool_client_id,
        # Cognito logout endpoint accepts both 'logout_uri' and 'redirect_uri'
        # but some versions require 'redirect_uri', so we include both for compatibility
        "logout_uri": logout_target or "",
        "redirect_uri": logout_target or "",
    }
    return f"{cfg.cognito_logout_url}?{urlencode(params)}"


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
    import httpx

    if not cfg.cognito_token_url or not cfg.cognito_user_pool_client_id or not cfg.cognito_redirect_uri:
        raise CognitoAuthError("Cognito is not fully configured")

    data = {
        "grant_type": "authorization_code",
        "client_id": cfg.cognito_user_pool_client_id,
        "code": code,
        "redirect_uri": cfg.cognito_redirect_uri,
    }

    # Add client secret if configured
    if cfg.cognito_user_pool_client_secret:
        data["client_secret"] = cfg.cognito_user_pool_client_secret

    async with httpx.AsyncClient() as client:
        response = await client.post(
            cfg.cognito_token_url,
            data=data,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )

        if response.status_code != 200:
            logger.error(f"Token exchange failed: {response.text}")
            raise CognitoAuthError(f"Token exchange failed: {response.status_code}")

        return response.json()


async def validate_id_token(cfg: HubConfig, id_token: str) -> dict[str, Any]:
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
        from daylily_cognito.jwks import verify_token_with_jwks

        claims = await asyncio.to_thread(
            verify_token_with_jwks,
            id_token,
            str(cfg.cognito_region),
            str(cfg.cognito_user_pool_id),
            _get_daylily_jwks_cache(cfg),
        )
        audience = str(claims.get("aud") or claims.get("client_id") or "").strip()
        if audience != str(cfg.cognito_user_pool_client_id):
            raise CognitoAuthError("Token validation failed: invalid audience")

        return claims

    except CognitoAuthError:
        raise
    except Exception as e:
        msg = str(e)
        if "expired" in msg.lower():
            raise CognitoAuthError("Token has expired")
        raise CognitoAuthError(f"Token validation failed: {e}")


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
        access_token: Optional access token (not currently used)

    Returns:
        CognitoUserInfo with all extracted user data

    Raises:
        CognitoAuthError: If token validation fails
    """
    # Validate and decode ID token
    id_claims = await validate_id_token(cfg, id_token)

    # Extract basic user info
    sub = id_claims.get("sub", "")
    email = id_claims.get("email", "")
    name = id_claims.get("name") or id_claims.get("cognito:username")
    email_verified = id_claims.get("email_verified", False)

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
