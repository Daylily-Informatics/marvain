"""Marvain - AWS Cognito OIDC Authentication.

Provides OIDC login redirect URL builder, callback token exchange,
JWT validation with cached JWKs, and Cognito group-to-role mapping.

Adapted from lsmc-hub patterns.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any
from urllib.parse import urlencode

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


class JWKSCache:
    """Cache for Cognito JWKS (JSON Web Key Set)."""

    def __init__(self, ttl_seconds: int = 3600):
        self._jwks: dict[str, Any] | None = None
        self._fetched_at: float = 0
        self._ttl = ttl_seconds

    def _is_expired(self) -> bool:
        return time.time() - self._fetched_at > self._ttl

    async def get_jwks(self, jwks_url: str) -> dict[str, Any]:
        """Get JWKS, fetching from Cognito if expired or not cached."""
        if self._jwks is None or self._is_expired():
            await self._fetch_jwks(jwks_url)
        return self._jwks  # type: ignore

    async def _fetch_jwks(self, jwks_url: str) -> None:
        """Fetch JWKS from Cognito."""
        import httpx

        async with httpx.AsyncClient() as client:
            response = await client.get(jwks_url)
            response.raise_for_status()
            self._jwks = response.json()
            self._fetched_at = time.time()
            logger.debug(f"Fetched JWKS from {jwks_url}")


# Global JWKS cache instance
_jwks_cache = JWKSCache()


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
        "scope": "openid email profile",
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

    # Default to base URL (without /auth/callback)
    logout_target = redirect_uri
    if not logout_target and cfg.cognito_redirect_uri:
        logout_target = cfg.cognito_redirect_uri.replace("/auth/callback", "")

    params = {
        "client_id": cfg.cognito_user_pool_client_id,
        "logout_uri": logout_target or "",
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
    from jose import JWTError, jwt
    from jose.exceptions import ExpiredSignatureError

    if not cfg.cognito_jwks_url or not cfg.cognito_issuer or not cfg.cognito_user_pool_client_id:
        raise CognitoAuthError("Cognito is not fully configured")

    try:
        # Get unverified header to find the key ID
        unverified_header = jwt.get_unverified_header(id_token)
        kid = unverified_header.get("kid")

        if not kid:
            raise CognitoAuthError("Token missing key ID (kid)")

        # Get JWKS and find the matching key
        jwks = await _jwks_cache.get_jwks(cfg.cognito_jwks_url)
        key = None
        for k in jwks.get("keys", []):
            if k.get("kid") == kid:
                key = k
                break

        if not key:
            # Key not found - refresh cache and try again
            await _jwks_cache._fetch_jwks(cfg.cognito_jwks_url)
            jwks = await _jwks_cache.get_jwks(cfg.cognito_jwks_url)
            for k in jwks.get("keys", []):
                if k.get("kid") == kid:
                    key = k
                    break

        if not key:
            raise CognitoAuthError(f"Unable to find key with kid: {kid}")

        # Validate the token
        claims = jwt.decode(
            id_token,
            key,
            algorithms=["RS256"],
            audience=cfg.cognito_user_pool_client_id,
            issuer=cfg.cognito_issuer,
            options={"verify_at_hash": False},
        )

        return claims

    except ExpiredSignatureError:
        raise CognitoAuthError("Token has expired")
    except JWTError as e:
        raise CognitoAuthError(f"Token validation failed: {e}")


def extract_cognito_groups(claims: dict[str, Any]) -> list[str]:
    """Extract Cognito User Pool groups from token claims."""
    groups = claims.get("cognito:groups", [])
    if isinstance(groups, list):
        return groups
    return []


async def get_user_info_from_tokens(
    cfg: HubConfig, id_token: str, access_token: str | None = None
) -> CognitoUserInfo:
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

    logger.info(
        f"Cognito login for {email} ({sub}), groups={cognito_groups}, roles={roles}"
    )

    return CognitoUserInfo(
        sub=sub,
        email=email,
        name=name,
        cognito_groups=cognito_groups,
        roles=roles,
        email_verified=email_verified,
    )

