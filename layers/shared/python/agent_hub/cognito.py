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
from urllib.parse import urlencode, urlsplit, urlunsplit

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
    """Get a reusable daylily-auth-cognito JWKS cache for the configured pool."""
    global _daylily_jwks_cache, _daylily_jwks_cache_key

    region = str(cfg.cognito_region or "").strip()
    pool_id = str(cfg.cognito_user_pool_id or "").strip()
    cache_key = (region, pool_id)

    if _daylily_jwks_cache is None or _daylily_jwks_cache_key != cache_key:
        from daylily_auth_cognito.runtime.jwks import JWKSCache

        _daylily_jwks_cache = JWKSCache(region, pool_id)
        _daylily_jwks_cache_key = cache_key

    return _daylily_jwks_cache


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

    url = build_authorization_url(
        domain=_domain(cfg),
        client_id=cfg.cognito_user_pool_client_id,
        redirect_uri=cfg.cognito_redirect_uri,
        response_type="code",
        scope="openid email profile aws.cognito.signin.user.admin",
        state=state,
    )
    identity_provider = str(getattr(cfg, "cognito_identity_provider", "") or "").strip()
    if not identity_provider:
        return url
    parts = urlsplit(url)
    query = f"{parts.query}&{urlencode({'identity_provider': identity_provider})}"
    return urlunsplit((parts.scheme, parts.netloc, parts.path, query, parts.fragment))


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

    expected_client_id = str(cfg.cognito_user_pool_client_id or "").strip()

    def _extract_audiences(claim_value: Any) -> list[str]:
        if isinstance(claim_value, str):
            v = claim_value.strip()
            return [v] if v else []
        if isinstance(claim_value, list):
            out: list[str] = []
            for item in claim_value:
                if item is None:
                    continue
                s = str(item).strip()
                if s:
                    out.append(s)
            return out
        return []

    try:
        from daylily_auth_cognito.runtime.jwks import verify_token_with_jwks

        cache = _get_daylily_jwks_cache(cfg)
        claims = await asyncio.to_thread(
            verify_token_with_jwks,
            id_token,
            str(cfg.cognito_region),
            str(cfg.cognito_user_pool_id),
            cache,
        )
        audiences = _extract_audiences(claims.get("aud")) + _extract_audiences(claims.get("client_id"))
        if expected_client_id not in audiences:
            raise CognitoAuthError(
                f"Token validation failed: invalid audience (expected={expected_client_id}, got={audiences})"
            )

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
    id_claims = await validate_id_token(cfg, id_token)
    if access_token:
        from daylily_auth_cognito.runtime.verifier import CognitoTokenVerifier

        verifier = CognitoTokenVerifier(
            region=str(cfg.cognito_region or "us-east-1"),
            user_pool_id=str(cfg.cognito_user_pool_id or ""),
            app_client_id=str(cfg.cognito_user_pool_client_id or ""),
        )
        access_claims = await asyncio.to_thread(verifier.verify_token, access_token)
        if str(access_claims.get("sub") or "") != str(id_claims.get("sub") or ""):
            raise CognitoAuthError("Token validation failed: access token subject mismatch")

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
