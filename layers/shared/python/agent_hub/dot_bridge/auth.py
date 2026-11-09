"""Cognito OAuth resource authentication for the Marvain MCP endpoint."""

from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import urlsplit

from daylily_auth_cognito.runtime.jwks import JWKSCache
from jose import JWTError, jwt

_SCOPE = re.compile(r"[\x21\x23-\x5B\x5D-\x7E]+")


class DotAuthenticationError(PermissionError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


@dataclass(frozen=True)
class DotOAuthConfig:
    cognito_region: str
    cognito_user_pool_id: str
    client_id: str
    resource_uri: str
    run_scope: str
    recall_scope: str
    update_scope: str

    def __post_init__(self) -> None:
        prefix, separator, pool = self.cognito_user_pool_id.partition("_")
        if not self.cognito_region or prefix != self.cognito_region or not separator or not pool:
            raise ValueError("The dot OAuth user pool must be in the configured Cognito region")
        if not self.client_id or self.client_id != self.client_id.strip():
            raise ValueError("The dot OAuth client ID is required")
        url = urlsplit(self.resource_uri)
        if url.scheme != "https" or not url.hostname or url.username or url.query or url.fragment or not url.path:
            raise ValueError("The dot MCP resource must be an absolute HTTPS endpoint with a path")
        if self.resource_uri != url.geturl() or not self.resource_uri.isascii() or '"' in self.resource_uri:
            raise ValueError("The dot MCP resource must be a canonical HTTPS URI")
        if any(_SCOPE.fullmatch(scope) is None for scope in self.scopes):
            raise ValueError("Each dot OAuth operation requires an explicit scope token")

    @property
    def issuer(self) -> str:
        return f"https://cognito-idp.{self.cognito_region}.amazonaws.com/{self.cognito_user_pool_id}"

    @property
    def scopes(self) -> tuple[str, ...]:
        return tuple(dict.fromkeys((self.run_scope, self.recall_scope, self.update_scope)))

    @property
    def metadata_path(self) -> str:
        return f"/.well-known/oauth-protected-resource{urlsplit(self.resource_uri).path}"

    @property
    def metadata_uri(self) -> str:
        resource = urlsplit(self.resource_uri)
        return f"{resource.scheme}://{resource.netloc}{self.metadata_path}"


@dataclass(frozen=True)
class DotOAuthPrincipal:
    """Verified linked-account identity, scoped to the configured OAuth client and resource."""

    issuer: str
    subject: str


class DotOAuthVerifier:
    def __init__(self, config: DotOAuthConfig) -> None:
        self.config = config
        self.jwks = JWKSCache(config.cognito_region, config.cognito_user_pool_id)

    def authenticate(self, authorization: str, required_scope: str) -> DotOAuthPrincipal:
        scheme, _, token = authorization.partition(" ")
        if scheme.lower() != "bearer" or not token or any(character.isspace() for character in token):
            raise DotAuthenticationError("invalid_token", "A linked account access token is required.")

        # daylily-auth-cognito 2.1.5's verifier supplies no audience to JOSE.
        # Its shared JWKS cache still owns key retrieval for audience-bound tokens.
        try:
            key_id = jwt.get_unverified_header(token).get("kid")
            if not isinstance(key_id, str) or not key_id:
                raise DotAuthenticationError("invalid_token", "The linked account access token is invalid.")
            key = self.jwks.get_key(key_id)
            claims = jwt.decode(
                token,
                key,
                algorithms=["RS256"],
                issuer=self.config.issuer,
                audience=self.config.resource_uri,
                options={"require_exp": True, "require_iss": True, "require_aud": True, "require_sub": True},
            )
        except (JWTError, KeyError) as exc:
            raise DotAuthenticationError("invalid_token", "The linked account access token is invalid.") from exc

        subject = claims["sub"]
        if claims.get("token_use") != "access" or claims.get("client_id") != self.config.client_id or not subject:
            raise DotAuthenticationError("invalid_token", "The linked account access token is invalid.")
        scopes = claims.get("scope")
        if not isinstance(scopes, str) or required_scope not in scopes.split():
            raise DotAuthenticationError("insufficient_scope", "The linked account must grant this tool's scope.")
        return DotOAuthPrincipal(issuer=claims["iss"], subject=subject)
