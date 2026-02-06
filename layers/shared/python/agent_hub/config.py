from __future__ import annotations

import json
import os
from dataclasses import dataclass


class ConfigError(RuntimeError):
    pass


def _req(name: str) -> str:
    v = os.getenv(name)
    if not v:
        raise ConfigError(f"Missing required env var: {name}")
    return v


@dataclass(frozen=True)
class HubConfig:
    stage: str
    db_resource_arn: str
    db_secret_arn: str
    db_name: str
    transcript_queue_url: str | None
    action_queue_url: str | None
    audit_bucket: str | None
    artifact_bucket: str | None
    admin_secret_arn: str | None
    openai_secret_arn: str | None
    planner_model: str | None
    # Cognito settings
    cognito_region: str
    cognito_user_pool_id: str | None
    cognito_user_pool_client_id: str | None
    cognito_user_pool_client_secret: str | None
    cognito_domain: str | None
    cognito_redirect_uri: str | None
    cognito_group_role_map: str | None  # JSON string: '{"admins": ["admin"]}'
    # Session settings
    session_secret_key: str | None  # Direct secret key (for local dev)
    session_secret_arn: str | None  # Secrets Manager ARN (for Lambda)
    # LiveKit settings
    livekit_url: str | None
    livekit_secret_arn: str | None
    # WebSocket API settings
    ws_api_url: str | None  # WebSocket API Gateway URL for real-time updates

    @property
    def cognito_issuer(self) -> str | None:
        """Get the Cognito issuer URL."""
        if not self.cognito_user_pool_id:
            return None
        return f"https://cognito-idp.{self.cognito_region}.amazonaws.com/{self.cognito_user_pool_id}"

    @property
    def cognito_jwks_url(self) -> str | None:
        """Get the Cognito JWKS URL."""
        issuer = self.cognito_issuer
        if not issuer:
            return None
        return f"{issuer}/.well-known/jwks.json"

    @property
    def cognito_authorize_url(self) -> str | None:
        """Get the Cognito authorization URL."""
        if not self.cognito_domain:
            return None
        return f"https://{self.cognito_domain}/oauth2/authorize"

    @property
    def cognito_token_url(self) -> str | None:
        """Get the Cognito token URL."""
        if not self.cognito_domain:
            return None
        return f"https://{self.cognito_domain}/oauth2/token"

    @property
    def cognito_logout_url(self) -> str | None:
        """Get the Cognito logout URL."""
        if not self.cognito_domain:
            return None
        return f"https://{self.cognito_domain}/logout"

    def get_cognito_group_role_mapping(self) -> dict[str, list[str]]:
        """Get the Cognito group-to-role mapping.

        Returns:
            Dict mapping Cognito group names to lists of application roles
        """
        if not self.cognito_group_role_map:
            return {}
        try:
            mapping = json.loads(self.cognito_group_role_map)
            if isinstance(mapping, dict):
                return mapping
        except json.JSONDecodeError:
            pass
        return {}


def load_config() -> HubConfig:
    return HubConfig(
        stage=os.getenv("STAGE", "dev"),
        db_resource_arn=_req("DB_RESOURCE_ARN"),
        db_secret_arn=_req("DB_SECRET_ARN"),
        db_name=_req("DB_NAME"),
        transcript_queue_url=os.getenv("TRANSCRIPT_QUEUE_URL"),
        action_queue_url=os.getenv("ACTION_QUEUE_URL"),
        audit_bucket=os.getenv("AUDIT_BUCKET"),
        artifact_bucket=os.getenv("ARTIFACT_BUCKET"),
        admin_secret_arn=os.getenv("ADMIN_SECRET_ARN"),
        openai_secret_arn=os.getenv("OPENAI_SECRET_ARN"),
        planner_model=os.getenv("PLANNER_MODEL"),
        # Cognito settings
        cognito_region=os.getenv("COGNITO_REGION", "us-east-1"),
        cognito_user_pool_id=os.getenv("COGNITO_USER_POOL_ID"),
        # Prefer Daylily-Ursa naming, but keep backward-compat.
        cognito_user_pool_client_id=(os.getenv("COGNITO_APP_CLIENT_ID") or os.getenv("COGNITO_USER_POOL_CLIENT_ID")),
        cognito_user_pool_client_secret=os.getenv("COGNITO_APP_CLIENT_SECRET"),
        cognito_domain=os.getenv("COGNITO_DOMAIN"),
        cognito_redirect_uri=os.getenv("COGNITO_REDIRECT_URI"),
        cognito_group_role_map=os.getenv("COGNITO_GROUP_ROLE_MAP"),
        # Session settings
        session_secret_key=os.getenv("SESSION_SECRET_KEY"),
        session_secret_arn=os.getenv("SESSION_SECRET_ARN"),
        # LiveKit settings
        livekit_url=os.getenv("LIVEKIT_URL"),
        livekit_secret_arn=os.getenv("LIVEKIT_SECRET_ARN"),
        # WebSocket API settings
        ws_api_url=os.getenv("WS_API_URL"),
    )
