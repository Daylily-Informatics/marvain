from __future__ import annotations

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
    cognito_user_pool_id: str | None
    cognito_user_pool_client_id: str | None
    cognito_domain: str | None
    livekit_url: str | None
    livekit_secret_arn: str | None


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
        cognito_user_pool_id=os.getenv("COGNITO_USER_POOL_ID"),
        # Prefer Daylily-Ursa naming, but keep backward-compat.
        cognito_user_pool_client_id=(
            os.getenv("COGNITO_APP_CLIENT_ID") or os.getenv("COGNITO_USER_POOL_CLIENT_ID")
        ),
        cognito_domain=os.getenv("COGNITO_DOMAIN"),
        livekit_url=os.getenv("LIVEKIT_URL"),
        livekit_secret_arn=os.getenv("LIVEKIT_SECRET_ARN"),
    )
