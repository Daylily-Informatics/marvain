from __future__ import annotations

import io
import os
import uuid
from pathlib import Path
from unittest import mock

import pytest
from daylily_auth_cognito.admin.client import CognitoAdminClient
from daylily_auth_cognito.admin.passwords import set_user_password
from daylily_auth_cognito.admin.users import create_user, delete_user

from marvain_cli.config import ResolvedEnv
from marvain_cli.ops import Ctx, resolve_user_access_token

pytestmark = pytest.mark.e2e


if os.getenv("MARVAIN_E2E_ENABLED", "0") != "1":
    pytest.skip("MARVAIN_E2E_ENABLED!=1", allow_module_level=True)

if os.getenv("MARVAIN_COGNITO_PASSWORD_E2E_ENABLED", "0") != "1":
    pytest.skip("MARVAIN_COGNITO_PASSWORD_E2E_ENABLED!=1", allow_module_level=True)


REQUIRED_ENV = [
    "MARVAIN_COGNITO_USER_POOL_ID",
    "MARVAIN_COGNITO_APP_CLIENT_ID",
]


@pytest.fixture(scope="session", autouse=True)
def _required_env_present() -> None:
    missing = [key for key in REQUIRED_ENV if not os.getenv(key)]
    if missing:
        pytest.skip(f"Missing required Cognito password E2E env vars: {', '.join(missing)}")


@pytest.fixture()
def generated_cognito_user() -> tuple[str, str]:
    region = os.environ.get("AWS_REGION") or os.environ.get("AWS_DEFAULT_REGION") or "us-east-1"
    user_pool_id = os.environ["MARVAIN_COGNITO_USER_POOL_ID"]
    admin = CognitoAdminClient(
        region=region,
        aws_profile=os.environ.get("AWS_PROFILE"),
        user_pool_id=user_pool_id,
    )
    suffix = uuid.uuid4().hex
    domain = os.environ.get("MARVAIN_E2E_EMAIL_DOMAIN", "example.test")
    email = f"marvain-password-e2e-{suffix}@{domain}"
    password = f"TestPass-{suffix[:12]}-Aa1!"

    create_user(admin, email=email, temporary_password=password, email_verified=True, suppress_message=True)
    set_user_password(admin, email=email, password=password, permanent=True)
    try:
        yield email, password
    finally:
        delete_user(admin, email=email)


def test_generated_user_authenticates_through_password_stdin(generated_cognito_user: tuple[str, str]) -> None:
    email, password = generated_cognito_user
    region = os.environ.get("AWS_REGION") or os.environ.get("AWS_DEFAULT_REGION") or "us-east-1"
    user_pool_id = os.environ["MARVAIN_COGNITO_USER_POOL_ID"]
    app_client_id = os.environ["MARVAIN_COGNITO_APP_CLIENT_ID"]
    resources = {
        "CognitoUserPoolId": user_pool_id,
        "CognitoAppClientId": app_client_id,
    }
    ctx = Ctx(
        config_path=Path("/tmp/marvain-cognito-password-e2e.yaml"),
        cfg={"envs": {"cleanroom": {"resources": resources}}},
        env=ResolvedEnv(
            env="cleanroom",
            aws_profile=os.environ.get("AWS_PROFILE") or "",
            aws_region=region,
            stack_name="marvain-cognito-password-e2e",
            raw={"resources": resources},
        ),
    )

    with mock.patch("sys.stdin", io.StringIO(f"{password}\n")):
        access_token = resolve_user_access_token(
            ctx,
            access_token=None,
            cognito_email=email,
            password_stdin=True,
            dry_run=False,
        )

    assert access_token
