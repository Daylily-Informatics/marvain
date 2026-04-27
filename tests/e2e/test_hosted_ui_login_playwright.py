from __future__ import annotations

import os
import uuid

import pytest
from daylily_auth_cognito.admin.client import CognitoAdminClient
from daylily_auth_cognito.admin.passwords import set_user_password
from daylily_auth_cognito.admin.users import create_user, delete_user

pytestmark = pytest.mark.e2e


if os.getenv("MARVAIN_E2E_ENABLED", "0") != "1":
    pytest.skip("MARVAIN_E2E_ENABLED!=1", allow_module_level=True)

if os.getenv("MARVAIN_HOSTED_UI_E2E_ENABLED", "0") != "1":
    pytest.skip("MARVAIN_HOSTED_UI_E2E_ENABLED!=1", allow_module_level=True)


REQUIRED_ENV = [
    "MARVAIN_GUI_BASE_URL",
    "MARVAIN_COGNITO_USER_POOL_ID",
]


@pytest.fixture(scope="session", autouse=True)
def _required_env_present() -> None:
    missing = [k for k in REQUIRED_ENV if not os.getenv(k)]
    if missing:
        pytest.skip(f"Missing required hosted UI e2e env vars: {', '.join(missing)}")


@pytest.fixture()
def generated_cognito_user() -> tuple[str, str]:
    region = os.environ.get("AWS_REGION") or os.environ.get("AWS_DEFAULT_REGION") or "us-east-1"
    admin = CognitoAdminClient(
        region=region,
        aws_profile=os.environ.get("AWS_PROFILE"),
        user_pool_id=os.environ["MARVAIN_COGNITO_USER_POOL_ID"],
    )
    suffix = uuid.uuid4().hex
    domain = os.environ.get("MARVAIN_E2E_EMAIL_DOMAIN", "daylilyinformatics.com")
    email = f"marvain-e2e-{suffix}@{domain}"
    password = f"TestPass-{suffix[:12]}-Aa1!"

    create_user(admin, email=email, temporary_password=password, email_verified=True, suppress_message=True)
    set_user_password(admin, email=email, password=password, permanent=True)
    try:
        yield email, password
    finally:
        delete_user(admin, email=email)


def test_generated_email_user_can_login_through_cognito_hosted_ui(generated_cognito_user: tuple[str, str]) -> None:
    sync_api = pytest.importorskip("playwright.sync_api")
    email, password = generated_cognito_user
    gui_base_url = os.environ["MARVAIN_GUI_BASE_URL"].rstrip("/")
    headless = os.getenv("MARVAIN_PLAYWRIGHT_HEADLESS", "1") != "0"

    with sync_api.sync_playwright() as playwright:
        try:
            browser = playwright.chromium.launch(headless=headless)
        except Exception as exc:
            pytest.skip(f"Playwright Chromium is not installed or cannot launch: {exc}")
        context = browser.new_context(ignore_https_errors=True)
        page = context.new_page()
        try:
            page.goto(f"{gui_base_url}/", wait_until="domcontentloaded", timeout=30_000)
            page.wait_for_url("**amazoncognito.com/login**", timeout=30_000)

            username = page.locator("input#signInFormUsername:visible, input[name='username']:visible").first
            password_field = page.locator("input#signInFormPassword:visible, input[name='password']:visible").first
            submit = page.locator(
                "input[type='submit']:visible, button[type='submit']:visible, button[name='signInSubmitButton']:visible"
            ).first

            assert username.count() == 1
            assert password_field.count() == 1
            assert submit.count() == 1

            username.fill(email)
            password_field.fill(password)
            submit.click()

            page.wait_for_url(f"{gui_base_url}/**", timeout=45_000)
            body = page.locator("body").inner_text(timeout=10_000)
            assert "Authentication Error" not in body
            assert "Invalid state parameter" not in body
            assert "Invalid audience" not in body
            assert context.cookies(gui_base_url)
        finally:
            context.close()
            browser.close()
