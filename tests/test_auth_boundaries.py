from __future__ import annotations

from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]


def _read(path: str) -> str:
    return (REPO_ROOT / path).read_text(encoding="utf-8")


def test_hub_api_uses_current_daylily_auth_cognito_dependency() -> None:
    requirements = _read("functions/hub_api/requirements.txt")

    assert "daylily-auth-cognito==2.1.5" in requirements
    assert "daylily-auth-cognito==2.1.4" not in requirements
    assert "daylily-auth-cognito==2.0.1" not in requirements
    assert "python-jose[cryptography]" not in requirements


def test_ws_message_packages_browser_session_and_cognito_auth_dependencies() -> None:
    requirements = _read("functions/ws_message/requirements.txt")

    assert "itsdangerous" in requirements
    assert "daylily-auth-cognito==2.1.5" in requirements
    assert "daylily-auth-cognito==2.1.4" not in requirements
    assert "python-jose[cryptography]" not in requirements


def test_service_code_does_not_import_daylily_auth_cognito_cli() -> None:
    service_roots = [
        REPO_ROOT / "functions",
        REPO_ROOT / "layers" / "shared" / "python",
        REPO_ROOT / "apps",
    ]
    offenders: list[str] = []
    for root in service_roots:
        for path in root.rglob("*.py"):
            text = path.read_text(encoding="utf-8", errors="ignore")
            if "daylily_auth_cognito.cli" in text:
                offenders.append(str(path.relative_to(REPO_ROOT)))

    assert offenders == []


def test_runtime_and_browser_auth_boundaries_are_used() -> None:
    auth_text = _read("layers/shared/python/agent_hub/auth.py")
    cognito_text = _read("layers/shared/python/agent_hub/cognito.py")
    app_text = _read("functions/hub_api/app.py")

    assert "daylily_auth_cognito.runtime.verifier" in auth_text
    assert "daylily_auth_cognito.runtime.jwks" in cognito_text
    assert "from jose import" not in cognito_text
    assert "daylily_auth_cognito.browser.session" in app_text


def test_gui_does_not_store_raw_oauth_token_cookies() -> None:
    app_text = _read("functions/hub_api/app.py")

    assert "marvain_access_token" not in app_text
    assert "marvain_refresh_token" not in app_text
    assert "refresh_token" not in app_text
    assert "Token refresh" not in app_text
