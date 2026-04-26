from __future__ import annotations

from typing import Any

from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer

SESSION_WS_TOKEN_SALT = "marvain-ws-session-v1"


def mint_ws_session_token(
    *,
    secret_key: str,
    user_id: str,
    cognito_sub: str,
    email: str | None,
) -> str:
    serializer = URLSafeTimedSerializer(secret_key=secret_key, salt=SESSION_WS_TOKEN_SALT)
    return serializer.dumps(
        {
            "typ": "marvain_ws_session",
            "user_id": str(user_id),
            "cognito_sub": str(cognito_sub),
            "email": email,
        }
    )


def verify_ws_session_token(*, secret_key: str, token: str, max_age: int = 3600) -> dict[str, Any]:
    serializer = URLSafeTimedSerializer(secret_key=secret_key, salt=SESSION_WS_TOKEN_SALT)
    try:
        payload = serializer.loads(str(token), max_age=max_age)
    except (BadSignature, SignatureExpired) as exc:
        raise PermissionError("Invalid session token") from exc
    if not isinstance(payload, dict) or payload.get("typ") != "marvain_ws_session":
        raise PermissionError("Invalid session token")
    if not payload.get("user_id") or not payload.get("cognito_sub"):
        raise PermissionError("Invalid session token")
    return payload
