from __future__ import annotations

import asyncio
import json
import os
import time
import uuid

import pytest
import requests
import websockets
from daylily_auth_cognito.admin.client import CognitoAdminClient

pytestmark = pytest.mark.e2e


if os.getenv("MARVAIN_E2E_ENABLED", "0") != "1":
    pytest.skip("MARVAIN_E2E_ENABLED!=1", allow_module_level=True)


REQUIRED_ENV = [
    "MARVAIN_HUB_REST_API_BASE",
    "MARVAIN_HUB_WS_URL",
    "MARVAIN_ADMIN_API_KEY",
    "MARVAIN_COGNITO_USER_POOL_CLIENT_ID",
    "MARVAIN_COGNITO_TEST_USERNAME",
    "MARVAIN_COGNITO_TEST_PASSWORD",
]


@pytest.fixture(scope="session", autouse=True)
def _required_env_present():
    missing = [k for k in REQUIRED_ENV if not os.getenv(k)]
    if missing:
        pytest.skip(f"Missing required e2e env vars: {', '.join(missing)}")


@pytest.fixture(scope="session")
def cfg() -> dict[str, str]:
    return {
        "rest_base": os.environ["MARVAIN_HUB_REST_API_BASE"].rstrip("/"),
        "ws_url": os.environ["MARVAIN_HUB_WS_URL"],
        "admin_key": os.environ["MARVAIN_ADMIN_API_KEY"],
        "client_id": os.environ["MARVAIN_COGNITO_USER_POOL_CLIENT_ID"],
        "username": os.environ["MARVAIN_COGNITO_TEST_USERNAME"],
        "password": os.environ["MARVAIN_COGNITO_TEST_PASSWORD"],
        "region": os.environ.get("AWS_REGION") or os.environ.get("AWS_DEFAULT_REGION") or "us-east-1",
    }


@pytest.fixture(scope="session")
def user_access_token(cfg: dict[str, str]) -> str:
    admin = CognitoAdminClient(region=cfg["region"], app_client_id=cfg["client_id"])
    resp = admin.cognito.initiate_auth(
        AuthFlow="USER_PASSWORD_AUTH",
        ClientId=cfg["client_id"],
        AuthParameters={
            "USERNAME": cfg["username"],
            "PASSWORD": cfg["password"],
        },
    )
    return str(resp["AuthenticationResult"]["AccessToken"])


def _post_json(url: str, *, headers: dict[str, str], body: dict) -> requests.Response:
    return requests.post(url, headers=headers, json=body, timeout=20)


def _bootstrap(cfg: dict[str, str]) -> dict[str, str]:
    suffix = uuid.uuid4().hex[:8]
    resp = _post_json(
        f"{cfg['rest_base']}/v1/admin/bootstrap",
        headers={"X-Admin-Key": cfg["admin_key"]},
        body={"agent_name": f"e2e-agent-{suffix}", "default_space_name": f"e2e-space-{suffix}"},
    )
    resp.raise_for_status()
    data = resp.json()
    return {
        "agent_id": data["agent_id"],
        "space_id": data["space_id"],
        "device_id": data["device_id"],
        "device_token": data["device_token"],
    }


def _claim_owner(cfg: dict[str, str], *, agent_id: str, access_token: str) -> None:
    resp = _post_json(
        f"{cfg['rest_base']}/v1/agents/{agent_id}/claim_owner",
        headers={"Authorization": f"Bearer {access_token}"},
        body={},
    )
    resp.raise_for_status()


async def _recv_until(ws, predicate, *, timeout_s: float = 20.0) -> dict:
    end = time.time() + timeout_s
    while time.time() < end:
        msg = json.loads(await asyncio.wait_for(ws.recv(), timeout=end - time.time()))
        if predicate(msg):
            return msg
    raise TimeoutError("Timed out waiting for WS message")


def test_user_ws_receives_events_new(cfg: dict[str, str], user_access_token: str):
    ids = _bootstrap(cfg)
    _claim_owner(cfg, agent_id=ids["agent_id"], access_token=user_access_token)

    async def _scenario():
        async with websockets.connect(cfg["ws_url"]) as ws:
            await ws.send(json.dumps({"action": "hello", "access_token": user_access_token}))
            hello = await _recv_until(ws, lambda m: m.get("type") == "hello")
            assert hello.get("ok") is True

            await ws.send(json.dumps({"action": "subscribe_events", "agent_id": ids["agent_id"]}))
            sub = await _recv_until(ws, lambda m: m.get("type") == "subscribe_events")
            assert sub.get("ok") is True

            ingest = _post_json(
                f"{cfg['rest_base']}/v1/events",
                headers={"Authorization": f"Bearer {ids['device_token']}"},
                body={
                    "space_id": ids["space_id"],
                    "type": "transcript_chunk",
                    "payload": {"text": "e2e websocket event test"},
                },
            )
            ingest.raise_for_status()

            msg = await _recv_until(ws, lambda m: m.get("type") == "events.new")
            assert msg.get("agent_id") == ids["agent_id"]
            assert msg.get("payload", {}).get("event", {}).get("type") == "transcript_chunk"

    asyncio.run(_scenario())


def test_rotate_token_invalidates_old_token_for_rest_and_ws(cfg: dict[str, str], user_access_token: str):
    ids = _bootstrap(cfg)
    _claim_owner(cfg, agent_id=ids["agent_id"], access_token=user_access_token)

    rotate = _post_json(
        f"{cfg['rest_base']}/v1/devices/{ids['device_id']}/rotate-token",
        headers={"Authorization": f"Bearer {user_access_token}"},
        body={},
    )
    rotate.raise_for_status()
    new_token = rotate.json()["device_token"]

    old_token_resp = _post_json(
        f"{cfg['rest_base']}/v1/events",
        headers={"Authorization": f"Bearer {ids['device_token']}"},
        body={
            "space_id": ids["space_id"],
            "type": "transcript_chunk",
            "payload": {"text": "old token should fail"},
        },
    )
    assert old_token_resp.status_code == 401

    new_token_resp = _post_json(
        f"{cfg['rest_base']}/v1/events",
        headers={"Authorization": f"Bearer {new_token}"},
        body={
            "space_id": ids["space_id"],
            "type": "transcript_chunk",
            "payload": {"text": "new token should pass"},
        },
    )
    new_token_resp.raise_for_status()

    async def _scenario():
        async with websockets.connect(cfg["ws_url"]) as ws:
            await ws.send(json.dumps({"action": "hello", "device_token": ids["device_token"]}))
            old_hello = await _recv_until(ws, lambda m: m.get("type") == "hello")
            assert old_hello.get("ok") is False
            assert old_hello.get("error") == "invalid_device_token"

    asyncio.run(_scenario())
