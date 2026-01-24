from __future__ import annotations

import json
import os

import boto3

from agent_hub.auth import authenticate_device
from agent_hub.rds_data import RdsData, RdsDataEnv

_TABLE = os.getenv("WS_TABLE")
_dynamo = boto3.resource("dynamodb")

_db = None


def _get_db() -> RdsData:
    global _db
    if _db is None:
        _db = RdsData(RdsDataEnv(
            resource_arn=os.environ["DB_RESOURCE_ARN"],
            secret_arn=os.environ["DB_SECRET_ARN"],
            database=os.environ["DB_NAME"],
        ))
    return _db


def _mgmt_api(event):
    domain = event.get("requestContext", {}).get("domainName")
    stage = event.get("requestContext", {}).get("stage")
    endpoint_url = f"https://{domain}/{stage}"
    return boto3.client("apigatewaymanagementapi", endpoint_url=endpoint_url)


def _send(event, connection_id: str, payload: dict):
    data = json.dumps(payload).encode("utf-8")
    _mgmt_api(event).post_to_connection(ConnectionId=connection_id, Data=data)


def handler(event, context):
    if not _TABLE:
        return {"statusCode": 500, "body": "WS_TABLE not configured"}

    connection_id = event.get("requestContext", {}).get("connectionId")
    if not connection_id:
        return {"statusCode": 400, "body": "Missing connectionId"}

    body = event.get("body") or "{}"
    try:
        msg = json.loads(body)
    except Exception:
        _send(event, connection_id, {"type": "error", "error": "invalid_json"})
        return {"statusCode": 200, "body": "ok"}

    action = msg.get("action") or ""
    table = _dynamo.Table(_TABLE)

    if action == "hello":
        token = str(msg.get("device_token") or "").strip()
        if not token:
            _send(event, connection_id, {"type": "hello", "ok": False, "error": "missing_device_token"})
            return {"statusCode": 200, "body": "ok"}

        dev = authenticate_device(_get_db(), token)
        if not dev:
            _send(event, connection_id, {"type": "hello", "ok": False, "error": "invalid_device_token"})
            return {"statusCode": 200, "body": "ok"}

        table.update_item(
            Key={"connection_id": connection_id},
            UpdateExpression="SET #s=:s, agent_id=:a, device_id=:d, scopes=:sc",
            ExpressionAttributeNames={"#s": "status"},
            ExpressionAttributeValues={
                ":s": "authenticated",
                ":a": dev.agent_id,
                ":d": dev.device_id,
                ":sc": dev.scopes,
            },
        )

        _send(
            event,
            connection_id,
            {"type": "hello", "ok": True, "agent_id": dev.agent_id, "device_id": dev.device_id, "scopes": dev.scopes},
        )
        return {"statusCode": 200, "body": "ok"}

    # Stub: you can add more message types here (approve_action, subscribe_presence, etc.)
    _send(event, connection_id, {"type": "ack", "action": action or "(default)", "ok": True})
    return {"statusCode": 200, "body": "ok"}
