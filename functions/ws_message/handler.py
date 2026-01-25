from __future__ import annotations

import json
import os

import boto3

from agent_hub.auth import authenticate_device, authenticate_user_access_token
from agent_hub.memberships import list_agents_for_user
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
        access_token = str(msg.get("access_token") or "").strip()
        device_token = str(msg.get("device_token") or "").strip()

        # v1: accept Cognito access_token (preferred) for human users.
        if access_token:
            try:
                user = authenticate_user_access_token(_get_db(), access_token)
            except PermissionError:
                _send(event, connection_id, {"type": "hello", "ok": False, "error": "invalid_access_token"})
                return {"statusCode": 200, "body": "ok"}

            agents = list_agents_for_user(_get_db(), user_id=user.user_id)
            agents_out = [
                {
                    "agent_id": a.agent_id,
                    "name": a.name,
                    "role": a.role,
                    "relationship_label": a.relationship_label,
                    "disabled": bool(a.disabled),
                }
                for a in agents
            ]

            expr_names = {"#s": "status"}
            expr_values = {
                ":s": "authenticated",
                ":pt": "user",
                ":uid": user.user_id,
                ":cs": user.cognito_sub,
                ":ag": agents_out,
            }
            set_parts = [
                "#s=:s",
                "principal_type=:pt",
                "user_id=:uid",
                "cognito_sub=:cs",
                "agents=:ag",
            ]
            remove_parts = ["agent_id", "device_id", "scopes"]
            if user.email:
                expr_values[":em"] = user.email
                set_parts.append("email=:em")
            else:
                remove_parts.append("email")

            update_expr = "SET " + ", ".join(set_parts) + " REMOVE " + ", ".join(remove_parts)
            table.update_item(
                Key={"connection_id": connection_id},
                UpdateExpression=update_expr,
                ExpressionAttributeNames=expr_names,
                ExpressionAttributeValues=expr_values,
            )

            _send(
                event,
                connection_id,
                {
                    "type": "hello",
                    "ok": True,
                    "principal_type": "user",
                    "user_id": user.user_id,
                    "cognito_sub": user.cognito_sub,
                    "email": user.email,
                    "agents": agents_out,
                },
            )
            return {"statusCode": 200, "body": "ok"}

        # Back-compat: device_token for satellites/devices.
        if not device_token:
            _send(
                event,
                connection_id,
                {"type": "hello", "ok": False, "error": "missing_access_token_or_device_token"},
            )
            return {"statusCode": 200, "body": "ok"}

        dev = authenticate_device(_get_db(), device_token)
        if not dev:
            _send(event, connection_id, {"type": "hello", "ok": False, "error": "invalid_device_token"})
            return {"statusCode": 200, "body": "ok"}

        table.update_item(
            Key={"connection_id": connection_id},
            UpdateExpression=(
                "SET #s=:s, principal_type=:pt, agent_id=:a, device_id=:d, scopes=:sc "
                "REMOVE user_id, cognito_sub, email, agents"
            ),
            ExpressionAttributeNames={"#s": "status"},
            ExpressionAttributeValues={
                ":s": "authenticated",
                ":pt": "device",
                ":a": dev.agent_id,
                ":d": dev.device_id,
                ":sc": dev.scopes,
            },
        )

        _send(
            event,
            connection_id,
            {
                "type": "hello",
                "ok": True,
                "principal_type": "device",
                "agent_id": dev.agent_id,
                "device_id": dev.device_id,
                "scopes": dev.scopes,
            },
        )
        return {"statusCode": 200, "body": "ok"}

    # Stub: you can add more message types here (approve_action, subscribe_presence, etc.)
    _send(event, connection_id, {"type": "ack", "action": action or "(default)", "ok": True})
    return {"statusCode": 200, "body": "ok"}
