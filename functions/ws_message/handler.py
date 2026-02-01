from __future__ import annotations

import json
import os
import time
import logging

import boto3

from agent_hub.auth import authenticate_device, authenticate_user_access_token
from agent_hub.memberships import list_agents_for_user, check_agent_permission
from agent_hub.rds_data import RdsData, RdsDataEnv

logger = logging.getLogger()
logger.setLevel(logging.INFO)

_TABLE = os.getenv("WS_TABLE")
_ACTION_QUEUE_URL = os.getenv("ACTION_QUEUE_URL")
_dynamo = boto3.resource("dynamodb")
_sqs = boto3.client("sqs")

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


def _handle_action_decision(event, connection_id: str, table, conn_item: dict, action_id: str, approve: bool, reason: str = ""):
    """Handle approve or reject action decision."""
    action_type = "approve_action" if approve else "reject_action"

    principal_type = conn_item.get("principal_type")
    user_id = conn_item.get("user_id")

    # Load action
    rows = _get_db().query(
        """
        SELECT action_id::TEXT, agent_id::TEXT, kind, status
        FROM actions
        WHERE action_id = :action_id::uuid
        """,
        {"action_id": action_id},
    )
    if not rows:
        _send(event, connection_id, {"type": action_type, "ok": False, "error": "action_not_found"})
        return {"statusCode": 200, "body": "ok"}

    action_row = rows[0]
    agent_id = action_row["agent_id"]
    current_status = action_row["status"]

    # Check permission - must be admin or owner to approve/reject
    if principal_type == "user":
        if not check_agent_permission(_get_db(), agent_id=agent_id, user_id=user_id, required_role="admin"):
            _send(event, connection_id, {"type": action_type, "ok": False, "error": "permission_denied"})
            return {"statusCode": 200, "body": "ok"}
    else:
        # Devices cannot approve/reject actions
        _send(event, connection_id, {"type": action_type, "ok": False, "error": "devices_cannot_decide"})
        return {"statusCode": 200, "body": "ok"}

    # Only proposed actions can be approved/rejected
    if current_status != "proposed":
        _send(event, connection_id, {
            "type": action_type,
            "ok": False,
            "error": "invalid_status",
            "current_status": current_status,
        })
        return {"statusCode": 200, "body": "ok"}

    if approve:
        # Approve: update status and queue for execution
        _get_db().execute(
            """
            UPDATE actions
            SET status = 'approved', updated_at = now()
            WHERE action_id = :action_id::uuid
            """,
            {"action_id": action_id},
        )

        # Queue for execution
        if _ACTION_QUEUE_URL:
            _sqs.send_message(
                QueueUrl=_ACTION_QUEUE_URL,
                MessageBody=json.dumps({"action_id": action_id, "agent_id": agent_id}),
            )

        _send(event, connection_id, {"type": action_type, "ok": True, "action_id": action_id, "new_status": "approved"})
    else:
        # Reject: update status
        _get_db().execute(
            """
            UPDATE actions
            SET status = 'rejected', updated_at = now()
            WHERE action_id = :action_id::uuid
            """,
            {"action_id": action_id},
        )
        _send(event, connection_id, {"type": action_type, "ok": True, "action_id": action_id, "new_status": "rejected"})

    logger.info("Action %s %s by user %s", action_id, "approved" if approve else "rejected", user_id)
    return {"statusCode": 200, "body": "ok"}


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

    # Get connection info for authorization
    conn_item = table.get_item(Key={"connection_id": connection_id}).get("Item", {})
    if conn_item.get("status") != "authenticated":
        _send(event, connection_id, {"type": "error", "error": "not_authenticated", "action": action})
        return {"statusCode": 200, "body": "ok"}

    principal_type = conn_item.get("principal_type")
    user_id = conn_item.get("user_id")
    agents = conn_item.get("agents", [])

    # -------------------------------------------------------------------------
    # ping - simple heartbeat
    # -------------------------------------------------------------------------
    if action == "ping":
        _send(event, connection_id, {"type": "pong", "timestamp": int(time.time() * 1000)})
        return {"statusCode": 200, "body": "ok"}

    # -------------------------------------------------------------------------
    # list_actions - list pending/proposed actions for an agent
    # -------------------------------------------------------------------------
    if action == "list_actions":
        agent_id = str(msg.get("agent_id") or "").strip()
        status_filter = str(msg.get("status") or "proposed").strip()
        limit = min(int(msg.get("limit") or 50), 100)

        if not agent_id:
            _send(event, connection_id, {"type": "list_actions", "ok": False, "error": "missing_agent_id"})
            return {"statusCode": 200, "body": "ok"}

        # Check user has at least member access
        if principal_type == "user":
            if not check_agent_permission(_get_db(), agent_id=agent_id, user_id=user_id, required_role="member"):
                _send(event, connection_id, {"type": "list_actions", "ok": False, "error": "permission_denied"})
                return {"statusCode": 200, "body": "ok"}
        else:
            # Device can only query its own agent
            dev_agent = conn_item.get("agent_id")
            if dev_agent != agent_id:
                _send(event, connection_id, {"type": "list_actions", "ok": False, "error": "permission_denied"})
                return {"statusCode": 200, "body": "ok"}

        rows = _get_db().query(
            """
            SELECT action_id::TEXT, kind, payload, required_scopes, status, created_at::TEXT
            FROM actions
            WHERE agent_id = :agent_id::uuid AND status = :status
            ORDER BY created_at DESC
            LIMIT :limit
            """,
            {"agent_id": agent_id, "status": status_filter, "limit": limit},
        )
        actions_out = [
            {
                "action_id": r["action_id"],
                "kind": r["kind"],
                "payload": r.get("payload") or {},
                "required_scopes": r.get("required_scopes") or [],
                "status": r["status"],
                "created_at": r["created_at"],
            }
            for r in rows
        ]
        _send(event, connection_id, {"type": "list_actions", "ok": True, "actions": actions_out})
        return {"statusCode": 200, "body": "ok"}

    # -------------------------------------------------------------------------
    # approve_action - approve a proposed action
    # -------------------------------------------------------------------------
    if action == "approve_action":
        action_id = str(msg.get("action_id") or "").strip()
        if not action_id:
            _send(event, connection_id, {"type": "approve_action", "ok": False, "error": "missing_action_id"})
            return {"statusCode": 200, "body": "ok"}

        return _handle_action_decision(event, connection_id, table, conn_item, action_id, approve=True)

    # -------------------------------------------------------------------------
    # reject_action - reject a proposed action
    # -------------------------------------------------------------------------
    if action == "reject_action":
        action_id = str(msg.get("action_id") or "").strip()
        reason = str(msg.get("reason") or "").strip()
        if not action_id:
            _send(event, connection_id, {"type": "reject_action", "ok": False, "error": "missing_action_id"})
            return {"statusCode": 200, "body": "ok"}

        return _handle_action_decision(event, connection_id, table, conn_item, action_id, approve=False, reason=reason)

    # -------------------------------------------------------------------------
    # subscribe_presence - subscribe to presence updates for a space
    # -------------------------------------------------------------------------
    if action == "subscribe_presence":
        agent_id = str(msg.get("agent_id") or "").strip()
        space_id = str(msg.get("space_id") or "").strip()

        if not agent_id:
            _send(event, connection_id, {"type": "subscribe_presence", "ok": False, "error": "missing_agent_id"})
            return {"statusCode": 200, "body": "ok"}

        # Check permission
        if principal_type == "user":
            if not check_agent_permission(_get_db(), agent_id=agent_id, user_id=user_id, required_role="member"):
                _send(event, connection_id, {"type": "subscribe_presence", "ok": False, "error": "permission_denied"})
                return {"statusCode": 200, "body": "ok"}
        else:
            dev_agent = conn_item.get("agent_id")
            if dev_agent != agent_id:
                _send(event, connection_id, {"type": "subscribe_presence", "ok": False, "error": "permission_denied"})
                return {"statusCode": 200, "body": "ok"}

        # Store subscription in connection record
        subscriptions = conn_item.get("subscriptions") or []
        sub_key = f"presence:{agent_id}" if not space_id else f"presence:{agent_id}:{space_id}"
        if sub_key not in subscriptions:
            subscriptions.append(sub_key)
            table.update_item(
                Key={"connection_id": connection_id},
                UpdateExpression="SET subscriptions = :subs",
                ExpressionAttributeValues={":subs": subscriptions},
            )

        _send(event, connection_id, {
            "type": "subscribe_presence",
            "ok": True,
            "subscription": sub_key,
        })
        return {"statusCode": 200, "body": "ok"}

    # Default: unknown action
    _send(event, connection_id, {"type": "error", "error": "unknown_action", "action": action})
    return {"statusCode": 200, "body": "ok"}
