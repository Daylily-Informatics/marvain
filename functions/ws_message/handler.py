from __future__ import annotations

import json
import logging
import os
import time
import uuid

import boto3
from agent_hub.audit import append_audit_entry
from agent_hub.auth import authenticate_device, authenticate_user_access_token
from agent_hub.contracts import CmdRunAction, DeviceActionAck, DeviceActionResult
from agent_hub.config import load_config
from agent_hub.memberships import check_agent_permission, list_agents_for_user
from agent_hub.metrics import emit_count, emit_ms
from agent_hub.rds_data import RdsData, RdsDataEnv

logger = logging.getLogger()
logger.setLevel(logging.INFO)

_TABLE = os.getenv("WS_TABLE")
_WS_SUBSCRIPTIONS_TABLE = os.getenv("WS_SUBSCRIPTIONS_TABLE")
_ACTION_QUEUE_URL = os.getenv("ACTION_QUEUE_URL")
_WS_AUTH_TTL = int(os.getenv("WS_AUTH_TTL_SECONDS", "3600"))
_dynamo = boto3.resource("dynamodb")
_sqs = boto3.client("sqs")

_db = None
_cfg = None


def _get_db() -> RdsData:
    global _db
    if _db is None:
        _db = RdsData(
            RdsDataEnv(
                resource_arn=os.environ["DB_RESOURCE_ARN"],
                secret_arn=os.environ["DB_SECRET_ARN"],
                database=os.environ["DB_NAME"],
            )
        )
    return _db


def _get_cfg():
    global _cfg
    if _cfg is None:
        _cfg = load_config()
    return _cfg


def _mgmt_api(event):
    domain = event.get("requestContext", {}).get("domainName")
    stage = event.get("requestContext", {}).get("stage")
    endpoint_url = f"https://{domain}/{stage}"
    return boto3.client("apigatewaymanagementapi", endpoint_url=endpoint_url)


def _send(event, connection_id: str, payload: dict):
    data = json.dumps(payload).encode("utf-8")
    _mgmt_api(event).post_to_connection(ConnectionId=connection_id, Data=data)


def _model_dump(model) -> dict:
    if hasattr(model, "model_dump"):
        return model.model_dump()
    return model.dict()  # pragma: no cover - pydantic v1 fallback


def _subscription_table():
    if not _WS_SUBSCRIPTIONS_TABLE:
        return None
    return _dynamo.Table(_WS_SUBSCRIPTIONS_TABLE)


def _upsert_subscription_index(connection_id: str, topic_key: str, ttl: int | None) -> None:
    subs_table = _subscription_table()
    if subs_table is None:
        return
    item = {
        "topic_key": topic_key,
        "connection_id": connection_id,
        "ttl": int(ttl or (int(time.time()) + _WS_AUTH_TTL)),
    }
    try:
        subs_table.put_item(Item=item)
    except Exception as exc:
        logger.warning("Failed to update subscription index for %s: %s", topic_key, exc)


def _load_action_with_execution(action_id: str) -> dict | None:
    rows = _get_db().query(
        """
        SELECT action_id::TEXT as action_id,
               agent_id::TEXT as agent_id,
               space_id::TEXT as space_id,
               kind,
               status,
               target_device_id::TEXT as target_device_id,
               correlation_id::TEXT as correlation_id,
               COALESCE(EXTRACT(EPOCH FROM (now() - created_at)) * 1000, 0) as age_ms
        FROM actions
        WHERE action_id = :action_id::uuid
        LIMIT 1
        """,
        {"action_id": action_id},
    )
    if not rows:
        return None
    return rows[0]


def _get_device_connections(table, target_device_id: str) -> list[str]:
    """Find all WebSocket connection IDs for a specific device.

    Uses the ``device_id_index`` GSI for efficient lookup.

    Returns list of connection_ids where device_id matches and status is authenticated.
    """
    try:
        response = table.query(
            IndexName="device_id_index",
            KeyConditionExpression="device_id = :did",
            FilterExpression="#s = :status",
            ExpressionAttributeNames={"#s": "status"},
            ExpressionAttributeValues={
                ":did": target_device_id,
                ":status": "authenticated",
            },
        )
        return [item["connection_id"] for item in response.get("Items", [])]
    except Exception as e:
        logger.warning("Device connection index query failed for device %s: %s", target_device_id, e)
        return []


def _send_to_device(event, table, target_device_id: str, message: dict) -> tuple[int, int]:
    """Send a message to all WebSocket connections for a device.

    Returns (sent_count, stale_count).
    """
    from botocore.exceptions import ClientError

    connection_ids = _get_device_connections(table, target_device_id)
    if not connection_ids:
        return (0, 0)

    mgmt_api = _mgmt_api(event)
    data = json.dumps(message).encode("utf-8")

    sent_count = 0
    stale_connections = []

    for conn_id in connection_ids:
        try:
            mgmt_api.post_to_connection(ConnectionId=conn_id, Data=data)
            sent_count += 1
        except ClientError as e:
            error_code = e.response.get("Error", {}).get("Code", "")
            if error_code == "GoneException":
                stale_connections.append(conn_id)
            else:
                logger.warning("Failed to send to device connection %s: %s", conn_id, e)
        except Exception as e:
            logger.warning("Failed to send to device connection %s: %s", conn_id, e)

    # Clean up stale connections
    for conn_id in stale_connections:
        try:
            table.delete_item(Key={"connection_id": conn_id})
            logger.debug("Cleaned up stale connection: %s", conn_id)
        except Exception:
            pass

    return (sent_count, len(stale_connections))


def _handle_action_decision(
    event, connection_id: str, table, conn_item: dict, action_id: str, approve: bool, reason: str = ""
):
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
        _send(
            event,
            connection_id,
            {
                "type": action_type,
                "ok": False,
                "error": "invalid_status",
                "current_status": current_status,
            },
        )
        return {"statusCode": 200, "body": "ok"}

    new_status = "approved" if approve else "rejected"

    if approve:
        # Approve: update status with approver info and queue for execution
        _get_db().execute(
            """
            UPDATE actions
            SET status = 'approved', updated_at = now(),
                approved_by = :user_id::uuid, approved_at = now()
            WHERE action_id = :action_id::uuid
            """,
            {"action_id": action_id, "user_id": user_id},
        )

        # Queue for execution
        if _ACTION_QUEUE_URL:
            _sqs.send_message(
                QueueUrl=_ACTION_QUEUE_URL,
                MessageBody=json.dumps({"action_id": action_id, "agent_id": agent_id}),
            )

        _send(event, connection_id, {"type": action_type, "ok": True, "action_id": action_id, "new_status": new_status})
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
        _send(event, connection_id, {"type": action_type, "ok": True, "action_id": action_id, "new_status": new_status})

    # Audit log the action decision
    cfg = _get_cfg()
    if cfg.audit_bucket:
        append_audit_entry(
            _get_db(),
            bucket=cfg.audit_bucket,
            agent_id=agent_id,
            entry_type="action_decision",
            entry={
                "action_id": action_id,
                "decision": new_status,
                "by_user_id": user_id,
                "reason": reason,
            },
        )

    logger.info("Action %s %s by user %s", action_id, new_status, user_id)
    return {"statusCode": 200, "body": "ok"}


def _handle_device_action_ack(event, connection_id: str, conn_item: dict, msg: dict) -> dict:
    """Handle device -> hub command acknowledgement."""
    if str(conn_item.get("principal_type") or "") != "device":
        _send(event, connection_id, {"type": "device_action_ack", "ok": False, "error": "device_only"})
        return {"statusCode": 200, "body": "ok"}

    try:
        ack = DeviceActionAck(**msg)
    except Exception as exc:
        _send(event, connection_id, {"type": "device_action_ack", "ok": False, "error": f"invalid_payload: {exc}"})
        return {"statusCode": 200, "body": "ok"}

    action_row = _load_action_with_execution(ack.action_id)
    if not action_row:
        _send(event, connection_id, {"type": "device_action_ack", "ok": False, "error": "action_not_found"})
        return {"statusCode": 200, "body": "ok"}

    device_id = str(conn_item.get("device_id") or "")
    target_device_id = str(action_row.get("target_device_id") or "")
    if target_device_id and target_device_id != device_id:
        _send(event, connection_id, {"type": "device_action_ack", "ok": False, "error": "permission_denied"})
        return {"statusCode": 200, "body": "ok"}

    action_corr = str(action_row.get("correlation_id") or "")
    if action_corr and action_corr != ack.correlation_id:
        _send(event, connection_id, {"type": "device_action_ack", "ok": False, "error": "correlation_mismatch"})
        return {"statusCode": 200, "body": "ok"}

    _get_db().execute(
        """
        UPDATE actions
        SET status = 'device_acknowledged',
            updated_at = now(),
            device_acknowledged_at = now(),
            execution_metadata = COALESCE(execution_metadata, '{}'::jsonb) || :meta::jsonb
        WHERE action_id = :action_id::uuid
          AND status IN ('awaiting_device_result', 'device_acknowledged')
        """,
        {
            "action_id": ack.action_id,
            "meta": json.dumps(
                {
                    "acknowledged_by_device_id": ack.device_id,
                    "acknowledged_at_ms": ack.received_at,
                }
            ),
        },
    )

    emit_count(
        "ActionExecutionCount",
        dimensions={
            "ActionKind": str(action_row.get("kind") or "unknown"),
            "Status": "device_acknowledged",
        },
    )

    _send(event, connection_id, {"type": "device_action_ack", "ok": True, "action_id": ack.action_id})
    return {"statusCode": 200, "body": "ok"}


def _handle_device_action_result(event, connection_id: str, conn_item: dict, msg: dict) -> dict:
    """Handle device -> hub command completion result."""
    if str(conn_item.get("principal_type") or "") != "device":
        _send(event, connection_id, {"type": "device_action_result", "ok": False, "error": "device_only"})
        return {"statusCode": 200, "body": "ok"}

    try:
        result_in = DeviceActionResult(**msg)
    except Exception as exc:
        _send(event, connection_id, {"type": "device_action_result", "ok": False, "error": f"invalid_payload: {exc}"})
        return {"statusCode": 200, "body": "ok"}

    action_row = _load_action_with_execution(result_in.action_id)
    if not action_row:
        _send(event, connection_id, {"type": "device_action_result", "ok": False, "error": "action_not_found"})
        return {"statusCode": 200, "body": "ok"}

    device_id = str(conn_item.get("device_id") or "")
    target_device_id = str(action_row.get("target_device_id") or "")
    if target_device_id and target_device_id != device_id:
        _send(event, connection_id, {"type": "device_action_result", "ok": False, "error": "permission_denied"})
        return {"statusCode": 200, "body": "ok"}

    action_corr = str(action_row.get("correlation_id") or "")
    if action_corr and action_corr != result_in.correlation_id:
        _send(event, connection_id, {"type": "device_action_result", "ok": False, "error": "correlation_mismatch"})
        return {"statusCode": 200, "body": "ok"}

    new_status = "executed" if result_in.status == "success" else "failed"
    err_text = None if result_in.status == "success" else (result_in.error or f"device_{result_in.status}")
    result_json = json.dumps(result_in.result or {})

    _get_db().execute(
        """
        UPDATE actions
        SET status = :status,
            updated_at = now(),
            executed_at = now(),
            completed_at = now(),
            device_response_at = now(),
            awaiting_result_until = NULL,
            result = :result::jsonb,
            error = :error
        WHERE action_id = :action_id::uuid
          AND status IN ('awaiting_device_result', 'device_acknowledged')
        """,
        {
            "action_id": result_in.action_id,
            "status": new_status,
            "result": result_json,
            "error": err_text,
        },
    )

    try:
        from agent_hub.broadcast import broadcast_event

        broadcast_event(
            event_type="actions.updated",
            agent_id=str(action_row.get("agent_id") or ""),
            space_id=action_row.get("space_id"),
            payload={
                "action_id": result_in.action_id,
                "kind": str(action_row.get("kind") or result_in.kind),
                "status": new_status,
                "error": err_text,
            },
        )
    except Exception as exc:
        logger.warning("Failed to broadcast device action result: %s", exc)

    emit_count(
        "ActionExecutionCount",
        dimensions={
            "ActionKind": str(action_row.get("kind") or "unknown"),
            "Status": new_status,
        },
    )
    emit_ms(
        "CommandResultLatencyMs",
        value_ms=float(action_row.get("age_ms") or 0),
        dimensions={"ActionKind": str(action_row.get("kind") or "unknown")},
    )

    _send(event, connection_id, {"type": "device_action_result", "ok": True, "action_id": result_in.action_id})
    return {"statusCode": 200, "body": "ok"}


def _handle_topic_subscription(
    *,
    event,
    connection_id: str,
    table,
    conn_item: dict,
    principal_type: str,
    user_id: str | None,
    msg: dict,
    topic: str,
) -> dict:
    """Handle topic subscription for events/actions/presence/memories."""
    action_name = f"subscribe_{topic}"
    agent_id = str(msg.get("agent_id") or "").strip()
    space_id = str(msg.get("space_id") or "").strip()

    if not agent_id:
        _send(event, connection_id, {"type": action_name, "ok": False, "error": "missing_agent_id"})
        return {"statusCode": 200, "body": "ok"}

    if principal_type == "user":
        if not check_agent_permission(_get_db(), agent_id=agent_id, user_id=user_id, required_role="member"):
            _send(event, connection_id, {"type": action_name, "ok": False, "error": "permission_denied"})
            return {"statusCode": 200, "body": "ok"}
    else:
        dev_agent = str(conn_item.get("agent_id") or "")
        if dev_agent != agent_id:
            _send(event, connection_id, {"type": action_name, "ok": False, "error": "permission_denied"})
            return {"statusCode": 200, "body": "ok"}

    subscriptions = conn_item.get("subscriptions") or []
    sub_key = f"{topic}:{agent_id}" if not space_id else f"{topic}:{agent_id}:{space_id}"
    if sub_key not in subscriptions:
        subscriptions.append(sub_key)
        table.update_item(
            Key={"connection_id": connection_id},
            UpdateExpression="SET subscriptions = :subs",
            ExpressionAttributeValues={":subs": subscriptions},
        )
    _upsert_subscription_index(connection_id, sub_key, conn_item.get("ttl"))

    _send(
        event,
        connection_id,
        {
            "type": action_name,
            "ok": True,
            "subscription": sub_key,
            "agent_id": agent_id,
            "space_id": space_id or None,
        },
    )
    emit_count(
        "SubscriptionAdded",
        dimensions={
            "Topic": topic,
        },
    )
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
                logger.info(f"[hello] Attempting to authenticate access_token, length={len(access_token)}")
                user = authenticate_user_access_token(_get_db(), access_token)
                logger.info(f"[hello] Authentication successful for user_id={user.user_id}")
            except PermissionError as e:
                logger.error(f"[hello] Authentication failed: {e}")
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

            now_ts = int(time.time())
            expr_names = {"#s": "status", "#ttl": "ttl"}
            expr_values = {
                ":s": "authenticated",
                ":pt": "user",
                ":uid": user.user_id,
                ":cs": user.cognito_sub,
                ":ag": agents_out,
                ":aat": now_ts,
                ":ttl": now_ts + _WS_AUTH_TTL,
            }
            set_parts = [
                "#s=:s",
                "principal_type=:pt",
                "user_id=:uid",
                "cognito_sub=:cs",
                "agents=:ag",
                "authenticated_at=:aat",
                "#ttl=:ttl",
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

        # Update last_hello_at and last_seen for presence tracking
        _get_db().execute(
            "UPDATE devices SET last_hello_at = now(), last_seen = now() WHERE device_id = :device_id::uuid",
            {"device_id": dev.device_id},
        )

        dev_now_ts = int(time.time())
        table.update_item(
            Key={"connection_id": connection_id},
            UpdateExpression=(
                "SET #s=:s, principal_type=:pt, agent_id=:a, device_id=:d, scopes=:sc, "
                "authenticated_at=:aat, #ttl=:ttl "
                "REMOVE user_id, cognito_sub, email, agents"
            ),
            ExpressionAttributeNames={"#s": "status", "#ttl": "ttl"},
            ExpressionAttributeValues={
                ":s": "authenticated",
                ":pt": "device",
                ":a": dev.agent_id,
                ":d": dev.device_id,
                ":sc": dev.scopes,
                ":aat": dev_now_ts,
                ":ttl": dev_now_ts + _WS_AUTH_TTL,
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

    # Check auth expiry — require re-authentication if TTL exceeded
    auth_at = conn_item.get("authenticated_at")
    if auth_at is not None and int(time.time()) - int(auth_at) > _WS_AUTH_TTL:
        # Mark connection as expired so DynamoDB TTL can clean it up
        table.update_item(
            Key={"connection_id": connection_id},
            UpdateExpression="SET #s = :s",
            ExpressionAttributeNames={"#s": "status"},
            ExpressionAttributeValues={":s": "expired"},
        )
        _send(
            event,
            connection_id,
            {
                "type": "error",
                "error": "auth_expired",
                "message": "Session expired. Send hello with a fresh token to re-authenticate.",
                "action": action,
            },
        )
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
    # DEVICE COMMAND MESSAGES (cmd.*)
    # These messages are sent to devices to request actions or configuration.
    # -------------------------------------------------------------------------

    # cmd.ping - ping a specific device (hub -> device)
    if action == "cmd.ping":
        target_device_id = str(msg.get("target_device_id") or "").strip()
        if not target_device_id:
            _send(event, connection_id, {"type": "cmd.ping", "ok": False, "error": "missing_target_device_id"})
            return {"statusCode": 200, "body": "ok"}

        # Only allow users with admin role or the device's own agent to ping
        if principal_type == "user":
            # Find the agent that owns the target device
            rows = _get_db().query(
                "SELECT agent_id::TEXT FROM devices WHERE device_id = :device_id::uuid AND revoked_at IS NULL",
                {"device_id": target_device_id},
            )
            if not rows:
                _send(event, connection_id, {"type": "cmd.ping", "ok": False, "error": "device_not_found"})
                return {"statusCode": 200, "body": "ok"}
            target_agent_id = rows[0]["agent_id"]
            if not check_agent_permission(_get_db(), agent_id=target_agent_id, user_id=user_id, required_role="admin"):
                _send(event, connection_id, {"type": "cmd.ping", "ok": False, "error": "permission_denied"})
                return {"statusCode": 200, "body": "ok"}
        else:
            # Device can only ping devices of its own agent
            dev_agent = conn_item.get("agent_id")
            rows = _get_db().query(
                "SELECT agent_id::TEXT FROM devices WHERE device_id = :device_id::uuid AND revoked_at IS NULL",
                {"device_id": target_device_id},
            )
            if not rows or rows[0]["agent_id"] != dev_agent:
                _send(event, connection_id, {"type": "cmd.ping", "ok": False, "error": "permission_denied"})
                return {"statusCode": 200, "body": "ok"}

        # Broadcast cmd.ping to the target device via WebSocket
        sent_at = int(time.time() * 1000)
        device_message = {
            "type": "cmd.ping",
            "from_connection_id": connection_id,
            "sent_at": sent_at,
        }
        sent_count, stale_count = _send_to_device(event, table, target_device_id, device_message)

        _send(
            event,
            connection_id,
            {
                "type": "cmd.ping",
                "ok": True,
                "target_device_id": target_device_id,
                "sent_at": sent_at,
                "device_connections": sent_count,
                "device_online": sent_count > 0,
            },
        )
        return {"statusCode": 200, "body": "ok"}

    # cmd.pong - response to cmd.ping (device -> hub)
    if action == "cmd.pong":
        original_sent_at = msg.get("original_sent_at")
        _send(
            event,
            connection_id,
            {
                "type": "cmd.pong",
                "ok": True,
                "device_id": conn_item.get("device_id"),
                "received_at": int(time.time() * 1000),
                "original_sent_at": original_sent_at,
            },
        )
        return {"statusCode": 200, "body": "ok"}

    # cmd.run_action - request a device to execute an action
    if action == "cmd.run_action":
        target_device_id = str(msg.get("target_device_id") or "").strip()
        action_kind = str(msg.get("kind") or "").strip()
        action_payload = msg.get("payload") or {}
        run_action_id = str(msg.get("action_id") or str(uuid.uuid4()))
        correlation_id = str(msg.get("correlation_id") or str(uuid.uuid4()))

        if not target_device_id or not action_kind:
            _send(
                event,
                connection_id,
                {"type": "cmd.run_action", "ok": False, "error": "missing_target_device_id_or_kind"},
            )
            return {"statusCode": 200, "body": "ok"}

        # Permission check: user needs admin on the device's agent
        if principal_type == "user":
            rows = _get_db().query(
                "SELECT agent_id::TEXT FROM devices WHERE device_id = :device_id::uuid AND revoked_at IS NULL",
                {"device_id": target_device_id},
            )
            if not rows:
                _send(event, connection_id, {"type": "cmd.run_action", "ok": False, "error": "device_not_found"})
                return {"statusCode": 200, "body": "ok"}
            target_agent_id = rows[0]["agent_id"]
            if not check_agent_permission(_get_db(), agent_id=target_agent_id, user_id=user_id, required_role="admin"):
                _send(event, connection_id, {"type": "cmd.run_action", "ok": False, "error": "permission_denied"})
                return {"statusCode": 200, "body": "ok"}
        else:
            _send(event, connection_id, {"type": "cmd.run_action", "ok": False, "error": "user_only"})
            return {"statusCode": 200, "body": "ok"}

        # Broadcast cmd.run_action to the target device via WebSocket
        sent_at = int(time.time() * 1000)
        cmd = CmdRunAction(
            action_id=run_action_id,
            correlation_id=correlation_id,
            kind=action_kind,
            payload=action_payload,
            sent_at=sent_at,
            from_connection_id=connection_id,
        )
        device_message = _model_dump(cmd)
        sent_count, stale_count = _send_to_device(event, table, target_device_id, device_message)

        if sent_count == 0:
            _send(
                event,
                connection_id,
                {
                    "type": "cmd.run_action",
                    "ok": False,
                    "error": "device_not_connected",
                    "target_device_id": target_device_id,
                },
            )
            return {"statusCode": 200, "body": "ok"}

        _send(
            event,
            connection_id,
            {
                "type": "cmd.run_action",
                "ok": True,
                "target_device_id": target_device_id,
                "kind": action_kind,
                "action_id": run_action_id,
                "correlation_id": correlation_id,
                "sent_at": sent_at,
                "device_connections": sent_count,
            },
        )
        return {"statusCode": 200, "body": "ok"}

    # cmd.config - send configuration update to a device
    if action == "cmd.config":
        target_device_id = str(msg.get("target_device_id") or "").strip()
        config_data = msg.get("config") or {}

        if not target_device_id:
            _send(event, connection_id, {"type": "cmd.config", "ok": False, "error": "missing_target_device_id"})
            return {"statusCode": 200, "body": "ok"}

        # Permission check: user needs admin on the device's agent
        if principal_type == "user":
            rows = _get_db().query(
                "SELECT agent_id::TEXT FROM devices WHERE device_id = :device_id::uuid AND revoked_at IS NULL",
                {"device_id": target_device_id},
            )
            if not rows:
                _send(event, connection_id, {"type": "cmd.config", "ok": False, "error": "device_not_found"})
                return {"statusCode": 200, "body": "ok"}
            target_agent_id = rows[0]["agent_id"]
            if not check_agent_permission(_get_db(), agent_id=target_agent_id, user_id=user_id, required_role="admin"):
                _send(event, connection_id, {"type": "cmd.config", "ok": False, "error": "permission_denied"})
                return {"statusCode": 200, "body": "ok"}
        else:
            _send(event, connection_id, {"type": "cmd.config", "ok": False, "error": "user_only"})
            return {"statusCode": 200, "body": "ok"}

        # Broadcast cmd.config to the target device via WebSocket
        sent_at = int(time.time() * 1000)
        device_message = {
            "type": "cmd.config",
            "from_connection_id": connection_id,
            "config": config_data,
            "sent_at": sent_at,
        }
        sent_count, stale_count = _send_to_device(event, table, target_device_id, device_message)

        if sent_count == 0:
            _send(
                event,
                connection_id,
                {
                    "type": "cmd.config",
                    "ok": False,
                    "error": "device_not_connected",
                    "target_device_id": target_device_id,
                },
            )
            return {"statusCode": 200, "body": "ok"}

        _send(
            event,
            connection_id,
            {
                "type": "cmd.config",
                "ok": True,
                "target_device_id": target_device_id,
                "sent_at": sent_at,
                "device_connections": sent_count,
            },
        )
        return {"statusCode": 200, "body": "ok"}

    # -------------------------------------------------------------------------
    # DEVICE -> HUB execution callbacks
    # -------------------------------------------------------------------------
    if action == "device_action_ack":
        return _handle_device_action_ack(event, connection_id, conn_item, msg)

    if action == "device_action_result":
        return _handle_device_action_result(event, connection_id, conn_item, msg)

    if action == "config_ack":
        _send(event, connection_id, {"type": "config_ack", "ok": True})
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

    # Topic subscriptions.
    if action == "subscribe_presence":
        return _handle_topic_subscription(
            event=event,
            connection_id=connection_id,
            table=table,
            conn_item=conn_item,
            principal_type=principal_type,
            user_id=user_id,
            msg=msg,
            topic="presence",
        )
    if action == "subscribe_events":
        return _handle_topic_subscription(
            event=event,
            connection_id=connection_id,
            table=table,
            conn_item=conn_item,
            principal_type=principal_type,
            user_id=user_id,
            msg=msg,
            topic="events",
        )
    if action == "subscribe_actions":
        return _handle_topic_subscription(
            event=event,
            connection_id=connection_id,
            table=table,
            conn_item=conn_item,
            principal_type=principal_type,
            user_id=user_id,
            msg=msg,
            topic="actions",
        )
    if action == "subscribe_memories":
        return _handle_topic_subscription(
            event=event,
            connection_id=connection_id,
            table=table,
            conn_item=conn_item,
            principal_type=principal_type,
            user_id=user_id,
            msg=msg,
            topic="memories",
        )

    # Default: unknown action
    _send(event, connection_id, {"type": "error", "error": "unknown_action", "action": action})
    return {"statusCode": 200, "body": "ok"}
