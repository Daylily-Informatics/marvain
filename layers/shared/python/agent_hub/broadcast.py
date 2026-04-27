"""Broadcast module for real-time WebSocket event streaming.

This module sends events to WebSocket-connected clients via API Gateway
Management API. Topic subscriptions are stored in DynamoDB (WsSubscriptionsTable);
authenticated connection records are stored in DynamoDB (WsConnectionsTable).
"""

from __future__ import annotations

import json
import logging
import os
import time
from typing import Any

import boto3
from botocore.exceptions import ClientError

from agent_hub.contracts import build_ws_envelope
from agent_hub.memberships import check_agent_permission
from agent_hub.metrics import emit_count, emit_metric
from agent_hub.rds_data import RdsData, RdsDataEnv

logger = logging.getLogger(__name__)

_WS_TABLE_NAME = os.getenv("WS_TABLE")
_WS_SUBSCRIPTIONS_TABLE = os.getenv("WS_SUBSCRIPTIONS_TABLE")
_WS_API_ENDPOINT = os.getenv("WS_API_ENDPOINT")  # e.g., https://{api-id}.execute-api.{region}.amazonaws.com/{stage}
_WS_AUTH_TTL = int(os.getenv("WS_AUTH_TTL_SECONDS", "3600"))

_dynamo = None
_mgmt_api = None
_db = None


def _get_dynamodb():
    global _dynamo
    if _dynamo is None:
        _dynamo = boto3.resource("dynamodb")
    return _dynamo


def _get_db() -> RdsData | None:
    global _db
    if _db is not None:
        return _db
    resource_arn = os.getenv("DB_RESOURCE_ARN", "").strip()
    secret_arn = os.getenv("DB_SECRET_ARN", "").strip()
    database = os.getenv("DB_NAME", "").strip()
    if not resource_arn or not secret_arn or not database:
        return None
    _db = RdsData(RdsDataEnv(resource_arn=resource_arn, secret_arn=secret_arn, database=database))
    return _db


def _get_mgmt_api():
    """Get API Gateway Management API client.

    Note: In Lambda context, WS_API_ENDPOINT should be set to the WebSocket API endpoint.
    """
    global _mgmt_api
    if _mgmt_api is None and _WS_API_ENDPOINT:
        _mgmt_api = boto3.client("apigatewaymanagementapi", endpoint_url=_WS_API_ENDPOINT)
    return _mgmt_api


def _get_subscriptions_table():
    if not _WS_SUBSCRIPTIONS_TABLE:
        return None
    return _get_dynamodb().Table(_WS_SUBSCRIPTIONS_TABLE)


def _iter_authenticated_connections() -> list[dict[str, Any]]:
    """Load authenticated WebSocket connections from DynamoDB."""
    if not _WS_TABLE_NAME:
        return []

    table = _get_dynamodb().Table(_WS_TABLE_NAME)
    out: list[dict[str, Any]] = []
    scan_kwargs = {
        "FilterExpression": "#s = :status",
        "ExpressionAttributeNames": {"#s": "status"},
        "ExpressionAttributeValues": {":status": "authenticated"},
    }

    try:
        response = table.scan(**scan_kwargs)
        out.extend(response.get("Items", []))
        while "LastEvaluatedKey" in response:
            response = table.scan(ExclusiveStartKey=response["LastEvaluatedKey"], **scan_kwargs)
            out.extend(response.get("Items", []))
        return out
    except Exception as e:
        logger.warning("Failed to scan WebSocket connections: %s", e)
        return []


def _load_connections_by_id(connection_ids: list[str]) -> list[dict[str, Any]]:
    if not _WS_TABLE_NAME or not connection_ids:
        return []
    table = _get_dynamodb().Table(_WS_TABLE_NAME)
    out: list[dict[str, Any]] = []
    unique_ids = sorted(set(connection_ids))
    for i in range(0, len(unique_ids), 100):
        chunk = unique_ids[i : i + 100]
        keys = [{"connection_id": cid} for cid in chunk]
        try:
            response = _get_dynamodb().batch_get_item(RequestItems={table.name: {"Keys": keys}})
            out.extend(response.get("Responses", {}).get(table.name, []))
        except Exception as e:
            logger.warning("Failed to batch load WS connections: %s", e)
            return []
    return out


def _connection_can_access_agent(conn: dict[str, Any], agent_id: str) -> bool:
    """Check whether a connection is authorized for an agent."""
    principal_type = str(conn.get("principal_type") or "")
    if principal_type == "device":
        return str(conn.get("agent_id") or "") == agent_id
    if principal_type == "user":
        authenticated_at = conn.get("authenticated_at")
        if authenticated_at is not None:
            try:
                if int(authenticated_at) + _WS_AUTH_TTL < int(time.time()):
                    return False
            except Exception:
                return False
        user_id = str(conn.get("user_id") or "").strip()
        db = _get_db()
        if user_id and db is not None:
            try:
                return check_agent_permission(db, agent_id=agent_id, user_id=user_id, required_role="member")
            except Exception as exc:
                logger.warning("Live WS membership check failed for user %s: %s", user_id, exc)
        agents = conn.get("agents") or []
        for a in agents:
            if isinstance(a, dict) and str(a.get("agent_id") or "") == agent_id:
                return True
    return False


def _topic_for_event(event_type: str) -> str | None:
    if event_type == "events.new":
        return "events"
    if event_type == "actions.updated":
        return "actions"
    if event_type == "presence.updated":
        return "presence"
    if event_type == "memories.new":
        return "memories"
    return None


def _subscription_patterns(topic: str, agent_id: str, space_id: str | None) -> list[str]:
    patterns = [f"{topic}:{agent_id}"]
    if space_id:
        patterns.append(f"{topic}:{agent_id}:{space_id}")
    return patterns


def _find_topic_subscribers(*, topic: str, agent_id: str, space_id: str | None = None) -> list[dict[str, Any]]:
    """Find connections subscribed to a topic for an agent/space."""
    return _find_topic_subscribers_from_index(topic=topic, agent_id=agent_id, space_id=space_id)


def _find_topic_subscribers_from_index(
    *, topic: str, agent_id: str, space_id: str | None = None
) -> list[dict[str, Any]]:
    """Return subscribers from the subscription index."""
    subs_table = _get_subscriptions_table()
    if subs_table is None:
        logger.warning("WS_SUBSCRIPTIONS_TABLE is not configured; topic broadcasts are disabled")
        return []

    patterns = _subscription_patterns(topic, agent_id, space_id)
    connection_ids: set[str] = set()
    try:
        for topic_key in patterns:
            response = subs_table.query(
                KeyConditionExpression="topic_key = :topic",
                ExpressionAttributeValues={":topic": topic_key},
            )
            for item in response.get("Items", []):
                cid = str(item.get("connection_id") or "").strip()
                if cid:
                    connection_ids.add(cid)
            while "LastEvaluatedKey" in response:
                response = subs_table.query(
                    KeyConditionExpression="topic_key = :topic",
                    ExpressionAttributeValues={":topic": topic_key},
                    ExclusiveStartKey=response["LastEvaluatedKey"],
                )
                for item in response.get("Items", []):
                    cid = str(item.get("connection_id") or "").strip()
                    if cid:
                        connection_ids.add(cid)
    except Exception as exc:
        logger.warning("Subscription index lookup failed: %s", exc)
        return []

    if not connection_ids:
        return []

    rows = _load_connections_by_id(list(connection_ids))
    out: list[dict[str, Any]] = []
    for conn in rows:
        if str(conn.get("status") or "") != "authenticated":
            continue
        if not _connection_can_access_agent(conn, agent_id):
            continue
        out.append(conn)
    return out


def _find_user_connections(user_id: str) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for conn in _iter_authenticated_connections():
        if str(conn.get("principal_type") or "") != "user":
            continue
        if str(conn.get("user_id") or "") == user_id:
            out.append(conn)
    return out


def _find_connection_by_id(connection_id: str) -> list[dict[str, Any]]:
    if not _WS_TABLE_NAME:
        return []
    table = _get_dynamodb().Table(_WS_TABLE_NAME)
    try:
        item = table.get_item(Key={"connection_id": connection_id}).get("Item")
        if item and str(item.get("status") or "") == "authenticated":
            return [item]
        return []
    except Exception as e:
        logger.warning("Failed to load connection %s: %s", connection_id, e)
        return []


def _send_to_connections(*, connections: list[dict[str, Any]], message: dict[str, Any]) -> int:
    """Send a message to connection records."""
    mgmt_api = _get_mgmt_api()
    if not mgmt_api:
        logger.debug("WebSocket broadcast not configured (no WS_API_ENDPOINT)")
        return 0

    data = json.dumps(message).encode("utf-8")
    sent_count = 0
    stale_connections: list[str] = []
    for conn in connections:
        connection_id = str(conn.get("connection_id") or "")
        if not connection_id:
            continue
        try:
            mgmt_api.post_to_connection(ConnectionId=connection_id, Data=data)
            sent_count += 1
        except ClientError as e:
            error_code = e.response.get("Error", {}).get("Code", "")
            if error_code == "GoneException":
                stale_connections.append(connection_id)
            else:
                logger.warning("Failed to send to connection %s: %s", connection_id, e)
        except Exception as e:
            logger.warning("Failed to send to connection %s: %s", connection_id, e)

    if stale_connections and _WS_TABLE_NAME:
        table = _get_dynamodb().Table(_WS_TABLE_NAME)
        for conn_id in stale_connections:
            try:
                table.delete_item(Key={"connection_id": conn_id})
            except Exception:
                pass

    dropped = max(0, len(connections) - sent_count)
    emit_metric(
        name="BroadcastFanoutSize",
        value=float(len(connections)),
        unit="Count",
        dimensions={"Type": str(message.get("type") or "unknown")},
    )
    emit_count("BroadcastDelivered", dimensions={"Type": str(message.get("type") or "unknown")})
    if dropped:
        emit_count("BroadcastDropped", dimensions={"Type": str(message.get("type") or "unknown")})
    return sent_count


def broadcast_target(
    *,
    target_key: str,
    agent_id: str,
    payload: dict[str, Any],
    space_id: str | None = None,
) -> int:
    """Broadcast a direct message to a recipient target.

    Args:
        target_key: Recipient key: ``space:<space_id>``, ``user:<user_id>``,
            or ``connection:<connection_id>``.
        agent_id: Agent context for authorization checks.
        payload: Payload body to deliver.
        space_id: Optional default space_id for direct delivery.
    """
    target_kind, _, target_id = str(target_key or "").partition(":")
    target_id = target_id.strip()
    if not target_kind or not target_id:
        return 0

    target_space = space_id
    connections: list[dict[str, Any]] = []
    if target_kind == "space":
        target_space = target_id
        connections = _find_topic_subscribers(topic="events", agent_id=agent_id, space_id=target_space)
    elif target_kind == "user":
        connections = [c for c in _find_user_connections(target_id) if _connection_can_access_agent(c, agent_id)]
    elif target_kind == "connection":
        connections = [c for c in _find_connection_by_id(target_id) if _connection_can_access_agent(c, agent_id)]
    else:
        return 0

    message = build_ws_envelope(
        event_type="message",
        agent_id=agent_id,
        space_id=target_space,
        payload=payload,
    )
    return _send_to_connections(connections=connections, message=message)


def broadcast_event(
    *,
    event_type: str,
    agent_id: str,
    space_id: str | None = None,
    payload: dict[str, Any],
) -> int:
    """Broadcast an event to subscribed WebSocket connections.

    Args:
        event_type: Event type (`events.new`, `actions.updated`, etc.)
        agent_id: Agent context for authorization checks.
        space_id: Optional space scope for filtering subscribers.
        payload: Event payload sent in the ``payload`` field.

    Returns:
        Number of messages successfully sent
    """
    topic = _topic_for_event(event_type)
    if not topic:
        logger.debug("Unsupported broadcast event type: %s", event_type)
        return 0

    connections = _find_topic_subscribers(topic=topic, agent_id=agent_id, space_id=space_id)
    if not connections:
        return 0

    message = build_ws_envelope(
        event_type=event_type,
        agent_id=agent_id,
        space_id=space_id,
        payload=payload,
    )
    sent_count = _send_to_connections(connections=connections, message=message)
    logger.debug("Broadcast %s to %d/%d connections", event_type, sent_count, len(connections))
    return sent_count
