"""Broadcast module for real-time WebSocket event streaming.

This module sends events to WebSocket-connected clients via API Gateway
Management API. Subscriptions are stored in DynamoDB (WsConnectionsTable).

Usage:
    from agent_hub.broadcast import broadcast_event

    broadcast_event(
        event_type="events.new",
        agent_id="...",
        space_id="...",
        payload={"event_id": "...", "type": "transcript_chunk", ...},
    )
"""

from __future__ import annotations

import json
import logging
import os
from typing import Any

import boto3
from botocore.exceptions import ClientError

logger = logging.getLogger(__name__)

_WS_TABLE_NAME = os.getenv("WS_TABLE")
_WS_API_ENDPOINT = os.getenv("WS_API_ENDPOINT")  # e.g., https://{api-id}.execute-api.{region}.amazonaws.com/{stage}

_dynamo = None
_mgmt_api = None


def _get_dynamodb():
    global _dynamo
    if _dynamo is None:
        _dynamo = boto3.resource("dynamodb")
    return _dynamo


def _get_mgmt_api():
    """Get API Gateway Management API client.

    Note: In Lambda context, WS_API_ENDPOINT should be set to the WebSocket API endpoint.
    """
    global _mgmt_api
    if _mgmt_api is None and _WS_API_ENDPOINT:
        _mgmt_api = boto3.client("apigatewaymanagementapi", endpoint_url=_WS_API_ENDPOINT)
    return _mgmt_api


def _find_subscribed_connections(agent_id: str, space_id: str | None = None) -> list[dict]:
    """Find all connections subscribed to events for this agent/space.

    Returns list of connection records that match the subscription pattern.
    Subscription keys are stored as: "events:{agent_id}" or "events:{agent_id}:{space_id}"
    """
    if not _WS_TABLE_NAME:
        return []

    table = _get_dynamodb().Table(_WS_TABLE_NAME)

    # We need to scan for connections with matching subscriptions
    # This is not ideal for large scale, but sufficient for current usage
    # A GSI on agent_id would improve this
    try:
        # Build subscription patterns to match
        patterns = [f"events:{agent_id}"]
        if space_id:
            patterns.append(f"events:{agent_id}:{space_id}")

        # Scan for connections with agent_id (filter in Python for subscriptions)
        response = table.scan(
            FilterExpression="agent_id = :aid AND #s = :status",
            ExpressionAttributeNames={"#s": "status"},
            ExpressionAttributeValues={
                ":aid": agent_id,
                ":status": "authenticated",
            },
        )

        matching = []
        for item in response.get("Items", []):
            subs = item.get("subscriptions") or []
            # Check if any subscription matches our patterns
            for pattern in patterns:
                if pattern in subs:
                    matching.append(item)
                    break

        return matching
    except Exception as e:
        logger.warning("Failed to query subscribed connections: %s", e)
        return []


def broadcast_event(
    *,
    event_type: str,
    agent_id: str,
    space_id: str | None = None,
    payload: dict[str, Any],
) -> int:
    """Broadcast an event to all subscribed WebSocket connections.

    Args:
        event_type: Type of event (e.g., "events.new", "actions.updated", "presence.updated")
        agent_id: Agent ID to scope the broadcast
        space_id: Optional space ID for more specific targeting
        payload: Event payload to send

    Returns:
        Number of messages successfully sent
    """
    mgmt_api = _get_mgmt_api()
    if not mgmt_api:
        logger.debug("WebSocket broadcast not configured (no WS_API_ENDPOINT)")
        return 0

    connections = _find_subscribed_connections(agent_id, space_id)
    if not connections:
        return 0

    message = {
        "type": event_type,
        "agent_id": agent_id,
        "space_id": space_id,
        **payload,
    }
    data = json.dumps(message).encode("utf-8")

    sent_count = 0
    stale_connections = []

    for conn in connections:
        connection_id = conn.get("connection_id")
        if not connection_id:
            continue

        try:
            mgmt_api.post_to_connection(ConnectionId=connection_id, Data=data)
            sent_count += 1
        except ClientError as e:
            error_code = e.response.get("Error", {}).get("Code", "")
            if error_code == "GoneException":
                # Connection is stale, mark for cleanup
                stale_connections.append(connection_id)
            else:
                logger.warning("Failed to send to connection %s: %s", connection_id, e)
        except Exception as e:
            logger.warning("Failed to send to connection %s: %s", connection_id, e)

    # Clean up stale connections
    if stale_connections and _WS_TABLE_NAME:
        table = _get_dynamodb().Table(_WS_TABLE_NAME)
        for conn_id in stale_connections:
            try:
                table.delete_item(Key={"connection_id": conn_id})
                logger.debug("Cleaned up stale connection: %s", conn_id)
            except Exception:
                pass

    logger.debug("Broadcast %s to %d/%d connections", event_type, sent_count, len(connections))
    return sent_count
