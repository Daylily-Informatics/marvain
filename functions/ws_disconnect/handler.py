from __future__ import annotations

import json
import os

import boto3
from agent_hub.config import load_config
from agent_hub.device_routing import DeviceRoutingError, record_device_disconnect
from agent_hub.rds_data import RdsData, RdsDataEnv

_TABLE = os.getenv("WS_TABLE")
_SUBS_TABLE = os.getenv("WS_SUBSCRIPTIONS_TABLE")
_dynamo = boto3.resource("dynamodb")
_db: RdsData | None = None


def _get_db() -> RdsData:
    global _db
    if _db is None:
        cfg = load_config()
        _db = RdsData(RdsDataEnv(resource_arn=cfg.db_resource_arn, secret_arn=cfg.db_secret_arn, database=cfg.db_name))
    return _db


def _response(status_code: int, payload: dict) -> dict:
    return {"statusCode": status_code, "body": json.dumps(payload, sort_keys=True)}


def handler(event, context):
    if not _TABLE:
        return _response(500, {"ok": False, "error": "WS_TABLE not configured"})
    if not _SUBS_TABLE:
        return _response(500, {"ok": False, "error": "WS_SUBSCRIPTIONS_TABLE not configured"})
    connection_id = event.get("requestContext", {}).get("connectionId")
    if not connection_id:
        return _response(400, {"ok": False, "error": "Missing connectionId"})

    table = _dynamo.Table(_TABLE)
    item_response = table.get_item(Key={"connection_id": connection_id}, ConsistentRead=True)
    connection = item_response.get("Item")
    if connection is None:
        return _response(200, {"ok": True, "connection_id": connection_id, "already_absent": True})
    if not isinstance(connection, dict):
        return _response(500, {"ok": False, "error": "connection_registry_malformed"})

    disconnect_event_id = None
    if str(connection.get("principal_type") or "") == "device":
        try:
            disconnect_event_id = record_device_disconnect(
                _get_db(),
                connection=connection,
                reason="api_gateway_disconnect",
            )
        except DeviceRoutingError as exc:
            return _response(500, {"ok": False, "error": exc.code})

    subs_table = _dynamo.Table(_SUBS_TABLE)
    try:
        items = []
        exclusive_start_key = None
        while True:
            query = {
                "IndexName": "connection_id_index",
                "KeyConditionExpression": "connection_id = :cid",
                "ExpressionAttributeValues": {":cid": connection_id},
            }
            if exclusive_start_key is not None:
                query["ExclusiveStartKey"] = exclusive_start_key
            response = subs_table.query(
                **query,
            )
            page = response.get("Items")
            if not isinstance(page, list) or any(not isinstance(item, dict) for item in page):
                return _response(500, {"ok": False, "error": "subscription_registry_malformed"})
            items.extend(page)
            exclusive_start_key = response.get("LastEvaluatedKey")
            if exclusive_start_key is None:
                break
            if not isinstance(exclusive_start_key, dict) or not exclusive_start_key:
                return _response(500, {"ok": False, "error": "subscription_registry_malformed"})
        for item in items:
            topic_key = str(item.get("topic_key") or "")
            if not topic_key:
                return _response(500, {"ok": False, "error": "subscription_registry_malformed"})
            subs_table.delete_item(Key={"topic_key": topic_key, "connection_id": connection_id})
    except Exception as exc:
        return _response(500, {"ok": False, "error": f"subscription_cleanup_failed:{type(exc).__name__}"})

    table.delete_item(Key={"connection_id": connection_id})
    return _response(
        200,
        {
            "ok": True,
            "connection_id": connection_id,
            "disconnect_event_id": disconnect_event_id,
            "subscriptions_removed": len(items),
        },
    )
