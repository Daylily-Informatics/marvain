from __future__ import annotations

import os
import time

import boto3

_TABLE = os.getenv("WS_TABLE")
# Grace period for sending a hello message before the unauthenticated
# connection is auto-cleaned by DynamoDB TTL (seconds).
_CONNECT_GRACE = int(os.getenv("WS_CONNECT_GRACE_SECONDS", "60"))
_dynamo = boto3.resource("dynamodb")


def handler(event, context):
    if not _TABLE:
        return {"statusCode": 500, "body": "WS_TABLE not configured"}
    connection_id = event.get("requestContext", {}).get("connectionId")
    if not connection_id:
        return {"statusCode": 400, "body": "Missing connectionId"}

    now = int(time.time())
    table = _dynamo.Table(_TABLE)
    table.put_item(
        Item={
            "connection_id": connection_id,
            "status": "connected",
            "connected_at": now,
            "ttl": now + _CONNECT_GRACE,
        }
    )
    return {"statusCode": 200, "body": "ok"}
