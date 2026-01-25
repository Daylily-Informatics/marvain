from __future__ import annotations

import os
import time

import boto3

_TABLE = os.getenv("WS_TABLE")
_dynamo = boto3.resource("dynamodb")


def handler(event, context):
    if not _TABLE:
        return {"statusCode": 500, "body": "WS_TABLE not configured"}
    connection_id = event.get("requestContext", {}).get("connectionId")
    if not connection_id:
        return {"statusCode": 400, "body": "Missing connectionId"}

    table = _dynamo.Table(_TABLE)
    table.put_item(
        Item={
            "connection_id": connection_id,
            "status": "connected",
            "connected_at": int(time.time()),
        }
    )
    return {"statusCode": 200, "body": "ok"}
