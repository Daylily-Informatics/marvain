from __future__ import annotations

import os

import boto3

_TABLE = os.getenv("WS_TABLE")
_SUBS_TABLE = os.getenv("WS_SUBSCRIPTIONS_TABLE")
_dynamo = boto3.resource("dynamodb")


def handler(event, context):
    if not _TABLE:
        return {"statusCode": 500, "body": "WS_TABLE not configured"}
    connection_id = event.get("requestContext", {}).get("connectionId")
    if not connection_id:
        return {"statusCode": 400, "body": "Missing connectionId"}

    table = _dynamo.Table(_TABLE)
    table.delete_item(Key={"connection_id": connection_id})

    if _SUBS_TABLE:
        subs_table = _dynamo.Table(_SUBS_TABLE)
        try:
            response = subs_table.query(
                IndexName="connection_id_index",
                KeyConditionExpression="connection_id = :cid",
                ExpressionAttributeValues={":cid": connection_id},
            )
            items = list(response.get("Items", []))
            while "LastEvaluatedKey" in response:
                response = subs_table.query(
                    IndexName="connection_id_index",
                    KeyConditionExpression="connection_id = :cid",
                    ExpressionAttributeValues={":cid": connection_id},
                    ExclusiveStartKey=response["LastEvaluatedKey"],
                )
                items.extend(response.get("Items", []))
            for item in items:
                topic_key = str(item.get("topic_key") or "")
                if topic_key:
                    subs_table.delete_item(Key={"topic_key": topic_key, "connection_id": connection_id})
        except Exception:
            # Best-effort cleanup only.
            pass
    return {"statusCode": 200, "body": "ok"}
