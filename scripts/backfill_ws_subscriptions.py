#!/usr/bin/env python3
from __future__ import annotations

import argparse
import os
import time

import boto3


def main() -> int:
    parser = argparse.ArgumentParser(description="Backfill WS subscription index from connection table")
    parser.add_argument("--ws-table", default=os.getenv("WS_TABLE"), help="WebSocket connections table name")
    parser.add_argument("--subs-table", default=os.getenv("WS_SUBSCRIPTIONS_TABLE"), help="Subscriptions table name")
    parser.add_argument("--region", default=os.getenv("AWS_REGION") or os.getenv("AWS_DEFAULT_REGION") or "us-east-1")
    args = parser.parse_args()

    if not args.ws_table or not args.subs_table:
        raise SystemExit("Both --ws-table and --subs-table are required")

    dynamo = boto3.resource("dynamodb", region_name=args.region)
    ws_table = dynamo.Table(args.ws_table)
    subs_table = dynamo.Table(args.subs_table)

    now = int(time.time())
    scanned = 0
    written = 0

    resp = ws_table.scan()
    while True:
        items = resp.get("Items", [])
        for item in items:
            scanned += 1
            if str(item.get("status") or "") != "authenticated":
                continue
            conn_id = str(item.get("connection_id") or "")
            if not conn_id:
                continue
            ttl = int(item.get("ttl") or (now + 3600))
            subscriptions = item.get("subscriptions") or []
            for topic_key in subscriptions:
                topic = str(topic_key or "").strip()
                if not topic:
                    continue
                subs_table.put_item(
                    Item={
                        "topic_key": topic,
                        "connection_id": conn_id,
                        "ttl": ttl,
                    }
                )
                written += 1

        lek = resp.get("LastEvaluatedKey")
        if not lek:
            break
        resp = ws_table.scan(ExclusiveStartKey=lek)

    print(f"scanned={scanned} written={written}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
