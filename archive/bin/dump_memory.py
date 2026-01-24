#!/usr/bin/env python3
"""Dump agent DynamoDB state (events + memories) as JSON."""

import argparse
import json
import os
import sys

import boto3
from boto3.dynamodb.conditions import Key


def _query_items(table, partition_key: str):
    """Query all items for a given partition key."""
    items = []
    start_key = None
    while True:
        params = {"KeyConditionExpression": Key("pk").eq(partition_key)}
        if start_key:
            params["ExclusiveStartKey"] = start_key
        resp = table.query(**params)
        items.extend(resp.get("Items", []))
        start_key = resp.get("LastEvaluatedKey")
        if not start_key:
            break
    return items


def _categorize_items(items):
    buckets = {"events": [], "memories": [], "other": []}
    for item in items:
        sk = str(item.get("sk", ""))
        if "#EVENT#" in sk:
            buckets["events"].append(item)
        elif "#MEMORY#" in sk:
            buckets["memories"].append(item)
        else:
            buckets["other"].append(item)
    return buckets


def _dump(label: str, table_name: str, agent_id: str, items):
    payload = {
        "table": table_name,
        "agent_id": agent_id,
        "count": len(items),
        "items": items,
    }
    print(f"# {label} (agent_id={agent_id})")
    print(json.dumps(payload, indent=2, default=str))
    print()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--region",
        default=os.environ.get("AWS_REGION", "us-east-1"),
        help="AWS region for DynamoDB operations (default: %(default)s)",
    )
    parser.add_argument(
        "--state-table",
        default=os.environ.get("AGENT_STATE_TABLE", ""),
        help="DynamoDB table name for unified agent state (events + memories)",
    )
    parser.add_argument(
        "--agent-id",
        default=os.environ.get("AGENT_ID", "marvain-agent"),
        help="Agent id / partition key suffix to query (default: %(default)s)",
    )
    parser.add_argument(
        "--target",
        choices=["all", "events", "memories", "other"],
        default="all",
        help="Select which categories to dump (default: all)",
    )
    args = parser.parse_args()

    if not args.state_table:
        sys.exit("Missing state table name (set AGENT_STATE_TABLE or --state-table)")

    dynamodb = boto3.resource("dynamodb", region_name=args.region)
    table = dynamodb.Table(args.state_table)

    partition_key = f"AGENT#{args.agent_id}"
    items = _query_items(table, partition_key)
    buckets = _categorize_items(items)

    if args.target in {"events", "all"}:
        _dump("Events", args.state_table, args.agent_id, buckets["events"])

    if args.target in {"memories", "all"}:
        _dump("Memories", args.state_table, args.agent_id, buckets["memories"])

    if args.target in {"other", "all"}:
        _dump("Other items", args.state_table, args.agent_id, buckets["other"])


if __name__ == "__main__":
    main()
