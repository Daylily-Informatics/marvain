#!/usr/bin/env python3

import argparse
import sys
from typing import Any

import boto3
from botocore.exceptions import BotoCoreError, ClientError


def _format_output_entry(entry: dict[str, Any]) -> str:
    key = entry.get("OutputKey", "")
    desc = entry.get("Description", "")
    value = entry.get("OutputValue", "")
    lines = [f"- Key: {key}"]
    if desc:
        lines.append(f"  Description: {desc}")
    lines.append(f"  Value: {value}")
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Print CloudFormation output keys, descriptions, and values for a stack.",
    )
    parser.add_argument("stack", help="Stack name to inspect")
    parser.add_argument("--region", help="AWS region (falls back to environment)")
    args = parser.parse_args()

    session_kwargs = {"region_name": args.region} if args.region else {}
    cf = boto3.Session(**session_kwargs).client("cloudformation")

    try:
        resp = cf.describe_stacks(StackName=args.stack)
    except (BotoCoreError, ClientError) as e:
        print(f"Error describing stack {args.stack}: {e}", file=sys.stderr)
        return 1

    stacks = resp.get("Stacks") or []
    if not stacks:
        print(f"No stack found for {args.stack}", file=sys.stderr)
        return 1

    outputs = stacks[0].get("Outputs") or []
    if not outputs:
        print(f"No outputs found for stack {args.stack}.")
        return 0

    print(f"Outputs for stack {args.stack}:")
    print()
    for entry in outputs:
        print(_format_output_entry(entry))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
