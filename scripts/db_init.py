#!/usr/bin/env python3
from __future__ import annotations

import argparse
import os
import sys

import boto3


def split_sql(sql_text: str) -> list[str]:
    # Naive splitter: good enough for our small schema file.
    stmts: list[str] = []
    buf: list[str] = []
    for line in sql_text.splitlines():
        # Strip single-line comments
        if line.strip().startswith("--"):
            continue
        buf.append(line)
        if ";" in line:
            joined = "\n".join(buf)
            parts = joined.split(";")
            # Keep everything up to last ';'
            for p in parts[:-1]:
                s = p.strip()
                if s:
                    stmts.append(s)
            buf = [parts[-1]]
    tail = "\n".join(buf).strip()
    if tail:
        stmts.append(tail)
    return stmts


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--resource-arn", required=True)
    ap.add_argument("--secret-arn", required=True)
    ap.add_argument("--database", required=True)
    ap.add_argument("--region", default=os.getenv("AWS_REGION") or os.getenv("AWS_DEFAULT_REGION") or "us-east-1")
    ap.add_argument("--sql-file", default=os.path.join(os.path.dirname(__file__), "..", "sql", "001_init.sql"))
    args = ap.parse_args()

    with open(args.sql_file, "r", encoding="utf-8") as f:
        sql_text = f.read()

    stmts = split_sql(sql_text)
    if not stmts:
        print("No SQL statements found", file=sys.stderr)
        return 2

    client = boto3.client("rds-data", region_name=args.region)

    for i, stmt in enumerate(stmts, start=1):
        print(f"[{i}/{len(stmts)}] {stmt.splitlines()[0][:80]}...")
        client.execute_statement(
            resourceArn=args.resource_arn,
            secretArn=args.secret_arn,
            database=args.database,
            sql=stmt,
        )

    print("DB init complete")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
