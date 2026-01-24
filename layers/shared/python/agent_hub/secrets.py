from __future__ import annotations

import json
import os
from functools import lru_cache
from typing import Any

import boto3


@lru_cache(maxsize=32)
def get_secret_json(secret_arn: str) -> dict[str, Any]:
    client = boto3.client("secretsmanager")
    resp = client.get_secret_value(SecretId=secret_arn)
    s = resp.get("SecretString") or "{}"
    try:
        return json.loads(s)
    except json.JSONDecodeError:
        # allow raw string secrets too
        return {"value": s}


def get_env_secret_json(env_var: str) -> dict[str, Any] | None:
    arn = os.getenv(env_var)
    if not arn:
        return None
    return get_secret_json(arn)
