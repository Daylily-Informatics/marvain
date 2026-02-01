from __future__ import annotations

import json
import logging
import os
import urllib.error
import urllib.request
from functools import lru_cache
from typing import Any

from agent_hub.rate_limit import (
    RetryableError,
    exponential_backoff,
    is_rate_limit_error,
    is_transient_error,
)
from agent_hub.secrets import get_secret_json

logger = logging.getLogger(__name__)

OPENAI_API_BASE = os.getenv("OPENAI_API_BASE", "https://api.openai.com/v1")


@lru_cache(maxsize=1)
def _get_api_key(openai_secret_arn: str) -> str:
    data = get_secret_json(openai_secret_arn)
    key = data.get("api_key") or data.get("value")
    if not key or key == "REPLACE_ME":
        raise RuntimeError("OpenAI API key not set. Update Secrets Manager secret for OpenAI.")
    return str(key)


def _http_json_raw(method: str, url: str, payload: dict[str, Any], *, api_key: str, timeout_s: int = 30) -> dict[str, Any]:
    """Make HTTP request without retry logic."""
    body = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(url, data=body, method=method)
    req.add_header("Authorization", f"Bearer {api_key}")
    req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=timeout_s) as resp:
            raw = resp.read()
        return json.loads(raw.decode("utf-8"))
    except urllib.error.HTTPError as e:
        # Check if this is a retryable error
        error_body = ""
        try:
            error_body = e.read().decode("utf-8")
        except Exception:
            pass
        error_msg = f"HTTP {e.code}: {error_body}"

        if e.code == 429 or is_rate_limit_error(Exception(error_msg)):
            logger.warning("Rate limit hit: %s", error_msg[:500])
            raise RetryableError(error_msg) from e
        if e.code in (502, 503, 504) or is_transient_error(Exception(error_msg)):
            logger.warning("Transient error: %s", error_msg[:500])
            raise RetryableError(error_msg) from e
        raise
    except urllib.error.URLError as e:
        # Connection errors are often transient
        if is_transient_error(e):
            raise RetryableError(str(e)) from e
        raise


@exponential_backoff(max_retries=3, base_delay=1.0, max_delay=60.0, retryable_exceptions=(RetryableError,))
def _http_json(method: str, url: str, payload: dict[str, Any], *, api_key: str, timeout_s: int = 30) -> dict[str, Any]:
    """Make HTTP request with exponential backoff retry."""
    return _http_json_raw(method, url, payload, api_key=api_key, timeout_s=timeout_s)


def extract_output_text(resp: dict[str, Any]) -> str:
    """Best-effort extraction of assistant text from a Responses API response."""
    # Many shapes exist; we walk known fields conservatively.
    if "output_text" in resp and isinstance(resp["output_text"], str):
        return resp["output_text"]

    out = resp.get("output")
    if isinstance(out, list):
        # Look for content entries with text.
        texts: list[str] = []
        for item in out:
            if not isinstance(item, dict):
                continue
            for c in item.get("content", []) or []:
                if isinstance(c, dict) and "text" in c:
                    texts.append(str(c["text"]))
        if texts:
            return "\n".join(texts)

    # Fallback: stringify
    return json.dumps(resp)


def call_responses(
    *,
    openai_secret_arn: str,
    model: str,
    system: str,
    user: str,
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    api_key = _get_api_key(openai_secret_arn)
    payload: dict[str, Any] = {
        "model": model,
        "input": [
            {"role": "system", "content": [{"type": "input_text", "text": system}]},
            {"role": "user", "content": [{"type": "input_text", "text": user}]},
        ],
    }
    if extra:
        payload.update(extra)
    return _http_json("POST", f"{OPENAI_API_BASE}/responses", payload, api_key=api_key)


def call_embeddings(
    *,
    openai_secret_arn: str,
    model: str,
    text: str,
) -> list[float]:
    api_key = _get_api_key(openai_secret_arn)
    payload = {"model": model, "input": text}
    resp = _http_json("POST", f"{OPENAI_API_BASE}/embeddings", payload, api_key=api_key)
    data = resp.get("data") or []
    if not data:
        raise RuntimeError("No embedding returned")
    emb = data[0].get("embedding")
    if not isinstance(emb, list):
        raise RuntimeError("Unexpected embedding response")
    return [float(x) for x in emb]
