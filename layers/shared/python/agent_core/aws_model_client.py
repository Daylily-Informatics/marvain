from __future__ import annotations

import json
import logging
import os
from typing import Any, Dict, List, Optional

import boto3


class AwsModelClient:
    """Wrapper for AWS Bedrock Runtime.

    We prefer Bedrock's `converse` API (more uniform across models). We also expose
    `invoke()` as a best-effort fallback.
    """

    def __init__(self, model_id: str, region: Optional[str] = None):
        if not model_id:
            raise ValueError("MODEL_ID must be set (empty model_id).")

        self.model_id = model_id
        self.region = region

        if region:
            self.bedrock = boto3.client("bedrock-runtime", region_name=region)
        else:
            self.bedrock = boto3.client("bedrock-runtime")

    @classmethod
    def from_env(cls) -> "AwsModelClient":
        model_id = os.environ.get("MODEL_ID", "").strip()
        region = (os.environ.get("AWS_REGION") or os.environ.get("REGION") or "").strip() or None
        return cls(model_id=model_id, region=region)

    def converse(
        self,
        system_text: str,
        user_text: str,
        *,
        max_tokens: int = 512,
        temperature: float = 0.2,
        top_p: float = 0.9,
    ) -> str:
        """Call Bedrock Converse and return assistant text."""
        try:
            resp = self.bedrock.converse(
                modelId=self.model_id,
                system=[{"text": system_text}],
                messages=[
                    {
                        "role": "user",
                        "content": [{"text": user_text}],
                    }
                ],
                inferenceConfig={
                    "maxTokens": int(max_tokens),
                    "temperature": float(temperature),
                    "topP": float(top_p),
                },
            )
        except Exception as e:
            logging.warning("Bedrock.converse failed (model=%s): %s", self.model_id, e)
            raise

        try:
            parts = resp["output"]["message"]["content"]
            texts = [p.get("text", "") for p in parts if isinstance(p, dict)]
            return "".join(texts).strip()
        except Exception:
            # last resort: return full response as JSON
            return json.dumps(resp, default=str)

    def invoke(self, body_bytes: bytes, *, content_type: str = "application/json") -> Dict[str, Any]:
        """Raw invoke_model passthrough."""
        return self.bedrock.invoke_model(
            modelId=self.model_id,
            contentType=content_type,
            accept="application/json",
            body=body_bytes,
        )
