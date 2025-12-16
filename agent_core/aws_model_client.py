from __future__ import annotations

import os
import json
import logging
from typing import Any, Dict, List, Optional, Tuple

import boto3

logger = logging.getLogger(__name__)


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, str(default)))
    except Exception:
        return default


class AwsModelClient:
    """Thin wrapper around AWS Bedrock Runtime.

    This is intentionally minimal. It prefers the Converse API and falls back to a local
    stub if Bedrock isn't reachable.
    """

    def __init__(self, *, model_id: str, region: Optional[str] = None):
        self.model_id = model_id
        self.region = region or os.environ.get("AWS_REGION") or os.environ.get("AWS_DEFAULT_REGION") or "us-east-1"
        self._client = boto3.client("bedrock-runtime", region_name=self.region)

        self.max_tokens = _env_int("MAX_TOKENS", 800)
        self.temperature = float(os.environ.get("TEMPERATURE", "0.2"))
        self.top_p = float(os.environ.get("TOP_P", "0.9"))

    @classmethod
    def from_env(cls) -> "AwsModelClient":
        model_id = os.environ.get("MODEL_ID")
        if not model_id:
            raise RuntimeError("MODEL_ID env var is required")
        region = os.environ.get("AWS_REGION") or os.environ.get("AWS_DEFAULT_REGION")
        return cls(model_id=model_id, region=region)

    # -------------------------------------------------------------------------

    @staticmethod
    def _openai_tools_to_bedrock(tools: Optional[List[Dict[str, Any]]]) -> Optional[Dict[str, Any]]:
        if not tools:
            return None
        bedrock_tools = []
        for t in tools:
            if t.get("type") != "function":
                continue
            fn = t.get("function") or {}
            name = fn.get("name")
            if not name:
                continue
            bedrock_tools.append(
                {
                    "toolSpec": {
                        "name": name,
                        "description": fn.get("description") or "",
                        "inputSchema": {"json": fn.get("parameters") or {"type": "object"}},
                    }
                }
            )
        if not bedrock_tools:
            return None
        return {"tools": bedrock_tools}

    @staticmethod
    def _openai_messages_to_bedrock(messages: List[Dict[str, Any]]) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
        """Convert OpenAI-ish messages into Bedrock Converse format.

        Returns (system_blocks, message_list).
        """
        system_blocks: List[Dict[str, Any]] = []
        bedrock_messages: List[Dict[str, Any]] = []

        for m in messages:
            role = m.get("role")
            content = m.get("content", "")
            if content is None:
                content = ""
            if role == "system":
                # Bedrock expects system as separate blocks
                system_blocks.append({"text": str(content)})
                continue
            if role not in ("user", "assistant"):
                role = "user"
            bedrock_messages.append({"role": role, "content": [{"text": str(content)}]})

        return system_blocks, bedrock_messages

    @staticmethod
    def _extract_text_and_tool_calls(converse_response: Dict[str, Any]) -> Tuple[str, List[Dict[str, Any]]]:
        """Extract plain text and toolUse blocks from a Bedrock Converse response."""
        tool_calls: List[Dict[str, Any]] = []
        parts: List[str] = []

        msg = (((converse_response or {}).get("output") or {}).get("message") or {})
        for block in msg.get("content") or []:
            if "text" in block:
                parts.append(block["text"])
            if "toolUse" in block:
                tu = block["toolUse"]
                tool_calls.append(
                    {
                        "id": tu.get("toolUseId"),
                        "name": tu.get("name"),
                        "input": tu.get("input") or {},
                    }
                )
        return ("".join(parts).strip(), tool_calls)

    def _fallback_stub(self, messages: List[Dict[str, Any]], reason: str) -> Dict[str, Any]:
        # Cheap, deterministic fallback that still respects the planner JSON contract.
        user_text = ""
        for m in reversed(messages):
            if m.get("role") == "user":
                user_text = str(m.get("content", ""))
                break
        reply = f"Bedrock unavailable ({reason}). Echoing user text: {user_text[:400]}".strip()
        return {
            "text": json.dumps({"reply_text": reply, "actions": [{"kind": "LOG", "payload": {"reason": reason}}], "new_memories": []}),
            "tool_calls": [],
            "raw": {"fallback": True, "reason": reason},
            "model_id": self.model_id,
        }

    def chat(self, *, messages: List[Dict[str, Any]], tools: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
        """Call Bedrock (Converse) and return a normalized response dict."""
        if os.environ.get("LOCAL_FAKE_LLM") == "1":
            return self._fallback_stub(messages, "LOCAL_FAKE_LLM=1")

        system_blocks, bedrock_messages = self._openai_messages_to_bedrock(messages)
        tool_config = self._openai_tools_to_bedrock(tools)

        try:
            kwargs: Dict[str, Any] = {
                "modelId": self.model_id,
                "messages": bedrock_messages,
                "inferenceConfig": {
                    "maxTokens": self.max_tokens,
                    "temperature": self.temperature,
                    "topP": self.top_p,
                },
            }
            if system_blocks:
                kwargs["system"] = system_blocks
            if tool_config:
                kwargs["toolConfig"] = tool_config

            resp = self._client.converse(**kwargs)
            text, tool_calls = self._extract_text_and_tool_calls(resp)

            return {"text": text, "tool_calls": tool_calls, "raw": resp, "model_id": self.model_id}
        except Exception as e:
            logger.warning("Bedrock converse failed; using fallback stub. error=%s", e, exc_info=True)
            return self._fallback_stub(messages, str(e))
