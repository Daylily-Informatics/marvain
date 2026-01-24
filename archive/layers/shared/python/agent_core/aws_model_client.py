from __future__ import annotations

import json
import logging
import os
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Tuple

import boto3


@dataclass
class ToolResult:
    """Result from executing a tool."""
    tool_use_id: str
    content: Any
    is_error: bool = False


@dataclass
class ToolRequest:
    """A tool invocation request from the model."""
    tool_use_id: str
    name: str
    input: Dict[str, Any]


@dataclass
class ConversationTurn:
    """Represents a single turn in a conversation with potential tool use."""
    text: str = ""
    tool_requests: List[ToolRequest] = field(default_factory=list)
    stop_reason: str = ""
    raw_response: Dict[str, Any] = field(default_factory=dict)

    @property
    def has_tool_use(self) -> bool:
        return bool(self.tool_requests) or self.stop_reason == "tool_use"


class AwsModelClient:
    """Wrapper for AWS Bedrock Runtime with full tool use support.

    We prefer Bedrock's `converse` API (more uniform across models). We also expose
    `invoke()` as a best-effort fallback.
    """

    # Retry configuration
    MAX_RETRIES = 3
    INITIAL_BACKOFF = 1.0
    MAX_BACKOFF = 30.0

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

    def _should_retry(self, exception: Exception) -> bool:
        """Determine if an exception is retryable."""
        error_str = str(exception).lower()
        retryable_errors = [
            "throttling",
            "rate exceeded",
            "too many requests",
            "service unavailable",
            "internal server error",
            "connection",
            "timeout",
        ]
        return any(err in error_str for err in retryable_errors)

    def _call_with_retry(self, func: Callable, *args, **kwargs) -> Any:
        """Execute a function with exponential backoff retry."""
        last_exception = None
        backoff = self.INITIAL_BACKOFF

        for attempt in range(self.MAX_RETRIES):
            try:
                return func(*args, **kwargs)
            except Exception as e:
                last_exception = e
                if not self._should_retry(e) or attempt == self.MAX_RETRIES - 1:
                    raise

                logging.warning(
                    "Bedrock call failed (attempt %d/%d), retrying in %.1fs: %s",
                    attempt + 1, self.MAX_RETRIES, backoff, e
                )
                time.sleep(backoff)
                backoff = min(backoff * 2, self.MAX_BACKOFF)

        raise last_exception  # type: ignore

    def _build_tool_config(self, tools: Optional[List[Dict[str, Any]]]) -> Optional[Dict[str, Any]]:
        """Convert tool specs to Bedrock toolConfig format."""
        if not tools:
            return None

        tool_specs = []
        for tool in tools:
            spec = {
                "toolSpec": {
                    "name": tool.get("name", ""),
                    "description": tool.get("description", ""),
                    "inputSchema": {
                        "json": tool.get("input_schema", {"type": "object", "properties": {}})
                    }
                }
            }
            tool_specs.append(spec)

        return {"tools": tool_specs}

    def _parse_tool_requests(self, content: List[Dict[str, Any]]) -> List[ToolRequest]:
        """Parse tool use requests from response content."""
        requests = []
        for item in content:
            if "toolUse" in item:
                tool_use = item["toolUse"]
                requests.append(ToolRequest(
                    tool_use_id=tool_use.get("toolUseId", ""),
                    name=tool_use.get("name", ""),
                    input=tool_use.get("input", {}),
                ))
        return requests

    def _extract_text(self, content: List[Dict[str, Any]]) -> str:
        """Extract text from response content."""
        texts = []
        for item in content:
            if isinstance(item, dict) and "text" in item:
                texts.append(item["text"])
        return "".join(texts).strip()

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
            resp = self._call_with_retry(
                self.bedrock.converse,
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

    def converse_with_tools(
        self,
        system_text: str,
        messages: List[Dict[str, Any]],
        tools: Optional[List[Dict[str, Any]]] = None,
        *,
        max_tokens: int = 1024,
        temperature: float = 0.2,
        top_p: float = 0.9,
    ) -> ConversationTurn:
        """Call Bedrock Converse with tool support.

        Args:
            system_text: System prompt text
            messages: List of conversation messages in Bedrock format
            tools: List of tool specifications
            max_tokens: Maximum tokens in response
            temperature: Sampling temperature
            top_p: Top-p sampling parameter

        Returns:
            ConversationTurn with text, tool requests, and metadata
        """
        kwargs: Dict[str, Any] = {
            "modelId": self.model_id,
            "system": [{"text": system_text}],
            "messages": messages,
            "inferenceConfig": {
                "maxTokens": int(max_tokens),
                "temperature": float(temperature),
                "topP": float(top_p),
            },
        }

        tool_config = self._build_tool_config(tools)
        if tool_config:
            kwargs["toolConfig"] = tool_config

        try:
            resp = self._call_with_retry(self.bedrock.converse, **kwargs)
        except Exception as e:
            logging.error("Bedrock.converse_with_tools failed (model=%s): %s", self.model_id, e)
            raise

        stop_reason = resp.get("stopReason", "")
        content = resp.get("output", {}).get("message", {}).get("content", [])

        return ConversationTurn(
            text=self._extract_text(content),
            tool_requests=self._parse_tool_requests(content),
            stop_reason=stop_reason,
            raw_response=resp,
        )

    def build_tool_result_message(self, results: List[ToolResult]) -> Dict[str, Any]:
        """Build a user message containing tool results.

        Args:
            results: List of tool execution results

        Returns:
            A message dict suitable for adding to the conversation
        """
        content = []
        for result in results:
            tool_result: Dict[str, Any] = {
                "toolUseId": result.tool_use_id,
                "content": [
                    {"json": result.content} if isinstance(result.content, dict)
                    else {"text": str(result.content)}
                ],
            }
            if result.is_error:
                tool_result["status"] = "error"
            content.append({"toolResult": tool_result})

        return {"role": "user", "content": content}

    def build_assistant_message(self, turn: ConversationTurn) -> Dict[str, Any]:
        """Build an assistant message from a conversation turn.

        This is useful for continuing conversations after tool use.
        """
        content = []
        if turn.text:
            content.append({"text": turn.text})
        for req in turn.tool_requests:
            content.append({
                "toolUse": {
                    "toolUseId": req.tool_use_id,
                    "name": req.name,
                    "input": req.input,
                }
            })
        return {"role": "assistant", "content": content}

    def invoke(self, body_bytes: bytes, *, content_type: str = "application/json") -> Dict[str, Any]:
        """Raw invoke_model passthrough."""
        return self._call_with_retry(
            self.bedrock.invoke_model,
            modelId=self.model_id,
            contentType=content_type,
            accept="application/json",
            body=body_bytes,
        )
