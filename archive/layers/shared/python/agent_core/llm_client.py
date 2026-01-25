from __future__ import annotations

import json
import logging
import os
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from agent_core.aws_model_client import AwsModelClient, ConversationTurn, ToolRequest, ToolResult


def _load_prompt(name: str, default_text: str) -> str:
    """Load prompt text from config layer or local repo."""
    candidates: List[Path] = []

    # Lambda layer mount
    candidates.append(Path(f"/opt/prompts/{name}.txt"))

    # Explicit override
    prompts_dir = os.environ.get("PROMPTS_DIR")
    if prompts_dir:
        candidates.append(Path(prompts_dir) / f"{name}.txt")

    # Repo-relative search (local dev)
    here = Path(__file__).resolve()
    for parent in list(here.parents)[:10]:
        candidates.append(parent / "layers" / "config" / "prompts" / f"{name}.txt")

    for p in candidates:
        try:
            if p.exists():
                return p.read_text(encoding="utf-8").strip()
        except Exception as e:
            logging.debug("prompt load failed for %s: %s", p, e)

    return default_text.strip()


BASE_SYSTEM_PROMPT = _load_prompt(
    "system",
    default_text="""You are a helpful AI agent.

Return a single JSON object:
{
  "reply_text": "<string>",
  "actions": [],
  "new_memories": []
}

Do not wrap JSON in markdown fences.
""",
)

HEARTBEAT_PROMPT = _load_prompt(
    "heartbeat",
    default_text="""You are a system heartbeat for an AI agent.

Your job: review recent context and decide if any background actions or memories should be recorded.

Return a single JSON object:
{
  "reply_text": "<string or empty>",
  "actions": [],
  "new_memories": []
}

Do not wrap JSON in markdown fences.
""",
)


# Maximum tool use iterations to prevent infinite loops
MAX_TOOL_ITERATIONS = 5


def build_system_prompt(
    *,
    memories: List[Dict[str, Any]],
    personality_extra: Optional[str] = None,
    voice_extra: Optional[str] = None,
    heartbeat_mode: bool = False,
    tools_spec: Optional[List[Dict[str, Any]]] = None,
    speaker_context: Optional[Dict[str, Any]] = None,
) -> str:
    """Compose the system prompt from base instructions, context, and optional extras."""
    base = HEARTBEAT_PROMPT if heartbeat_mode else BASE_SYSTEM_PROMPT
    prompt = base.strip()

    if tools_spec:
        prompt += "\n\n## Available Tools\n"
        prompt += "You can use these tools by including tool calls in your response. "
        prompt += "The system will execute them and provide results.\n"
        for t in tools_spec:
            try:
                prompt += f"\n### {t.get('name')}\n{t.get('description')}\n"
                if t.get('input_schema'):
                    prompt += f"Parameters: {json.dumps(t['input_schema'], indent=2)}\n"
            except Exception:
                pass

    if memories:
        try:
            context_json = json.dumps(memories, default=str)
        except Exception as e:
            logging.debug("Could not JSON-encode memories: %s", e)
            context_json = str(memories)
        prompt += "\n\n## Recent Context\n" + context_json

    if speaker_context:
        prompt += "\n\n## Current Speaker Information\n"
        prompt += json.dumps(speaker_context, indent=2)

    if voice_extra:
        prompt += "\n\n## Voice Context\n" + voice_extra.strip()

    if personality_extra:
        prompt += "\n\n## Personality Instructions\n" + personality_extra.strip()

    return prompt.strip()


def chat_with_tools(
    model_client: AwsModelClient,
    messages: List[Dict[str, str]],
    tools: List[Dict[str, Any]],
    tool_executor: Optional[Callable[[ToolRequest], ToolResult]] = None,
) -> str:
    """Call the LLM and return raw assistant output.

    This uses Bedrock Converse for portability across supported models.
    If tool_executor is provided, tool use requests will be executed automatically.
    """
    system_msg = next((m for m in messages if m.get("role") == "system"), None)
    user_msg = next((m for m in reversed(messages) if m.get("role") == "user"), None)

    system_text = system_msg.get("content", "") if system_msg else ""
    user_text = user_msg.get("content", "") if user_msg else ""

    # If tools were supplied but no executor, we reinforce the JSON output contract.
    if tools and not tool_executor:
        system_text += (
            "\n\nIMPORTANT: Output MUST be a single JSON object with keys reply_text, actions, new_memories. "
            "Do not use markdown fences."
        )

    try:
        if tool_executor and tools:
            return _chat_with_tool_execution(
                model_client, system_text, user_text, tools, tool_executor
            )
        else:
            return model_client.converse(system_text=system_text, user_text=user_text)
    except Exception as e:
        logging.error("chat_with_tools: model call failed: %s", e)
        # fail soft
        return json.dumps(
            {
                "reply_text": "[ERROR] LLM invocation failed. Check Bedrock access, region, and MODEL_ID.",
                "actions": [],
                "new_memories": [{"kind": "META", "text": f"LLM error: {str(e)}"}],
            }
        )


def _chat_with_tool_execution(
    model_client: AwsModelClient,
    system_text: str,
    user_text: str,
    tools: List[Dict[str, Any]],
    tool_executor: Callable[[ToolRequest], ToolResult],
) -> str:
    """Execute a conversation with automatic tool use.

    This function handles the tool use loop:
    1. Send message to model
    2. If model requests tools, execute them
    3. Send results back to model
    4. Repeat until model returns final response or max iterations
    """
    # Build initial conversation
    conversation: List[Dict[str, Any]] = [
        {"role": "user", "content": [{"text": user_text}]}
    ]

    collected_text_parts: List[str] = []
    collected_tool_calls: List[Dict[str, Any]] = []

    for iteration in range(MAX_TOOL_ITERATIONS):
        logging.debug("Tool execution iteration %d", iteration + 1)

        turn = model_client.converse_with_tools(
            system_text=system_text,
            messages=conversation,
            tools=tools,
        )

        # Collect any text from this turn
        if turn.text:
            collected_text_parts.append(turn.text)

        # Track tool calls for logging/debugging
        for req in turn.tool_requests:
            collected_tool_calls.append({
                "name": req.name,
                "input": req.input,
                "tool_use_id": req.tool_use_id,
            })

        # If no tool use, we're done
        if not turn.has_tool_use:
            logging.debug("Model finished without tool use (stop_reason=%s)", turn.stop_reason)
            break

        # Execute tools and collect results
        results: List[ToolResult] = []
        for tool_req in turn.tool_requests:
            logging.info("Executing tool: %s with input: %s", tool_req.name, tool_req.input)
            try:
                result = tool_executor(tool_req)
                results.append(result)
                logging.info("Tool %s completed: %s", tool_req.name, result.content)
            except Exception as e:
                logging.error("Tool %s failed: %s", tool_req.name, e)
                results.append(ToolResult(
                    tool_use_id=tool_req.tool_use_id,
                    content=f"Error executing tool: {str(e)}",
                    is_error=True,
                ))

        # Add assistant message with tool use to conversation
        conversation.append(model_client.build_assistant_message(turn))

        # Add tool results to conversation
        conversation.append(model_client.build_tool_result_message(results))

    else:
        logging.warning("Reached maximum tool iterations (%d)", MAX_TOOL_ITERATIONS)

    # Return the final text response
    final_text = " ".join(collected_text_parts).strip()
    if not final_text:
        # If no text but we had tool calls, generate a summary
        final_text = json.dumps({
            "reply_text": "I've completed the requested actions.",
            "actions": collected_tool_calls,
            "new_memories": [],
        })

    return final_text


def converse_with_full_tools(
    model_client: AwsModelClient,
    system_text: str,
    user_text: str,
    tools: List[Dict[str, Any]],
    tool_executor: Callable[[ToolRequest], ToolResult],
) -> Dict[str, Any]:
    """Execute a full conversation with tool use and return structured result.

    Returns:
        Dict with keys:
        - reply_text: Final text response
        - tool_calls: List of tool calls made
        - tool_results: List of tool results
        - iterations: Number of conversation turns
    """
    conversation: List[Dict[str, Any]] = [
        {"role": "user", "content": [{"text": user_text}]}
    ]

    all_tool_calls: List[Dict[str, Any]] = []
    all_tool_results: List[Dict[str, Any]] = []
    final_text = ""
    iterations = 0

    for iteration in range(MAX_TOOL_ITERATIONS):
        iterations = iteration + 1
        turn = model_client.converse_with_tools(
            system_text=system_text,
            messages=conversation,
            tools=tools,
        )

        if turn.text:
            final_text = turn.text

        if not turn.has_tool_use:
            break

        results: List[ToolResult] = []
        for tool_req in turn.tool_requests:
            all_tool_calls.append({
                "name": tool_req.name,
                "input": tool_req.input,
                "tool_use_id": tool_req.tool_use_id,
            })
            try:
                result = tool_executor(tool_req)
                results.append(result)
                all_tool_results.append({
                    "tool_use_id": tool_req.tool_use_id,
                    "content": result.content,
                    "is_error": result.is_error,
                })
            except Exception as e:
                error_result = ToolResult(
                    tool_use_id=tool_req.tool_use_id,
                    content=f"Error: {str(e)}",
                    is_error=True,
                )
                results.append(error_result)
                all_tool_results.append({
                    "tool_use_id": tool_req.tool_use_id,
                    "content": str(e),
                    "is_error": True,
                })

        conversation.append(model_client.build_assistant_message(turn))
        conversation.append(model_client.build_tool_result_message(results))

    return {
        "reply_text": final_text,
        "tool_calls": all_tool_calls,
        "tool_results": all_tool_results,
        "iterations": iterations,
    }
