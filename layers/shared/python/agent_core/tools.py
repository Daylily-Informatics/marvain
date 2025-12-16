"""Tool specification and execution for the agent.

Tools are defined with Bedrock-compatible schemas and can be executed
via the tool_executor function.
"""

from __future__ import annotations

import json
import logging
import os
from datetime import datetime
from typing import Any, Callable, Dict, List, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from agent_core.aws_model_client import ToolRequest, ToolResult


TOOLS_SPEC: List[Dict[str, Any]] = [
    {
        "name": "remember",
        "description": "Store a memory in the agent memory store. Use this to record important facts, insights, or observations about the conversation or speakers.",
        "input_schema": {
            "type": "object",
            "properties": {
                "kind": {
                    "type": "string",
                    "enum": ["FACT", "SPECULATION", "AI_INSIGHT", "ACTION", "META"],
                    "description": "Memory kind: FACT for confirmed information, SPECULATION for uncertain info, AI_INSIGHT for analysis, ACTION for completed actions, META for system notes",
                },
                "text": {
                    "type": "string",
                    "description": "The memory content to store"
                },
                "speaker_id": {
                    "type": "string",
                    "description": "Optional: Associate memory with a specific speaker ID"
                },
            },
            "required": ["kind", "text"],
        },
    },
    {
        "name": "recall",
        "description": "Search and retrieve memories from the agent memory store. Use this to look up past conversations, facts, or context about speakers.",
        "input_schema": {
            "type": "object",
            "properties": {
                "query": {
                    "type": "string",
                    "description": "Search query or keywords to find relevant memories"
                },
                "speaker_id": {
                    "type": "string",
                    "description": "Optional: Filter memories by speaker ID"
                },
                "kind": {
                    "type": "string",
                    "enum": ["FACT", "SPECULATION", "AI_INSIGHT", "ACTION", "META", "ALL"],
                    "description": "Optional: Filter by memory kind (default: ALL)"
                },
                "limit": {
                    "type": "integer",
                    "description": "Maximum number of memories to return (default: 10)"
                },
            },
            "required": ["query"],
        },
    },
    {
        "name": "get_speaker_profile",
        "description": "Retrieve the profile and conversation history for a known speaker.",
        "input_schema": {
            "type": "object",
            "properties": {
                "speaker_id": {
                    "type": "string",
                    "description": "The speaker's voice ID or name"
                },
            },
            "required": ["speaker_id"],
        },
    },
    {
        "name": "update_speaker_profile",
        "description": "Update information in a speaker's profile.",
        "input_schema": {
            "type": "object",
            "properties": {
                "speaker_id": {
                    "type": "string",
                    "description": "The speaker's voice ID"
                },
                "name": {
                    "type": "string",
                    "description": "Update the speaker's name"
                },
                "notes": {
                    "type": "string",
                    "description": "Additional notes about the speaker"
                },
                "preferences": {
                    "type": "object",
                    "description": "Speaker preferences (e.g., communication style)"
                },
            },
            "required": ["speaker_id"],
        },
    },
    {
        "name": "background_action",
        "description": "Queue a background action for asynchronous execution. Actions are logged and can trigger external integrations.",
        "input_schema": {
            "type": "object",
            "properties": {
                "action": {
                    "type": "string",
                    "description": "Action name/type"
                },
                "args": {
                    "type": "object",
                    "description": "Action arguments and parameters"
                },
                "priority": {
                    "type": "string",
                    "enum": ["low", "normal", "high"],
                    "description": "Action priority (default: normal)"
                },
            },
            "required": ["action"],
        },
    },
    {
        "name": "web_search",
        "description": "Search the web for information. Returns summarized search results.",
        "input_schema": {
            "type": "object",
            "properties": {
                "query": {
                    "type": "string",
                    "description": "Search query"
                },
                "num_results": {
                    "type": "integer",
                    "description": "Number of results to return (default: 5, max: 10)"
                },
            },
            "required": ["query"],
        },
    },
    {
        "name": "get_current_time",
        "description": "Get the current date and time in UTC.",
        "input_schema": {
            "type": "object",
            "properties": {},
            "required": [],
        },
    },
]


class ToolExecutor:
    """Executes tools and returns results.

    This class provides a registry of tool implementations that can be
    invoked by the LLM through the tool use API.
    """

    def __init__(
        self,
        agent_id: str,
        memory_store_module: Optional[Any] = None,
        voice_registry_module: Optional[Any] = None,
    ):
        self.agent_id = agent_id
        self._memory_store = memory_store_module
        self._voice_registry = voice_registry_module
        self._custom_handlers: Dict[str, Callable] = {}
        self._action_queue: List[Dict[str, Any]] = []

    def register_handler(self, tool_name: str, handler: Callable) -> None:
        """Register a custom handler for a tool."""
        self._custom_handlers[tool_name] = handler

    def get_queued_actions(self) -> List[Dict[str, Any]]:
        """Get and clear the queue of background actions."""
        actions = self._action_queue.copy()
        self._action_queue.clear()
        return actions

    def execute(self, request: "ToolRequest") -> "ToolResult":
        """Execute a tool request and return the result."""
        from agent_core.aws_model_client import ToolResult

        tool_name = request.name
        tool_input = request.input

        logging.info("ToolExecutor: executing %s with input %s", tool_name, tool_input)

        try:
            # Check for custom handler first
            if tool_name in self._custom_handlers:
                result = self._custom_handlers[tool_name](tool_input)
                return ToolResult(
                    tool_use_id=request.tool_use_id,
                    content=result,
                    is_error=False,
                )

            # Built-in tool handlers
            handler = getattr(self, f"_handle_{tool_name}", None)
            if handler:
                result = handler(tool_input)
                return ToolResult(
                    tool_use_id=request.tool_use_id,
                    content=result,
                    is_error=False,
                )

            # Unknown tool
            return ToolResult(
                tool_use_id=request.tool_use_id,
                content=f"Unknown tool: {tool_name}",
                is_error=True,
            )

        except Exception as e:
            logging.error("ToolExecutor: %s failed: %s", tool_name, e)
            return ToolResult(
                tool_use_id=request.tool_use_id,
                content=f"Tool execution error: {str(e)}",
                is_error=True,
            )

    def _handle_remember(self, input_data: Dict[str, Any]) -> Dict[str, Any]:
        """Store a memory."""
        if not self._memory_store:
            return {"status": "error", "message": "Memory store not configured"}

        kind = input_data.get("kind", "FACT")
        text = input_data.get("text", "")
        speaker_id = input_data.get("speaker_id")

        if not text:
            return {"status": "error", "message": "Memory text is required"}

        memory_obj = {
            "kind": kind,
            "text": text,
            "meta": {},
        }
        if speaker_id:
            memory_obj["meta"]["speaker_id"] = speaker_id

        try:
            self._memory_store.put_memory(memory_obj)
            return {
                "status": "success",
                "message": f"Memory stored: {kind} - {text[:50]}..."
            }
        except Exception as e:
            return {"status": "error", "message": str(e)}

    def _handle_recall(self, input_data: Dict[str, Any]) -> Dict[str, Any]:
        """Search memories."""
        if not self._memory_store:
            return {"status": "error", "message": "Memory store not configured", "memories": []}

        query = input_data.get("query", "")
        speaker_id = input_data.get("speaker_id")
        kind = input_data.get("kind", "ALL")
        limit = min(input_data.get("limit", 10), 50)

        try:
            # Use recent_memories with optional filtering
            memories = self._memory_store.recent_memories(
                self.agent_id,
                limit=limit * 3,  # Fetch more to filter
            )

            # Filter by kind if specified
            if kind and kind != "ALL":
                memories = [m for m in memories if m.get("kind") == kind]

            # Filter by speaker_id if specified
            if speaker_id:
                memories = [
                    m for m in memories
                    if m.get("meta", {}).get("speaker_id") == speaker_id
                ]

            # Simple text matching for query
            if query:
                query_lower = query.lower()
                scored = []
                for m in memories:
                    text = str(m.get("text", "")).lower()
                    if query_lower in text:
                        scored.append((2, m))  # Exact match
                    elif any(word in text for word in query_lower.split()):
                        scored.append((1, m))  # Partial match
                scored.sort(key=lambda x: x[0], reverse=True)
                memories = [m for _, m in scored]

            return {
                "status": "success",
                "memories": memories[:limit],
                "total_found": len(memories),
            }
        except Exception as e:
            return {"status": "error", "message": str(e), "memories": []}

    def _handle_get_speaker_profile(self, input_data: Dict[str, Any]) -> Dict[str, Any]:
        """Get a speaker's profile."""
        if not self._voice_registry:
            return {"status": "error", "message": "Voice registry not configured"}

        speaker_id = input_data.get("speaker_id", "")
        if not speaker_id:
            return {"status": "error", "message": "speaker_id is required"}

        try:
            profile = self._voice_registry.get_speaker_profile(self.agent_id, speaker_id)
            if profile:
                return {"status": "success", "profile": profile}
            else:
                return {"status": "not_found", "message": f"No profile found for {speaker_id}"}
        except Exception as e:
            return {"status": "error", "message": str(e)}

    def _handle_update_speaker_profile(self, input_data: Dict[str, Any]) -> Dict[str, Any]:
        """Update a speaker's profile."""
        if not self._voice_registry:
            return {"status": "error", "message": "Voice registry not configured"}

        speaker_id = input_data.get("speaker_id", "")
        if not speaker_id:
            return {"status": "error", "message": "speaker_id is required"}

        updates = {}
        if "name" in input_data:
            updates["speaker_name"] = input_data["name"]
        if "notes" in input_data:
            updates["notes"] = input_data["notes"]
        if "preferences" in input_data:
            updates["preferences"] = input_data["preferences"]

        if not updates:
            return {"status": "error", "message": "No updates provided"}

        try:
            self._voice_registry.update_speaker_profile(self.agent_id, speaker_id, updates)
            return {"status": "success", "message": f"Updated profile for {speaker_id}"}
        except Exception as e:
            return {"status": "error", "message": str(e)}

    def _handle_background_action(self, input_data: Dict[str, Any]) -> Dict[str, Any]:
        """Queue a background action."""
        action = input_data.get("action", "")
        args = input_data.get("args", {})
        priority = input_data.get("priority", "normal")

        if not action:
            return {"status": "error", "message": "action name is required"}

        action_record = {
            "action": action,
            "args": args,
            "priority": priority,
            "queued_at": datetime.utcnow().isoformat(),
            "agent_id": self.agent_id,
        }
        self._action_queue.append(action_record)

        logging.info("ToolExecutor: queued background action: %s", action)
        return {
            "status": "queued",
            "message": f"Action '{action}' queued for background execution",
            "action_id": len(self._action_queue) - 1,
        }

    def _handle_web_search(self, input_data: Dict[str, Any]) -> Dict[str, Any]:
        """Perform a web search (stub - needs external implementation)."""
        query = input_data.get("query", "")
        num_results = min(input_data.get("num_results", 5), 10)

        if not query:
            return {"status": "error", "message": "query is required"}

        # This is a stub - real implementation would call an external search API
        logging.info("ToolExecutor: web_search requested for: %s", query)
        return {
            "status": "not_implemented",
            "message": "Web search is not yet implemented. Please integrate with a search API.",
            "query": query,
            "num_results": num_results,
        }

    def _handle_get_current_time(self, input_data: Dict[str, Any]) -> Dict[str, Any]:
        """Get current time."""
        now = datetime.utcnow()
        return {
            "status": "success",
            "utc_time": now.isoformat() + "Z",
            "unix_timestamp": int(now.timestamp()),
            "formatted": now.strftime("%Y-%m-%d %H:%M:%S UTC"),
        }


def create_tool_executor(
    agent_id: str,
    memory_store_module: Optional[Any] = None,
    voice_registry_module: Optional[Any] = None,
) -> ToolExecutor:
    """Factory function to create a configured ToolExecutor."""
    return ToolExecutor(
        agent_id=agent_id,
        memory_store_module=memory_store_module,
        voice_registry_module=voice_registry_module,
    )


def get_tool_specs() -> List[Dict[str, Any]]:
    """Get the list of available tool specifications."""
    return TOOLS_SPEC.copy()
