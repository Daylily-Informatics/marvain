"""Tool specification for the LLM.

This skeleton uses an OpenAI-style function schema, and the Bedrock client adapter
will convert it to Bedrock's toolSpec format when using the Converse API.

Tools are *optional*; the agent can also just emit the planner JSON directly.
"""

from __future__ import annotations

TOOLS_SPEC = [
    {
        "type": "function",
        "function": {
            "name": "add_memory",
            "description": "Create a new memory for the agent to persist.",
            "parameters": {
                "type": "object",
                "properties": {
                    "kind": {
                        "type": "string",
                        "enum": ["FACT", "SPECULATION", "AI_INSIGHT", "ACTION", "META"],
                        "description": "Memory kind.",
                    },
                    "content": {"type": "string", "description": "Memory text."},
                    "metadata": {"type": "object", "description": "Optional metadata.", "additionalProperties": True},
                },
                "required": ["kind", "content"],
                "additionalProperties": False,
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "create_action",
            "description": "Create a background action for the agent runtime to dispatch.",
            "parameters": {
                "type": "object",
                "properties": {
                    "kind": {"type": "string", "description": "Action kind (e.g., LOG, NOOP, NOTIFY)."},
                    "payload": {"type": "object", "description": "Optional action payload.", "additionalProperties": True},
                },
                "required": ["kind"],
                "additionalProperties": False,
            },
        },
    },
]
