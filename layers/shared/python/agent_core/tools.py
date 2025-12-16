"""Tool specification available to the agent.

This skeleton does not execute real tools by default; it *records* actions and logs them.
Wire real integrations in `agent_core.actions.dispatch_background_actions`.
"""

TOOLS_SPEC = [
    {
        "name": "remember",
        "description": "Store a memory in the agent memory store.",
        "input_schema": {
            "type": "object",
            "properties": {
                "kind": {
                    "type": "string",
                    "enum": ["FACT", "SPECULATION", "AI_INSIGHT", "ACTION", "META"],
                    "description": "Memory kind",
                },
                "text": {"type": "string", "description": "The memory text"},
            },
            "required": ["kind", "text"],
        },
    },
    {
        "name": "background_action",
        "description": "Queue a background action for external execution (no-op in skeleton).",
        "input_schema": {
            "type": "object",
            "properties": {
                "action": {"type": "string", "description": "Action name"},
                "args": {"type": "object", "description": "Action arguments"},
            },
            "required": ["action"],
        },
    },
    {
        "name": "web_search",
        "description": "Search the web for information (not implemented in skeleton).",
        "input_schema": {
            "type": "object",
            "properties": {
                "query": {"type": "string", "description": "Search query"},
            },
            "required": ["query"],
        },
    },
]
