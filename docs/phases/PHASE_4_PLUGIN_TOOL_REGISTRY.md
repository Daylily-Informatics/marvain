# Phase 4: Plugin-Based Action Tool Registry

> **Parent plan**: [GUI_OVERHAUL_PLAN.md](../GUI_OVERHAUL_PLAN.md)
> **Risk**: Low — backward compatible refactor
> **Depends on**: Phase 1 (template macros for tool catalog page)

## Overview

Refactor the tool registry to auto-discover tools from the `tools/` package. Each tool module exports a `TOOL_SPEC` dict. The GUI action-kind dropdown is populated dynamically from the registry. Add a "Tool Catalog" page showing all available tools with descriptions and required scopes.

## Scope

- `layers/shared/python/agent_hub/tools/registry.py` — auto-discovery via `importlib` + module `TOOL_SPEC` convention
- `layers/shared/python/agent_hub/tools/*.py` — add `TOOL_SPEC` export to each existing tool module
- `functions/hub_api/app.py` — new endpoint `GET /api/tools` returning tool catalog; new GUI route `GET /tools` for tool catalog page
- `functions/hub_api/templates/actions.html` — populate kind dropdown dynamically from `/api/tools`
- `functions/hub_api/templates/tools.html` — new Tool Catalog page
- Update `functions/hub_api/templates/base.html` nav to include Tools link

## TOOL_SPEC Convention

Each tool module exports a `TOOL_SPEC` dict:

```python
# layers/shared/python/agent_hub/tools/send_message.py

TOOL_SPEC = {
    "name": "send_message",
    "description": "Send a message to a user or space via WebSocket broadcast",
    "required_scopes": ["events:write"],
    "payload_schema": {
        "type": "object",
        "properties": {
            "message": {"type": "string", "description": "Message content"},
            "target": {"type": "string", "description": "Target user or space ID"},
        },
        "required": ["message"],
    },
}
```

## Definition of Done

- Adding a new tool = drop a .py file in `tools/` with `TOOL_SPEC` and a handler → it appears in GUI automatically
- `GET /api/tools` returns list of all registered tools with name, description, required_scopes, payload_schema
- Tool Catalog page shows all tools with descriptions
- All 5 existing tools migrated to new convention
- No hardcoded tool names in GUI templates

## Verification

```bash
# List all tools via API
curl -s http://localhost:8443/api/tools | jq '.[] | .name'

# Create a dummy tool, restart, verify it appears
echo 'TOOL_SPEC = {"name": "test_tool", ...}' > layers/shared/python/agent_hub/tools/test_tool.py

# Existing action creation still works
curl -X POST http://localhost:8443/api/actions -H 'Content-Type: application/json' \
  -d '{"agent_id":"...","kind":"send_message","payload":{"message":"test"}}'
```

