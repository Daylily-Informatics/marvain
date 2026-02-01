"""Planner output validation and schema enforcement."""
from __future__ import annotations

import json
import logging
import os
from pathlib import Path
from typing import Any

import jsonschema

logger = logging.getLogger(__name__)

# Load schema once at module import
_SCHEMA_PATH = Path(__file__).parent / "schema.json"
_SCHEMA: dict[str, Any] | None = None


def _load_schema() -> dict[str, Any]:
    """Load and cache the planner output schema."""
    global _SCHEMA
    if _SCHEMA is None:
        with open(_SCHEMA_PATH) as f:
            _SCHEMA = json.load(f)
    return _SCHEMA


def validate_planner_output(output: dict[str, Any]) -> tuple[bool, str | None]:
    """Validate planner output against the JSON schema.
    
    Args:
        output: The parsed JSON output from the planner LLM.
        
    Returns:
        Tuple of (is_valid, error_message). If valid, error_message is None.
    """
    try:
        schema = _load_schema()
        jsonschema.validate(instance=output, schema=schema)
        return True, None
    except jsonschema.ValidationError as e:
        return False, f"Schema validation failed: {e.message} at path {list(e.absolute_path)}"
    except Exception as e:
        return False, f"Validation error: {str(e)}"


def sanitize_planner_output(output: dict[str, Any]) -> dict[str, Any]:
    """Sanitize and normalize planner output.
    
    Ensures all expected keys exist with proper defaults,
    and removes any unexpected keys.
    
    Args:
        output: The parsed JSON output from the planner LLM.
        
    Returns:
        Sanitized output with guaranteed structure.
    """
    sanitized = {
        "episodic": [],
        "semantic": [],
        "actions": [],
    }
    
    # Process episodic memories
    for item in output.get("episodic") or []:
        if not isinstance(item, dict):
            continue
        content = str(item.get("content") or "").strip()
        if not content:
            continue
        sanitized["episodic"].append({
            "content": content[:4096],  # Enforce max length
            "participants": [str(p) for p in (item.get("participants") or [])],
        })
    
    # Process semantic memories
    for item in output.get("semantic") or []:
        if not isinstance(item, dict):
            continue
        content = str(item.get("content") or "").strip()
        if not content:
            continue
        sanitized["semantic"].append({
            "content": content[:4096],
            "participants": [str(p) for p in (item.get("participants") or [])],
        })
    
    # Process actions
    for item in output.get("actions") or []:
        if not isinstance(item, dict):
            continue
        kind = str(item.get("kind") or "").strip()
        if not kind:
            continue
        sanitized["actions"].append({
            "kind": kind[:128],
            "payload": item.get("payload") if isinstance(item.get("payload"), dict) else {},
            "required_scopes": [str(s) for s in (item.get("required_scopes") or [])],
            "auto_approve": bool(item.get("auto_approve")),
        })
    
    return sanitized

