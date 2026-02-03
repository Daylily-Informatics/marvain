"""Tests for planner validation and rate limiting."""
from __future__ import annotations

import json
import pytest
from pathlib import Path

# Add functions/planner to path for imports
import sys
sys.path.insert(0, str(Path(__file__).parent.parent / "functions" / "planner"))

from validation import validate_planner_output, sanitize_planner_output


class TestValidatePlannerOutput:
    """Tests for schema validation."""

    def test_valid_empty_output(self):
        """Empty output should be valid."""
        output = {}
        is_valid, error = validate_planner_output(output)
        assert is_valid is True
        assert error is None

    def test_valid_full_output(self):
        """Full valid output should pass."""
        output = {
            "episodic": [
                {"content": "User mentioned they like coffee", "participants": ["user-123"]}
            ],
            "semantic": [
                {"content": "User prefers dark roast coffee", "participants": []}
            ],
            "actions": [
                {
                    "kind": "send_message",
                    "payload": {"text": "Hello!"},
                    "required_scopes": ["message:send"],
                    "auto_approve": False
                }
            ]
        }
        is_valid, error = validate_planner_output(output)
        assert is_valid is True
        assert error is None

    def test_invalid_episodic_missing_content(self):
        """Episodic memory without content should fail."""
        output = {
            "episodic": [{"participants": ["user-123"]}]
        }
        is_valid, error = validate_planner_output(output)
        assert is_valid is False
        assert "content" in error.lower()

    def test_invalid_action_missing_kind(self):
        """Action without kind should fail."""
        output = {
            "actions": [{"payload": {"text": "Hello"}}]
        }
        is_valid, error = validate_planner_output(output)
        assert is_valid is False
        assert "kind" in error.lower()

    def test_invalid_extra_properties(self):
        """Extra properties should fail with additionalProperties: false."""
        output = {
            "episodic": [],
            "semantic": [],
            "actions": [],
            "unknown_field": "should fail"
        }
        is_valid, error = validate_planner_output(output)
        assert is_valid is False


class TestSanitizePlannerOutput:
    """Tests for output sanitization."""

    def test_sanitize_empty_output(self):
        """Empty output should return defaults."""
        output = {}
        result = sanitize_planner_output(output)
        assert result == {"episodic": [], "semantic": [], "actions": []}

    def test_sanitize_strips_whitespace(self):
        """Content should be stripped of whitespace."""
        output = {
            "episodic": [{"content": "  hello world  ", "participants": []}]
        }
        result = sanitize_planner_output(output)
        assert result["episodic"][0]["content"] == "hello world"

    def test_sanitize_filters_empty_content(self):
        """Empty content items should be filtered out."""
        output = {
            "episodic": [
                {"content": "", "participants": []},
                {"content": "valid", "participants": []},
                {"content": "   ", "participants": []},
            ]
        }
        result = sanitize_planner_output(output)
        assert len(result["episodic"]) == 1
        assert result["episodic"][0]["content"] == "valid"

    def test_sanitize_truncates_long_content(self):
        """Content longer than 4096 chars should be truncated."""
        long_content = "x" * 5000
        output = {
            "episodic": [{"content": long_content, "participants": []}]
        }
        result = sanitize_planner_output(output)
        assert len(result["episodic"][0]["content"]) == 4096

    def test_sanitize_converts_participants_to_strings(self):
        """Participants should be converted to strings."""
        output = {
            "episodic": [{"content": "test", "participants": [123, "user", None]}]
        }
        result = sanitize_planner_output(output)
        assert result["episodic"][0]["participants"] == ["123", "user", "None"]

    def test_sanitize_action_defaults(self):
        """Actions should have proper defaults."""
        output = {
            "actions": [{"kind": "test_action"}]
        }
        result = sanitize_planner_output(output)
        action = result["actions"][0]
        assert action["kind"] == "test_action"
        assert action["payload"] == {}
        assert action["required_scopes"] == []
        assert action["auto_approve"] is False

    def test_sanitize_filters_invalid_items(self):
        """Non-dict items should be filtered out."""
        output = {
            "episodic": ["string", 123, None, {"content": "valid"}],
            "actions": ["string", {"kind": "valid"}]
        }
        result = sanitize_planner_output(output)
        assert len(result["episodic"]) == 1
        assert len(result["actions"]) == 1

    def test_sanitize_handles_none_values(self):
        """None values should be handled gracefully."""
        output = {
            "episodic": None,
            "semantic": None,
            "actions": None
        }
        result = sanitize_planner_output(output)
        assert result == {"episodic": [], "semantic": [], "actions": []}

