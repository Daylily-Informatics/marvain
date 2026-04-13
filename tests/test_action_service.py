from __future__ import annotations

from types import SimpleNamespace
from unittest import mock

from agent_hub.action_service import prepare_action_request


def test_prepare_action_request_unions_requested_and_registry_required_scopes():
    registry = mock.Mock()
    registry.get.return_value = SimpleNamespace(required_scopes=["scope:b", "scope:a", "scope:b"])

    with mock.patch("agent_hub.action_service.get_registry", return_value=registry):
        normalized_payload, required_scopes = prepare_action_request(
            kind="tool_kind",
            payload={"anything": True},
            required_scopes=["scope:c", "scope:a"],
        )

    assert normalized_payload == {"anything": True}
    assert required_scopes == ["scope:a", "scope:b", "scope:c"]


def test_prepare_action_request_falls_back_to_requested_scopes_when_registry_entry_missing():
    registry = mock.Mock()
    registry.get.return_value = None

    with (
        mock.patch("agent_hub.action_service.get_registry", return_value=registry),
        mock.patch("agent_hub.action_service._require_known_tool"),
    ):
        normalized_payload, required_scopes = prepare_action_request(
            kind="tool_kind",
            payload={"anything": True},
            required_scopes=["scope:c", "scope:a", "scope:c"],
        )

    assert normalized_payload == {"anything": True}
    assert required_scopes == ["scope:a", "scope:c"]
