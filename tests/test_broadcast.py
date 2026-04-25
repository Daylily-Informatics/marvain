"""Tests for WebSocket broadcast helpers."""

from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

# Add shared layer to import path.
repo_root = Path(__file__).resolve().parents[1]
shared = repo_root / "layers" / "shared" / "python"
if str(shared) not in sys.path:
    sys.path.insert(0, str(shared))


@patch("agent_hub.broadcast._send_to_connections")
@patch("agent_hub.broadcast._find_topic_subscribers_from_index")
def test_broadcast_event_reaches_user_subscriber(mock_find_subscribers, mock_send):
    from agent_hub.broadcast import broadcast_event

    mock_find_subscribers.return_value = [
        {
            "connection_id": "conn-user-1",
            "status": "authenticated",
            "principal_type": "user",
            "agents": [{"agent_id": "agent-1"}],
            "subscriptions": ["events:agent-1"],
        }
    ]
    mock_send.return_value = 1

    sent = broadcast_event(
        event_type="events.new",
        agent_id="agent-1",
        payload={"event": {"event_id": "evt-1"}},
    )

    assert sent == 1
    mock_send.assert_called_once()
    kwargs = mock_send.call_args.kwargs
    assert kwargs["message"]["type"] == "events.new"
    assert kwargs["message"]["payload"]["event"]["event_id"] == "evt-1"


@patch("agent_hub.broadcast._send_to_connections")
@patch("agent_hub.broadcast._find_topic_subscribers_from_index")
def test_broadcast_event_skips_user_without_agent_access(mock_find_subscribers, mock_send):
    from agent_hub.broadcast import broadcast_event

    mock_find_subscribers.return_value = []
    mock_send.return_value = 0

    sent = broadcast_event(
        event_type="events.new",
        agent_id="agent-1",
        payload={"event": {"event_id": "evt-1"}},
    )

    assert sent == 0
    mock_send.assert_not_called()


@patch("agent_hub.broadcast._send_to_connections")
@patch("agent_hub.broadcast._find_user_connections")
def test_broadcast_target_user(mock_find_user_connections, mock_send):
    from agent_hub.broadcast import broadcast_target

    mock_find_user_connections.return_value = [
        {
            "connection_id": "conn-user-1",
            "status": "authenticated",
            "principal_type": "user",
            "user_id": "user-1",
            "agents": [{"agent_id": "agent-1"}],
        }
    ]
    mock_send.return_value = 1

    sent = broadcast_target(
        target_key="user:user-1",
        agent_id="agent-1",
        payload={"content": "hello"},
    )

    assert sent == 1
    kwargs = mock_send.call_args.kwargs
    assert kwargs["message"]["type"] == "message"
    assert kwargs["message"]["payload"]["content"] == "hello"


@patch("agent_hub.broadcast._find_topic_subscribers_from_index")
def test_topic_subscribers_do_not_fallback_to_scan(mock_from_index):
    from agent_hub.broadcast import _find_topic_subscribers

    mock_from_index.return_value = []
    found = _find_topic_subscribers(topic="actions", agent_id="agent-1")
    assert found == []
    mock_from_index.assert_called_once_with(topic="actions", agent_id="agent-1", space_id=None)


@patch("agent_hub.broadcast._load_connections_by_id")
@patch("agent_hub.broadcast._get_subscriptions_table")
def test_topic_subscribers_index_path_filters_connections(mock_get_subs_table, mock_load_connections):
    from agent_hub.broadcast import _find_topic_subscribers_from_index

    subs_table = MagicMock()
    subs_table.query.side_effect = [
        {"Items": [{"connection_id": "conn-1"}, {"connection_id": "conn-2"}]},
        {"Items": [{"connection_id": "conn-3"}]},
    ]
    mock_get_subs_table.return_value = subs_table

    mock_load_connections.return_value = [
        {
            "connection_id": "conn-1",
            "status": "authenticated",
            "principal_type": "user",
            "agents": [{"agent_id": "agent-1"}],
        },
        {
            "connection_id": "conn-2",
            "status": "authenticated",
            "principal_type": "device",
            "agent_id": "agent-2",
        },
        {
            "connection_id": "conn-3",
            "status": "connected",
            "principal_type": "user",
            "agents": [{"agent_id": "agent-1"}],
        },
    ]

    found = _find_topic_subscribers_from_index(topic="actions", agent_id="agent-1", space_id="space-1")

    assert len(found) == 1
    assert found[0]["connection_id"] == "conn-1"
