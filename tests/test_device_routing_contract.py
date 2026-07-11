from __future__ import annotations

import json
from unittest.mock import MagicMock

import pytest
from agent_hub.device_routing import (
    DeviceRoute,
    DeviceRoutingError,
    dispatch_to_device_route,
    load_device_route,
    query_device_connection_items,
    require_route_scopes,
    select_route_connections,
)


def _route(*, suffix: str = "1") -> DeviceRoute:
    return DeviceRoute(
        device_id=f"device-{suffix}",
        agent_id="agent-1",
        location_id=f"location-{suffix}",
        location_name=f"Location {suffix}",
        space_id=f"space-{suffix}",
        space_name=f"Space {suffix}",
        scopes=("device:command",),
        capabilities={"kind": "satellite"},
    )


def test_load_device_route_requires_persisted_matching_location_and_space() -> None:
    db = MagicMock()
    db.query.return_value = [
        {
            "device_id": "device-1",
            "agent_id": "agent-1",
            "location_id": "location-1",
            "location_name": "Location 1",
            "space_id": "space-1",
            "space_name": "Space 1",
            "space_location_id": "location-1",
            "scopes_json": '["device:command"]',
            "capabilities_json": '{"kind":"satellite"}',
        }
    ]

    route = load_device_route(db, device_id="device-1", expected_agent_id="agent-1")

    assert route == _route()
    sql = db.query.call_args.args[0]
    assert "current_space_id" in sql
    assert "d.location_id" in sql
    assert "d.revoked_at IS NULL" in sql


def test_route_rejects_space_location_mismatch() -> None:
    row = {
        **_route().receipt(),
        "space_location_id": "location-2",
        "scopes_json": "[]",
        "capabilities_json": "{}",
    }
    with pytest.raises(DeviceRoutingError, match="device location"):
        DeviceRoute.from_row(row)


def test_route_scope_check_is_explicit() -> None:
    with pytest.raises(DeviceRoutingError) as exc_info:
        require_route_scopes(_route(), ["camera:capture"])
    assert exc_info.value.code == "target_device_missing_scopes"


def test_two_devices_in_two_locations_select_only_intended_route() -> None:
    items = [
        {
            "connection_id": "connection-1",
            "connection_epoch": "epoch-1",
            "status": "authenticated",
            "principal_type": "device",
            "device_id": "device-1",
            "agent_id": "agent-1",
            "location_id": "location-1",
            "space_id": "space-1",
        },
        {
            "connection_id": "connection-2",
            "connection_epoch": "epoch-2",
            "status": "authenticated",
            "principal_type": "device",
            "device_id": "device-2",
            "agent_id": "agent-1",
            "location_id": "location-2",
            "space_id": "space-2",
        },
    ]

    selected = select_route_connections(items, _route(suffix="1"))

    assert [connection.connection_id for connection in selected] == ["connection-1"]


def test_dispatch_receipt_proves_post_to_intended_device_connection() -> None:
    route = _route()
    table = MagicMock()
    table.query.return_value = {
        "Items": [
            {
                "connection_id": "connection-1",
                "connection_epoch": "epoch-1",
                "status": "authenticated",
                "principal_type": "device",
                "device_id": route.device_id,
                "agent_id": route.agent_id,
                "location_id": route.location_id,
                "space_id": route.space_id,
            },
            {
                "connection_id": "connection-other",
                "connection_epoch": "epoch-other",
                "status": "authenticated",
                "principal_type": "device",
                "device_id": "device-2",
                "agent_id": route.agent_id,
                "location_id": "location-2",
                "space_id": "space-2",
            },
        ]
    }
    management = MagicMock()

    receipt = dispatch_to_device_route(
        table=table,
        management_client=management,
        route=route,
        message={"type": "cmd.ping", "action_id": "action-1"},
        correlation_id="correlation-1",
    )

    management.post_to_connection.assert_called_once()
    assert management.post_to_connection.call_args.kwargs["ConnectionId"] == "connection-1"
    assert json.loads(management.post_to_connection.call_args.kwargs["Data"])["action_id"] == "action-1"
    assert receipt.connection_epochs == ("epoch-1",)
    assert receipt.sent_count == 1


def test_registration_without_authenticated_route_is_not_delivery_proof() -> None:
    table = MagicMock()
    table.query.return_value = {
        "Items": [
            {
                "connection_id": "connection-1",
                "connection_epoch": "epoch-1",
                "status": "connected",
                "principal_type": "device",
                "device_id": "device-1",
                "agent_id": "agent-1",
                "location_id": "location-1",
                "space_id": "space-1",
            }
        ]
    }

    with pytest.raises(DeviceRoutingError) as exc_info:
        dispatch_to_device_route(
            table=table,
            management_client=MagicMock(),
            route=_route(),
            message={"type": "cmd.ping"},
            correlation_id="correlation-1",
        )
    assert exc_info.value.code == "device_not_connected_to_assigned_topology"


def test_connection_registry_query_reads_all_pages() -> None:
    table = MagicMock()
    table.query.side_effect = [
        {"Items": [{"connection_id": "connection-1"}], "LastEvaluatedKey": {"cursor": "next"}},
        {"Items": [{"connection_id": "connection-2"}]},
    ]

    items = query_device_connection_items(table, device_id="device-1")

    assert [item["connection_id"] for item in items] == ["connection-1", "connection-2"]
    assert table.query.call_args_list[1].kwargs["ExclusiveStartKey"] == {"cursor": "next"}
