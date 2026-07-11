from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Mapping, Protocol

from agent_hub.rds_data import RdsData


class DeviceRoutingError(RuntimeError):
    def __init__(self, code: str, *, detail: str | None = None) -> None:
        super().__init__(detail or code)
        self.code = code
        self.detail = detail or code


def _required_text(value: Any, field_name: str) -> str:
    text = str(value or "").strip()
    if not text:
        raise DeviceRoutingError("device_route_invalid", detail=f"{field_name} is required")
    return text


def _json_list(value: Any, field_name: str) -> tuple[str, ...]:
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except json.JSONDecodeError as exc:
            raise DeviceRoutingError("device_route_invalid", detail=f"{field_name} is invalid JSON") from exc
    if not isinstance(value, list):
        raise DeviceRoutingError("device_route_invalid", detail=f"{field_name} must be a string list")
    normalized: list[str] = []
    seen: set[str] = set()
    for item in value:
        if not isinstance(item, str) or not item or item != item.strip():
            raise DeviceRoutingError(
                "device_route_invalid",
                detail=f"{field_name} entries must be non-empty strings without surrounding whitespace",
            )
        if item == "*":
            raise DeviceRoutingError("device_route_invalid", detail=f"{field_name} must contain explicit values")
        if item in seen:
            raise DeviceRoutingError("device_route_invalid", detail=f"{field_name} entries must be unique")
        seen.add(item)
        normalized.append(item)
    return tuple(normalized)


def _json_object(value: Any, field_name: str) -> dict[str, Any]:
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except json.JSONDecodeError as exc:
            raise DeviceRoutingError("device_route_invalid", detail=f"{field_name} is invalid JSON") from exc
    if not isinstance(value, dict):
        raise DeviceRoutingError("device_route_invalid", detail=f"{field_name} must be an object")
    return dict(value)


@dataclass(frozen=True)
class DeviceRoute:
    device_id: str
    agent_id: str
    location_id: str
    location_name: str
    space_id: str
    space_name: str
    scopes: tuple[str, ...]
    capabilities: dict[str, Any]

    @classmethod
    def from_row(cls, row: Mapping[str, Any]) -> DeviceRoute:
        location_id = _required_text(row.get("location_id"), "location_id")
        space_location_id = _required_text(row.get("space_location_id"), "space_location_id")
        if location_id != space_location_id:
            raise DeviceRoutingError(
                "device_topology_mismatch",
                detail="device location does not match its current space location",
            )
        return cls(
            device_id=_required_text(row.get("device_id"), "device_id"),
            agent_id=_required_text(row.get("agent_id"), "agent_id"),
            location_id=location_id,
            location_name=_required_text(row.get("location_name"), "location_name"),
            space_id=_required_text(row.get("space_id"), "space_id"),
            space_name=_required_text(row.get("space_name"), "space_name"),
            scopes=_json_list(row.get("scopes_json"), "scopes"),
            capabilities=_json_object(row.get("capabilities_json"), "capabilities"),
        )

    def receipt(self) -> dict[str, Any]:
        return {
            "device_id": self.device_id,
            "agent_id": self.agent_id,
            "location_id": self.location_id,
            "location_name": self.location_name,
            "space_id": self.space_id,
            "space_name": self.space_name,
            "scopes": list(self.scopes),
            "capabilities": self.capabilities,
        }


def load_device_route(db: RdsData, *, device_id: str, expected_agent_id: str | None = None) -> DeviceRoute:
    device_id = _required_text(device_id, "device_id")
    rows = db.query(
        """
        SELECT d.device_id::TEXT AS device_id,
               d.agent_id::TEXT AS agent_id,
               d.location_id::TEXT AS location_id,
               d.current_space_id::TEXT AS space_id,
               d.scopes::TEXT AS scopes_json,
               d.capabilities::TEXT AS capabilities_json,
               l.name AS location_name,
               s.name AS space_name,
               s.location_id::TEXT AS space_location_id
        FROM devices d
        JOIN locations l
          ON l.location_id = d.location_id
         AND l.disabled_at IS NULL
        JOIN spaces s
          ON s.space_id = d.current_space_id
         AND s.location_id = d.location_id
        WHERE d.device_id = :device_id::uuid
          AND d.revoked_at IS NULL
          AND d.disabled_at IS NULL
        LIMIT 1
        """,
        {"device_id": device_id},
    )
    if not rows:
        raise DeviceRoutingError("device_route_not_configured")
    route = DeviceRoute.from_row(rows[0])
    if expected_agent_id is not None and route.agent_id != _required_text(expected_agent_id, "expected_agent_id"):
        raise DeviceRoutingError("device_not_owned_by_agent")
    return route


def require_route_scopes(route: DeviceRoute, required_scopes: list[str] | tuple[str, ...]) -> None:
    normalized = tuple(dict.fromkeys(_required_text(scope, "required_scope") for scope in required_scopes))
    missing = [scope for scope in normalized if scope not in route.scopes]
    if missing:
        raise DeviceRoutingError(
            "target_device_missing_scopes",
            detail=f"target device is missing scopes: {', '.join(missing)}",
        )


@dataclass(frozen=True)
class DeviceConnection:
    connection_id: str
    connection_epoch: str


def select_route_connections(items: list[Mapping[str, Any]], route: DeviceRoute) -> tuple[DeviceConnection, ...]:
    selected: list[DeviceConnection] = []
    for item in items:
        if str(item.get("status") or "") != "authenticated":
            continue
        if str(item.get("principal_type") or "") != "device":
            continue
        if str(item.get("device_id") or "") != route.device_id:
            continue
        if str(item.get("agent_id") or "") != route.agent_id:
            continue
        if str(item.get("location_id") or "") != route.location_id:
            continue
        if str(item.get("space_id") or "") != route.space_id:
            continue
        selected.append(
            DeviceConnection(
                connection_id=_required_text(item.get("connection_id"), "connection_id"),
                connection_epoch=_required_text(item.get("connection_epoch"), "connection_epoch"),
            )
        )
    return tuple(selected)


class _ConnectionTable(Protocol):
    def query(self, **kwargs: Any) -> dict[str, Any]: ...

    def delete_item(self, **kwargs: Any) -> Any: ...


class _ManagementClient(Protocol):
    def post_to_connection(self, **kwargs: Any) -> Any: ...


def query_device_connection_items(table: _ConnectionTable, *, device_id: str) -> list[Mapping[str, Any]]:
    items: list[Mapping[str, Any]] = []
    exclusive_start_key: dict[str, Any] | None = None
    while True:
        query: dict[str, Any] = {
            "IndexName": "device_id_index",
            "KeyConditionExpression": "device_id = :did",
            "ExpressionAttributeValues": {":did": _required_text(device_id, "device_id")},
        }
        if exclusive_start_key is not None:
            query["ExclusiveStartKey"] = exclusive_start_key
        try:
            response = table.query(**query)
        except Exception as exc:
            raise DeviceRoutingError("device_connection_registry_unavailable", detail=str(exc)) from exc
        page = response.get("Items")
        if not isinstance(page, list) or any(not isinstance(item, Mapping) for item in page):
            raise DeviceRoutingError("device_connection_registry_malformed")
        items.extend(page)
        next_key = response.get("LastEvaluatedKey")
        if next_key is None:
            return items
        if not isinstance(next_key, dict) or not next_key:
            raise DeviceRoutingError("device_connection_registry_malformed")
        exclusive_start_key = next_key


@dataclass(frozen=True)
class DeviceDispatchReceipt:
    route: DeviceRoute
    correlation_id: str
    connection_epochs: tuple[str, ...]
    sent_count: int
    stale_count: int

    def as_dict(self) -> dict[str, Any]:
        return {
            "route": self.route.receipt(),
            "correlation_id": self.correlation_id,
            "connection_epochs": list(self.connection_epochs),
            "sent_count": self.sent_count,
            "stale_count": self.stale_count,
        }


def _is_gone_error(exc: Exception) -> bool:
    response = getattr(exc, "response", None)
    if not isinstance(response, dict):
        return False
    error = response.get("Error")
    return isinstance(error, dict) and str(error.get("Code") or "") == "GoneException"


def dispatch_to_device_route(
    *,
    table: _ConnectionTable,
    management_client: _ManagementClient,
    route: DeviceRoute,
    message: dict[str, Any],
    correlation_id: str,
) -> DeviceDispatchReceipt:
    items = query_device_connection_items(table, device_id=route.device_id)
    connections = select_route_connections(items, route)
    if not connections:
        raise DeviceRoutingError("device_not_connected_to_assigned_topology")

    payload = json.dumps(message, separators=(",", ":")).encode("utf-8")
    sent_epochs: list[str] = []
    stale_count = 0
    for connection in connections:
        try:
            management_client.post_to_connection(ConnectionId=connection.connection_id, Data=payload)
            sent_epochs.append(connection.connection_epoch)
        except Exception as exc:
            if not _is_gone_error(exc):
                raise DeviceRoutingError("device_dispatch_failed", detail=str(exc)) from exc
            stale_count += 1
            table.delete_item(Key={"connection_id": connection.connection_id})

    if not sent_epochs:
        raise DeviceRoutingError("device_disconnected_during_dispatch")
    return DeviceDispatchReceipt(
        route=route,
        correlation_id=_required_text(correlation_id, "correlation_id"),
        connection_epochs=tuple(sent_epochs),
        sent_count=len(sent_epochs),
        stale_count=stale_count,
    )


def record_device_connection_state(
    db: RdsData,
    *,
    route: DeviceRoute,
    connection_id: str,
    connection_epoch: str,
    state: str,
    reason: str,
) -> str:
    state = _required_text(state, "state")
    if state not in {"connected", "reconnected", "superseded", "stale", "disconnected"}:
        raise DeviceRoutingError("device_connection_state_invalid")
    rows = db.query(
        """
        WITH heartbeat AS (
          UPDATE devices
          SET last_hello_at = CASE WHEN :connected THEN now() ELSE last_hello_at END,
              last_heartbeat_at = CASE WHEN :connected THEN now() ELSE last_heartbeat_at END,
              last_seen = now()
          WHERE device_id = :device_id::uuid
            AND agent_id = :agent_id::uuid
            AND revoked_at IS NULL
          RETURNING device_id
        )
        INSERT INTO events(agent_id, space_id, device_id, location_id, type, payload)
        SELECT :agent_id::uuid,
               :space_id::uuid,
               :device_id::uuid,
               :location_id::uuid,
               :event_type,
               :payload::jsonb
        FROM heartbeat
        RETURNING event_id::TEXT AS event_id
        """,
        {
            "agent_id": route.agent_id,
            "space_id": route.space_id,
            "device_id": route.device_id,
            "location_id": route.location_id,
            "event_type": f"device.connection.{state}",
            "connected": state in {"connected", "reconnected"},
            "payload": json.dumps(
                {
                    "connection_id": _required_text(connection_id, "connection_id"),
                    "connection_epoch": _required_text(connection_epoch, "connection_epoch"),
                    "state": state,
                    "reason": _required_text(reason, "reason"),
                    "route": route.receipt(),
                }
            ),
        },
    )
    if not rows:
        raise DeviceRoutingError("device_connection_receipt_not_persisted")
    return _required_text(rows[0].get("event_id"), "event_id")


def record_device_disconnect(db: RdsData, *, connection: Mapping[str, Any], reason: str) -> str:
    """Persist one idempotent disconnect receipt from the authenticated registry row."""
    if str(connection.get("principal_type") or "") != "device":
        raise DeviceRoutingError("device_connection_principal_invalid")
    connection_id = _required_text(connection.get("connection_id"), "connection_id")
    connection_epoch = _required_text(connection.get("connection_epoch"), "connection_epoch")
    device_id = _required_text(connection.get("device_id"), "device_id")
    agent_id = _required_text(connection.get("agent_id"), "agent_id")
    location_id = _required_text(connection.get("location_id"), "location_id")
    space_id = _required_text(connection.get("space_id"), "space_id")
    reason = _required_text(reason, "reason")
    payload = json.dumps(
        {
            "connection_id": connection_id,
            "connection_epoch": connection_epoch,
            "state": "disconnected",
            "reason": reason,
            "route": {
                "device_id": device_id,
                "agent_id": agent_id,
                "location_id": location_id,
                "space_id": space_id,
            },
        }
    )
    rows = db.query(
        """
        WITH verified_route AS (
          SELECT d.device_id, d.agent_id, l.location_id, s.space_id
          FROM devices d
          JOIN locations l
            ON l.location_id = :location_id::uuid
           AND l.agent_id = :agent_id::uuid
          JOIN spaces s
            ON s.space_id = :space_id::uuid
           AND s.agent_id = :agent_id::uuid
           AND s.location_id = :location_id::uuid
          WHERE d.device_id = :device_id::uuid
            AND d.agent_id = :agent_id::uuid
          LIMIT 1
        ), existing AS (
          SELECT event_id
          FROM events
          WHERE agent_id = :agent_id::uuid
            AND device_id = :device_id::uuid
            AND type = 'device.connection.disconnected'
            AND payload ->> 'connection_epoch' = :connection_epoch
          LIMIT 1
        ), inserted AS (
          INSERT INTO events(agent_id, space_id, device_id, location_id, type, payload)
          SELECT :agent_id::uuid,
                 :space_id::uuid,
                 :device_id::uuid,
                 :location_id::uuid,
                 'device.connection.disconnected',
                 :payload::jsonb
          FROM verified_route
          WHERE NOT EXISTS (SELECT 1 FROM existing)
          RETURNING event_id
        )
        SELECT event_id::TEXT AS event_id FROM inserted
        UNION ALL
        SELECT event_id::TEXT AS event_id FROM existing
        LIMIT 1
        """,
        {
            "agent_id": agent_id,
            "space_id": space_id,
            "device_id": device_id,
            "location_id": location_id,
            "connection_epoch": connection_epoch,
            "payload": payload,
        },
    )
    if not rows:
        raise DeviceRoutingError("device_disconnect_receipt_not_persisted")
    return _required_text(rows[0].get("event_id"), "event_id")


def record_device_heartbeat(db: RdsData, *, route: DeviceRoute) -> None:
    rows = db.query(
        """
        UPDATE devices
        SET last_heartbeat_at = now(),
            last_seen = now()
        WHERE device_id = :device_id::uuid
          AND agent_id = :agent_id::uuid
          AND location_id = :location_id::uuid
          AND current_space_id = :space_id::uuid
          AND revoked_at IS NULL
          AND disabled_at IS NULL
        RETURNING device_id::TEXT AS device_id
        """,
        {
            "device_id": route.device_id,
            "agent_id": route.agent_id,
            "location_id": route.location_id,
            "space_id": route.space_id,
        },
    )
    if not rows:
        raise DeviceRoutingError("device_heartbeat_route_rejected")


__all__ = [
    "DeviceConnection",
    "DeviceDispatchReceipt",
    "DeviceRoute",
    "DeviceRoutingError",
    "dispatch_to_device_route",
    "load_device_route",
    "query_device_connection_items",
    "record_device_connection_state",
    "record_device_disconnect",
    "record_device_heartbeat",
    "require_route_scopes",
    "select_route_connections",
]
