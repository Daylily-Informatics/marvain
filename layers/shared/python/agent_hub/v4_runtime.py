"""Explicit server-side 4.x device route and policy selections.

Operational UUIDs select a provisioned route; canonical relationships are read
from TapDB lineage, never inferred from these configuration values.
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass
from datetime import datetime
from typing import Any

import boto3

from agent_hub.memory_service import MemoryAccessPolicy, MemoryLayer, MemoryPurpose, RetentionDecision
from agent_hub.semantic_lifecycle import MarvainSemanticLifecycle
from agent_hub.semantic_tapdb import DaylilyTapdbSemanticStore, TEMPLATE_CODES


def load_bindings() -> dict[str, Any]:
    """Read the selected binding secret without caching across bootstrap updates."""
    arn = os.environ.get("MARVAIN_V4_BINDINGS_SECRET_ARN", "").strip()
    if not arn:
        raise ValueError("MARVAIN_V4_BINDINGS_SECRET_ARN is required")
    response = boto3.client("secretsmanager").get_secret_value(SecretId=arn)
    value = response.get("SecretString")
    if not isinstance(value, str):
        raise ValueError("Binding secret must contain a JSON string")
    data = json.loads(value)
    if not isinstance(data, dict):
        raise ValueError("Binding secret must contain a JSON object")
    return data


@dataclass(frozen=True)
class V4Route:
    device_id: str
    agent_id: str
    space_id: str
    space_euid: str
    device_euid: str
    actor_euid: str
    principal_euid: str
    policy: MemoryAccessPolicy


def load_route(*, device_id: str, agent_id: str, space_id: str) -> V4Route:
    data = load_bindings()
    routes = data.get("routes") if isinstance(data, dict) else None
    if not isinstance(routes, list):
        raise ValueError("4.x bindings require a routes array")
    matches = [item for item in routes if isinstance(item, dict) and
               (item.get("device_id"), item.get("agent_id"), item.get("space_id")) ==
               (device_id, agent_id, space_id)]
    if len(matches) != 1:
        raise ValueError("exactly one configured device/agent/space route is required")
    item = matches[0]
    raw = item["policy"]
    retention = []
    for layer in MemoryLayer:
        decision = raw["retention"][layer.value]
        expiry = decision.get("expires_at")
        retention.append((layer, RetentionDecision(
            expires_at=datetime.fromisoformat(expiry.replace("Z", "+00:00")) if expiry else None,
            retain_until_revoked=decision.get("retain_until_revoked", False),
        )))
    revoked = raw.get("revoked_at")
    policy = MemoryAccessPolicy(
        owner_principal_id=raw["owner_principal_euid"],
        reader_principal_ids=tuple(raw["reader_principal_euids"]),
        allowed_purposes=frozenset(MemoryPurpose(value) for value in raw["allowed_purposes"]),
        raw_capture_allowed=raw["raw_capture_allowed"], retention=tuple(retention),
        revoked_at=datetime.fromisoformat(revoked.replace("Z", "+00:00")) if revoked else None,
    )
    return V4Route(device_id, agent_id, space_id, item["space_euid"], item["device_euid"],
                   item["actor_euid"], item["principal_euid"], policy)


def resolve_route(store: DaylilyTapdbSemanticStore, route: V4Route) -> tuple[Any, Any, Any, tuple[Any, ...]]:
    """Resolve configured canonical endpoints and their authentication lineage."""
    with store.read_view() as view:
        space = view.get_object(route.space_euid)
        device = view.get_object(route.device_euid)
        actor = view.get_object(route.actor_euid)
        principal = view.get_object(route.principal_euid)
        if (space.template_code != TEMPLATE_CODES["space"] or device.template_code != TEMPLATE_CODES["device"]
                or actor.template_code != TEMPLATE_CODES["agent"]
                or principal.template_code != TEMPLATE_CODES["principal"] or principal.lifecycle_state != "active"):
            raise ValueError("configured route contains an invalid canonical identity")
        principals = view.linked_objects(actor.semantic_id, relationship_type="AUTHENTICATED_AS")
        embodiments = view.linked_objects(actor.semantic_id, relationship_type="HAS_EMBODIMENT")
        if not any(p.semantic_id == principal.semantic_id for p in principals):
            raise ValueError("configured principal is not linked to the configured actor")
        if not any(any(d.semantic_id == device.semantic_id for d in
                       view.linked_objects(e.semantic_id, relationship_type="USES_DEVICE")) for e in embodiments):
            raise ValueError("configured device is not linked to the configured actor")
        for obj, table, source_id in ((space, "spaces", route.space_id), (device, "devices", route.device_id)):
            references = view.linked_objects(obj.semantic_id, relationship_type="has_external_reference")
            expected = f"agent/{route.agent_id}/{table}/{source_id}"
            if not any(ref.properties.get("system") == "marvain-postgres" and
                       ref.properties.get("foreign_uid") == expected for ref in references):
                raise ValueError(f"configured {table} object lacks its persisted source reference")
        owner = view.get_object(route.policy.owner_principal_id)
        readers = tuple(view.get_object(key) for key in route.policy.reader_principal_ids)
        MarvainSemanticLifecycle._policy_links(route.policy, owner, readers)
        return space, device, owner, readers


def resolve_caller(*, store: DaylilyTapdbSemanticStore, device_id: str, agent_id: str) -> str:
    """Map a verified device identity to its configured canonical principal via lineage."""
    data = load_bindings()
    callers = data.get("callers") if isinstance(data, dict) else None
    if not isinstance(callers, list):
        raise ValueError("4.x bindings require a callers array")
    matches = [item for item in callers if isinstance(item, dict) and
               (item.get("device_id"), item.get("agent_id")) == (device_id, agent_id)]
    if len(matches) != 1:
        raise ValueError("exactly one configured authenticated caller is required")
    item = matches[0]
    with store.read_view() as view:
        actor = view.get_object(item["actor_euid"])
        principal = view.get_object(item["principal_euid"])
        device = view.get_object(item["device_euid"])
        if (actor.template_code != TEMPLATE_CODES["agent"] or principal.template_code != TEMPLATE_CODES["principal"]
                or principal.lifecycle_state != "active" or device.template_code != TEMPLATE_CODES["device"]):
            raise ValueError("configured caller identities are invalid")
        if not any(p.semantic_id == principal.semantic_id for p in
                   view.linked_objects(actor.semantic_id, relationship_type="AUTHENTICATED_AS")):
            raise ValueError("caller principal is not linked to its actor")
        embodiments = view.linked_objects(actor.semantic_id, relationship_type="HAS_EMBODIMENT")
        if not any(any(d.semantic_id == device.semantic_id for d in
                       view.linked_objects(e.semantic_id, relationship_type="USES_DEVICE")) for e in embodiments):
            raise ValueError("caller device is not linked to its actor")
        references = view.linked_objects(device.semantic_id, relationship_type="has_external_reference")
        expected = f"agent/{agent_id}/devices/{device_id}"
        if not any(ref.properties.get("system") == "marvain-postgres" and
                   ref.properties.get("foreign_uid") == expected for ref in references):
            raise ValueError("caller device lacks its authenticated operational reference")
        return principal.semantic_id


def resolve_human(*, store: DaylilyTapdbSemanticStore, user_id: str, subject: str) -> tuple[str, str]:
    """Resolve a human user from the server binding and canonical authentication lineage."""
    data = load_bindings()
    humans = data.get("humans") if isinstance(data, dict) else None
    if not isinstance(humans, list):
        raise ValueError("4.x bindings require a humans array")
    matches = [item for item in humans if isinstance(item, dict) and
               (item.get("user_id"), item.get("subject")) == (user_id, subject)]
    if len(matches) != 1:
        raise ValueError("exactly one authenticated human binding is required")
    item = matches[0]
    with store.read_view() as view:
        actor = view.get_object(item["actor_euid"])
        principal = view.get_object(item["principal_euid"])
        if (actor.template_code != TEMPLATE_CODES["person"] or principal.template_code != TEMPLATE_CODES["principal"]
                or principal.lifecycle_state != "active"):
            raise ValueError("human binding has invalid canonical identities")
        if not any(p.semantic_id == principal.semantic_id for p in
                   view.linked_objects(actor.semantic_id, relationship_type="AUTHENTICATED_AS")):
            raise ValueError("human principal is not linked to its actor")
        refs = view.linked_objects(principal.semantic_id, relationship_type="has_external_reference")
        if not any(ref.properties.get("external_identifier", {}).get("system") == item["issuer"] and
                   ref.properties.get("external_identifier", {}).get("target_euid") == subject for ref in refs):
            raise ValueError("human principal is not linked to the authenticated subject")
        return actor.semantic_id, principal.semantic_id
