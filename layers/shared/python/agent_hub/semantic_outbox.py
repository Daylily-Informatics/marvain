"""Transactional Marvain outbox records for canonical TapDB writes."""

from __future__ import annotations

import hashlib
import json
import re
import uuid
from dataclasses import dataclass
from typing import Any, Mapping, Protocol

MARVAIN_EXTERNAL_REFERENCE_SYSTEM = "marvain-postgres"
_IDEMPOTENCY_NAMESPACE = uuid.uuid5(uuid.NAMESPACE_URL, "https://marvain.daylily.bio/semantic-outbox/v1")
_SOURCE_TABLE_RE = re.compile(r"^[a-z][a-z0-9_]*$")
_SUPPORTED_OPERATIONS = frozenset({"link", "record", "graph"})


class SemanticOutboxError(ValueError):
    """The requested semantic write cannot be represented safely."""


class TransactionalDatabase(Protocol):
    def query(
        self,
        sql: str,
        params: Mapping[str, Any] | None = None,
        *,
        transaction_id: str | None = None,
    ) -> list[dict[str, Any]]: ...


@dataclass(frozen=True)
class PersistedExternalReference:
    """Stable identity for an already-persisted Marvain PostgreSQL row."""

    agent_id: str
    source_table: str
    source_id: str
    system: str = MARVAIN_EXTERNAL_REFERENCE_SYSTEM

    def __post_init__(self) -> None:
        if self.system != MARVAIN_EXTERNAL_REFERENCE_SYSTEM:
            raise SemanticOutboxError(f"system must be {MARVAIN_EXTERNAL_REFERENCE_SYSTEM!r}")
        table = str(self.source_table or "").strip()
        if not _SOURCE_TABLE_RE.fullmatch(table):
            raise SemanticOutboxError("source_table must be a lowercase PostgreSQL identifier")
        object.__setattr__(self, "agent_id", _normalize_uuid(self.agent_id, "agent_id"))
        object.__setattr__(self, "source_table", table)
        object.__setattr__(self, "source_id", _normalize_uuid(self.source_id, "source_id"))

    @classmethod
    def for_row(
        cls,
        *,
        agent_id: str | uuid.UUID,
        source_table: str,
        source_id: str | uuid.UUID,
    ) -> PersistedExternalReference:
        table = str(source_table or "").strip()
        if not _SOURCE_TABLE_RE.fullmatch(table):
            raise SemanticOutboxError("source_table must be a lowercase PostgreSQL identifier")
        return cls(
            agent_id=_normalize_uuid(agent_id, "agent_id"),
            source_table=table,
            source_id=_normalize_uuid(source_id, "source_id"),
        )

    @classmethod
    def from_payload(cls, payload: Mapping[str, Any]) -> PersistedExternalReference:
        if not isinstance(payload, Mapping):
            raise SemanticOutboxError("external_reference must be an object")
        system = str(payload.get("system") or "").strip()
        if system != MARVAIN_EXTERNAL_REFERENCE_SYSTEM:
            raise SemanticOutboxError(f"external_reference.system must be {MARVAIN_EXTERNAL_REFERENCE_SYSTEM!r}")
        reference = cls.for_row(
            agent_id=payload.get("agent_id"),
            source_table=str(payload.get("source_table") or ""),
            source_id=payload.get("source_id"),
        )
        if str(payload.get("foreign_uid") or "").strip() != reference.foreign_uid:
            raise SemanticOutboxError("external_reference.foreign_uid does not match its persisted source row")
        return reference

    @property
    def foreign_uid(self) -> str:
        return f"agent/{self.agent_id}/{self.source_table}/{self.source_id}"

    def to_payload(self) -> dict[str, str]:
        return {
            "system": self.system,
            "foreign_uid": self.foreign_uid,
            "agent_id": self.agent_id,
            "source_table": self.source_table,
            "source_id": self.source_id,
        }


@dataclass(frozen=True)
class GraphSourceRef:
    """An existing Marvain row whose canonical EUID is resolved by the writer."""
    source_table: str
    source_id: str
    target_template_code: str


@dataclass(frozen=True)
class SemanticOutboxRecord:
    semantic_outbox_id: str
    semantic_sync_id: str
    agent_id: str
    idempotency_key: str
    payload_sha256: str
    payload: dict[str, Any]


_ENQUEUE_RECORD_SQL = """
WITH sync_row AS (
  INSERT INTO semantic_sync_status(
    agent_id,
    source_system,
    source_table,
    source_id,
    source_external_reference,
    target_template_code,
    idempotency_key,
    status
  )
  VALUES(
    CAST(:agent_id AS uuid),
    :source_system,
    :source_table,
    CAST(:source_id AS uuid),
    CAST(:source_external_reference AS jsonb),
    :target_template_code,
    CAST(:idempotency_key AS uuid),
    'pending'
  )
  ON CONFLICT (agent_id, source_system, source_table, source_id, target_template_code)
  DO UPDATE SET semantic_sync_id = semantic_sync_status.semantic_sync_id
  WHERE semantic_sync_status.idempotency_key = EXCLUDED.idempotency_key
  RETURNING semantic_sync_id, agent_id, idempotency_key
),
outbox_row AS (
  INSERT INTO semantic_outbox(
    semantic_sync_id,
    agent_id,
    idempotency_key,
    payload,
    payload_sha256,
    status
  )
  SELECT
    semantic_sync_id,
    agent_id,
    idempotency_key,
    CAST(:payload AS jsonb),
    :payload_sha256,
    'pending'
  FROM sync_row
  ON CONFLICT (agent_id, idempotency_key)
  DO UPDATE SET semantic_outbox_id = semantic_outbox.semantic_outbox_id
  WHERE semantic_outbox.semantic_sync_id = EXCLUDED.semantic_sync_id
    AND semantic_outbox.payload_sha256 = EXCLUDED.payload_sha256
  RETURNING semantic_outbox_id, semantic_sync_id, agent_id, idempotency_key
)
SELECT
  semantic_outbox_id::text AS semantic_outbox_id,
  semantic_sync_id::text AS semantic_sync_id,
  agent_id::text AS agent_id,
  idempotency_key::text AS idempotency_key
FROM outbox_row
"""


def semantic_idempotency_key(
    reference: PersistedExternalReference,
    *,
    operation: str,
    target: str,
) -> str:
    """Return a UUID key derived only from a persisted source reference and semantic effect."""

    operation_n = str(operation or "").strip()
    if operation_n not in _SUPPORTED_OPERATIONS:
        raise SemanticOutboxError(f"unsupported semantic operation: {operation_n!r}")
    target_n = str(target or "").strip()
    if not target_n:
        raise SemanticOutboxError("semantic idempotency target is required")
    material = _canonical_json(
        {
            "external_reference": reference.to_payload(),
            "operation": operation_n,
            "target": target_n,
            "version": 1,
        }
    )
    return str(uuid.uuid5(_IDEMPOTENCY_NAMESPACE, material))


def semantic_record_target(target_template_code: str) -> str:
    return _normalize_template_code(target_template_code)


def semantic_link_target(
    *,
    parent_semantic_id: str,
    child_semantic_id: str,
    relationship_type: str,
) -> str:
    return _canonical_json(
        {
            "child_semantic_id": _require_text(child_semantic_id, "child_semantic_id"),
            "parent_semantic_id": _require_text(parent_semantic_id, "parent_semantic_id"),
            "relationship_type": _require_text(relationship_type, "relationship_type"),
        }
    )


def enqueue_semantic_record(
    db: TransactionalDatabase,
    *,
    transaction_id: str,
    agent_id: str | uuid.UUID,
    source_table: str,
    source_id: str | uuid.UUID,
    target_template_code: str,
    name: str,
    lifecycle_state: str,
    properties: Mapping[str, Any],
) -> SemanticOutboxRecord:
    """Persist sync and outbox rows inside the caller's existing source transaction."""

    transaction_id_n = str(transaction_id or "").strip()
    if not transaction_id_n:
        raise SemanticOutboxError("transaction_id is required; semantic writes must share the source transaction")
    reference = PersistedExternalReference.for_row(
        agent_id=agent_id,
        source_table=source_table,
        source_id=source_id,
    )
    template_code = semantic_record_target(target_template_code)
    name_n = _require_text(name, "name")
    lifecycle_state_n = _require_text(lifecycle_state, "lifecycle_state")
    if not isinstance(properties, Mapping):
        raise SemanticOutboxError("properties must be an object")
    properties_n = dict(properties)
    property_agent_id = str(properties_n.get("agent_id") or "").strip()
    if property_agent_id and _normalize_uuid(property_agent_id, "properties.agent_id") != reference.agent_id:
        raise SemanticOutboxError("properties.agent_id must match the outbox agent_id")
    properties_n["agent_id"] = reference.agent_id

    idempotency_key = semantic_idempotency_key(reference, operation="record", target=template_code)
    payload: dict[str, Any] = {
        "action": "record",
        "agent_id": reference.agent_id,
        "external_reference": reference.to_payload(),
        "idempotency_key": idempotency_key,
        "lifecycle_state": lifecycle_state_n,
        "name": name_n,
        "properties": properties_n,
        "template_code": template_code,
    }
    payload_sha256 = hashlib.sha256(_canonical_json(payload).encode("utf-8")).hexdigest()
    rows = db.query(
        _ENQUEUE_RECORD_SQL,
        {
            "agent_id": reference.agent_id,
            "source_system": reference.system,
            "source_table": reference.source_table,
            "source_id": reference.source_id,
            "source_external_reference": reference.to_payload(),
            "target_template_code": template_code,
            "idempotency_key": idempotency_key,
            "payload": payload,
            "payload_sha256": payload_sha256,
        },
        transaction_id=transaction_id_n,
    )
    if len(rows) != 1:
        raise SemanticOutboxError("semantic outbox conflict: persisted source reference has different payload")
    row = rows[0]
    semantic_outbox_id = _normalize_uuid(row.get("semantic_outbox_id"), "semantic_outbox_id")
    semantic_sync_id = _normalize_uuid(row.get("semantic_sync_id"), "semantic_sync_id")
    returned_agent_id = _normalize_uuid(row.get("agent_id"), "returned agent_id")
    returned_idempotency_key = _normalize_uuid(row.get("idempotency_key"), "returned idempotency_key")
    if returned_agent_id != reference.agent_id or returned_idempotency_key != idempotency_key:
        raise SemanticOutboxError("semantic outbox returned a mismatched agent scope or idempotency key")
    return SemanticOutboxRecord(
        semantic_outbox_id=semantic_outbox_id,
        semantic_sync_id=semantic_sync_id,
        agent_id=reference.agent_id,
        idempotency_key=idempotency_key,
        payload_sha256=payload_sha256,
        payload=payload,
    )



def enqueue_semantic_graph(
    db: TransactionalDatabase, *, transaction_id: str, agent_id: str | uuid.UUID,
    source_table: str, source_id: str | uuid.UUID, objects: tuple[Any, ...],
    links: tuple[Any, ...], primary_key: str,
) -> SemanticOutboxRecord:
    """Queue one atomic graph with the persisted source operation in its transaction."""
    transaction_id_n = _require_text(transaction_id, "transaction_id")
    reference = PersistedExternalReference.for_row(agent_id=agent_id, source_table=source_table, source_id=source_id)
    keys = [item.key for item in objects]
    if not keys or len(keys) != len(set(keys)) or primary_key not in keys:
        raise SemanticOutboxError("graph requires unique object keys and a primary key")
    primary = objects[keys.index(primary_key)]
    template_code = semantic_record_target(primary.template_code)
    target = template_code
    key = semantic_idempotency_key(reference, operation="graph", target=target)
    def ref_payload(ref: Any) -> dict[str, Any]:
        if isinstance(ref, GraphSourceRef):
            source = PersistedExternalReference.for_row(agent_id=reference.agent_id,
                                                        source_table=ref.source_table, source_id=ref.source_id)
            return {"source_reference": source.to_payload(),
                    "target_template_code": semantic_record_target(ref.target_template_code)}
        return {"key": ref.key, "semantic_id": ref.semantic_id}
    payload = {
        "action": "graph", "agent_id": reference.agent_id,
        "external_reference": reference.to_payload(), "idempotency_key": key,
        "template_code": template_code, "primary_key": primary_key,
        "objects": [{"key": item.key, "template_code": item.template_code, "name": item.name,
                     "properties": item.properties, "lifecycle_state": item.lifecycle_state} for item in objects],
        "links": [{"parent": ref_payload(link.parent), "child": ref_payload(link.child),
                   "relationship_type": link.relationship_type} for link in links],
    }
    digest = hashlib.sha256(_canonical_json(payload).encode("utf-8")).hexdigest()
    rows = db.query(_ENQUEUE_RECORD_SQL, {
        "agent_id": reference.agent_id, "source_system": reference.system,
        "source_table": reference.source_table, "source_id": reference.source_id,
        "source_external_reference": reference.to_payload(), "target_template_code": template_code,
        "idempotency_key": key, "payload": payload, "payload_sha256": digest,
    }, transaction_id=transaction_id_n)
    if len(rows) != 1:
        raise SemanticOutboxError("semantic outbox conflict: persisted source reference has different payload")
    row = rows[0]
    return SemanticOutboxRecord(
        semantic_outbox_id=_normalize_uuid(row.get("semantic_outbox_id"), "semantic_outbox_id"),
        semantic_sync_id=_normalize_uuid(row.get("semantic_sync_id"), "semantic_sync_id"),
        agent_id=reference.agent_id, idempotency_key=key, payload_sha256=digest, payload=payload,
    )


def _normalize_template_code(value: Any) -> str:
    parts = [part.strip() for part in str(value or "").strip("/").split("/") if part.strip()]
    if len(parts) != 4:
        raise SemanticOutboxError("target_template_code must have category/type/subtype/version")
    return "/".join(parts) + "/"


def _normalize_uuid(value: Any, field: str) -> str:
    try:
        return str(uuid.UUID(str(value or "").strip()))
    except (AttributeError, TypeError, ValueError) as exc:
        raise SemanticOutboxError(f"{field} must be a UUID") from exc


def _require_text(value: Any, field: str) -> str:
    text = str(value or "").strip()
    if not text:
        raise SemanticOutboxError(f"{field} is required")
    return text


def _canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
