from __future__ import annotations

import json
import logging
import os
import uuid
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Callable, Mapping

from agent_hub.dot_bridge.delivery import EventDeliveryRetry
from agent_hub.semantic_outbox import (
    PersistedExternalReference,
    SemanticOutboxError,
    semantic_idempotency_key,
    semantic_link_target,
    semantic_record_target,
)
from agent_hub.semantic_tapdb import (
    EXTERNAL_REFERENCE_TEMPLATE, TEMPLATE_CODES, DaylilyTapdbSemanticStore, GraphLinkWrite, GraphObjectRef, GraphObjectWrite,
    validate_marvain_template_pack,
)
from daylily_tapdb.outbox.inbox import mark_inbox_processed, mark_inbox_processing, receive_message
from sqlalchemy import text

if TYPE_CHECKING:
    from agent_hub.dot_bridge.subscriptions import DotEventSubscriptions

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

EXTERNAL_REFERENCE_RELATIONSHIP = "has_external_reference"


@dataclass(frozen=True)
class SemanticEnvelope:
    action: str
    agent_id: str
    idempotency_key: uuid.UUID
    reference: PersistedExternalReference
    target: str


BatchDispatch = Callable[[dict[str, Any]], dict[str, Any]]


def _store() -> DaylilyTapdbSemanticStore:
    return DaylilyTapdbSemanticStore.from_environment()


def _json_body(record: Mapping[str, Any]) -> dict[str, Any]:
    if "body" not in record:
        raise ValueError("message body is required")
    body = record["body"]
    if not isinstance(body, str):
        raise ValueError("message body must be a JSON string")
    try:
        payload = json.loads(body)
    except json.JSONDecodeError as exc:
        raise ValueError("invalid_json") from exc
    if not isinstance(payload, dict):
        raise ValueError("message body must be an object")
    return payload


def _semantic_envelope(payload: Mapping[str, Any]) -> SemanticEnvelope:
    action = str(payload.get("action") or "").strip()
    if action in {"record", "graph"}:
        target = semantic_record_target(str(payload.get("template_code") or ""))
    elif action == "link":
        target = semantic_link_target(
            parent_semantic_id=str(payload.get("parent_semantic_id") or ""),
            child_semantic_id=str(payload.get("child_semantic_id") or ""),
            relationship_type=str(payload.get("relationship_type") or ""),
        )
    else:
        raise ValueError(f"unsupported queued action: {action!r}")

    reference_payload = payload.get("external_reference")
    if not isinstance(reference_payload, Mapping):
        raise SemanticOutboxError("external_reference must be an object")
    reference = PersistedExternalReference.from_payload(reference_payload)
    try:
        agent_id = str(uuid.UUID(str(payload.get("agent_id") or "").strip()))
    except (AttributeError, TypeError, ValueError) as exc:
        raise ValueError("agent_id must be a UUID") from exc
    if agent_id != reference.agent_id:
        raise ValueError("agent_id must match external_reference.agent_id")
    try:
        idempotency_key = uuid.UUID(str(payload.get("idempotency_key") or "").strip())
    except (AttributeError, TypeError, ValueError) as exc:
        raise ValueError("idempotency_key must be a UUID") from exc
    expected_key = semantic_idempotency_key(reference, operation=action, target=target)
    if str(idempotency_key) != expected_key:
        raise ValueError("idempotency_key does not match the persisted external reference")
    return SemanticEnvelope(
        action=action,
        agent_id=agent_id,
        idempotency_key=idempotency_key,
        reference=reference,
        target=target,
    )


def _record_semantic_in_session(
    payload: Mapping[str, Any],
    *,
    envelope: SemanticEnvelope,
    store: DaylilyTapdbSemanticStore,
    session: Any,
) -> dict[str, Any]:
    template_code = semantic_record_target(str(payload.get("template_code") or ""))
    name = str(payload.get("name") or "").strip()
    lifecycle_state = str(payload.get("lifecycle_state") or "").strip()
    properties = payload.get("properties")
    if not name:
        raise ValueError("name is required")
    if not lifecycle_state:
        raise ValueError("lifecycle_state is required")
    if not isinstance(properties, dict):
        raise ValueError("properties must be an object")
    property_agent_id = str(properties.get("agent_id") or "").strip()
    if property_agent_id != envelope.agent_id:
        raise ValueError("properties.agent_id must match the semantic envelope")

    instance = store.factory.create_instance(
        session,
        template_code=template_code,
        name=name,
        properties={**properties, "lifecycle_state": lifecycle_state},
        create_children=False,
    )
    instance.bstatus = lifecycle_state
    session.flush()

    reference = envelope.reference
    external_reference = store.factory.create_instance(
        session,
        template_code=EXTERNAL_REFERENCE_TEMPLATE,
        name=f"{reference.system}:{reference.foreign_uid}",
        properties={
            **reference.to_payload(),
            "root_euid": reference.foreign_uid,
            "href": "",
            "external_identifier": {
                "system": reference.system,
                "target_euid": reference.foreign_uid,
                "href": None,
                "base_url": None,
                "graph_data_path": None,
                "object_detail_path_template": None,
                "auth_mode": "none",
            },
        },
        create_children=False,
    )
    lineage = store.factory.link_instances(
        session,
        instance,
        external_reference,
        relationship_type=EXTERNAL_REFERENCE_RELATIONSHIP,
    )
    return {
        "ok": True,
        "semantic_id": str(instance.euid),
        "template_code": template_code,
        "external_reference_id": str(external_reference.euid),
        "lineage_id": str(lineage.euid),
    }


def _link_semantic_in_session(
    payload: Mapping[str, Any],
    *,
    store: DaylilyTapdbSemanticStore,
    session: Any,
) -> dict[str, Any]:
    from daylily_tapdb.services.object_lookup import find_object_by_euid

    parent_id = str(payload.get("parent_semantic_id") or "").strip()
    child_id = str(payload.get("child_semantic_id") or "").strip()
    relationship_type = str(payload.get("relationship_type") or "").strip()
    parent, parent_type = find_object_by_euid(session, parent_id)
    child, child_type = find_object_by_euid(session, child_id)
    if parent is None or parent_type != "instance":
        raise KeyError(f"unknown TapDB parent instance: {parent_id}")
    if child is None or child_type != "instance":
        raise KeyError(f"unknown TapDB child instance: {child_id}")
    lineage = store.factory.link_instances(
        session,
        parent,
        child,
        relationship_type=relationship_type,
    )
    return {"ok": True, "semantic_id": str(lineage.euid), "relationship_type": relationship_type}


def _dispatch_in_session(
    payload: Mapping[str, Any],
    *,
    envelope: SemanticEnvelope,
    store: DaylilyTapdbSemanticStore,
    session: Any,
) -> dict[str, Any]:
    if envelope.action == "graph":
        raw_objects = payload.get("objects")
        raw_links = payload.get("links")
        if not isinstance(raw_objects, list) or not isinstance(raw_links, list):
            raise ValueError("graph objects and links must be arrays")
        objects = tuple(GraphObjectWrite(**item) for item in raw_objects)
        def resolve_graph_ref(value: Mapping[str, Any]) -> GraphObjectRef:
            if "source_reference" not in value:
                return GraphObjectRef(**value)
            source = PersistedExternalReference.from_payload(value["source_reference"])
            if source.agent_id != envelope.agent_id:
                raise ValueError("graph source reference is outside the agent scope")
            template = semantic_record_target(str(value.get("target_template_code") or ""))
            row = session.execute(text("""SELECT tapdb_euid, status FROM semantic_sync_status
                WHERE agent_id = CAST(:agent_id AS uuid) AND source_system = :source_system
                  AND source_table = :source_table AND source_id = CAST(:source_id AS uuid)
                  AND target_template_code = :template"""),
                {"agent_id": source.agent_id, "source_system": source.system, "source_table": source.source_table,
                 "source_id": source.source_id, "template": template}).one_or_none()
            if row is None or row.status != "written" or not row.tapdb_euid:
                raise RuntimeError("canonical graph source is not yet written")
            return GraphObjectRef(semantic_id=str(row.tapdb_euid))
        links = tuple(GraphLinkWrite(parent=resolve_graph_ref(item["parent"]),
                                     child=resolve_graph_ref(item["child"]),
                                     relationship_type=item["relationship_type"]) for item in raw_links)
        primary_key = str(payload.get("primary_key") or "")
        primary = next((item for item in objects if item.key == primary_key), None)
        if primary is None or semantic_record_target(primary.template_code) != envelope.target:
            raise ValueError("graph primary object does not match the envelope")
        reference_key = "__marvain_source_reference__"
        if any(item.key == reference_key for item in objects):
            raise ValueError("graph uses a reserved reference key")
        reference = envelope.reference
        reference_object = GraphObjectWrite(
            key=reference_key, template_code=EXTERNAL_REFERENCE_TEMPLATE,
            name=f"{reference.system}:{reference.foreign_uid}",
            properties={**reference.to_payload(), "root_euid": reference.foreign_uid, "href": "",
                        "external_identifier": {"system": reference.system, "target_euid": reference.foreign_uid,
                                                "href": None, "base_url": None, "graph_data_path": None,
                                                "object_detail_path_template": None, "auth_mode": "none"}},
            lifecycle_state="recorded",
        )
        reference_link = GraphLinkWrite(parent=GraphObjectRef(key=primary_key),
                                        child=GraphObjectRef(key=reference_key),
                                        relationship_type=EXTERNAL_REFERENCE_RELATIONSHIP)
        result = store.create_graph_in_session(session, objects=objects + (reference_object,),
                                               links=links + (reference_link,))
        return {"ok": True, "semantic_id": result[primary_key].semantic_id}
    if envelope.action == "record":
        return _record_semantic_in_session(payload, envelope=envelope, store=store, session=session)
    if envelope.action == "link":
        return _link_semantic_in_session(payload, store=store, session=session)
    raise ValueError(f"unsupported queued action: {envelope.action!r}")


def _mark_sync_written(session: Any, *, envelope: SemanticEnvelope, semantic_id: str) -> None:
    result = session.execute(
        text(
            """
            UPDATE semantic_sync_status
            SET tapdb_euid = :tapdb_euid,
                status = 'written',
                attempts = attempts + 1,
                last_error = NULL,
                last_attempt_at = now(),
                written_at = now(),
                updated_at = now()
            WHERE agent_id = CAST(:agent_id AS uuid)
              AND idempotency_key = CAST(:idempotency_key AS uuid)
            RETURNING semantic_sync_id
            """
        ),
        {
            "agent_id": envelope.agent_id,
            "idempotency_key": str(envelope.idempotency_key),
            "tapdb_euid": semantic_id,
        },
    )
    if result.one_or_none() is None:
        raise RuntimeError("semantic_sync_status row is missing for the queued semantic write")


def _load_written_semantic_id(session: Any, *, envelope: SemanticEnvelope) -> str:
    result = session.execute(
        text(
            """
            SELECT tapdb_euid, status
            FROM semantic_sync_status
            WHERE agent_id = CAST(:agent_id AS uuid)
              AND idempotency_key = CAST(:idempotency_key AS uuid)
            LIMIT 1
            """
        ),
        {
            "agent_id": envelope.agent_id,
            "idempotency_key": str(envelope.idempotency_key),
        },
    )
    row = result.one_or_none()
    semantic_id = str(getattr(row, "tapdb_euid", "") or "").strip() if row is not None else ""
    status = str(getattr(row, "status", "") or "").strip() if row is not None else ""
    if not semantic_id or status != "written":
        raise RuntimeError("processed semantic inbox receipt has no matching written sync row")
    return semantic_id


def _mark_sync_failed(
    store: DaylilyTapdbSemanticStore,
    *,
    envelope: SemanticEnvelope,
    error: Exception,
) -> None:
    with store.connection.session_scope(commit=True) as session:
        result = session.execute(
            text(
                """
                UPDATE semantic_sync_status
                SET status = 'failed',
                    attempts = attempts + 1,
                    last_error = :last_error,
                    last_attempt_at = now(),
                    updated_at = now()
                WHERE agent_id = CAST(:agent_id AS uuid)
                  AND idempotency_key = CAST(:idempotency_key AS uuid)
                RETURNING semantic_sync_id
                """
            ),
            {
                "agent_id": envelope.agent_id,
                "idempotency_key": str(envelope.idempotency_key),
                "last_error": str(error)[:10_000],
            },
        )
        if result.one_or_none() is None:
            logger.error(
                "semantic_sync_status row missing agent_id=%s idempotency_key=%s",
                envelope.agent_id,
                envelope.idempotency_key,
            )


def _handoff_event_transport(
    store: DaylilyTapdbSemanticStore, envelope: SemanticEnvelope,
) -> DotEventSubscriptions | None:
    if envelope.action != "graph" or envelope.target != semantic_record_target(TEMPLATE_CODES["work_handoff"]):
        return None
    mode = os.environ.get("MARVAIN_DOT_EVENTS_MODE")
    if mode == "disabled":
        return None
    if mode != "enabled":
        raise ValueError("MARVAIN_DOT_EVENTS_MODE must explicitly select enabled or disabled")
    secret_arn = os.environ.get("MARVAIN_DOT_EVENTS_SECRET_ARN", "").strip()
    if not secret_arn:
        raise ValueError("Enabled dot events require MARVAIN_DOT_EVENTS_SECRET_ARN")
    from agent_hub.dot_bridge.subscriptions import DotEventSubscriptions

    return DotEventSubscriptions.from_secret(store, secret_arn)


def _dispatch_idempotent(payload: dict[str, Any]) -> dict[str, Any]:
    envelope = _semantic_envelope(payload)
    store = _store()
    event_transport = _handoff_event_transport(store, envelope)
    try:
        with store.connection.session_scope(commit=True) as session:
            receipt = receive_message(
                session,
                message_machine_uuid=envelope.idempotency_key,
                payload=payload,
                domain_code=store.domain_code,
                issuer_app_code=store.owner_repo_name,
                source_domain_code=store.domain_code,
                source_issuer_app_code=store.owner_repo_name,
                source_destination="tapdb_writer",
            )
            if receipt.status == "processed":
                semantic_id = _load_written_semantic_id(session, envelope=envelope)
                result = {
                    "ok": True,
                    "duplicate": True,
                    "idempotency_key": str(envelope.idempotency_key),
                    "receipt_id": str(receipt.receipt_machine_uuid),
                    "semantic_id": semantic_id,
                }
            else:
                if receipt.status != "received":
                    raise RuntimeError(f"semantic inbox message has non-retryable state: {receipt.status}")
                mark_inbox_processing(session, envelope.idempotency_key)
                written = _dispatch_in_session(payload, envelope=envelope, store=store, session=session)
                semantic_id = str(written.get("semantic_id") or "").strip()
                if not semantic_id:
                    raise RuntimeError("semantic writer did not return a persisted TapDB identifier")
                if event_transport is not None:
                    event_transport.enqueue_handoff(session, command_id=envelope.idempotency_key,
                                                    agent_id=envelope.agent_id, handoff_euid=semantic_id,
                                                    occurred_at=receipt.received_dt)
                _mark_sync_written(session, envelope=envelope, semantic_id=semantic_id)
                mark_inbox_processed(session, envelope.idempotency_key)
                result = {
                    **written,
                    "duplicate": False,
                    "idempotency_key": str(envelope.idempotency_key),
                    "receipt_id": str(receipt.receipt_machine_uuid),
                }
    except Exception as exc:
        try:
            _mark_sync_failed(store, envelope=envelope, error=exc)
        except Exception:
            logger.exception(
                "Failed to persist TapDB writer failure agent_id=%s idempotency_key=%s",
                envelope.agent_id,
                envelope.idempotency_key,
            )
        raise
    if event_transport is not None:
        try:
            delivered = event_transport.deliver_for_command(envelope.idempotency_key)
        except Exception as exc:
            # The owning receipt is committed. Only event transport may retry here.
            raise EventDeliveryRetry(canonical_result=result) from exc
        if not delivered:
            raise EventDeliveryRetry(canonical_result=result)
    return result


def _dispatch(payload: dict[str, Any]) -> dict[str, Any]:
    action = str(payload.get("action") or "").strip()
    if action == "validate_templates":
        result = validate_marvain_template_pack()
        return {"ok": not result.issues, "templates_loaded": result.templates_loaded, "issues": result.issues}
    if action == "seed_templates":
        overwrite = payload.get("overwrite")
        if not isinstance(overwrite, bool):
            raise ValueError("seed_templates requires a boolean overwrite field")
        summary = _store().seed_templates(overwrite=overwrite)
        return {
            "ok": True,
            "templates_loaded": summary.templates_loaded,
            "inserted": summary.inserted,
            "updated": summary.updated,
            "skipped": summary.skipped,
            "prefixes_ensured": summary.prefixes_ensured,
        }
    return _dispatch_idempotent(payload)


def process_sqs_batch(
    records: list[dict[str, Any]],
    *,
    dispatch: BatchDispatch | None = None,
) -> dict[str, Any]:
    dispatch_fn = dispatch or _dispatch_idempotent
    failures: list[dict[str, str]] = []
    processed = 0
    for record in records:
        message_id = str(record.get("messageId") or "").strip()
        if not message_id:
            raise ValueError("every SQS record must include messageId")
        try:
            dispatch_fn(_json_body(record))
            processed += 1
        except EventDeliveryRetry:
            logger.warning("Committed TapDB handoff has pending webhook delivery message_id=%s", message_id)
            failures.append({"itemIdentifier": message_id})
        except Exception:
            logger.exception("TapDB writer failed message_id=%s", message_id)
            failures.append({"itemIdentifier": message_id})
    return {
        "ok": not failures,
        "processed": processed,
        "batchItemFailures": failures,
    }


def handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    del context
    if "Records" not in event:
        try:
            return _dispatch(event)
        except EventDeliveryRetry as exc:
            return {**exc.canonical_result, "event_delivery": "pending"}
        except Exception as exc:
            logger.exception("TapDB writer invocation failed")
            return {"ok": False, "error": str(exc)}

    records = event["Records"]
    if not isinstance(records, list):
        raise ValueError("Records must be a list")
    return process_sqs_batch(records)
