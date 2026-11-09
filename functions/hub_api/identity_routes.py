"""Authenticated clean-bootstrap operations queued to the canonical graph writer."""

from __future__ import annotations

import json
from collections.abc import Callable
from typing import Annotated, Any, Literal
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, ConfigDict, StringConstraints, model_validator

from agent_hub.auth import AuthenticatedUser
from agent_hub.rds_data import RdsData
from agent_hub.semantic_outbox import GraphSourceRef, SemanticOutboxError, enqueue_semantic_graph
from agent_hub.semantic_tapdb import TEMPLATE_CODES, GraphLinkWrite, GraphObjectRef, GraphObjectWrite

Text = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=300)]
_EXTERNAL_REFERENCE = "reference/external_identifier/tapdb_object/1.0/"


class IdentityOperation(BaseModel):
    model_config = ConfigDict(extra="forbid")
    operation_id: UUID
    space_id: UUID


class AnimalCreate(IdentityOperation):
    display_name: Text
    species: Text


class PrincipalCreate(IdentityOperation):
    actor_kind: Literal["human", "software_agent"]
    person_id: UUID | None = None

    @model_validator(mode="after")
    def actor_source(self) -> PrincipalCreate:
        if (self.actor_kind == "human") != (self.person_id is not None):
            raise ValueError("human principals require person_id; software principals use the selected agent")
        return self


class EmbodimentCreate(IdentityOperation):
    actor_kind: Literal["human", "animal", "software_agent"]
    actor_source_id: UUID
    device_id: UUID
    display_name: Text


class CaretakerGrant(IdentityOperation):
    person_id: UUID
    animal_operation_id: UUID
    principal_operation_id: UUID


class IdentityAccepted(BaseModel):
    operation_id: UUID
    semantic_sync_id: UUID
    status: Literal["queued"] = "queued"


class IdentityStatus(BaseModel):
    operation_id: UUID
    semantic_sync_id: UUID
    status: str
    semantic_id: str | None
    target_template_code: str


_INSERT_OPERATION = """
INSERT INTO events(event_id, agent_id, space_id, type, payload)
VALUES (CAST(:operation_id AS uuid), CAST(:agent_id AS uuid), CAST(:space_id AS uuid),
        :event_type, CAST(:payload AS jsonb))
ON CONFLICT (event_id) DO UPDATE SET event_id = events.event_id
WHERE events.agent_id = EXCLUDED.agent_id AND events.space_id = EXCLUDED.space_id
  AND events.type = EXCLUDED.type AND events.payload = EXCLUDED.payload
RETURNING event_id::text AS event_id
"""


def build_identity_router(
    *, get_db: Callable[[], RdsData], get_user: Callable[..., AuthenticatedUser],
    require_agent_role: Callable[..., None], cognito_issuer: str | None,
) -> APIRouter:
    """Bind the existing user authentication and agent membership controls."""
    router = APIRouter()

    def scope(agent_id: UUID, space_id: UUID, user: AuthenticatedUser) -> tuple[RdsData, str, str]:
        agent, space = str(agent_id), str(space_id)
        require_agent_role(user=user, agent_id=agent, required_role="admin")
        db = get_db()
        rows = db.query(
            """SELECT s.space_id::text AS space_id FROM spaces s JOIN agents a ON a.agent_id = s.agent_id
               WHERE s.space_id = CAST(:space_id AS uuid) AND s.agent_id = CAST(:agent_id AS uuid)
                 AND s.lifecycle_state = 'active' AND s.disabled_at IS NULL
                 AND a.lifecycle_state = 'active' AND NOT a.disabled""",
            {"space_id": space, "agent_id": agent},
        )
        if len(rows) != 1:
            raise HTTPException(status_code=404, detail="Active agent space not found")
        return db, agent, space

    def source(db: RdsData, *, agent: str, kind: str, source_id: str) -> GraphSourceRef:
        if kind == "human":
            sql = """SELECT person_id FROM people WHERE person_id = CAST(:source_id AS uuid)
                     AND agent_id = CAST(:agent_id AS uuid) AND lifecycle_state = 'active' AND disabled_at IS NULL"""
            table, template = "people", TEMPLATE_CODES["person"]
        elif kind == "animal":
            sql = """SELECT event_id FROM events WHERE event_id = CAST(:source_id AS uuid)
                     AND agent_id = CAST(:agent_id AS uuid) AND type = 'identity.animal'"""
            table, template = "events", TEMPLATE_CODES["animal"]
        elif kind == "software_agent":
            sql = """SELECT agent_id FROM agents WHERE agent_id = CAST(:source_id AS uuid)
                     AND agent_id = CAST(:agent_id AS uuid) AND lifecycle_state = 'active' AND NOT disabled"""
            table, template = "agents", TEMPLATE_CODES["agent"]
        elif kind == "device":
            sql = """SELECT device_id FROM devices WHERE device_id = CAST(:source_id AS uuid)
                     AND agent_id = CAST(:agent_id AS uuid) AND lifecycle_state = 'active'
                     AND disabled_at IS NULL AND revoked_at IS NULL"""
            table, template = "devices", TEMPLATE_CODES["device"]
        else:
            raise ValueError("unsupported identity source")
        if len(db.query(sql, {"source_id": source_id, "agent_id": agent})) != 1:
            raise HTTPException(status_code=404, detail=f"Active {kind} source not found in this agent")
        return GraphSourceRef(source_table=table, source_id=source_id, target_template_code=template)

    def queue(db: RdsData, *, agent: str, space: str, user: AuthenticatedUser,
              operation_id: UUID, operation: str, intent: dict[str, Any],
              objects: tuple[GraphObjectWrite, ...], links: tuple[GraphLinkWrite, ...],
              primary_key: str) -> IdentityAccepted:
        op = str(operation_id)
        payload = json.dumps({"user_id": user.user_id, "subject": user.cognito_sub, **intent},
                             sort_keys=True, separators=(",", ":"))
        tx = db.begin()
        try:
            rows = db.query(_INSERT_OPERATION, {"operation_id": op, "agent_id": agent, "space_id": space,
                                                "event_type": f"identity.{operation}", "payload": payload},
                            transaction_id=tx)
            if len(rows) != 1:
                raise HTTPException(status_code=409, detail="Operation ID conflicts with an existing operation")
            queued = enqueue_semantic_graph(db, transaction_id=tx, agent_id=agent, source_table="events",
                                            source_id=op, objects=objects, links=links, primary_key=primary_key)
            db.commit(tx)
        except SemanticOutboxError as exc:
            db.rollback(tx)
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        except Exception:
            db.rollback(tx)
            raise
        return IdentityAccepted(operation_id=operation_id, semantic_sync_id=queued.semantic_sync_id)

    @router.post("/v1/agents/{agent_id}/identity/animals", status_code=202, response_model=IdentityAccepted)
    def create_animal(agent_id: UUID, body: AnimalCreate,
                      user: AuthenticatedUser = Depends(get_user)) -> IdentityAccepted:
        db, agent, space = scope(agent_id, body.space_id, user)
        obj = GraphObjectWrite("animal", TEMPLATE_CODES["animal"], body.display_name,
                               {"species": body.species}, "active")
        return queue(db, agent=agent, space=space, user=user, operation_id=body.operation_id,
                     operation="animal", intent={"display_name": body.display_name, "species": body.species},
                     objects=(obj,), links=(), primary_key="animal")

    @router.post("/v1/agents/{agent_id}/identity/principals", status_code=202, response_model=IdentityAccepted)
    def create_principal(agent_id: UUID, body: PrincipalCreate,
                         user: AuthenticatedUser = Depends(get_user)) -> IdentityAccepted:
        db, agent, space = scope(agent_id, body.space_id, user)
        issuer = str(cognito_issuer or "").strip()
        if not issuer:
            raise HTTPException(status_code=503, detail="Cognito issuer is not configured")
        actor_id = str(body.person_id) if body.person_id else agent
        actor = source(db, agent=agent, kind=body.actor_kind, source_id=actor_id)
        principal = GraphObjectWrite("principal", TEMPLATE_CODES["principal"], f"linked-account:{body.operation_id}",
            {"binding_kind": "authenticated_linked_account"}, "active")
        reference = GraphObjectWrite("credential", _EXTERNAL_REFERENCE, f"cognito-subject:{body.operation_id}",
            {"root_euid": user.cognito_sub, "external_identifier": {"system": issuer,
             "target_euid": user.cognito_sub, "href": None, "base_url": None, "graph_data_path": None,
             "object_detail_path_template": None, "auth_mode": "none"}}, "active")
        links = (GraphLinkWrite(actor, GraphObjectRef(key="principal"), "AUTHENTICATED_AS"),
                 GraphLinkWrite(GraphObjectRef(key="principal"), GraphObjectRef(key="credential"), "has_external_reference"))
        return queue(db, agent=agent, space=space, user=user, operation_id=body.operation_id,
                     operation="principal", intent={"actor_kind": body.actor_kind, "actor_source_id": actor_id,
                                                     "issuer": issuer},
                     objects=(principal, reference), links=links, primary_key="principal")

    @router.post("/v1/agents/{agent_id}/identity/embodiments", status_code=202, response_model=IdentityAccepted)
    def create_embodiment(agent_id: UUID, body: EmbodimentCreate,
                          user: AuthenticatedUser = Depends(get_user)) -> IdentityAccepted:
        db, agent, space = scope(agent_id, body.space_id, user)
        actor_id, device_id = str(body.actor_source_id), str(body.device_id)
        actor = source(db, agent=agent, kind=body.actor_kind, source_id=actor_id)
        device = source(db, agent=agent, kind="device", source_id=device_id)
        obj = GraphObjectWrite("embodiment", TEMPLATE_CODES["embodiment"], body.display_name, {}, "active")
        links = (GraphLinkWrite(actor, GraphObjectRef(key="embodiment"), "HAS_EMBODIMENT"),
                 GraphLinkWrite(GraphObjectRef(key="embodiment"), device, "USES_DEVICE"))
        return queue(db, agent=agent, space=space, user=user, operation_id=body.operation_id,
                     operation="embodiment", intent={"actor_kind": body.actor_kind, "actor_source_id": actor_id,
                         "device_id": device_id, "display_name": body.display_name},
                     objects=(obj,), links=links, primary_key="embodiment")

    @router.post("/v1/agents/{agent_id}/identity/caretakers", status_code=202, response_model=IdentityAccepted)
    def grant_caretaker(agent_id: UUID, body: CaretakerGrant,
                        user: AuthenticatedUser = Depends(get_user)) -> IdentityAccepted:
        db, agent, space = scope(agent_id, body.space_id, user)
        person_id, animal_id, principal_id = map(str, (body.person_id, body.animal_operation_id, body.principal_operation_id))
        person = source(db, agent=agent, kind="human", source_id=person_id)
        animal = source(db, agent=agent, kind="animal", source_id=animal_id)
        principal_rows = db.query(
            """SELECT event_id FROM events WHERE event_id = CAST(:principal_id AS uuid)
               AND agent_id = CAST(:agent_id AS uuid) AND type = 'identity.principal'
               AND payload->>'user_id' = :user_id AND payload->>'subject' = :subject
               AND payload->>'actor_kind' = 'human' AND payload->>'actor_source_id' = :person_id""",
            {"principal_id": principal_id, "agent_id": agent, "user_id": user.user_id,
             "subject": user.cognito_sub, "person_id": person_id},
        )
        if len(principal_rows) != 1:
            raise HTTPException(status_code=403, detail="Authenticated caretaker principal is not bound to this person")
        principal = GraphSourceRef("events", principal_id, TEMPLATE_CODES["principal"])
        grant = GraphObjectWrite("grant", TEMPLATE_CODES["consent_grant"], f"caretaker-grant:{body.operation_id}",
                                 {"consent_type": "caretaker_authority"}, "granted")
        ref = GraphObjectRef(key="grant")
        links = (GraphLinkWrite(person, animal, "CARETAKER_OF"), GraphLinkWrite(ref, person, "GRANTED_TO"),
                 GraphLinkWrite(ref, animal, "APPLIES_TO"), GraphLinkWrite(ref, principal, "AUTHENTICATED_BY"))
        return queue(db, agent=agent, space=space, user=user, operation_id=body.operation_id,
                     operation="caretaker", intent={"person_id": person_id, "animal_operation_id": animal_id,
                                                     "principal_operation_id": principal_id},
                     objects=(grant,), links=links, primary_key="grant")

    @router.get("/v1/agents/{agent_id}/identity/operations/{operation_id}", response_model=IdentityStatus)
    def operation_status(agent_id: UUID, operation_id: UUID,
                         user: AuthenticatedUser = Depends(get_user)) -> IdentityStatus:
        agent, op = str(agent_id), str(operation_id)
        require_agent_role(user=user, agent_id=agent, required_role="admin")
        rows = get_db().query(
            """SELECT s.semantic_sync_id::text AS semantic_sync_id, s.status, s.tapdb_euid,
                      s.target_template_code FROM semantic_sync_status s JOIN events e ON e.event_id = s.source_id
               WHERE s.agent_id = CAST(:agent_id AS uuid) AND e.agent_id = s.agent_id
                 AND s.source_table = 'events' AND e.type IN
                     ('identity.animal', 'identity.principal', 'identity.embodiment', 'identity.caretaker')
                 AND s.source_id = CAST(:operation_id AS uuid)""", {"agent_id": agent, "operation_id": op})
        if len(rows) != 1:
            raise HTTPException(status_code=404, detail="Identity operation not found")
        row = rows[0]
        return IdentityStatus(operation_id=operation_id, semantic_sync_id=row["semantic_sync_id"],
                              status=row["status"], semantic_id=row.get("tapdb_euid"),
                              target_template_code=row["target_template_code"])

    return router
