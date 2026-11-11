"""Operator-owned setup of an existing agent for authenticated browser sessions.

Operational rows and graph intents are committed together. The existing TapDB
writer owns canonical IDs; this module never manufactures them.
"""
from __future__ import annotations

import hashlib
import json
import os
import secrets
from datetime import datetime, timezone
from typing import Any, Callable, Literal
from uuid import UUID, uuid4

import boto3
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, ConfigDict, Field

from agent_hub.semantic_outbox import GraphSourceRef, enqueue_semantic_graph, enqueue_semantic_record
from agent_hub.semantic_tapdb import (
    DaylilyTapdbSemanticStore, EXTERNAL_REFERENCE_TEMPLATE, TEMPLATE_CODES,
    GraphLinkWrite, GraphObjectRef, GraphObjectWrite,
)
from agent_hub.semantic_lifecycle import MarvainSemanticLifecycle
from agent_hub.v4_runtime import load_bindings, load_route, resolve_route


class BrowserActivationIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    operation_id: UUID
    agent_id: UUID
    owner_email: str
    person_name: str = Field(min_length=1)
    space_name: str = Field(min_length=1)
    room_mode: Literal["stable", "ephemeral"]
    retention: Literal["retain_until_revoked"]
    raw_capture_allowed: Literal[True]
    audience: Literal["owner_and_agent"]
    worker_device_token: str = Field(min_length=32, repr=False)


def _payload(row: dict[str, Any]) -> dict[str, Any]:
    value = row["payload"]
    return json.loads(value) if isinstance(value, str) else value


def build_browser_activation_router(*, get_db: Callable, require_admin: Callable,
                                    cognito_issuer: str) -> APIRouter:
    router = APIRouter(dependencies=[Depends(require_admin)])

    @router.post("/v1/admin/browser-activation", status_code=202)
    def prepare(body: BrowserActivationIn) -> dict[str, Any]:
        db = get_db()
        aid, op = str(body.agent_id), str(body.operation_id)
        intent = body.model_dump(mode="json", exclude={"worker_device_token"})
        token_hash = hashlib.sha256(body.worker_device_token.encode()).hexdigest()
        existing = db.query("SELECT payload FROM events WHERE event_id=:op::uuid AND type='identity.browser_setup'", {"op": op})
        if existing:
            saved = _payload(existing[0])
            if saved["intent"] != intent or saved["worker_token_hash"] != token_hash:
                raise HTTPException(409, "Activation operation conflicts with its persisted intent")
            return {"operation_id": op, "status": "queued", "space_id": saved["space_id"]}
        owners = db.query(
            """SELECT u.user_id::text AS user_id, u.cognito_sub, a.name AS agent_name
               FROM users u JOIN agent_memberships m ON m.user_id=u.user_id
               JOIN agents a ON a.agent_id=m.agent_id
               WHERE m.agent_id=:aid::uuid AND lower(u.email)=lower(:email)
                 AND m.role='owner' AND m.revoked_at IS NULL AND NOT a.disabled
                 AND a.lifecycle_state='active'""", {"aid": aid, "email": body.owner_email})
        if len(owners) != 1:
            raise HTTPException(409, "Select exactly one signed-in owner of the existing active agent")
        if not cognito_issuer:
            raise HTTPException(503, "Cognito issuer is required")
        owner = owners[0]
        previous = db.query("""SELECT event_id FROM events WHERE agent_id=:aid::uuid
            AND type='identity.browser_setup' AND payload->>'user_id'=:uid""", {"aid": aid, "uid": owner["user_id"]})
        if previous:
            raise HTTPException(409, "Browser activation already exists; resume its original operation")
        spaces = db.query("""SELECT space_id::text AS space_id, privacy_mode, livekit_room_mode FROM spaces
            WHERE agent_id=:aid::uuid AND name=:name AND lifecycle_state='active'""", {"aid": aid, "name": body.space_name})
        if len(spaces) > 1:
            raise HTTPException(409, "Space name is ambiguous")
        if spaces and (spaces[0]["privacy_mode"] or spaces[0]["livekit_room_mode"] != body.room_mode):
            raise HTTPException(409, "Existing space settings differ from the explicit activation policy")
        space = spaces[0]["space_id"] if spaces else str(uuid4())
        persons = db.query("""SELECT p.person_id::text AS person_id, p.display_name FROM person_accounts pa
            JOIN people p ON p.person_id=pa.person_id WHERE pa.agent_id=:aid::uuid AND pa.user_id=:uid::uuid
            AND p.lifecycle_state='active' AND p.disabled_at IS NULL""", {"aid": aid, "uid": owner["user_id"]})
        if len(persons) > 1:
            raise HTTPException(409, "Owner has ambiguous person bindings")
        person = persons[0]["person_id"] if persons else str(uuid4())
        worker, browser = str(uuid4()), str(uuid4())
        saved = {"intent": intent, "user_id": owner["user_id"], "subject": owner["cognito_sub"],
                 "issuer": cognito_issuer, "space_id": space, "person_id": person,
                 "worker_device_id": worker, "browser_device_id": browser, "worker_token_hash": token_hash}
        tx = db.begin()
        try:
            if not spaces:
                db.execute("""INSERT INTO spaces(space_id,agent_id,name,privacy_mode,livekit_room_mode)
                    VALUES (:sid::uuid,:aid::uuid,:name,false,:mode)""",
                    {"sid": space, "aid": aid, "name": body.space_name, "mode": body.room_mode}, transaction_id=tx)
            if not persons:
                db.execute("INSERT INTO people(person_id,agent_id,display_name) VALUES (:pid::uuid,:aid::uuid,:name)",
                           {"pid": person, "aid": aid, "name": body.person_name}, transaction_id=tx)
                db.execute("INSERT INTO person_accounts(agent_id,user_id,person_id) VALUES (:aid::uuid,:uid::uuid,:pid::uuid)",
                           {"aid": aid, "uid": owner["user_id"], "pid": person}, transaction_id=tx)
            for did, name, digest, scopes in (
                (worker, "INITagent AWS responder", token_hash,
                 ["events:read", "events:write", "memories:read", "memories:write", "artifacts:write", "presence:write"]),
                (browser, body.space_name + " browser", hashlib.sha256(secrets.token_bytes(32)).hexdigest(), []),
            ):
                db.execute("""INSERT INTO devices(device_id,agent_id,name,token_hash,scopes,capabilities,provisioned_at,provisioned_by,current_space_id)
                    VALUES (:did::uuid,:aid::uuid,:name,:hash,:scopes::jsonb,:caps::jsonb,now(),:uid,:sid::uuid)""",
                    {"did": did, "aid": aid, "name": name, "hash": digest, "scopes": json.dumps(scopes),
                     "caps": json.dumps({"kind": "worker" if did == worker else "authenticated_browser"}),
                     "uid": owner["user_id"], "sid": space}, transaction_id=tx)
            for table, source, template, name, properties in (
                ("agents", aid, "agent", owner["agent_name"], {"agent_id": aid, "disabled": False}),
                ("spaces", space, "space", body.space_name, {"agent_id": aid, "privacy_mode": False, "livekit_room_mode": body.room_mode}),
                ("people", person, "person", persons[0]["display_name"] if persons else body.person_name, {}),
                ("devices", worker, "device", "AWS responder", {"capabilities": {"kind": "worker"}}),
                ("devices", browser, "device", body.space_name + " browser", {"capabilities": {"kind": "authenticated_browser"}}),
            ):
                prior = db.query("""SELECT status FROM semantic_sync_status WHERE agent_id=:aid::uuid
                    AND source_table=:table AND source_id=:source::uuid AND target_template_code=:template""",
                    {"aid": aid, "table": table, "source": source, "template": TEMPLATE_CODES[template]}, transaction_id=tx)
                if not prior:
                    enqueue_semantic_record(db, transaction_id=tx, agent_id=aid, source_table=table,
                        source_id=source, target_template_code=TEMPLATE_CODES[template], name=name,
                        lifecycle_state="active", properties=properties)
            db.execute("""INSERT INTO consent_grants(agent_id,person_id,consent_type,scope)
                VALUES (:aid::uuid,:pid::uuid,'recording',:scope::jsonb)""",
                {"aid": aid, "pid": person, "scope": json.dumps({"space_id": space,
                 "raw_capture_allowed": True, "retention": body.retention, "audience": body.audience,
                 "authorization": "Explicit owner instruction in activation request"})}, transaction_id=tx)
            db.execute("""INSERT INTO events(event_id,agent_id,space_id,type,payload)
                VALUES (:op::uuid,:aid::uuid,:sid::uuid,'identity.browser_setup',:payload::jsonb)""",
                {"op": op, "aid": aid, "sid": space, "payload": json.dumps(saved)}, transaction_id=tx)
            objects = [GraphObjectWrite("worker", TEMPLATE_CODES["principal"], "AWS responder principal", {}, "active"),
                       GraphObjectWrite("human", TEMPLATE_CODES["principal"], body.person_name + " login", {}, "active"),
                       GraphObjectWrite("worker_body", TEMPLATE_CODES["embodiment"], "AWS responder", {}, "active"),
                       GraphObjectWrite("browser_body", TEMPLATE_CODES["embodiment"], body.space_name, {}, "active")]
            credential = GraphObjectWrite("credential", EXTERNAL_REFERENCE_TEMPLATE, "Cognito login",
                {"root_euid": owner["cognito_sub"], "external_identifier": {"system": cognito_issuer,
                 "target_euid": owner["cognito_sub"], "href": None, "base_url": None, "graph_data_path": None,
                 "object_detail_path_template": None, "auth_mode": "none"}}, "active")
            objects.append(credential)
            actor = GraphSourceRef("agents", aid, TEMPLATE_CODES["agent"])
            links = [GraphLinkWrite(actor, GraphObjectRef(key="worker"), "AUTHENTICATED_AS"),
                GraphLinkWrite(GraphSourceRef("people", person, TEMPLATE_CODES["person"]), GraphObjectRef(key="human"), "AUTHENTICATED_AS"),
                GraphLinkWrite(GraphObjectRef(key="human"), GraphObjectRef(key="credential"), "has_external_reference")]
            for key, did in (("worker_body", worker), ("browser_body", browser)):
                links.extend((GraphLinkWrite(actor, GraphObjectRef(key=key), "HAS_EMBODIMENT"),
                    GraphLinkWrite(GraphObjectRef(key=key), GraphSourceRef("devices", did, TEMPLATE_CODES["device"]), "USES_DEVICE")))
            enqueue_semantic_graph(db, transaction_id=tx, agent_id=aid, source_table="events", source_id=op,
                                   objects=tuple(objects), links=tuple(links), primary_key="worker")
            db.commit(tx)
        except Exception:
            db.rollback(tx)
            raise
        return {"operation_id": op, "space_id": space, "status": "queued"}

    @router.get("/v1/admin/browser-activation/{operation_id}")
    def status(operation_id: UUID) -> dict[str, Any]:
        db, op = get_db(), str(operation_id)
        rows = db.query("SELECT payload FROM events WHERE event_id=:op::uuid AND type='identity.browser_setup'", {"op": op})
        if len(rows) != 1:
            raise HTTPException(404, "Browser activation not found")
        p = _payload(rows[0]); aid = p["intent"]["agent_id"]
        references = [("agents", aid, "agent"), ("spaces", p["space_id"], "space"),
                      ("people", p["person_id"], "person"), ("devices", p["worker_device_id"], "device"),
                      ("devices", p["browser_device_id"], "device"), ("events", op, "principal")]
        canonical = {}
        for table, source, template in references:
            result = db.query("""SELECT status,tapdb_euid,last_error FROM semantic_sync_status
                WHERE agent_id=:aid::uuid AND source_table=:table AND source_id=:source::uuid
                  AND target_template_code=:template""", {"aid": aid, "table": table, "source": source, "template": TEMPLATE_CODES[template]})
            if len(result) != 1:
                raise HTTPException(409, "Activation source receipt missing")
            r = result[0]
            if r["status"] != "written":
                return {"operation_id": op, "status": r["status"], "source_table": table,
                        "source_id": source, "error": r.get("last_error")}
            canonical[source] = r["tapdb_euid"]
        store = DaylilyTapdbSemanticStore.from_environment()
        with store.read_view() as view:
            principals = view.linked_objects(canonical[p["person_id"]], relationship_type="AUTHENTICATED_AS")
            matches = []
            for principal in principals:
                refs = view.linked_objects(principal.semantic_id, relationship_type="has_external_reference")
                if any(ref.properties.get("external_identifier", {}).get("system") == p["issuer"] and
                       ref.properties.get("external_identifier", {}).get("target_euid") == p["subject"] for ref in refs):
                    matches.append(principal.semantic_id)
        if len(matches) != 1:
            raise HTTPException(409, "Canonical human principal is ambiguous or missing")
        human, worker = matches[0], canonical[op]
        policy = {"owner_principal_euid": human, "reader_principal_euids": [human, worker],
                  "allowed_purposes": ["recall", "detail", "history", "export"], "raw_capture_allowed": True,
                  "retention": {layer: {"retain_until_revoked": True} for layer in
                                ("raw_artifact", "attributed_event", "episode", "knowledge")}}
        routes = [{"device_id": did, "agent_id": aid, "space_id": p["space_id"],
                   "space_euid": canonical[p["space_id"]], "device_euid": canonical[did],
                   "actor_euid": canonical[aid], "principal_euid": worker, "policy": policy}
                  for did in (p["worker_device_id"], p["browser_device_id"])]
        return {"status": "written", "operation_id": op, "agent_id": aid, "space_id": p["space_id"],
                "worker_device_id": p["worker_device_id"], "bindings": {
                    "routes": routes,
                    "callers": [{"device_id": p["worker_device_id"], "agent_id": aid,
                        "device_euid": canonical[p["worker_device_id"]], "actor_euid": canonical[aid], "principal_euid": worker}],
                    "humans": [{"user_id": p["user_id"], "subject": p["subject"], "issuer": p["issuer"],
                        "actor_euid": canonical[p["person_id"]], "principal_euid": human}],
                    "browsers": [{"user_id": p["user_id"], "subject": p["subject"], "agent_id": aid,
                        "space_id": p["space_id"], "device_id": p["browser_device_id"], "record_media": True}],
                }}
    return router


def browser_route(*, user: Any, agent_id: str, space_id: str):
    bindings = load_bindings()
    matches = [item for item in bindings.get("browsers", []) if
               (item["user_id"], item["subject"], item["agent_id"], item["space_id"]) ==
               (user.user_id, user.cognito_sub, agent_id, space_id)]
    if len(matches) != 1:
        raise HTTPException(409, "This sign-in and space need browser activation before joining")
    route = load_route(device_id=matches[0]["device_id"], agent_id=agent_id, space_id=space_id)
    return route, matches[0]


def prepare_browser_scene(*, db: Any, user: Any, agent_id: str, space_id: str,
                          room_mode: str, session_id: str | None) -> dict[str, Any]:
    route, binding = browser_route(user=user, agent_id=agent_id, space_id=space_id)
    if session_id:
        sid = str(UUID(session_id))
        rows = db.query("""SELECT livekit_room,status,metadata FROM sessions WHERE session_id=:sid::uuid
            AND agent_id=:aid::uuid AND space_id=:space::uuid""", {"sid": sid, "aid": agent_id, "space": space_id})
        if len(rows) != 1:
            raise HTTPException(404, "Browser session not found")
        metadata = rows[0]["metadata"]
        if isinstance(metadata, str): metadata = json.loads(metadata)
        if metadata.get("actor_type") != "user" or metadata.get("actor_id") != user.user_id:
            raise HTTPException(403, "Session belongs to another principal")
        if rows[0]["status"] in {"closed", "ended", "failed"}:
            raise HTTPException(409, "Session has ended; start a new session")
        return {"session_id": sid, "room": rows[0]["livekit_room"], "record_media": binding["record_media"]}
    dispatcher = os.environ.get("SEMANTIC_OUTBOX_DISPATCHER_FUNCTION_NAME", "").strip()
    if not dispatcher:
        raise HTTPException(503, "Session memory dispatcher is not configured")
    store = DaylilyTapdbSemanticStore.from_environment()
    space, device, owner, readers = resolve_route(store, route)
    sid = str(uuid4())
    room = space_id if room_mode == "stable" else f"{space_id}:{sid.replace('-', '')[:12]}"
    objects, links = MarvainSemanticLifecycle(store).scene_session_graph(space=space, device=device,
        session_key=sid, started_at=datetime.now(timezone.utc), policy=route.policy, owner=owner, readers=readers)
    tx = db.begin()
    try:
        db.execute("""INSERT INTO sessions(session_id,agent_id,space_id,persona_id,livekit_room,status,metadata)
            VALUES (:sid::uuid,:aid::uuid,:space::uuid,
              (SELECT persona_id FROM personas WHERE agent_id=:aid::uuid AND is_default AND lifecycle_state='active'
               AND disabled_at IS NULL ORDER BY created_at DESC LIMIT 1),:room,'opening',:metadata::jsonb)""",
            {"sid": sid, "aid": agent_id, "space": space_id, "room": room,
             "metadata": json.dumps({"room_mode": room_mode, "actor_type": "user", "actor_id": user.user_id,
                                      "record_media": binding["record_media"]})}, transaction_id=tx)
        queued = enqueue_semantic_graph(db, transaction_id=tx, agent_id=agent_id, source_table="sessions",
                                        source_id=sid, objects=objects, links=links, primary_key="scene")
        db.commit(tx)
    except Exception:
        db.rollback(tx)
        raise
    response = boto3.client("lambda").invoke(
        FunctionName=dispatcher, InvocationType="RequestResponse",
        Payload=json.dumps({"action": "dispatch_one", "semantic_outbox_id": queued.semantic_outbox_id}).encode(),
    )
    response["Payload"].close()
    if response.get("FunctionError"):
        raise HTTPException(503, "Session memory dispatch failed; inspect the semantic dispatcher result")
    return {"session_id": sid, "status": "queued"}
