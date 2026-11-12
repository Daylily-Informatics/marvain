"""Owner-granted, space-scoped saved camera moments with canonical provenance."""
from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from urllib.parse import urlsplit
from uuid import uuid4

from fastapi import HTTPException

from agent_hub.memory_service import MemoryLayer, MemoryPurpose
from agent_hub.semantic_lifecycle import MarvainSemanticLifecycle
from agent_hub.semantic_tapdb import (
    DaylilyTapdbSemanticStore, EXTERNAL_REFERENCE_TEMPLATE, TEMPLATE_CODES,
    GraphLinkWrite, GraphObjectRef, GraphObjectWrite,
)
from agent_hub.v4_runtime import resolve_human, resolve_route
from browser_activation import browser_route
from recognition_browser import _uuid, require_admin


def ref(euid):
    return GraphObjectRef(semantic_id=euid)


def new(key):
    return GraphObjectRef(key=key)


@dataclass
class CaptureContext:
    store: object
    route: object
    human: str
    principal: str
    privacy_mode: bool

    def policy_links(self, key):
        return (GraphLinkWrite(new(key), ref(self.route.policy.owner_principal_id), "OWNER_PRINCIPAL"),) + tuple(
            GraphLinkWrite(new(key), ref(reader), "READER_PRINCIPAL")
            for reader in self.route.policy.reader_principal_ids
        )


def context(db, *, user, agent_id, space_id):
    agent_id, space_id = _uuid(agent_id), _uuid(space_id)
    require_admin(db, user, agent_id)
    route, _ = browser_route(user=user, agent_id=agent_id, space_id=space_id)
    store = DaylilyTapdbSemanticStore.from_environment()
    resolve_route(store, route)
    human, principal = resolve_human(store=store, user_id=user.user_id, subject=user.cognito_sub)
    if principal != route.policy.owner_principal_id:
        raise HTTPException(403, "Saved moments require the authenticated space owner")
    rows = db.query("SELECT privacy_mode FROM spaces WHERE space_id=:space::uuid AND agent_id=:agent::uuid",
                    {"space": space_id, "agent": agent_id})
    if len(rows) != 1:
        raise HTTPException(404, "Space not found")
    return CaptureContext(store, route, human, principal, bool(rows[0]["privacy_mode"]))


def linked(view, source, relationship, target):
    return any(obj.semantic_id == target for obj in view.linked_objects(source, relationship_type=relationship))


def current_grant(view, ctx):
    grants = [obj for obj in view.linked_objects(ctx.route.space_euid, relationship_type="HAS_CAPTURE_GRANT")
              if obj.template_code == TEMPLATE_CODES["consent_grant"]
              and obj.properties.get("consent_type") == "saved_moments"
              and linked(view, obj.semantic_id, "GRANTED_TO", ctx.route.actor_euid)
              and linked(view, obj.semantic_id, "GRANTED_BY", ctx.principal)]
    return max(grants, key=lambda obj: obj.properties["decided_at"]) if grants else None


def grant_details(grant):
    if grant is None:
        return {"grant_id": None, "mode": "off", "trigger": None, "max_clip_seconds": 0,
                "event_guidance": "", "decided_at": None}
    return {"grant_id": grant.semantic_id, **{key: grant.properties[key] for key in (
        "mode", "trigger", "max_clip_seconds", "event_guidance", "decided_at")}}


def state(ctx):
    with ctx.store.read_view() as view:
        return {**grant_details(current_grant(view, ctx)), "privacy_mode": ctx.privacy_mode,
                "retention": ctx.route.policy.as_properties()["retention"]["raw_artifact"]}


def update_grant(ctx, body):
    mode, trigger = body.get("mode"), body.get("trigger")
    if mode not in {"off", "snapshots", "snapshots_and_clips"}:
        raise HTTPException(400, "Choose Off, Snapshots, or Snapshots and clips")
    if trigger not in {"request_only", "request_or_event"}:
        raise HTTPException(400, "Choose requests only or requests and relevant events")
    duration = body.get("max_clip_seconds")
    if type(duration) is not int or not 1 <= duration <= 10:
        raise HTTPException(400, "Choose a clip duration from 1 to 10 seconds")
    guidance = str(body.get("event_guidance") or "").strip()
    if len(guidance) > 1000:
        raise HTTPException(400, "Event guidance must be at most 1000 characters")
    if mode != "off":
        if body.get("confirmed") is not True:
            raise HTTPException(400, "Confirm permission to save camera media in this space")
        require_raw_capture(ctx)
    with ctx.store.read_view() as view:
        previous = current_grant(view, ctx)
    details = {"consent_type": "saved_moments", "mode": mode, "trigger": trigger,
               "max_clip_seconds": duration, "event_guidance": guidance,
               "decided_at": datetime.now(timezone.utc).isoformat(),
               "access_policy": ctx.route.policy.as_properties()}
    links = (
        GraphLinkWrite(ref(ctx.route.space_euid), new("grant"), "HAS_CAPTURE_GRANT"),
        GraphLinkWrite(new("grant"), ref(ctx.route.actor_euid), "GRANTED_TO"),
        GraphLinkWrite(new("grant"), ref(ctx.principal), "GRANTED_BY"),
        GraphLinkWrite(new("grant"), ref(ctx.human), "CONSENT_SUBJECT"),
    ) + ctx.policy_links("grant")
    if previous:
        links += (GraphLinkWrite(new("grant"), ref(previous.semantic_id), "SUPERSEDES"),)
        if mode == "off":
            links += (GraphLinkWrite(new("grant"), ref(previous.semantic_id), "REVOKES"),)
    result = ctx.store.create_graph(objects=(GraphObjectWrite("grant", TEMPLATE_CODES["consent_grant"],
        f"saved-moments-grant:{uuid4()}", details, "revoked" if mode == "off" else "granted"),), links=links)
    return {"status": "saved", **grant_details(result["grant"])}


def require_raw_capture(ctx):
    if ctx.privacy_mode:
        raise HTTPException(403, "Space privacy mode blocks new saved moments")
    if not ctx.route.policy.raw_capture_allowed or not ctx.route.policy.permits(
        authenticated_principal_id=ctx.principal, purpose=MemoryPurpose.DETAIL,
        layer=MemoryLayer.RAW_ARTIFACT, at=datetime.now(timezone.utc),
    ):
        raise HTTPException(403, "The current space policy does not permit raw camera storage")


def authorize(db, *, ctx, user, body):
    require_raw_capture(ctx)
    sid = _uuid(body.get("session_id"))
    rows = db.query("""SELECT metadata,status FROM sessions WHERE session_id=:sid::uuid
        AND agent_id=:agent::uuid AND space_id=:space::uuid""",
        {"sid": sid, "agent": ctx.route.agent_id, "space": ctx.route.space_id})
    if len(rows) != 1:
        raise HTTPException(404, "Session does not belong to the selected space")
    metadata = rows[0]["metadata"]
    if isinstance(metadata, str):
        metadata = json.loads(metadata)
    if metadata.get("actor_type") != "user" or metadata.get("actor_id") != str(user.user_id):
        raise HTTPException(403, "Session belongs to another person")
    if rows[0]["status"] in {"closed", "ended", "failed"}:
        raise HTTPException(409, "The session has ended")
    kind, trigger = body.get("kind"), body.get("trigger")
    reason = str(body.get("reason") or "").strip()
    if kind not in {"snapshot", "clip"} or trigger not in {"request", "event"}:
        raise HTTPException(400, "A snapshot or clip and its request/event trigger are required")
    if not reason or len(reason) > 1000:
        raise HTTPException(400, "A capture reason of 1–1000 characters is required")
    with ctx.store.read_view() as view:
        grant = current_grant(view, ctx)
    if not grant or grant.properties["mode"] == "off":
        raise HTTPException(403, "Saved moments are off; the owner must grant capture in this space")
    if kind == "clip" and grant.properties["mode"] != "snapshots_and_clips":
        raise HTTPException(403, "This space grants snapshots only")
    if trigger == "event" and grant.properties["trigger"] != "request_or_event":
        raise HTTPException(403, "This space permits capture only on an explicit request")
    duration = body.get("duration_seconds")
    if type(duration) is not int or (kind == "snapshot" and duration != 0) or (
        kind == "clip" and not 1 <= duration <= grant.properties["max_clip_seconds"]
    ):
        raise HTTPException(400, "Clip duration exceeds the space grant, or snapshot duration is not zero")
    if body.get("grant_id") is not None and body["grant_id"] != grant.semantic_id:
        raise HTTPException(409, "Capture grant changed; request a new capture under the current grant")
    return {"session_id": sid, "kind": kind, "trigger": trigger, "reason": reason,
            "duration_seconds": duration, **grant_details(grant)}


async def save(db, *, request, user, cfg, s3):
    form = await request.form()
    ctx = context(db, user=user, agent_id=form.get("agent_id"), space_id=form.get("space_id"))
    try:
        duration = int(str(form.get("duration_seconds")))
        captured_at = datetime.fromisoformat(str(form.get("captured_at")).replace("Z", "+00:00"))
        if captured_at.tzinfo is None:
            raise ValueError("Timestamp requires timezone")
    except (ValueError, TypeError) as exc:
        raise HTTPException(400, "Capture duration and a timestamp with timezone are required") from exc
    if not form.get("grant_id"):
        raise HTTPException(400, "The authorizing grant is required")
    details = authorize(db, ctx=ctx, user=user, body={**dict(form), "duration_seconds": duration})
    file = form.get("file")
    media_type = str(getattr(file, "content_type", "")).split(";")[0]
    expected = "image/jpeg" if details["kind"] == "snapshot" else "video/webm"
    if media_type != expected:
        raise HTTPException(400, f"This capture requires {expected}")
    content = await file.read(4 * 1024 * 1024 + 1)
    if not content or len(content) > 4 * 1024 * 1024:
        raise HTTPException(400, "Capture must contain media and fit within the 4 MiB upload format")
    if not cfg.artifact_bucket:
        raise HTTPException(503, "Private artifact storage is not configured")
    from api_app import _scene_for_session
    scene, session = _scene_for_session(session_id=details["session_id"], agent_id=ctx.route.agent_id)
    key = f"private-saved-moments/user_id={user.user_id}/{uuid4()}"
    uploaded = s3.put_object(Bucket=cfg.artifact_bucket, Key=key, Body=content, ContentType=media_type)
    uri = f"s3://{cfg.artifact_bucket}/{key}"
    properties = {key: details[key] for key in ("kind", "trigger", "reason", "duration_seconds")}
    properties.update(media_type=media_type, byte_count=len(content), version_id=uploaded["VersionId"],
                      captured_at=captured_at.isoformat(), saved_at=datetime.now(timezone.utc).isoformat(),
                      has_audio=False, access_policy=ctx.route.policy.as_properties())
    artifact = GraphObjectWrite("moment", TEMPLATE_CODES["artifact_reference"], details["reason"], properties, "available")
    external = GraphObjectWrite("source", EXTERNAL_REFERENCE_TEMPLATE, uri, {"root_euid": uri,
        "external_identifier": {"system": "aws-s3", "target_euid": uri, "href": None, "base_url": None,
            "graph_data_path": None, "object_detail_path_template": None, "auth_mode": "none"}}, "active")
    links = (
        GraphLinkWrite(ref(ctx.route.space_euid), new("moment"), "HAS_SAVED_MOMENT"),
        GraphLinkWrite(new("moment"), ref(ctx.route.actor_euid), "CAPTURED_FOR"),
        GraphLinkWrite(new("moment"), ref(ctx.principal), "OWNED_BY"),
        GraphLinkWrite(new("moment"), ref(ctx.route.device_euid), "CAPTURED_BY_DEVICE"),
        GraphLinkWrite(new("moment"), ref(details["grant_id"]), "AUTHORIZED_BY"),
        GraphLinkWrite(new("moment"), ref(scene), "IN_SCENE"),
        GraphLinkWrite(new("moment"), ref(session), "IN_SESSION"),
        GraphLinkWrite(new("moment"), new("source"), "has_external_reference"),
    ) + ctx.policy_links("moment")
    result = ctx.store.create_graph(objects=(artifact, external), links=links)
    return {"status": "stored", "moment_id": result["moment"].semantic_id,
            "grant_id": details["grant_id"], **{key: properties[key] for key in (
                "kind", "trigger", "reason", "captured_at", "saved_at", "duration_seconds")}}


def list_moments(ctx, *, bucket, s3, include_media=True):
    moments = []
    with ctx.store.read_view() as view:
        objects = view.linked_objects(ctx.route.space_euid, relationship_type="HAS_SAVED_MOMENT")
        for obj in sorted(objects, key=lambda obj: obj.properties["saved_at"], reverse=True):
            if obj.template_code != TEMPLATE_CODES["artifact_reference"]:
                continue
            if not linked(view, obj.semantic_id, "CAPTURED_FOR", ctx.route.actor_euid):
                continue
            if not linked(view, obj.semantic_id, "OWNED_BY", ctx.principal):
                continue
            policy = MarvainSemanticLifecycle._read_policy(view, obj)
            if not all(policy_value.permits(authenticated_principal_id=ctx.principal, purpose=MemoryPurpose.DETAIL,
                layer=MemoryLayer.RAW_ARTIFACT, at=datetime.now(timezone.utc)) for policy_value in (policy, ctx.route.policy)):
                continue
            item = {"moment_id": obj.semantic_id, **{key: obj.properties[key] for key in (
                "kind", "trigger", "reason", "duration_seconds", "captured_at", "saved_at")}}
            if include_media:
                refs = view.linked_objects(obj.semantic_id, relationship_type="has_external_reference")
                if len(refs) != 1:
                    raise ValueError("Saved moment requires one typed S3 reference")
                parsed = urlsplit(refs[0].properties["external_identifier"]["target_euid"])
                if parsed.scheme != "s3" or parsed.netloc != bucket or not parsed.path.startswith("/private-saved-moments/"):
                    raise ValueError("Saved moment is outside the private artifact store")
                item["media_url"] = s3.generate_presigned_url("get_object", Params={"Bucket": bucket,
                    "Key": parsed.path[1:], "VersionId": obj.properties["version_id"]}, ExpiresIn=900)
            moments.append(item)
            if len(moments) == 50:
                break
    return {"moments": moments, "scope": "Latest 50 authorized saved moments in this space"}
