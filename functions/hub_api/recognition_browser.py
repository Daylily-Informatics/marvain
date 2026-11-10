"""Authenticated browser capture, reviewed enrollment and scoped identity corroboration."""
from __future__ import annotations

import hashlib
import json
import os
import secrets
from datetime import datetime, timezone
from uuid import UUID, uuid4

from fastapi import HTTPException
from agent_hub.memberships import check_agent_permission
from agent_hub.semantic_outbox import enqueue_semantic_graph, GraphSourceRef
from agent_hub.semantic_tapdb import TEMPLATE_CODES, EXTERNAL_REFERENCE_TEMPLATE, GraphObjectWrite, GraphObjectRef, GraphLinkWrite
from agent_hub.recognition_matching import identify_embedding
from browser_activation import browser_route


def _json(value):
    return json.loads(value) if isinstance(value, str) else value


def _uuid(value):
    try:
        return str(UUID(str(value)))
    except (ValueError, TypeError) as exc:
        raise HTTPException(400, "A valid UUID is required") from exc


def _browser_session(request):
    if "recognition_session" not in request.session:
        request.session["recognition_session"] = secrets.token_urlsafe(32)
    return hashlib.sha256(request.session["recognition_session"].encode()).hexdigest()


def require_admin(db, user, agent_id):
    if not check_agent_permission(db, user_id=user.user_id, agent_id=agent_id, required_role="admin"):
        raise HTTPException(403, "Requires admin permission on the agent")


def require_consent(db, *, agent_id, person_id, modality):
    rows = db.query("""SELECT consent_id::text AS consent_id FROM consent_grants
        WHERE agent_id=:agent::uuid AND person_id=:person::uuid AND consent_type IN (:modality,'global')
          AND revoked_at IS NULL AND (expires_at IS NULL OR expires_at>now())""",
        {"agent": agent_id, "person": person_id, "modality": modality})
    if not rows:
        raise HTTPException(403, f"Active {modality} consent is required")


def create_check(db, *, request, user, agent_id, space_id, purpose, target_id, modalities):
    agent_id, space_id, target_id = map(_uuid, (agent_id, space_id, target_id))
    require_admin(db, user, agent_id)
    browser_route(user=user, agent_id=agent_id, space_id=space_id)
    if purpose not in {"private_memory_export", "sensitive_action_approval"}:
        raise HTTPException(400, "Unsupported identity-check purpose")
    if not modalities or set(modalities)-{"voice","face"} or len(modalities)!=len(set(modalities)):
        raise HTTPException(400, "Select voice, face, or both")
    table, key = ("actions","action_id") if purpose=="sensitive_action_approval" else ("sessions","session_id")
    if not db.query(f"SELECT 1 FROM {table} WHERE {key}=:target::uuid AND agent_id=:agent::uuid",
                    {"target": target_id, "agent": agent_id}):
        raise HTTPException(404, "Target does not belong to this agent")
    people = db.query("""SELECT person_id::text AS person_id FROM person_accounts
        WHERE agent_id=:agent::uuid AND user_id=:user::uuid""", {"agent": agent_id, "user": user.user_id})
    if len(people)!=1:
        raise HTTPException(409, "Link this sign-in to one person before requesting an identity check")
    from agent_hub.v4_runtime import resolve_human
    from agent_hub.semantic_tapdb import DaylilyTapdbSemanticStore
    actor, _ = resolve_human(store=DaylilyTapdbSemanticStore.from_environment(),user_id=user.user_id,subject=user.cognito_sub)
    linked = db.query("""SELECT tapdb_euid FROM semantic_sync_status WHERE agent_id=:agent::uuid
        AND source_table='people' AND source_id=:person::uuid AND status='written' AND target_template_code=:template""",
        {"agent":agent_id,"person":people[0]["person_id"],"template":TEMPLATE_CODES["person"]})
    if len(linked)!=1 or linked[0]["tapdb_euid"]!=actor:
        raise HTTPException(409,"This account needs its canonical person binding reconciled before an identity check")
    for modality in modalities:
        require_consent(db, agent_id=agent_id, person_id=people[0]["person_id"], modality=modality)
    check = str(uuid4())
    db.execute("""INSERT INTO identity_checks(check_id,agent_id,space_id,user_id,auth_subject,browser_session,
        person_id,purpose,target_id,modalities,expires_at)
        VALUES (:id::uuid,:agent::uuid,:space::uuid,:user::uuid,:subject,:browser,:person::uuid,:purpose,
                :target::uuid,:modalities::jsonb,now()+interval '5 minutes')""",
        {"id": check,"agent": agent_id,"space": space_id,"user": user.user_id,"subject": user.cognito_sub,
         "browser": _browser_session(request),"person": people[0]["person_id"],"purpose": purpose,
         "target": target_id,"modalities": json.dumps(modalities)})
    return {"check_id": check, "status": "capture_required", "modalities": modalities, "expires_in_seconds": 300}


def _load_check(db, *, request, user, check_id, transaction_id=None):
    rows = db.query("""SELECT *, check_id::text AS id,person_id::text AS expected_person,
        agent_id::text AS agent,space_id::text AS space,target_id::text AS target
        FROM identity_checks WHERE check_id=:id::uuid AND user_id=:user::uuid
          AND auth_subject=:subject AND browser_session=:browser AND expires_at>now()
          AND consumed_at IS NULL FOR UPDATE""",
        {"id": _uuid(check_id),"user": user.user_id,"subject": user.cognito_sub,"browser": _browser_session(request)},
        transaction_id=transaction_id)
    if len(rows)!=1:
        raise HTTPException(409, "Identity check is absent, expired, consumed, or belongs to another sign-in")
    return rows[0]


async def capture(db, *, request, user, cfg, s3, sqs):
    form = await request.form()
    agent, space = _uuid(form.get("agent_id")), _uuid(form.get("space_id"))
    require_admin(db, user, agent)
    route, binding = browser_route(user=user, agent_id=agent, space_id=space)
    modality = str(form.get("modality") or "")
    if modality not in {"voice","face"}:
        raise HTTPException(400, "modality must be voice or face")
    person = str(form.get("person_id") or "")
    check_id = str(form.get("check_id") or "")
    if bool(person)==bool(check_id):
        raise HTTPException(400, "Select an enrollment person or an identity check")
    if person:
        person = _uuid(person)
        require_consent(db, agent_id=agent, person_id=person, modality=modality)
    file = form.get("file")
    content_type = str(getattr(file, "content_type", ""))
    if file is None or (modality=="face" and content_type not in {"image/jpeg","image/png"}) or (
        modality=="voice" and not content_type.startswith("audio/")):
        raise HTTPException(400, "A voice recording or JPEG/PNG face capture is required")
    content = await file.read()
    if not content:
        raise HTTPException(400, "Capture is empty")
    if not cfg.artifact_bucket or (modality=="voice" and not os.environ.get("RECOGNITION_QUEUE_URL")):
        raise HTTPException(503, "Recognition storage/queue is not configured")
    event_id, artifact_id = str(uuid4()), str(uuid4())
    filename = f"{modality}.jpg" if modality=="face" else "voice.webm"
    key = f"private-recognition/user_id={user.user_id}/{artifact_id}/{filename}"
    sha = hashlib.sha256(content).hexdigest()  # Existing artifact provenance, computed from upload bytes only.
    tx = db.begin()
    try:
        check = None
        if check_id:
            check = _load_check(db, request=request, user=user, check_id=check_id, transaction_id=tx)
            if check["agent"]!=agent or check["space"]!=space or modality not in _json(check["modalities"]):
                raise HTTPException(409, "Capture does not match the scoped identity check")
            captures = _json(check["captures"])
            if modality in captures:
                raise HTTPException(409, "This modality is already submitted; start a new check to retry")
            require_consent(db, agent_id=agent, person_id=check["expected_person"], modality=modality)
        result = s3.put_object(Bucket=cfg.artifact_bucket, Key=key, Body=content, ContentType=content_type)
        uri = f"s3://{cfg.artifact_bucket}/{key}"
        params = {"id": artifact_id,"agent": agent,"space": space,"device": binding["device_id"],
                  "filename": filename,"bucket": cfg.artifact_bucket,"key": key,"uri": uri,
                  "media": content_type,"sha": sha,"size": len(content),"version": result["VersionId"],"etag": result["ETag"]}
        db.execute("""INSERT INTO artifact_references(artifact_id,agent_id,space_id,device_id,purpose,filename,bucket,
            object_key,uri,media_type,expected_sha256,actual_sha256,expected_byte_count,actual_byte_count,
            lifecycle_state,upload_expires_at,verification_observed_at,completed_at,s3_version_id,s3_etag)
            VALUES (:id::uuid,:agent::uuid,:space::uuid,:device::uuid,'recognition',:filename,:bucket,:key,:uri,
                    :media,:sha,:sha,:size,:size,'available',now()+interval '1 hour',now(),now(),:version,:etag)""",
            params, transaction_id=tx)
        payload = {"artifact_bucket": cfg.artifact_bucket,"artifact_key": key,"artifact_sha256": sha,
                   "content_type": content_type,"captured_at": datetime.now(timezone.utc).isoformat(),
                   "source": "browser_enrollment" if person else "identity_check"}
        if person: payload["enroll_person_id"] = person
        if check_id: payload["check_id"] = check_id
        event = {"event_id": event_id,"agent_id": agent,"space_id": space,"device_id": binding["device_id"],
                 "type": "voice.sample" if modality=="voice" else "face.snapshot","payload": payload}
        db.execute("""INSERT INTO events(event_id,agent_id,space_id,device_id,artifact_id,type,payload)
            VALUES (:id::uuid,:agent::uuid,:space::uuid,:device::uuid,:artifact::uuid,:type,:payload::jsonb)""",
            {"id": event_id,"agent": agent,"space": space,"device": binding["device_id"],"artifact": artifact_id,
             "type": event["type"],"payload": json.dumps(payload)}, transaction_id=tx)
        db.execute("UPDATE artifact_references SET source_event_id=:event::uuid WHERE artifact_id=:artifact::uuid",
                   {"event": event_id,"artifact": artifact_id}, transaction_id=tx)
        ref = GraphObjectRef(key="event")
        enqueue_semantic_graph(db, transaction_id=tx, agent_id=agent, source_table="events",source_id=event_id,primary_key="event",
            objects=(GraphObjectWrite("event",TEMPLATE_CODES["event_sensor"],f"capture:{event_id}",
                      {"event_type":event["type"],"source":payload["source"],"access_policy":route.policy.as_properties()},"recorded"),
                     GraphObjectWrite("artifact",TEMPLATE_CODES["artifact_reference"],f"capture-artifact:{artifact_id}",
                      {"media_type":content_type,"sha256":sha,"byte_count":len(content)},"available"),
                     GraphObjectWrite("external",EXTERNAL_REFERENCE_TEMPLATE,uri,{"root_euid":uri,"external_identifier":{
                      "system":"aws-s3","target_euid":uri,"href":None,"base_url":None,"graph_data_path":None,
                      "object_detail_path_template":None,"auth_mode":"none"}},"active")),
            links=(GraphLinkWrite(ref,GraphObjectRef(key="artifact"),"HAS_ARTIFACT"),
                   GraphLinkWrite(GraphObjectRef(key="artifact"),GraphObjectRef(key="external"),"has_external_reference"),
                   GraphLinkWrite(ref,GraphObjectRef(semantic_id=route.device_euid),"FROM_DEVICE"),
                   GraphLinkWrite(ref,GraphObjectRef(semantic_id=route.policy.owner_principal_id),"OWNER_PRINCIPAL")))
        if check:
            captures[modality] = event_id
            db.execute("UPDATE identity_checks SET captures=:captures::jsonb WHERE check_id=:id::uuid",
                       {"captures":json.dumps(captures),"id":check_id}, transaction_id=tx)
        db.commit(tx)
    except Exception:
        db.rollback(tx)
        raise
    if modality=="face":
        from recognition_face import record_face
        receipt = record_face(db,event=event,artifact={"bucket":cfg.artifact_bucket,"object_key":key,"uri":uri,
            "media_type":content_type,"sha256":sha,"version_id":result["VersionId"]},enrollment_person_id=person or None)
    else:
        sqs.send_message(QueueUrl=os.environ.get("RECOGNITION_QUEUE_URL"),MessageBody=json.dumps(event))
        receipt = {"status":"queued"}
    return {**receipt,"event_id":event_id,"person_id":person or None,"modality":modality}


def consume_check(db, *, request, user, check_id, purpose, target_id):
    tx = db.begin()
    try:
        check = _load_check(db,request=request,user=user,check_id=check_id,transaction_id=tx)
        if check["purpose"]!=purpose or check["target"]!=target_id:
            raise HTTPException(403,"Identity check is scoped to another operation")
        require_admin(db,user,check["agent"])
        captures, modalities = _json(check["captures"]), _json(check["modalities"])
        observations = []
        for modality in modalities:
            if modality not in captures:
                raise HTTPException(409,"Complete every selected capture before continuing")
            rows = db.query("""SELECT ro.recognition_observation_id::text AS id,ro.embedding::text AS embedding,
                    ro.model_id,ro.model_version,ar.bucket,ar.object_key,ar.s3_version_id
                FROM recognition_observations ro JOIN artifact_references ar ON ar.artifact_id=ro.artifact_id
                JOIN events e ON e.event_id=ro.source_event_id
                WHERE ro.source_event_id=:event::uuid AND ro.agent_id=:agent::uuid
                  AND e.payload->>'source'='identity_check' AND e.payload->>'check_id'=:check
                  AND ro.created_at>=:created::timestamptz AND ar.lifecycle_state='available'""",
                {"event":captures[modality],"agent":check["agent"],"check":check["id"],"created":check["created_at"]},transaction_id=tx)
            if len(rows)!=1:
                raise HTTPException(409,"Recognition is still processing this capture")
            row=rows[0]
            if modality=="voice":
                match=identify_embedding(db,agent_id=check["agent"],modality=modality,model_id=row["model_id"],
                    model_version=row["model_version"],embedding=json.loads(row["embedding"]),transaction_id=tx)
            else:
                from recognition_face import identify_face
                match=identify_face(db,agent_id=check["agent"],image={"S3Object":{"Bucket":row["bucket"],
                    "Name":row["object_key"],"Version":row["s3_version_id"]}},transaction_id=tx)
            if not match["matched"] or match["best"]["person_id"]!=check["expected_person"]:
                raise HTTPException(403,"Identity is unknown, ambiguous, or differs from this signed-in person; operation not authorized")
            observations.append(row["id"])
        # Bind to the account again at use time; a changed account link invalidates the check.
        if not db.query("""SELECT 1 FROM person_accounts WHERE agent_id=:agent::uuid AND user_id=:user::uuid
            AND person_id=:person::uuid""",{"agent":check["agent"],"user":user.user_id,"person":check["expected_person"]},transaction_id=tx):
            raise HTTPException(403,"The account-to-person link changed")
        db.execute("UPDATE identity_checks SET consumed_at=now(),result='matched' WHERE check_id=:id::uuid",
                   {"id":check["id"]},transaction_id=tx)
        from agent_hub.v4_runtime import resolve_human
        from agent_hub.semantic_tapdb import DaylilyTapdbSemanticStore
        _, principal = resolve_human(store=DaylilyTapdbSemanticStore.from_environment(),user_id=user.user_id,subject=user.cognito_sub)
        ref=GraphObjectRef(key="check")
        links=[GraphLinkWrite(ref,GraphObjectRef(semantic_id=principal),"AUTHENTICATED_BY"),
               GraphLinkWrite(ref,GraphSourceRef("people",check["expected_person"],TEMPLATE_CODES["person"]),"ASSOCIATES_ACTOR")]
        links.extend(GraphLinkWrite(ref,GraphSourceRef("recognition_observations",oid,TEMPLATE_CODES["recognition_observation"]),"BASED_ON") for oid in observations)
        enqueue_semantic_graph(db,transaction_id=tx,agent_id=check["agent"],source_table="identity_checks",source_id=check["id"],primary_key="check",
            objects=(GraphObjectWrite("check",TEMPLATE_CODES["event_sensor"],f"identity-check:{check['id']}",
                {"purpose":purpose,"target_id":target_id,"modalities":modalities,"result":"matched","not_liveness_proof":True},"consumed"),),links=tuple(links))
        db.commit(tx)
    except Exception:
        db.rollback(tx)
        raise
    return check["id"]


def revoke_projection(*, db, user, projection_id, reason):
    rows=db.query("SELECT agent_id::text AS agent_id,modality FROM biometric_projections WHERE biometric_projection_id=:id::uuid",
                  {"id":_uuid(projection_id)})
    if not rows: raise HTTPException(404,"Enrollment not found")
    agent=rows[0]["agent_id"]
    require_admin(db,user,agent)
    existing=db.query("SELECT reason FROM biometric_projection_revocations WHERE revocation_id=:id::uuid",{"id":projection_id})
    if existing:
        return {"status":"revoked","projection_id":projection_id}
    tx=db.begin()
    try:
        db.execute("""UPDATE biometric_projections SET lifecycle_state='revoked',revoked_at=now(),revoked_by_actor_type='user',
            revoked_by_actor_id=:user,revocation_reason=:reason WHERE biometric_projection_id=:id::uuid""",
            {"id":projection_id,"user":user.user_id,"reason":reason},transaction_id=tx)
        for table in ("voiceprints","faceprints"):
            db.execute(f"UPDATE {table} SET revoked_at=now() WHERE biometric_projection_id=:id::uuid",{"id":projection_id},transaction_id=tx)
        db.execute("""INSERT INTO biometric_projection_revocations(revocation_id,user_id,reason)
            VALUES (:id::uuid,:user::uuid,:reason) ON CONFLICT (revocation_id) DO NOTHING""",
            {"id":projection_id,"user":user.user_id,"reason":reason},transaction_id=tx)
        ref=GraphObjectRef(key="revocation")
        enqueue_semantic_graph(db,transaction_id=tx,agent_id=agent,source_table="biometric_projection_revocations",source_id=projection_id,
            primary_key="revocation",objects=(GraphObjectWrite("revocation",TEMPLATE_CODES["event_sensor"],f"enrollment-revocation:{projection_id}",
                {"reason":reason,"user_id":user.user_id},"revoked"),),links=(GraphLinkWrite(ref,
                GraphSourceRef("biometric_projections",projection_id,TEMPLATE_CODES["actor_association"]),"REVOKES"),))
        db.commit(tx)
    except Exception:
        db.rollback(tx)
        raise
    return {"status":"revoked","projection_id":projection_id}
