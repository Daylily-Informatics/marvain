"""Preserve unchanged grants and write person/consent lineage with each mutation."""
import json
from uuid import uuid4
from agent_hub.semantic_outbox import enqueue_semantic_graph, enqueue_semantic_record, GraphSourceRef
from agent_hub.semantic_tapdb import TEMPLATE_CODES, GraphObjectWrite, GraphObjectRef, GraphLinkWrite


def update_consents(db, *, agent_id, person_id, user_id, consents):
    desired = {kind: expiry for kind, expiry in consents}
    tx = db.begin()
    try:
        active = db.query("""SELECT consent_id::text AS id,consent_type,expires_at::text AS expires_at
            FROM consent_grants WHERE agent_id=:agent::uuid AND person_id=:person::uuid AND revoked_at IS NULL FOR UPDATE""",
            {"agent":agent_id,"person":person_id},transaction_id=tx)
        retained=set()
        for grant in active:
            kind=grant["consent_type"]
            # Earlier browser activation persisted its recording grant without a canonical source record.
            # Materialize that existing grant as part of its first consent edit; never invent a replacement grant.
            canonical = db.query("""SELECT status FROM semantic_sync_status WHERE agent_id=:agent::uuid
                AND source_table='consent_grants' AND source_id=:id::uuid AND target_template_code=:template""",
                {"agent":agent_id,"id":grant["id"],"template":TEMPLATE_CODES["consent_grant"]},transaction_id=tx)
            if not canonical:
                enqueue_semantic_graph(db,transaction_id=tx,agent_id=agent_id,source_table="consent_grants",source_id=grant["id"],primary_key="grant",
                    objects=(GraphObjectWrite("grant",TEMPLATE_CODES["consent_grant"],f"consent:{grant['id']}",
                        {"consent_type":kind,"expires_at":grant["expires_at"],"source":"existing_persisted_grant"},"active"),),
                    links=(GraphLinkWrite(GraphObjectRef(key="grant"),GraphSourceRef("people",person_id,TEMPLATE_CODES["person"]),"CONSENT_SUBJECT"),))
            # Existing UI expiry is day-granular; an unchanged grant keeps its original identity.
            same = kind in desired and ((grant["expires_at"] or "")[:10] == (desired[kind] or "")[:10])
            if same:
                retained.add(kind)
                continue
            db.execute("UPDATE consent_grants SET revoked_at=now() WHERE consent_id=:id::uuid",{"id":grant["id"]},transaction_id=tx)
            rid=str(uuid4())
            db.execute("INSERT INTO recognition_consent_changes(change_id,consent_id,user_id,operation) VALUES (:id::uuid,:consent::uuid,:user::uuid,'revoked')",
                {"id":rid,"consent":grant["id"],"user":user_id},transaction_id=tx)
            enqueue_semantic_graph(db,transaction_id=tx,agent_id=agent_id,source_table="recognition_consent_changes",source_id=rid,primary_key="change",
                objects=(GraphObjectWrite("change",TEMPLATE_CODES["event_sensor"],f"consent-revocation:{rid}",{"consent_type":kind,"user_id":user_id},"revoked"),),
                links=(GraphLinkWrite(GraphObjectRef(key="change"),GraphSourceRef("people",person_id,TEMPLATE_CODES["person"]),"ASSOCIATES_ACTOR"),
                       GraphLinkWrite(GraphObjectRef(key="change"),GraphSourceRef("consent_grants",grant["id"],TEMPLATE_CODES["consent_grant"]),"REVOKES")))
        for kind, expiry in desired.items():
            if kind in retained: continue
            cid=str(uuid4())
            db.execute("""INSERT INTO consent_grants(consent_id,agent_id,person_id,consent_type,expires_at)
                VALUES (:id::uuid,:agent::uuid,:person::uuid,:kind,:expiry::timestamptz)""",
                {"id":cid,"agent":agent_id,"person":person_id,"kind":kind,"expiry":expiry},transaction_id=tx)
            enqueue_semantic_graph(db,transaction_id=tx,agent_id=agent_id,source_table="consent_grants",source_id=cid,primary_key="grant",
                objects=(GraphObjectWrite("grant",TEMPLATE_CODES["consent_grant"],f"consent:{cid}",
                    {"consent_type":kind,"expires_at":expiry,"granted_by_user_id":user_id},"active"),),
                links=(GraphLinkWrite(GraphObjectRef(key="grant"),GraphSourceRef("people",person_id,TEMPLATE_CODES["person"]),"CONSENT_SUBJECT"),))
        db.commit(tx)
    except Exception:
        db.rollback(tx)
        raise
    return {"ok":True,"person_id":person_id}
