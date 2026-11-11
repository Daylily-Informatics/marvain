"""Dog reference enrollment and recognition with canonical TapDB relationships."""
from __future__ import annotations

import json
import logging
import os
from dataclasses import dataclass
from datetime import datetime, timezone
from urllib.parse import urlsplit
from uuid import uuid4

import boto3
from fastapi import HTTPException

from agent_hub.dog_identity import MODEL_ID, MODEL_VERSION, match_dog
from agent_hub.memory_service import MemoryLayer, MemoryPurpose
from agent_hub.semantic_lifecycle import MarvainSemanticLifecycle
from agent_hub.semantic_tapdb import (
    DaylilyTapdbSemanticStore, EXTERNAL_REFERENCE_TEMPLATE, TEMPLATE_CODES,
    GraphLinkWrite, GraphObjectRef, GraphObjectWrite,
)
from agent_hub.v4_runtime import resolve_human, resolve_route
from browser_activation import browser_route, prepare_browser_scene
from recognition_browser import require_admin, _uuid


def _ref(euid):
    return GraphObjectRef(semantic_id=euid)


def _new(key):
    return GraphObjectRef(key=key)


@dataclass
class DogContext:
    store: object
    route: object
    human_id: str
    principal_id: str
    owner: object
    readers: tuple

    def policy_links(self, key):
        return (GraphLinkWrite(_new(key), _ref(self.owner.semantic_id), "OWNER_PRINCIPAL"),) + tuple(
            GraphLinkWrite(_new(key), _ref(reader.semantic_id), "READER_PRINCIPAL") for reader in self.readers
        )


def context(db, *, user, agent_id, space_id):
    agent_id, space_id = _uuid(agent_id), _uuid(space_id)
    require_admin(db, user, agent_id)
    route, _ = browser_route(user=user, agent_id=agent_id, space_id=space_id)
    store = DaylilyTapdbSemanticStore.from_environment()
    _, _, owner, readers = resolve_route(store, route)
    human, principal = resolve_human(store=store, user_id=user.user_id, subject=user.cognito_sub)
    if principal != owner.semantic_id or not route.policy.permits(
        authenticated_principal_id=principal, purpose=MemoryPurpose.DETAIL,
        layer=MemoryLayer.RAW_ARTIFACT, at=datetime.now(timezone.utc),
    ):
        raise HTTPException(403, "Dog references require the current private-space owner and media policy")
    return DogContext(store, route, human, principal, owner, readers)


def _dogs(view, ctx):
    cared_for = {obj.semantic_id for obj in view.linked_objects(ctx.human_id, relationship_type="CARETAKER_OF")}
    return [obj for obj in view.linked_objects(ctx.route.actor_euid, relationship_type="HAS_ANIMAL")
            if obj.semantic_id in cared_for and obj.template_code == TEMPLATE_CODES["animal"]
            and obj.lifecycle_state == "active" and obj.properties.get("species") == "dog"]


def _dog(view, ctx, dog_id):
    found = [obj for obj in _dogs(view, ctx) if obj.semantic_id == dog_id]
    if len(found) != 1:
        raise HTTPException(404, "Dog not found for this agent and caretaker")
    return found[0]


def _state(view, reference):
    if view.linked_objects(reference.semantic_id, relationship_type="REVOKES", incoming=True):
        return "revoked"
    return "active" if view.linked_objects(reference.semantic_id, relationship_type="APPROVES_REFERENCE", incoming=True) else "review_required"


def _reference(view, ctx, reference_id):
    for dog in _dogs(view, ctx):
        for reference in view.linked_objects(dog.semantic_id, relationship_type="HAS_DOG_REFERENCE"):
            if reference.semantic_id == reference_id:
                return dog, reference
    raise HTTPException(404, "Dog reference not found for this caretaker")


def _s3_args(view, artifact, bucket):
    refs = view.linked_objects(artifact.semantic_id, relationship_type="has_external_reference")
    if len(refs) != 1:
        raise ValueError("Dog artifact requires one typed S3 external reference")
    uri = refs[0].properties["external_identifier"]["target_euid"]
    parsed = urlsplit(uri)
    if parsed.scheme != "s3" or parsed.netloc != bucket or not parsed.path.startswith("/private-dogs/"):
        raise ValueError("Dog artifact does not belong to the selected private store")
    return {"Bucket": bucket, "Key": parsed.path[1:], "VersionId": artifact.properties["version_id"]}


def _one(view, euid, relationship):
    objects = view.linked_objects(euid, relationship_type=relationship)
    if len(objects) != 1:
        raise ValueError(f"Dog reference requires one {relationship} artifact")
    return objects[0]


def _readable(view, ctx, obj):
    policy = MarvainSemanticLifecycle._read_policy(view, obj)
    return all(policy.permits(authenticated_principal_id=principal, purpose=MemoryPurpose.DETAIL,
                              layer=MemoryLayer.RAW_ARTIFACT, at=datetime.now(timezone.utc))
               for principal in {ctx.principal_id, *ctx.route.policy.reader_principal_ids})


def _photo(view, ctx, photo_id):
    photo = view.get_object(photo_id)
    if photo.template_code != TEMPLATE_CODES["artifact_reference"] or not _readable(view, ctx, photo):
        raise HTTPException(404, "Photo not available in this private space")
    dog_ids = {obj.semantic_id for obj in _dogs(view, ctx)}
    enrollment = any(obj.semantic_id in dog_ids for obj in view.linked_objects(photo_id, relationship_type="HAS_DOG_PHOTO", incoming=True))
    live = any(obj.semantic_id == ctx.route.actor_euid for obj in view.linked_objects(photo_id, relationship_type="HAS_DOG_CAPTURE", incoming=True))
    if not enrollment and not live:
        raise HTTPException(404, "Photo does not belong to this agent and caretaker")
    return photo


def _processing(view, photo):
    executions = view.linked_objects(photo.semantic_id, relationship_type="HAS_PROCESSING_EXECUTION")
    if not executions:
        return {"status": "not_started", "message": "Photo stored. Detection has not started."}, None
    execution = max(executions, key=lambda obj: obj.properties["started_at"])
    arn = execution.properties["external_identifier"]["target_euid"]
    client = boto3.client("stepfunctions")
    try:
        result = client.describe_execution(executionArn=arn)
    except client.exceptions.ExecutionDoesNotExist:
        return {"status": "result_expired", "message": "Photo stored. Detection result is no longer available; run detection again."}, None
    if result["status"] == "RUNNING":
        return {"status": "processing", "message": "Photo stored. Detecting the dog; initial model loading can take over a minute."}, None
    if result["status"] != "SUCCEEDED":
        return {"status": "failed", "message": "Photo stored. Detection failed: " + result.get("error", result["status"])}, None
    inference = json.loads(result["output"])
    if (inference["model_id"], inference["model_version"]) != (MODEL_ID, MODEL_VERSION):
        raise HTTPException(409, "Dog inference and reference model versions differ")
    count = len(inference["detections"])
    return {"status": "complete", "dogs_detected": count,
            "message": "Detection complete." if count == 1 else f"Photo stored. Detection found {count} dogs; a recognition reference needs exactly one."}, inference


def start_processing(ctx, *, photo_id, bucket):
    with ctx.store.read_view() as view:
        photo = _photo(view, ctx, photo_id)
        args = _s3_args(view, photo, bucket)
    result = boto3.client("stepfunctions").start_execution(
        stateMachineArn=os.environ["DOG_RECOGNITION_STATE_MACHINE_ARN"], name=str(uuid4()),
        input=json.dumps({"bucket": bucket, "key": args["Key"], "version_id": args["VersionId"]}))
    arn = result["executionArn"]
    ctx.store.create_graph(objects=(GraphObjectWrite("execution", EXTERNAL_REFERENCE_TEMPLATE, arn,
        {"started_at": result["startDate"].isoformat(), "root_euid": arn, "external_identifier": {
            "system": "aws-stepfunctions", "target_euid": arn, "href": None, "base_url": None,
            "graph_data_path": None, "object_detail_path_template": None, "auth_mode": "none"}}, "active"),),
        links=(GraphLinkWrite(_ref(photo_id), _new("execution"), "HAS_PROCESSING_EXECUTION"),))
    return {"photo_id": photo_id, "status": "processing", "upload_status": "stored"}


def photo_status(ctx, *, photo_id):
    with ctx.store.read_view() as view:
        photo = _photo(view, ctx, photo_id)
        processing, _ = _processing(view, photo)
        return {"photo_id": photo_id, "upload_status": "stored", **processing}


def list_dogs(ctx, *, bucket, s3):
    result = []
    with ctx.store.read_view() as view:
        for dog in _dogs(view, ctx):
            photos = []
            references = view.linked_objects(dog.semantic_id, relationship_type="HAS_DOG_REFERENCE")
            for photo in view.linked_objects(dog.semantic_id, relationship_type="HAS_DOG_PHOTO"):
                if not _readable(view, ctx, photo):
                    continue
                matched = [reference for reference in references if any(
                    source.semantic_id == photo.semantic_id for source in view.linked_objects(reference.semantic_id, relationship_type="HAS_ARTIFACT"))]
                reference = matched[0] if matched else None
                if reference:
                    processing, box = {"status": "complete", "dogs_detected": 1, "message": "Detection complete."}, reference.properties["box"]
                else:
                    processing, inference = _processing(view, photo)
                    box = inference["detections"][0]["box"] if inference and len(inference["detections"]) == 1 else None
                photos.append({"photo_id": photo.semantic_id, "upload_status": "stored", "processing": processing,
                    "photo_url": s3.generate_presigned_url("get_object", Params=_s3_args(view, photo, bucket), ExpiresIn=900),
                    "box": box, "reference_id": reference.semantic_id if reference else None,
                    "reference_state": _state(view, reference) if reference else None})
            result.append({"dog_id": dog.semantic_id, "display_name": dog.name, "photos": photos})
    return {"dogs": result}


def create_dog(ctx, *, name, caretaker_confirmed):
    if caretaker_confirmed is not True:
        raise HTTPException(400, "Confirm that you are authorized to register this dog")
    if not isinstance(name, str) or not name.strip() or len(name.strip()) > 200:
        raise HTTPException(400, "A dog name of 1–200 characters is required")
    result = ctx.store.create_graph(objects=(GraphObjectWrite("dog", TEMPLATE_CODES["animal"], name.strip(),
        {"species": "dog", "access_policy": ctx.route.policy.as_properties()}, "active"),), links=(
        GraphLinkWrite(_ref(ctx.route.actor_euid), _new("dog"), "HAS_ANIMAL"),
        GraphLinkWrite(_ref(ctx.human_id), _new("dog"), "CARETAKER_OF"),
        GraphLinkWrite(_new("dog"), _ref(ctx.principal_id), "REGISTERED_BY"),
    ) + ctx.policy_links("dog"))
    dog = result["dog"]
    return {"dog_id": dog.semantic_id, "display_name": dog.name, "status": "registered"}


def review_reference(ctx, *, reference_id, decision):
    if decision not in {"approve", "revoke"}:
        raise HTTPException(400, "Choose approve or revoke")
    with ctx.store.read_view() as view:
        dog, reference = _reference(view, ctx, reference_id)
        state = _state(view, reference)
        if state == "revoked" or (decision == "approve" and state == "active"):
            return {"reference_id": reference_id, "status": state}
    relationship = "APPROVES_REFERENCE" if decision == "approve" else "REVOKES"
    receipt = ctx.store.create_graph(objects=(GraphObjectWrite("review", TEMPLATE_CODES["actor_association"],
        f"dog-reference-review:{uuid4()}", {"basis": f"Caretaker {decision} of dog reference",
            "decided_at": datetime.now(timezone.utc).isoformat(), "access_policy": ctx.route.policy.as_properties()}, "asserted"),),
        links=(GraphLinkWrite(_new("review"), _ref(reference_id), relationship),
               GraphLinkWrite(_new("review"), _ref(reference_id), "BASED_ON"),
               GraphLinkWrite(_new("review"), _ref(dog.semantic_id), "ASSOCIATES_ACTOR"),
               GraphLinkWrite(_new("review"), _ref(ctx.human_id), "AUTHORED_BY"),
               GraphLinkWrite(_new("review"), _ref(ctx.principal_id), "AUTHENTICATED_BY")) + ctx.policy_links("review"))
    return {"reference_id": reference_id, "status": "active" if decision == "approve" else "revoked",
            "review_id": receipt["review"].semantic_id}


def _artifact(ctx, *, key, bucket, version, media_type, name):
    uri = f"s3://{bucket}/{key}"
    return (
        GraphObjectWrite(name, TEMPLATE_CODES["artifact_reference"], uri,
            {"media_type": media_type, "version_id": version, "access_policy": ctx.route.policy.as_properties()}, "available"),
        GraphObjectWrite(name+"_external", EXTERNAL_REFERENCE_TEMPLATE, uri,
            {"root_euid": uri, "external_identifier": {"system": "aws-s3", "target_euid": uri, "href": None,
             "base_url": None, "graph_data_path": None, "object_detail_path_template": None, "auth_mode": "none"}}, "active"),
    ), (GraphLinkWrite(_new(name), _new(name+"_external"), "has_external_reference"),) + ctx.policy_links(name)


def _gallery(ctx, *, bucket, s3):
    references = []
    with ctx.store.read_view() as view:
        for dog in _dogs(view, ctx):
            for reference in view.linked_objects(dog.semantic_id, relationship_type="HAS_DOG_REFERENCE"):
                if (_state(view, reference) != "active" or not _readable(view, ctx, reference)
                    or reference.properties["model_id"] != MODEL_ID or reference.properties["model_version"] != MODEL_VERSION):
                    continue
                vector = _one(view, reference.semantic_id, "HAS_EMBEDDING")
                embedding = json.loads(s3.get_object(**_s3_args(view, vector, bucket))["Body"].read())["embedding"]
                references.append({"dog_id": dog.semantic_id, "display_name": dog.name,
                                   "reference_id": reference.semantic_id, "embedding": embedding})
    return references


def approve_photo(ctx, *, photo_id, bucket, s3):
    with ctx.store.read_view() as view:
        photo = _photo(view, ctx, photo_id)
        dogs = view.linked_objects(photo_id, relationship_type="HAS_DOG_PHOTO", incoming=True)
        if len(dogs) != 1:
            raise HTTPException(409, "Choose a photo uploaded for dog enrollment")
        dog = _dog(view, ctx, dogs[0].semantic_id)
        existing = view.linked_objects(photo_id, relationship_type="HAS_ARTIFACT", incoming=True)
        references = {item.semantic_id for item in view.linked_objects(dog.semantic_id, relationship_type="HAS_DOG_REFERENCE")}
        for reference in existing:
            if reference.semantic_id in references:
                return {"reference_id": reference.semantic_id, "status": _state(view, reference)}
        processing, inference = _processing(view, photo)
        if processing["status"] != "complete" or len(inference["detections"]) != 1:
            raise HTTPException(409, "Photo is stored; approval requires detection of exactly one dog")
        args = _s3_args(view, photo, bucket)
    vector_key = args["Key"].rsplit("/", 1)[0] + "/embedding.json"
    vector = s3.put_object(Bucket=bucket, Key=vector_key,
        Body=json.dumps({"embedding": inference["detections"][0]["embedding"]}).encode(), ContentType="application/json")
    objects, links = _artifact(ctx, key=vector_key, bucket=bucket, version=vector["VersionId"],
                               media_type="application/json", name="vector")
    now = datetime.now(timezone.utc).isoformat()
    objects += (
        GraphObjectWrite("reference", TEMPLATE_CODES["recognition_observation"], f"dog-reference:{uuid4()}",
            {"modality": "dog_visual", "model_id": MODEL_ID, "model_version": MODEL_VERSION,
             "box": inference["detections"][0]["box"], "reference_kind": "dog_visual",
             "access_policy": ctx.route.policy.as_properties()}, "recorded"),
        GraphObjectWrite("review", TEMPLATE_CODES["actor_association"], f"dog-reference-review:{uuid4()}",
            {"basis": "Caretaker approval of detected dog in uploaded photo", "decided_at": now,
             "access_policy": ctx.route.policy.as_properties()}, "asserted"),
    )
    links += (GraphLinkWrite(_ref(dog.semantic_id), _new("reference"), "HAS_DOG_REFERENCE"),
              GraphLinkWrite(_new("reference"), _ref(photo_id), "HAS_ARTIFACT"),
              GraphLinkWrite(_new("reference"), _new("vector"), "HAS_EMBEDDING"),
              GraphLinkWrite(_new("review"), _new("reference"), "APPROVES_REFERENCE"),
              GraphLinkWrite(_new("review"), _new("reference"), "BASED_ON"),
              GraphLinkWrite(_new("review"), _ref(dog.semantic_id), "ASSOCIATES_ACTOR"),
              GraphLinkWrite(_new("review"), _ref(ctx.human_id), "AUTHORED_BY"),
              GraphLinkWrite(_new("review"), _ref(ctx.principal_id), "AUTHENTICATED_BY"))
    links += ctx.policy_links("reference") + ctx.policy_links("review")
    result = ctx.store.create_graph(objects=objects, links=links)
    return {"reference_id": result["reference"].semantic_id, "status": "active"}


async def capture(db, *, request, user, cfg, s3, dog_id=None):
    form = await request.form()
    ctx = context(db, user=user, agent_id=form.get("agent_id"), space_id=form.get("space_id"))
    if not ctx.route.policy.raw_capture_allowed:
        raise HTTPException(403, "The selected space does not allow raw media capture")
    session_id = str(form.get("session_id") or "")
    if dog_id:
        with ctx.store.read_view() as view:
            _dog(view, ctx, dog_id)
        capture_links = (GraphLinkWrite(_ref(dog_id), _new("photo"), "HAS_DOG_PHOTO"),)
    else:
        session_id = _uuid(session_id)
        prepare_browser_scene(db=db, user=user, agent_id=ctx.route.agent_id, space_id=ctx.route.space_id,
                              room_mode="stable", session_id=session_id)
        from api_app import _scene_for_session
        scene_id, session_euid = _scene_for_session(session_id=session_id, agent_id=ctx.route.agent_id)
        capture_links = (GraphLinkWrite(_ref(ctx.route.actor_euid), _new("photo"), "HAS_DOG_CAPTURE"),
                         GraphLinkWrite(_new("photo"), _ref(scene_id), "IN_SCENE"),
                         GraphLinkWrite(_new("photo"), _ref(session_euid), "IN_SESSION"))
    file = form.get("file")
    media_type = getattr(file, "content_type", "")
    if media_type not in {"image/jpeg", "image/png"}:
        raise HTTPException(400, "Select a JPEG or PNG")
    image = await file.read()
    if not image:
        raise HTTPException(400, "The image is empty")
    bucket = cfg.artifact_bucket
    key = f"private-dogs/user_id={user.user_id}/{uuid4()}/image"
    uploaded = s3.put_object(Bucket=bucket, Key=key, Body=image, ContentType=media_type)
    photo_objects, photo_links = _artifact(ctx, key=key, bucket=bucket, version=uploaded["VersionId"], media_type=media_type, name="photo")
    photo_objects[0].properties["captured_at"] = datetime.now(timezone.utc).isoformat()
    result = ctx.store.create_graph(objects=photo_objects, links=photo_links + capture_links)
    photo_id = result["photo"].semantic_id
    receipt = {"status": "uploaded", "upload_status": "stored", "photo_id": photo_id, "dog_id": dog_id}
    try:
        start_processing(ctx, photo_id=photo_id, bucket=bucket)
        receipt["processing_status"] = "processing"
    except Exception:
        logging.getLogger(__name__).exception("Dog detection could not start for stored photo %s", photo_id)
        receipt.update(processing_status="not_started", message="Photo uploaded successfully. Detection could not start; use Run detection beside the photo.")
    return receipt


def finish_capture(db, *, ctx, user, photo_id, session_id, bucket, s3):
    prepare_browser_scene(db=db, user=user, agent_id=ctx.route.agent_id, space_id=ctx.route.space_id,
                          room_mode="stable", session_id=_uuid(session_id))
    from api_app import _scene_for_session
    scene_id, session_euid = _scene_for_session(session_id=session_id, agent_id=ctx.route.agent_id)
    with ctx.store.read_view() as view:
        photo = _photo(view, ctx, photo_id)
        if not any(obj.semantic_id == session_euid for obj in view.linked_objects(photo_id, relationship_type="IN_SESSION")):
            raise HTTPException(403, "Photo belongs to a different session")
        processing, inference = _processing(view, photo)
        if processing["status"] != "complete":
            raise HTTPException(409, processing["message"])
        scene, session = view.get_object(scene_id), view.get_object(session_euid)
    detections = inference["detections"]
    identifier = str(uuid4())
    properties = {"modality": "dog_visual", "model_id": MODEL_ID, "model_version": MODEL_VERSION,
                  "captured_at": photo.properties["captured_at"], "access_policy": ctx.route.policy.as_properties()}
    objects, links = [], []
    references = _gallery(ctx, bucket=bucket, s3=s3)
    matches = [{"box": item["box"], **match_dog(item["embedding"], references,
        minimum_similarity=float(os.environ["DOG_MATCH_SIMILARITY"]), ambiguity_margin=float(os.environ["DOG_MATCH_MARGIN"]))}
        for item in detections]
    properties["results"] = matches  # Search/display projection; associations below are authoritative lineage.
    objects.append(GraphObjectWrite("observation", TEMPLATE_CODES["recognition_observation"],
        f"dog-observation:{identifier}", properties, "recorded"))
    links.extend((GraphLinkWrite(_new("observation"), _ref(photo.semantic_id), "HAS_ARTIFACT"),
                  GraphLinkWrite(_ref(photo.semantic_id), _new("observation"), "OBSERVED_AS"),
                  GraphLinkWrite(_new("observation"), _ref(scene.semantic_id), "IN_SCENE"),
                  GraphLinkWrite(_new("observation"), _ref(session.semantic_id), "IN_SESSION")))
    links.extend(ctx.policy_links("observation"))
    for index, match in enumerate(matches):
        candidate = match["candidate"]
        if candidate:
            hypothesis = f"hypothesis_{index}"
            objects.append(GraphObjectWrite(hypothesis, TEMPLATE_CODES["recognition_hypothesis"],
                f"dog-match:{identifier}:{index}", {"similarity": candidate["similarity"],
                    "model_id": MODEL_ID, "model_version": MODEL_VERSION, "access_policy": ctx.route.policy.as_properties()}, "candidate"))
            links.extend((GraphLinkWrite(_new(hypothesis), _new("observation"), "BASED_ON"),
                          GraphLinkWrite(_new(hypothesis), _ref(candidate["dog_id"]), "CANDIDATE_ACTOR"),
                          GraphLinkWrite(_new(hypothesis), _ref(candidate["reference_id"]), "MATCHED_REFERENCE")))
            links.extend(ctx.policy_links(hypothesis))
    result = ctx.store.create_graph(objects=tuple(objects), links=tuple(links))
    with ctx.store.read_view() as view:
        participants = tuple(view.get_object(euid) for euid in dict.fromkeys(
            item["candidate"]["dog_id"] for item in matches if item["candidate"]))
    descriptions = [f"possible match to {item['candidate']['display_name']}" if item["candidate"] else item["result"] for item in matches]
    content = "Dog camera observation: " + ("; ".join(descriptions) if descriptions else "no dog detected") + ". Visual reference matching is uncertain evidence."
    lifecycle = MarvainSemanticLifecycle(ctx.store)
    now = datetime.now(timezone.utc)
    captured_at = datetime.fromisoformat(photo.properties["captured_at"])
    episode = lifecycle.record_episode(name=f"dog-encounter:{identifier}", scene=scene, session=session,
        participants=(), evidence=(result["observation"],), occurred_at=captured_at, policy=ctx.route.policy,
        owner=ctx.owner, readers=ctx.readers, detail={"content": content})
    memory = lifecycle.commit_scoped_memory(evidence=(result["observation"],), episode=episode, participants=participants,
        content=content, kind="episodic", recorded_at=now, effective_at=captured_at, policy=ctx.route.policy, owner=ctx.owner, readers=ctx.readers)
    return {"status": "observed", "result": "dogs_detected" if matches else "no_dog_detected", "dogs": matches,
            "observation_id": result["observation"].semantic_id, "memory_id": memory.committed.semantic_id,
            "captured_at": photo.properties["captured_at"],
            "scope": "Dog reference candidates only; similarity is not identity certainty or authorization"}
