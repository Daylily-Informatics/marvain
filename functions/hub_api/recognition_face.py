"""AWS Rekognition reference-image recognition. No exported or synthetic face vectors."""
from __future__ import annotations

from datetime import datetime, timezone
from uuid import uuid4
import os

import boto3
from fastapi import HTTPException
from agent_hub.recognition_service import RecognitionObservation, RecognitionModality, ObservationState, HypothesisKind, RecognitionLifecycleService
from recognition_repository import RdsRecognitionRepository

MODEL_ID = "aws-rekognition-comparefaces"
API_VERSION = "2016-06-27"  # API contract version; AWS does not return the model version here.


def identify_face(db, *, agent_id, image, transaction_id=None):
    client = boto3.client("rekognition")
    references = db.query("""SELECT bp.person_id::text AS person_id,p.display_name,ar.bucket,ar.object_key,ar.s3_version_id
        FROM biometric_projections bp
        JOIN people p ON p.person_id=bp.person_id AND p.agent_id=bp.agent_id
        JOIN recognition_observations ro ON ro.recognition_observation_id=bp.recognition_observation_id
        JOIN artifact_references ar ON ar.artifact_id=ro.artifact_id
        JOIN consent_grants cg ON cg.consent_id=bp.consent_id
        WHERE bp.agent_id=:agent::uuid AND bp.modality='face' AND bp.model_id=:model
          AND bp.lifecycle_state='active' AND ar.lifecycle_state='available'
          AND p.lifecycle_state='active' AND p.disabled_at IS NULL
          AND cg.revoked_at IS NULL AND (cg.expires_at IS NULL OR cg.expires_at>now())
          AND cg.agent_id=bp.agent_id AND cg.person_id=bp.person_id AND cg.consent_type IN ('face','global')""",
        {"agent": agent_id, "model": MODEL_ID}, transaction_id=transaction_id)
    threshold = float(os.environ["REKOGNITION_FACE_THRESHOLD"])
    matches = {}
    names = {}
    for ref in references:
        names[ref["person_id"]] = ref["display_name"]
        response = client.compare_faces(
            SourceImage={"S3Object": {"Bucket": ref["bucket"], "Name": ref["object_key"], "Version": ref["s3_version_id"]}},
            TargetImage=image, SimilarityThreshold=threshold)
        for face in response["FaceMatches"]:
            similarity = float(face["Similarity"])/100
            matches[ref["person_id"]] = max(matches.get(ref["person_id"], 0), similarity)
    candidates = [{"person_id": person, "display_name": names[person], "confidence": score, "distance": 1-score}
                  for person, score in sorted(matches.items(), key=lambda item: item[1], reverse=True)]
    return {"matched": len(candidates)==1, "ambiguous": len(candidates)>1,
            "best": candidates[0] if candidates else None, "candidates": candidates}


def record_face(db, *, event, artifact, enrollment_person_id=None):
    image = {"S3Object": {"Bucket": artifact["bucket"], "Name": artifact["object_key"], "Version": artifact["version_id"]}}
    detected = boto3.client("rekognition").detect_faces(Image=image, Attributes=["DEFAULT"])
    if len(detected["FaceDetails"]) != 1:
        raise HTTPException(422, "Capture exactly one face")
    match = None
    best = None
    if enrollment_person_id:
        candidate, confidence, distance = enrollment_person_id, 1.0, 0.0
        rationale = "AWS detected one face; the named enrollment candidate requires human review"
    else:
        match = identify_face(db, agent_id=event["agent_id"], image=image)
        best = match["best"] if match["matched"] else None
        candidate = best["person_id"] if best else None
        confidence, distance = (best["confidence"], best["distance"]) if best else (0.0, None)
        rationale = "AWS Rekognition reference comparison; ambiguous or absent matches remain unknown"
    repository = RdsRecognitionRepository(db, agent_id=event["agent_id"])
    try:
        prep = repository.prepare_observation(source_event_id=event["event_id"], claimed_agent_id=event["agent_id"],
            claimed_space_id=event["space_id"], claimed_location_id=None, claimed_session_id=event.get("session_id"),
            source_device_id=event["device_id"], artifact_payload={k: artifact[k] for k in ("bucket","object_key","uri","media_type","sha256")},
            modality=RecognitionModality.FACE, model_id=MODEL_ID, model_version=API_VERSION, embedding_sha256=None)
        observation = prep.existing
        if observation is None:
            observation = RecognitionObservation(str(uuid4()), prep.artifact.artifact_id, event["agent_id"], event["device_id"],
                RecognitionModality.FACE, MODEL_ID, API_VERSION, None, ObservationState.OBSERVED,
                datetime.now(timezone.utc), space_id=event["space_id"], session_id=event.get("session_id"),
                source_event_id=event["event_id"])
            repository.persist_observation(artifact=prep.artifact, observation=observation)
        kind = HypothesisKind.CANDIDATE if candidate else HypothesisKind.NO_MATCH
        prep_h = repository.prepare_hypothesis(observation_id=observation.observation_id, kind=kind,
            candidate_person_id=candidate, confidence=confidence, distance=distance, rationale=rationale,
            requested_projection=bool(enrollment_person_id))
        service = RecognitionLifecycleService(repository)
        hypothesis = prep_h.existing
        if hypothesis is None:
            hypothesis = (service.propose_candidate(observation_id=observation.observation_id, candidate_person_id=candidate,
                confidence=confidence, distance=distance, rationale=rationale) if candidate else
                service.propose_no_match(observation_id=observation.observation_id, confidence=confidence, rationale=rationale))
        repository.commit()
    except Exception:
        repository.rollback()
        raise
    result = "enrollment_proposal" if enrollment_person_id else (
        "reference_match" if best else ("ambiguous" if match["ambiguous"] else "no_match"))
    return {"observation_id": observation.observation_id, "hypothesis_id": hypothesis.hypothesis_id,
            "status": "review_required" if enrollment_person_id else "observed", "result": result,
            "candidate_person": {"person_id":best["person_id"], "display_name":best["display_name"]} if best else None,
            "similarity": best["confidence"] if best else None,
            "scope": "Comparison to reviewed face references with active consent; not liveness or authorization"}
