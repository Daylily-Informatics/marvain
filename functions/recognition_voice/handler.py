"""SQS-triggered voice processing; no provisioned/idle recognition worker."""
import hashlib
import io
import json
import logging
import os
import subprocess
from pathlib import Path

import boto3
import resemblyzer
import soundfile
from resemblyzer import VoiceEncoder, preprocess_wav
from agent_hub.rds_data import RdsData, RdsDataEnv
from agent_hub.recognition_service import RecognitionLifecycleService, RecognitionModality, HypothesisKind
from agent_hub.recognition_matching import identify_embedding
from recognition_repository import RdsRecognitionRepository

logger=logging.getLogger(__name__)
logger.setLevel(logging.INFO)
_encoder=None
MODEL_ID="resemblyzer"
MODEL_VERSION="0.1.4-bundled-pretrained"


def process(event):
    global _encoder
    if event["type"]!="voice.sample" or event["agent_id"]!=os.environ["RECOGNITION_AGENT_ID"]:
        raise ValueError("Voice capture is outside the configured type/agent scope")
    payload=event["payload"]
    if payload["artifact_bucket"]!=os.environ["ARTIFACT_BUCKET"]:
        raise ValueError("Capture bucket does not match this deployment")
    db=RdsData(RdsDataEnv(resource_arn=os.environ["DB_RESOURCE_ARN"],secret_arn=os.environ["DB_SECRET_ARN"],database=os.environ["DB_NAME"]))
    data=boto3.client("s3").get_object(Bucket=payload["artifact_bucket"],Key=payload["artifact_key"])["Body"].read()
    decoded=subprocess.run(["ffmpeg","-nostdin","-loglevel","error","-i","pipe:0","-f","wav","-ac","1","-ar","16000","pipe:1"],
        input=data,stdout=subprocess.PIPE,stderr=subprocess.PIPE,check=True)
    waveform,rate=soundfile.read(io.BytesIO(decoded.stdout))
    wav=preprocess_wav(waveform,source_sr=rate)
    if not len(wav): raise ValueError("No speech was detected; capture a new sample")
    if _encoder is None:
        _encoder=VoiceEncoder(device="cpu",weights_fpath=Path(resemblyzer.__file__).parent/"pretrained.pt")
    embedding=_encoder.embed_utterance(wav).astype("float32").tolist()
    digest=hashlib.sha256(json.dumps([float(x) for x in embedding],separators=(",",":"),allow_nan=False).encode()).hexdigest()
    repo=RdsRecognitionRepository(db,agent_id=event["agent_id"])
    try:
        prep=repo.prepare_observation(source_event_id=event["event_id"],claimed_agent_id=event["agent_id"],
            claimed_space_id=event["space_id"],claimed_location_id=event.get("location_id"),claimed_session_id=event.get("session_id"),
            source_device_id=event["device_id"],modality=RecognitionModality.VOICE,model_id=MODEL_ID,model_version=MODEL_VERSION,
            embedding_sha256=digest,artifact_payload={"bucket":payload["artifact_bucket"],"object_key":payload["artifact_key"],
                "uri":f"s3://{payload['artifact_bucket']}/{payload['artifact_key']}","media_type":payload["content_type"],"sha256":payload["artifact_sha256"]})
        service=RecognitionLifecycleService(repo)
        observation=prep.existing or service.record_observation(artifact=prep.artifact,modality=RecognitionModality.VOICE,
            model_id=MODEL_ID,model_version=MODEL_VERSION,embedding=embedding)
        repo.store_embedding(observation.observation_id,embedding)
        person=payload.get("enroll_person_id")
        enrollment=bool(person)
        if enrollment:
            confidence,distance=1.0,0.0
            rationale="Consented voice enrollment candidate requires authenticated human review"
        else:
            match=identify_embedding(db,agent_id=event["agent_id"],modality="voice",model_id=MODEL_ID,
                model_version=MODEL_VERSION,embedding=embedding,transaction_id=repo.transaction_id)
            best=match["best"] if match["matched"] else None
            person=best["person_id"] if best else None
            confidence,distance=(best["confidence"],best["distance"]) if best else (0.0,None)
            rationale="Voice matched reviewed model-compatible enrollments; absent or ambiguous matches remain unknown"
        prep_h=repo.prepare_hypothesis(observation_id=observation.observation_id,kind=HypothesisKind.CANDIDATE if person else HypothesisKind.NO_MATCH,
            candidate_person_id=person,confidence=confidence,distance=distance,rationale=rationale,requested_projection=enrollment)
        if prep_h.existing is None:
            if person: service.propose_candidate(observation_id=observation.observation_id,candidate_person_id=person,
                confidence=confidence,distance=distance,rationale=rationale)
            else: service.propose_no_match(observation_id=observation.observation_id,confidence=confidence,rationale=rationale)
        repo.commit()
    except Exception:
        repo.rollback()
        raise
    return observation.observation_id


def handler(event, context):
    failures=[]
    for record in event["Records"]:
        try:
            observation=process(json.loads(record["body"]))
            logger.info("Voice observation persisted: %s",observation)
        except Exception:
            logger.exception("Voice capture processing failed")
            failures.append({"itemIdentifier":record["messageId"]})
    return {"batchItemFailures":failures}
