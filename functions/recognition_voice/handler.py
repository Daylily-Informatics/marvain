"""SQS-triggered voice processing; no provisioned/idle recognition worker."""
import hashlib
import io
import json
import logging
import os
import subprocess
from pathlib import Path
from uuid import NAMESPACE_URL, uuid5

import boto3
from agent_hub.rds_data import RdsData, RdsDataEnv
from agent_hub.recognition_service import RecognitionLifecycleService, RecognitionModality, HypothesisKind
from agent_hub.recognition_matching import identify_embedding
from agent_hub.semantic_outbox import GraphSourceRef, enqueue_semantic_graph
from agent_hub.semantic_tapdb import TEMPLATE_CODES, GraphLinkWrite, GraphObjectRef, GraphObjectWrite
from recognition_repository import RdsRecognitionRepository

logger=logging.getLogger(__name__)
logger.setLevel(logging.INFO)
_encoder=None
MODEL_ID="resemblyzer"
MODEL_VERSION="0.1.4-bundled-pretrained"


def _processing(db, event, status, **detail):
    db.execute("""UPDATE events SET payload=jsonb_set(payload,'{voice_processing}',:state::jsonb)
        WHERE event_id=:event::uuid AND agent_id=:agent::uuid""",
        {"event":event["event_id"],"agent":event["agent_id"],"state":json.dumps({"status":status,**detail})})


def _quality_decision(db, event, quality):
    decision_id=str(uuid5(NAMESPACE_URL, "marvain:voice-quality:"+event["event_id"]))
    tx=db.begin()
    try:
        db.execute("""UPDATE events SET payload=jsonb_set(payload,'{voice_quality}',:quality::jsonb)
            WHERE event_id=:event::uuid AND agent_id=:agent::uuid""",
            {"event":event["event_id"],"agent":event["agent_id"],"quality":json.dumps(quality)},transaction_id=tx)
        db.execute("""INSERT INTO events(event_id,agent_id,space_id,device_id,type,payload)
            VALUES (:id::uuid,:agent::uuid,:space::uuid,:device::uuid,'voice.quality',:quality::jsonb)
            ON CONFLICT (event_id) DO NOTHING""",
            {"id":decision_id,"agent":event["agent_id"],"space":event["space_id"],
             "device":event["device_id"],"quality":json.dumps(quality)},transaction_id=tx)
        enqueue_semantic_graph(db,transaction_id=tx,agent_id=event["agent_id"],source_table="events",
            source_id=decision_id,primary_key="quality",
            objects=(GraphObjectWrite("quality",TEMPLATE_CODES["event_sensor"],f"voice-quality:{decision_id}",
                quality,quality["status"]),),
            links=(GraphLinkWrite(GraphObjectRef(key="quality"),
                GraphSourceRef("events",event["event_id"],TEMPLATE_CODES["event_sensor"]),"BASED_ON"),))
        db.commit(tx)
    except Exception:
        db.rollback(tx)
        raise


def process(event):
    global _encoder
    if event["type"]!="voice.sample" or event["agent_id"]!=os.environ["RECOGNITION_AGENT_ID"]:
        raise ValueError("Voice capture is outside the configured type/agent scope")
    payload=event["payload"]
    if payload["artifact_bucket"]!=os.environ["ARTIFACT_BUCKET"]:
        raise ValueError("Capture bucket does not match this deployment")
    db=RdsData(RdsDataEnv(resource_arn=os.environ["DB_RESOURCE_ARN"],secret_arn=os.environ["DB_SECRET_ARN"],database=os.environ["DB_NAME"]))
    _processing(db,event,"processing",stage="loading_audio")
    logger.info("Voice capture %s: loading audio",event["event_id"])
    import numpy as np
    import soundfile
    import resemblyzer
    from resemblyzer import VoiceEncoder, preprocess_wav

    data=boto3.client("s3").get_object(Bucket=payload["artifact_bucket"],Key=payload["artifact_key"])["Body"].read()
    decoded=subprocess.run(["ffmpeg","-nostdin","-loglevel","error","-i","pipe:0","-f","wav","-ac","1","-ar","16000","pipe:1"],
        input=data,stdout=subprocess.PIPE,stderr=subprocess.PIPE,check=True)
    waveform,rate=soundfile.read(io.BytesIO(decoded.stdout))
    logger.info("Voice capture %s: evaluating speech",event["event_id"])
    duration=len(waveform)/rate
    clipped=float(np.mean(np.abs(waveform)>=0.999)) if len(waveform) else 0.0
    # ffmpeg already produces the encoder's 16 kHz input; avoid resampling it again.
    wav=preprocess_wav(waveform) if len(waveform) and np.any(waveform) else waveform
    speech_seconds=len(wav)/16000
    minimum_speech=5.0 if payload.get("enroll_person_id") else 1.5
    reasons=[]
    if speech_seconds<minimum_speech:
        reasons.append(f"Only {speech_seconds:.1f} seconds of detected speech; at least {minimum_speech:g} seconds are required. Read the prompt aloud at a normal pace.")
    if clipped>0.01:
        reasons.append("The recording is clipped. Move farther from the microphone or lower its input level, then record again.")
    quality={"status":"rejected" if reasons else "passed","duration_seconds":round(duration,2),
        "detected_speech_seconds":round(speech_seconds,2),"clipped_fraction":round(clipped,5),
        "minimum_speech_seconds":minimum_speech,"maximum_clipped_fraction":0.01,
        "method":"resemblyzer-vad-and-waveform-v1","reasons":reasons}
    _quality_decision(db,event,quality)
    if reasons:
        _processing(db,event,"rejected",message=" ".join(reasons))
        logger.info("Voice capture %s rejected: %s",event["event_id"]," ".join(reasons))
        return None
    _processing(db,event,"processing",stage="encoding_voice")
    logger.info("Voice capture %s: encoding voice",event["event_id"])
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
    _processing(db,event,"review_required" if enrollment else "observed",observation_id=observation.observation_id)
    return observation.observation_id


def handler(event, context):
    failures=[]
    for record in event["Records"]:
        try:
            observation=process(json.loads(record["body"]))
            if observation:
                logger.info("Voice observation persisted: %s",observation)
        except Exception:
            logger.exception("Voice capture processing failed")
            failures.append({"itemIdentifier":record["messageId"]})
    return {"batchItemFailures":failures}
