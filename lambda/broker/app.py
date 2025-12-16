from __future__ import annotations

import json
import logging
import os
import re
from typing import Any, Dict, Optional

from agent_core.logging_utils import configure_logging
from agent_core.schema import Event
from agent_core import memory_store
from agent_core.aws_model_client import AwsModelClient
from agent_core import llm_client
from agent_core.tools import TOOLS_SPEC
from agent_core import planner
from agent_core.actions import dispatch_background_actions
from agent_core.voice_registry import resolve_voice
from agent_core.speech import SpeechSynthesizer
from agent_core.utils import json_dumps_safe, truncate_str

logger = logging.getLogger(__name__)


_NAME_RE = re.compile(r"\bmy name is\s+([A-Za-z][A-Za-z '\-]{0,48})", re.IGNORECASE)


def _header_get(headers: Optional[Dict[str, Any]], key: str) -> Optional[str]:
    if not headers:
        return None
    for k, v in headers.items():
        if k.lower() == key.lower():
            return str(v)
    return None


def _derive_session_id(event: Dict[str, Any]) -> str:
    headers = event.get("headers") or {}
    sid = _header_get(headers, "x-session-id") or _header_get(headers, "X-Session-Id")
    if sid:
        return sid

    rc = event.get("requestContext") or {}
    rid = rc.get("requestId") or rc.get("requestID") or event.get("requestID") or event.get("requestId")
    if rid:
        return f"lambda-{rid}"
    return f"lambda-{os.urandom(8).hex()}"


def _parse_body(event: Dict[str, Any]) -> Dict[str, Any]:
    body = event.get("body")
    if body is None:
        return {}
    if isinstance(body, dict):
        return body
    if isinstance(body, (bytes, bytearray)):
        body = body.decode("utf-8", errors="replace")
    if isinstance(body, str):
        s = body.strip()
        if not s:
            return {}
        try:
            obj = json.loads(s)
            if isinstance(obj, dict):
                return obj
            # Non-dict JSON: wrap
            return {"payload": {"raw": obj}}
        except Exception:
            # Not JSON: treat as raw string
            return {"payload": {"raw": s}, "transcript": s}
    # Unknown type
    return {"payload": {"raw": str(body)}}


def _extract_claimed_name(transcript: str) -> Optional[str]:
    if not transcript:
        return None
    m = _NAME_RE.search(transcript)
    if not m:
        return None
    name = m.group(1).strip()
    # Trim at punctuation
    name = re.split(r"[\.,;:!\?\n]", name)[0].strip()
    # Avoid absurdly long / multi-word names; keep first 3 tokens
    toks = name.split()
    if not toks:
        return None
    return " ".join(toks[:3])


def handler(event, context):
    verbose = int(os.environ.get("VERBOSE", "0") or "0")
    configure_logging(verbose)
    logger.info("Broker invocation")

    agent_id = os.environ.get("AGENT_ID", "agent-default")

    try:
        session_id = _derive_session_id(event)
        body = _parse_body(event)

        transcript = str(body.get("transcript") or body.get("text") or "").strip()
        channel = str(body.get("channel") or "audio")

        voice_id = body.get("voice_id")
        if voice_id is None:
            voice_id = body.get("speaker_id")

        speaker_name = body.get("speaker_name") or body.get("user_name")
        speaker_name = str(speaker_name).strip() if speaker_name else None

        personality_prompt = body.get("personality_prompt")
        personality_prompt = str(personality_prompt).strip() if personality_prompt else None

        source = body.get("source")
        source = str(source).strip() if source else None

        voice_embedding = body.get("voice_embedding", None)
        had_voice_embedding = voice_embedding is not None

        claimed_name = speaker_name
        if voice_id is not None and not speaker_name:
            inferred = _extract_claimed_name(transcript)
            if inferred:
                claimed_name = inferred

        resolved_speaker = speaker_name
        is_new_voice = False

        if any([voice_id is not None, claimed_name, had_voice_embedding]):
            try:
                resolved_speaker, is_new_voice = resolve_voice(
                    agent_id=agent_id,
                    voice_id=str(voice_id) if voice_id is not None else None,
                    claimed_name=claimed_name,
                    embedding=voice_embedding,
                )
            except Exception:
                logger.exception("Voice resolution failed; falling back")
                resolved_speaker = claimed_name or speaker_name
                is_new_voice = False

        # Derive source if absent
        if not source:
            if resolved_speaker:
                source = resolved_speaker
            elif voice_id is not None:
                source = f"voice:{voice_id}"
            else:
                source = "unknown"

        # Strip voice_embedding from persisted raw payload (REQ-37)
        raw_payload = dict(body)
        if "voice_embedding" in raw_payload:
            raw_payload["voice_embedding"] = None
            raw_payload.pop("voice_embedding", None)

        # Ensure payload.raw exists even for dict bodies (REQ-33)
        if "payload" not in raw_payload:
            raw_payload["payload"] = {}
        if isinstance(raw_payload.get("payload"), dict) and "raw" not in raw_payload["payload"]:
            # store a stripped version of the request body (sans embedding) under payload.raw
            raw_payload["payload"]["raw"] = {k: v for k, v in raw_payload.items() if k != "payload"}

        agent_event = Event(
            agent_id=agent_id,
            session_id=session_id,
            source=source,
            channel=channel,
            payload={
                "transcript": transcript,
                "voice_id": str(voice_id) if voice_id is not None else None,
                "speaker_name": resolved_speaker,
                "had_voice_embedding": had_voice_embedding,
                "raw": raw_payload,
            },
        )

        # Persist event (REQ-36)
        memory_store.put_event(agent_event)
        logger.info("Event persisted session_id=%s", session_id)

        # Retrieve recent memories (REQ-38)
        memories = memory_store.recent_memories(agent_id, limit=40)
        logger.info("Retrieved %d memories for context", len(memories))
        memories_json = truncate_str(json_dumps_safe(memories), 6000)

        # Voice-aware instructions (REQ-48)
        voice_instructions = ""
        if resolved_speaker and not is_new_voice:
            voice_instructions = f"The current speaker is {resolved_speaker}. Treat memories as about this speaker unless stated otherwise."
        elif resolved_speaker and is_new_voice:
            voice_instructions = f"You just learned the speaker's name is {resolved_speaker}. Use this name going forward, and consider storing it as a FACT memory."
        elif is_new_voice and not resolved_speaker:
            voice_instructions = "This appears to be a new speaker with no known name. Before doing substantive work, ask for their name."

        system_prompt = llm_client.build_system_prompt(
            mode="broker",
            agent_id=agent_id,
            session_id=session_id,
            speaker_name=resolved_speaker,
            memories_json=memories_json,
            voice_instructions=voice_instructions,
            extra_personality_prompt=personality_prompt,
        )

        user_content = json_dumps_safe(
            {
                "event": {
                    "agent_id": agent_id,
                    "session_id": session_id,
                    "source": source,
                    "channel": channel,
                    "ts": agent_event.ts,
                },
                "transcript": transcript,
            }
        )

        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_content},
        ]

        model_client = AwsModelClient.from_env()
        llm_resp = llm_client.chat_with_tools(model_client, messages, TOOLS_SPEC)

        actions, new_memories, reply_text = planner.handle_llm_result(llm_resp, agent_event)
        logger.info("Planner produced actions=%d new_memories=%d", len(actions), len(new_memories))

        # Persist memories (REQ-41)
        for m in new_memories:
            memory_store.put_memory(m)

        # Dispatch actions (REQ-44)
        dispatch_background_actions(actions)

        response_obj: Dict[str, Any] = {
            "reply_text": reply_text,
            "actions": [a.to_dict() if hasattr(a, "to_dict") else a for a in actions],
        }

        # Optional speech synthesis (REQ-49/50)
        try:
            region = os.environ.get("AWS_REGION") or os.environ.get("REGION")
            bucket = os.environ.get("AUDIO_BUCKET")
            voice = os.environ.get("AGENT_VOICE_ID", "Matthew") or "Matthew"
            synth = SpeechSynthesizer(bucket=bucket, voice_id=voice, region=region)
            logger.info("SpeechSynthesizer initialized bucket=%s voice=%s", bucket, voice)
            audio = synth.synthesize(reply_text, key_prefix=f"audio/{agent_id}/{session_id}")
            response_obj["audio"] = audio
            logger.info("Speech synthesis ok")
        except Exception:
            logger.warning("Speech synthesis failed; continuing without audio", exc_info=True)

        return {
            "statusCode": 200,
            "headers": {"Content-Type": "application/json"},
            "body": json_dumps_safe(response_obj),
        }
    except Exception as e:
        logger.exception("Broker error")
        return {
            "statusCode": 500,
            "headers": {"Content-Type": "application/json"},
            "body": json_dumps_safe({"error": str(e)}),
        }
