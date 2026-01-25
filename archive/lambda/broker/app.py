from __future__ import annotations

import base64
import json
import logging
import os
import re
from datetime import datetime
from typing import Any, Dict, Optional, Tuple

from agent_core import aws_model_client, llm_client, logging_utils, memory_store, planner, tools, voice_registry
from agent_core.schema import Event
from agent_core.speech import SpeechSynthesizer
from agent_core.actions import dispatch_background_actions
from agent_core.tools import ToolExecutor, create_tool_executor


logging_utils.configure_logging(os.environ.get("VERBOSE", "0"))

AGENT_ID = os.environ.get("AGENT_ID", "agent1")
AGENT_VOICE_ID = os.environ.get("AGENT_VOICE_ID", "Matthew")
AGENT_VOICE_ENGINE = os.environ.get("AGENT_VOICE_ENGINE")
AUDIO_BUCKET = os.environ.get("AUDIO_BUCKET") or ""
REGION = os.environ.get("AWS_REGION") or os.environ.get("REGION") or None
ENABLE_TOOL_EXECUTION = os.environ.get("ENABLE_TOOL_EXECUTION", "1") == "1"

# Bedrock model client
_MODEL_CLIENT = aws_model_client.AwsModelClient.from_env()

# Tool executor (created per-request to ensure fresh state)
def _create_tool_executor() -> ToolExecutor:
    return create_tool_executor(
        agent_id=AGENT_ID,
        memory_store_module=memory_store,
        voice_registry_module=voice_registry,
    )


_NAME_RE = re.compile(r"(?i)\bmy name is\s+([\w\-\s]{1,80})")


def _now_iso() -> str:
    return datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _normalize_headers(headers: Optional[Dict[str, Any]]) -> Dict[str, str]:
    if not headers:
        return {}
    out: Dict[str, str] = {}
    for k, v in headers.items():
        if k is None:
            continue
        key = str(k).strip().lower()
        out[key] = str(v) if v is not None else ""
    return out


def _derive_session_id(event: Dict[str, Any]) -> str:
    headers = _normalize_headers(event.get("headers"))
    if "x-session-id" in headers and headers["x-session-id"]:
        return headers["x-session-id"]

    rc = event.get("requestContext") or {}
    rid = rc.get("requestId") or event.get("requestID") or rc.get("requestID")
    if rid:
        return f"lambda-{rid}"
    return "lambda-unknown"


def _parse_body(event: Dict[str, Any]) -> Tuple[Dict[str, Any], Any]:
    """Return (body_obj, raw_for_storage).

    - If body is dict-like -> returns it
    - If body is JSON string -> decoded dict
    - If body is non-JSON string -> returns {"transcript": <string>} and raw string
    - If body is base64 encoded (API GW) -> attempts to decode to UTF-8 first
    """
    body = event.get("body")
    if body is None:
        return {}, {}

    if isinstance(body, dict):
        return body, body

    # body is a string
    if isinstance(body, (bytes, bytearray)):
        body_str = body.decode("utf-8", errors="replace")
    else:
        body_str = str(body)

    if event.get("isBase64Encoded") is True:
        try:
            decoded = base64.b64decode(body_str)
            body_str = decoded.decode("utf-8", errors="replace")
        except Exception:
            # keep original string
            pass

    # try JSON
    try:
        obj = json.loads(body_str)
        if isinstance(obj, dict):
            return obj, obj
        # if JSON but not object, store it as raw and map transcript
        return {"transcript": str(obj)}, obj
    except Exception:
        # non-JSON: treat as transcript
        return {"transcript": body_str}, body_str


def handler(event, context):
    logging.info("Broker invoked")

    session_id = _derive_session_id(event)
    body_obj, raw_for_storage = _parse_body(event)

    transcript = body_obj.get("transcript") or body_obj.get("text") or ""
    channel = body_obj.get("channel", "audio")
    voice_id = body_obj.get("voice_id") or body_obj.get("speaker_id")
    speaker_name = body_obj.get("speaker_name") or body_obj.get("user_name")
    personality = body_obj.get("personality_prompt")
    source = body_obj.get("source") or "user"

    voice_embedding = body_obj.get("voice_embedding")
    had_voice_embedding = bool(voice_embedding)

    # Ensure we do NOT store embeddings in DynamoDB
    if isinstance(raw_for_storage, dict) and "voice_embedding" in raw_for_storage:
        raw_for_storage = dict(raw_for_storage)
        raw_for_storage.pop("voice_embedding", None)

    # Voice resolution + heuristic name extraction
    claimed_name: Optional[str] = None
    if not speaker_name and voice_id and transcript:
        m = _NAME_RE.search(transcript)
        if m:
            claimed_name = m.group(1).strip().rstrip(".!?,")
            # avoid grabbing huge trailing phrases
            if len(claimed_name.split()) > 6:
                claimed_name = " ".join(claimed_name.split()[:6])

    resolved_name: Optional[str] = speaker_name
    is_new_voice = False
    voice_extra_instructions = ""

    if voice_id or speaker_name or had_voice_embedding:
        try:
            resolved_name, is_new_voice = voice_registry.resolve_voice(
                agent_id=AGENT_ID,
                voice_id=str(voice_id) if voice_id is not None else None,
                claimed_name=speaker_name or claimed_name,
                embedding=voice_embedding,
            )
        except Exception as e:
            logging.error("Voice resolution failed (soft): %s", e)
            resolved_name, is_new_voice = (speaker_name or claimed_name), False

        if resolved_name:
            if is_new_voice and not speaker_name:
                voice_extra_instructions = (
                    f"The speaker introduced themselves as {resolved_name}. "
                    "Use this name going forward."
                )
            else:
                voice_extra_instructions = (
                    f"The current speaker is {resolved_name}. "
                    "Treat relevant memories as being about this speaker."
                )
        else:
            if voice_id and is_new_voice:
                voice_extra_instructions = (
                    "A new speaker is talking but their name is unknown. "
                    "Before doing substantive work, ask for their name."
                )
            elif voice_id:
                voice_extra_instructions = (
                    "An unidentified returning speaker is talking. "
                    "Ask for their name if it is still unknown."
                )

    # Persist inbound event
    effective_speaker_id = str(voice_id) if voice_id is not None else None
    agent_event = Event(
        agent_id=AGENT_ID,
        session_id=session_id,
        source=source,
        channel=channel,
        ts=_now_iso(),
        payload={
            "transcript": transcript,
            "voice_id": effective_speaker_id,
            "speaker_name": resolved_name,
            "had_voice_embedding": had_voice_embedding,
            "raw": raw_for_storage,
        },
        speaker_id=effective_speaker_id,
    )
    memory_store.put_event(agent_event)
    # Sanitize user input before logging to prevent log injection
    safe_session_id = str(session_id).replace('\n','').replace('\r','')
    safe_channel = str(channel).replace('\n','').replace('\r','')
    safe_effective_speaker_id = str(effective_speaker_id).replace('\n','').replace('\r','')
    logging.info("Event persisted (session=%s channel=%s speaker=%s)", safe_session_id, safe_channel, safe_effective_speaker_id)

    # Store RAW memory for every user interaction (for Rank 4/5 memory visualization)
    if transcript and source == "user":
        raw_memory = {
            "kind": "RAW",
            "text": transcript,
            "meta": {
                "source": source,
                "channel": channel,
                "speaker_name": resolved_name,
                "session_id": session_id,
            },
        }
        try:
            memory_store.put_memory(raw_memory, speaker_id=effective_speaker_id)
            logging.info("Stored RAW memory for user input")
        except Exception as e:
            logging.error("Failed to store RAW memory: %s", e)

    # Extract implicit memories from transcript
    implicit_memories = planner.extract_implicit_memories(
        transcript,
        speaker_id=effective_speaker_id,
        speaker_name=resolved_name,
    )
    for imp_mem in implicit_memories:
        try:
            memory_store.put_memory(imp_mem, speaker_id=effective_speaker_id)
            logging.info("Stored implicit memory: %s", imp_mem.get("text", "")[:50])
        except Exception as e:
            logging.error("Failed to store implicit memory: %s", e)

    # Retrieve recent context with speaker awareness
    context_items = memory_store.recent_memories(
        AGENT_ID,
        limit=40,
        session_id=session_id,
        speaker_id=effective_speaker_id,
    )
    logging.info("Context retrieved: %d items", len(context_items))

    # Build speaker context for the system prompt
    speaker_context = None
    if resolved_name or voice_id:
        speaker_context = {
            "current_speaker_name": resolved_name,
            "current_speaker_voice_id": str(voice_id) if voice_id else None,
            "is_new_speaker": is_new_voice,
        }

    # Build system prompt
    system_prompt = llm_client.build_system_prompt(
        memories=context_items,
        personality_extra=personality,
        voice_extra=voice_extra_instructions,
        heartbeat_mode=False,
        tools_spec=tools.TOOLS_SPEC,
        speaker_context=speaker_context,
    )

    messages = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": transcript},
    ]

    # Create tool executor for this request
    tool_executor = None
    if ENABLE_TOOL_EXECUTION:
        tool_executor = _create_tool_executor()
        logging.info("Tool execution enabled")

    # Call LLM with optional tool execution
    llm_raw = llm_client.chat_with_tools(
        _MODEL_CLIENT,
        messages,
        tools=tools.TOOLS_SPEC,
        tool_executor=tool_executor.execute if tool_executor else None,
    )

    # Plan -> actions + memories + reply
    action_list, new_memories, reply_text = planner.handle_llm_result(llm_raw, agent_event)
    logging.info("Planner result: actions=%d new_memories=%d", len(action_list), len(new_memories))

    # Add any queued actions from tool execution
    if tool_executor:
        queued_actions = tool_executor.get_queued_actions()
        if queued_actions:
            logging.info("Adding %d queued actions from tool execution", len(queued_actions))
            action_list.extend(queued_actions)

    # Persist new memories
    for mem in new_memories:
        try:
            memory_store.put_memory(mem)
        except Exception as e:
            logging.error("Failed to store memory: %s", e)

    # Dispatch actions (non-blocking in this skeleton)
    try:
        dispatch_background_actions(action_list)
    except Exception as e:
        logging.error("dispatch_background_actions failed (soft): %s", e)

    # Persist agent reply as an event for continuity
    if reply_text:
        memory_store.put_event(
            Event(
                agent_id=AGENT_ID,
                session_id=session_id,
                source="agent",
                channel=channel,
                ts=_now_iso(),
                payload={"transcript": reply_text},
            )
        )

        # Store RAW memory for agent response (for Rank 4/5 memory visualization)
        agent_raw_memory = {
            "kind": "RAW",
            "text": reply_text,
            "meta": {
                "source": "agent",
                "channel": channel,
                "session_id": session_id,
            },
        }
        try:
            memory_store.put_memory(agent_raw_memory)
            logging.info("Stored RAW memory for agent response")
        except Exception as e:
            logging.error("Failed to store agent RAW memory: %s", e)

    # Speech synthesis (optional, fail-soft)
    audio_obj = None
    if reply_text:
        try:
            logging.info("SpeechSynthesizer init: region=%s voice=%s bucket=%s", REGION, AGENT_VOICE_ID, AUDIO_BUCKET or None)
            synth = SpeechSynthesizer(
                voice_id=AGENT_VOICE_ID or "Matthew",
                region=REGION,
                bucket=AUDIO_BUCKET or None,
                engine=AGENT_VOICE_ENGINE or None,
            )
            audio_obj = synth.synthesize(reply_text, key_prefix=f"{AGENT_ID}/{session_id}")
            if audio_obj:
                logging.info("Speech synthesis succeeded")
        except Exception as e:
            logging.error("Speech synthesis failed (soft): %s", e)
            audio_obj = None

    resp_body = {"reply_text": reply_text, "actions": action_list}
    if audio_obj:
        resp_body["audio"] = audio_obj

    # Include speaker info for UI display
    resp_body["speaker_info"] = {
        "speaker_name": resolved_name,
        "voice_id": str(voice_id) if voice_id else None,
        "is_new_speaker": is_new_voice,
    }

    # Include tool execution info if available
    if tool_executor:
        queued = tool_executor.get_queued_actions()
        # Note: queued was already consumed above, but we track the count
        resp_body["tool_info"] = {
            "enabled": True,
            "iterations": 1,  # Basic tracking - could be enhanced
            "tool_calls": [
                {"name": a.get("action"), "input": a.get("args", {})}
                for a in action_list
                if a.get("queued_at")  # Only include tool-queued actions
            ],
        }

    return {
        "statusCode": 200,
        "headers": {"Content-Type": "application/json"},
        "body": json.dumps(resp_body),
    }
