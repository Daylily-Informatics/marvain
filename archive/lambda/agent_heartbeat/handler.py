from __future__ import annotations

import json
import logging
import os
from datetime import datetime

from agent_core import aws_model_client, llm_client, logging_utils, memory_store, planner
from agent_core.actions import dispatch_background_actions
from agent_core.schema import Event


logging_utils.configure_logging(os.environ.get("VERBOSE", "0"))

AGENT_ID = os.environ.get("AGENT_ID", "agent1")
_MODEL_CLIENT = aws_model_client.AwsModelClient.from_env()


def _now_iso() -> str:
    return datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def handler(event, context):
    logging.info("Heartbeat invoked")

    hb_event = Event(
        agent_id=AGENT_ID,
        session_id="system-heartbeat",
        source="system",
        channel="timer",
        ts=_now_iso(),
        payload={
            "kind": "HEARTBEAT",
            "raw_event": event,
        },
    )

    memory_store.put_event(hb_event)
    logging.info("Heartbeat event persisted")

    context_items = memory_store.recent_memories(AGENT_ID, limit=100)
    logging.info("Heartbeat context retrieved: %d items", len(context_items))

    system_prompt = llm_client.build_system_prompt(
        memories=context_items,
        personality_extra="You are in heartbeat mode. Do background evaluation only.",
        voice_extra=None,
        heartbeat_mode=True,
        tools_spec=None,
    )

    messages = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": "<<< SYSTEM HEARTBEAT >>>"},
    ]

    llm_raw = llm_client.chat_with_tools(_MODEL_CLIENT, messages, tools=[])

    action_list, new_memories, reply_text = planner.handle_llm_result(llm_raw, hb_event)
    logging.info("Heartbeat planner result: actions=%d new_memories=%d", len(action_list), len(new_memories))

    for mem in new_memories:
        try:
            memory_store.put_memory(mem)
        except Exception as e:
            logging.error("Heartbeat: failed to store memory: %s", e)

    try:
        dispatch_background_actions(action_list)
    except Exception as e:
        logging.error("Heartbeat: dispatch failed (soft): %s", e)

    body = {"status": "ok", "reply_text": reply_text or "", "actions": action_list}
    return {"statusCode": 200, "body": json.dumps(body)}
