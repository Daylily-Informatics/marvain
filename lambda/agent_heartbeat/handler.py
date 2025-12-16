from __future__ import annotations

import json
import logging
import os
from typing import Any, Dict

from agent_core.logging_utils import configure_logging
from agent_core.schema import Event
from agent_core import memory_store
from agent_core.aws_model_client import AwsModelClient
from agent_core import llm_client
from agent_core.tools import TOOLS_SPEC
from agent_core import planner
from agent_core.actions import dispatch_background_actions
from agent_core.utils import json_dumps_safe, truncate_str

logger = logging.getLogger(__name__)


def handler(event, context):
    verbose = int(os.environ.get("VERBOSE", "0") or "0")
    configure_logging(verbose)
    logger.info("Heartbeat invocation")

    agent_id = os.environ.get("AGENT_ID", "agent-default")

    # Create synthetic event (REQ-51)
    agent_event = Event(
        agent_id=agent_id,
        session_id="system-heartbeat",
        source="system",
        channel="timer",
        payload={
            "kind": "HEARTBEAT",
            "raw_event": event,
        },
    )

    try:
        memory_store.put_event(agent_event)
        logger.info("Heartbeat event persisted")

        memories = memory_store.recent_memories(agent_id, limit=100)
        logger.info("Retrieved %d memories for heartbeat context", len(memories))
        memories_json = truncate_str(json_dumps_safe(memories), 6000)

        # Heartbeat-specific prompt (REQ-52)
        system_prompt = llm_client.build_system_prompt(
            mode="heartbeat",
            agent_id=agent_id,
            session_id="system-heartbeat",
            speaker_name=None,
            memories_json=memories_json,
            voice_instructions="This is a scheduled heartbeat. No human is directly speaking.",
            extra_personality_prompt="Evaluate whether any background work is worth doing. Prefer safe, reversible actions.",
        )

        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": json_dumps_safe({"heartbeat": True})},
        ]

        model_client = AwsModelClient.from_env()
        llm_resp = llm_client.chat_with_tools(model_client, messages, TOOLS_SPEC)

        actions, new_memories, reply_text = planner.handle_llm_result(llm_resp, agent_event)
        logger.info("Heartbeat planner produced actions=%d new_memories=%d", len(actions), len(new_memories))

        for m in new_memories:
            memory_store.put_memory(m)

        dispatch_background_actions(actions)

        return {
            "statusCode": 200,
            "headers": {"Content-Type": "application/json"},
            "body": json_dumps_safe(
                {
                    "status": "ok",
                    "reply_text": reply_text,
                    "actions": [a.to_dict() if hasattr(a, "to_dict") else a for a in actions],
                }
            ),
        }
    except Exception as e:
        logger.exception("Heartbeat error")
        return {
            "statusCode": 500,
            "headers": {"Content-Type": "application/json"},
            "body": json_dumps_safe({"status": "error", "error": str(e)}),
        }
