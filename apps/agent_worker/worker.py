"""LiveKit Agent worker for Marvain.

This runs the realtime voice experience (OpenAI Realtime API) and talks to the Hub
via REST/WebSocket as a "satellite".

Architecture:
- LiveKit "room" name = Marvain "space_id" (UUID)
- One space can have many sequential rooms over time (ephemeral media sessions)
- Transcripts are stored in the Hub's events table, keyed by space_id
- When agent is recreated on rejoin, it can query Hub for prior context (Phase 2)

Based on LiveKit's Voice AI quickstart (realtime model).
"""

from __future__ import annotations

import asyncio
import logging
import os
from typing import TYPE_CHECKING

import requests
from dotenv import load_dotenv
from livekit import agents, rtc
from livekit.agents import Agent, AgentServer, AgentSession, room_io
from livekit.plugins import noise_cancellation, openai

if TYPE_CHECKING:
    pass

load_dotenv(os.getenv("ENV_FILE", ".env"))


def _ensure_stdio_open_and_inheritable() -> None:
    """Ensure stdio fds are valid and inherited by child processes.

    LiveKit Agents uses subprocesses for job execution. If this worker is launched
    with closed or close-on-exec stdio fds (common when daemonized), child Python
    processes can crash at startup with:
      init_sys_streams: can't initialize sys standard streams (Bad file descriptor)

    We defensively:
    - reopen missing fds to /dev/null
    - mark 0/1/2 inheritable so exec() children keep them
    """

    import os

    for fd in (0, 1, 2):
        try:
            os.fstat(fd)
        except OSError:
            newfd = os.open(os.devnull, os.O_RDWR)
            try:
                os.dup2(newfd, fd)
            finally:
                os.close(newfd)

        try:
            os.set_inheritable(fd, True)
        except OSError:
            # Best-effort; if the platform rejects, we'll still have valid fds.
            pass


_ensure_stdio_open_and_inheritable()

logger = logging.getLogger("marvain.agent_worker")

# Delay before disconnecting the agent after the last human leaves.
# Exposed for tests (set to 0) and for tuning in development.
AGENT_DISCONNECT_DELAY_SECONDS = float(os.getenv("AGENT_DISCONNECT_DELAY_SECONDS", "0.5"))

# Hub connection settings
HUB_API_BASE = os.getenv("HUB_API_BASE", "").rstrip("/")
HUB_DEVICE_TOKEN = os.getenv("HUB_DEVICE_TOKEN", "")


def hub_ingest_transcript(
    *,
    space_id: str,
    text: str,
    role: str,
    participant_identity: str | None = None,
    input_modality: str = "voice",
) -> None:
    """Send a transcript chunk to the Hub for persistence.

    Args:
        space_id: The Marvain space ID (from room name)
        text: The transcript text
        role: Either "user" or "assistant"
        participant_identity: The LiveKit participant identity
        input_modality: Either "voice" or "text"
    """
    if not HUB_API_BASE or not HUB_DEVICE_TOKEN or not space_id:
        logger.debug("Skipping transcript ingest: missing HUB_API_BASE, HUB_DEVICE_TOKEN, or space_id")
        return

    try:
        resp = requests.post(
            f"{HUB_API_BASE}/v1/events",
            headers={"Authorization": f"Bearer {HUB_DEVICE_TOKEN}"},
            json={
                "space_id": space_id,
                "type": "transcript_chunk",
                "payload": {
                    "text": text,
                    "role": role,
                    "participant_identity": participant_identity,
                    "source": "livekit_agent_worker",
                    "input_modality": input_modality,
                },
            },
            timeout=3,
        )
        if resp.ok:
            logger.debug(f"Ingested transcript ({role}): {text[:50]}...")
        else:
            logger.warning(f"Failed to ingest transcript: {resp.status_code}")
    except Exception as e:
        # Don't crash the realtime loop
        logger.warning(f"Failed to ingest transcript: {e}")


def hub_create_memory(
    *,
    space_id: str,
    content: str,
    tier: str = "episodic",
    metadata: dict | None = None,
) -> None:
    """Create a memory in the Hub's memory system.

    Args:
        space_id: The Marvain space ID
        content: The memory content text
        tier: Memory tier (episodic, semantic, procedural)
        metadata: Additional metadata (input_modality, role, room_name, etc.)
    """
    if not HUB_API_BASE or not HUB_DEVICE_TOKEN or not space_id:
        logger.debug("Skipping memory creation: missing HUB_API_BASE, HUB_DEVICE_TOKEN, or space_id")
        return

    try:
        resp = requests.post(
            f"{HUB_API_BASE}/v1/memories",
            headers={"Authorization": f"Bearer {HUB_DEVICE_TOKEN}"},
            json={
                "space_id": space_id,
                "tier": tier,
                "content": content,
                "metadata": metadata or {},
            },
            timeout=3,
        )
        if resp.ok:
            logger.debug(f"Created memory ({tier}): {content[:50]}...")
        else:
            logger.warning(f"Failed to create memory: {resp.status_code}")
    except Exception as e:
        logger.warning(f"Failed to create memory: {e}")


def _fetch_space_events(space_id: str, limit: int = 50) -> list[dict]:
    """Fetch recent events for context hydration.

    Returns list of events or empty list on failure.
    """
    if not HUB_API_BASE or not HUB_DEVICE_TOKEN:
        return []
    try:
        resp = requests.get(
            f"{HUB_API_BASE}/v1/spaces/{space_id}/events",
            headers={"Authorization": f"Bearer {HUB_DEVICE_TOKEN}"},
            params={"limit": limit},
            timeout=5,
        )
        if resp.ok:
            return resp.json().get("events", [])
        logger.warning(f"Failed to fetch space events: {resp.status_code}")
    except Exception as e:
        logger.warning(f"Failed to fetch space events: {e}")
    return []


def _fetch_recall_memories(agent_id: str, space_id: str | None, query: str, k: int = 8) -> list[dict]:
    """Fetch relevant memories via semantic search.

    Returns list of memories or empty list on failure.
    """
    if not HUB_API_BASE or not HUB_DEVICE_TOKEN:
        return []
    try:
        resp = requests.post(
            f"{HUB_API_BASE}/v1/recall",
            headers={"Authorization": f"Bearer {HUB_DEVICE_TOKEN}"},
            json={
                "agent_id": agent_id,
                "space_id": space_id,
                "query": query,
                "k": k,
            },
            timeout=10,
        )
        if resp.ok:
            return resp.json().get("memories", [])
        logger.warning(f"Failed to fetch memories: {resp.status_code}")
    except Exception as e:
        logger.warning(f"Failed to fetch memories: {e}")
    return []


def _build_context_block(events: list[dict], memories: list[dict]) -> str:
    """Build context block for agent instructions.

    Summarizes recent conversation and relevant memories.
    """
    parts = []

    # Add memory context if available
    if memories:
        parts.append("## Relevant Memories")
        for mem in memories[:5]:  # Limit to top 5
            tier = mem.get("tier", "")
            content = mem.get("content", "")[:500]  # Truncate long content
            parts.append(f"- [{tier}] {content}")

    # Add recent conversation summary if available
    if events:
        parts.append("\n## Recent Conversation in This Space")
        # Group by role and summarize - show last 10 events max
        for ev in reversed(events[:10]):
            payload = ev.get("payload", {})
            role = payload.get("role", "unknown")
            text = payload.get("text", "")[:200]  # Truncate
            if text and ev.get("type") == "transcript_chunk":
                speaker = "User" if role == "user" else "You"
                parts.append(f"- {speaker}: {text}")

    if not parts:
        return ""

    return "\n".join(parts)


BASE_INSTRUCTIONS = (
    "You are Forge, a persistent personal AI agent and companion. "
    "Be concise, curious, and pragmatic. "
    "If you are unsure, ask a clarifying question. "
    "You may be proactive with suggestions, but avoid being pushy."
)


class ForgeAssistant(Agent):
    def __init__(self, context_block: str = "") -> None:
        if context_block:
            instructions = f"{BASE_INSTRUCTIONS}\n\n# Context from Prior Sessions\n{context_block}"
        else:
            instructions = BASE_INSTRUCTIONS
        super().__init__(instructions=instructions)


# Agent name for explicit dispatch - must match the name in tokens minted by Hub API
AGENT_NAME = "forge"

server = AgentServer()


@server.rtc_session(agent_name=AGENT_NAME)
async def forge_agent(ctx: agents.JobContext):
    """Handle a LiveKit agent session for a Marvain space.

    Room names are ephemeral: "{space_id}:{session_id}". The space_id is passed
    via agent dispatch metadata so we can persist transcripts to the correct space.

    When the last human participant leaves, the agent disconnects from the room.
    Since each join creates a unique room name, agent dispatch is reliable.
    """
    # Connect to LiveKit room
    await ctx.connect()

    # Extract space_id from agent metadata (passed via RoomAgentDispatch in token)
    # Metadata is a JSON string in ctx.job.metadata
    import json as _json

    metadata = _json.loads(ctx.job.metadata or "{}")
    space_id = metadata.get("space_id")
    room_session_id = metadata.get("room_session_id", "unknown")

    if not space_id:
        logger.error(f"No space_id in agent metadata; room={ctx.room.name}, metadata={ctx.job.metadata}")
        return

    agent_id = metadata.get("agent_id")
    logger.info(f"Agent dispatched to space: {space_id} (room: {ctx.room.name}, session: {room_session_id})")

    # Context hydration: fetch prior events and memories for continuity
    context_block = ""
    if agent_id and HUB_API_BASE and HUB_DEVICE_TOKEN:
        logger.info(f"Fetching context for space {space_id}...")
        events = _fetch_space_events(space_id, limit=50)
        memories = _fetch_recall_memories(
            agent_id=agent_id,
            space_id=space_id,
            query="session context recent conversation important facts",
            k=8,
        )
        context_block = _build_context_block(events, memories)
        if context_block:
            logger.info(f"Context hydration: {len(events)} events, {len(memories)} memories")
        else:
            logger.debug("No prior context found for this space")

    # Track whether we should auto-disconnect when humans leave
    should_disconnect_on_empty = True

    def count_human_participants() -> int:
        """Count non-agent participants in the room."""
        count = 0
        for participant in ctx.room.remote_participants.values():
            if participant.kind != rtc.ParticipantKind.PARTICIPANT_KIND_AGENT:
                count += 1
        return count

    def on_participant_disconnected(participant: rtc.RemoteParticipant) -> None:
        """Handle participant disconnection - disconnect agent if no humans remain."""
        if not should_disconnect_on_empty:
            return

        # Skip if an agent disconnected (we only care about humans leaving)
        if participant.kind == rtc.ParticipantKind.PARTICIPANT_KIND_AGENT:
            logger.debug(f"Agent participant disconnected: {participant.identity}")
            return

        logger.info(f"Human participant disconnected: {participant.identity}")

        # Check if any human participants remain
        human_count = count_human_participants()
        logger.info(f"Remaining human participants: {human_count}")

        if human_count == 0:
            logger.info(f"No human participants remain in room {space_id}, agent disconnecting...")
            # Schedule disconnect - don't block the event handler
            asyncio.create_task(_disconnect_agent())

    async def _disconnect_agent() -> None:
        """Disconnect the agent from the room."""
        try:
            # Small delay to allow any final cleanup
            await asyncio.sleep(AGENT_DISCONNECT_DELAY_SECONDS)
            await ctx.room.disconnect()
            logger.info(f"Agent disconnected from room {space_id}")
        except Exception as e:
            logger.warning(f"Error disconnecting agent from room {space_id}: {e}")

    # Subscribe to participant disconnection events
    ctx.room.on("participant_disconnected", on_participant_disconnected)

    # Realtime model (speech-to-speech). Configure voice via env.
    voice = os.getenv("OPENAI_VOICE", "alloy")
    model = os.getenv("OPENAI_REALTIME_MODEL", "gpt-4o-realtime-preview")

    session = AgentSession(
        llm=openai.realtime.RealtimeModel(
            model=model,
            voice=voice,
        )
    )

    # Wire up transcript ingestion - forward conversation items to Hub
    from livekit.agents.voice import ConversationItemAddedEvent

    def on_conversation_item_added(event: ConversationItemAddedEvent) -> None:
        """Forward transcript chunks to the Hub for persistence."""
        item = event.item
        # Only process ChatMessage items, skip type discriminators
        if not hasattr(item, "role") or not hasattr(item, "text_content"):
            return

        role = item.role
        text = item.text_content

        # Only ingest user and assistant messages with content
        if role not in ("user", "assistant") or not text:
            return

        logger.debug(f"Conversation item ({role}): {text[:50]}...")
        hub_ingest_transcript(
            space_id=space_id,
            text=text,
            role=role,
            participant_identity=None,
            input_modality="voice",
        )
        # Auto-save as episodic memory
        hub_create_memory(
            space_id=space_id,
            content=text,
            tier="episodic",
            metadata={
                "role": role,
                "input_modality": "voice",
                "room_name": ctx.room.name,
                "room_session_id": room_session_id,
            },
        )

    session.on("conversation_item_added", on_conversation_item_added)

    # Handle typed chat messages from data channel
    import json as _json_dc

    @ctx.room.on("data_received")
    def on_data_received(data: rtc.DataPacket) -> None:
        """Handle typed chat messages from participants.

        When a user types a message in the chat UI, it's sent via LiveKit's
        data channel. We parse it and inject it into the conversation as if
        the user had spoken it.
        """
        try:
            payload = data.data.decode("utf-8")
            msg = _json_dc.loads(payload)

            # Only handle chat messages
            if msg.get("type") != "chat":
                return

            text = msg.get("text", "").strip()
            if not text:
                return

            sender = data.participant.identity if data.participant else "user"
            logger.info(f"Received typed chat from {sender}: {text[:50]}...")

            # Ingest to Hub for persistence
            hub_ingest_transcript(
                space_id=space_id,
                text=text,
                role="user",
                participant_identity=sender,
                input_modality="text",
            )
            # Auto-save as episodic memory
            hub_create_memory(
                space_id=space_id,
                content=text,
                tier="episodic",
                metadata={
                    "role": "user",
                    "input_modality": "text",
                    "room_name": ctx.room.name,
                    "room_session_id": room_session_id,
                    "participant_identity": sender,
                },
            )

            # Inject the typed message into the agent's conversation
            # Use generate_reply with the user's text as instructions
            asyncio.create_task(_handle_typed_message(text, sender))

        except Exception as e:
            logger.warning(f"Failed to process data channel message: {e}")

    async def _handle_typed_message(text: str, sender: str) -> None:
        """Process a typed chat message and generate a response.

        Interrupts any ongoing speech before responding to avoid overlapping voices.
        Uses user_input parameter to properly inject the message into the conversation
        history, so the agent responds to the typed message (not the last voice input).
        """
        try:
            # Interrupt any ongoing speech to avoid overlapping voices
            session.interrupt()

            # Small delay to let the interruption take effect
            await asyncio.sleep(0.1)

            # Use generate_reply with user_input to inject the typed message
            # into the conversation as a proper user turn. This ensures the agent
            # responds to this message, not the last voice input.
            await session.generate_reply(user_input=text)
        except Exception as e:
            logger.warning(f"Failed to generate reply for typed message: {e}")

    await session.start(
        room=ctx.room,
        agent=ForgeAssistant(context_block=context_block),
        room_options=room_io.RoomOptions(
            audio_input=room_io.AudioInputOptions(
                noise_cancellation=lambda params: noise_cancellation.BVCTelephony()
                if params.participant.kind == rtc.ParticipantKind.PARTICIPANT_KIND_SIP
                else noise_cancellation.BVC(),
            ),
            # Disable auto-close so our disconnect handler fires properly
            close_on_disconnect=False,
            # Do NOT delete room on close - the Hub API handles room deletion
            # before minting tokens. This ensures a single deletion point and
            # avoids race conditions with LiveKit Cloud's dispatch logic.
            delete_room_on_close=False,
        ),
    )

    # Initial greeting
    await session.generate_reply(instructions="Greet the user and offer your assistance. Start by speaking in English.")


if __name__ == "__main__":
    agents.cli.run_app(server)
