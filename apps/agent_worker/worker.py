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
import requests
from typing import TYPE_CHECKING

from dotenv import load_dotenv
from livekit import agents, rtc
from livekit.agents import AgentServer, AgentSession, Agent, room_io
from livekit.plugins import openai, noise_cancellation

if TYPE_CHECKING:
    from livekit.agents.llm import ChatContext

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
) -> None:
    """Send a transcript chunk to the Hub for persistence.

    Args:
        space_id: The Marvain space ID (from room name)
        text: The transcript text
        role: Either "user" or "assistant"
        participant_identity: The LiveKit participant identity
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


class ForgeAssistant(Agent):
    def __init__(self) -> None:
        super().__init__(
            instructions=(
                "You are Forge, a persistent personal AI agent and companion. "
                "Be concise, curious, and pragmatic. "
                "If you are unsure, ask a clarifying question. "
                "You may be proactive with suggestions, but avoid being pushy."
            )
        )


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

    logger.info(f"Agent dispatched to space: {space_id} (room: {ctx.room.name}, session: {room_session_id})")

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
            participant_identity=None,  # Could be enhanced later
        )

    session.on("conversation_item_added", on_conversation_item_added)

    await session.start(
        room=ctx.room,
        agent=ForgeAssistant(),
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
    await session.generate_reply(
        instructions="Greet the user and offer your assistance. Start by speaking in English."
    )


if __name__ == "__main__":
    agents.cli.run_app(server)
