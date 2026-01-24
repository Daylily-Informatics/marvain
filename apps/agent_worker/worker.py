"""LiveKit Agent worker (skeleton).

This runs the realtime voice experience (OpenAI Realtime API) and talks to the Hub
via REST/WebSocket as a "satellite".

For fastest iteration, run this locally on your laptop.
Later, ship it as a container to ECS/Fargate.

Based on LiveKit's Voice AI quickstart (realtime model).
"""

from __future__ import annotations

import os
import requests

from dotenv import load_dotenv
from livekit import agents, rtc
from livekit.agents import AgentServer, AgentSession, Agent, room_io
from livekit.plugins import openai, noise_cancellation

load_dotenv(os.getenv("ENV_FILE", ".env"))


HUB_API_BASE = os.getenv("HUB_API_BASE", "").rstrip("/")
HUB_DEVICE_TOKEN = os.getenv("HUB_DEVICE_TOKEN", "")
SPACE_ID = os.getenv("SPACE_ID", "")


def hub_ingest_transcript(text: str, *, participant_identity: str | None = None) -> None:
    """Send a transcript chunk to the Hub for persistence + planning.

    NOTE: This is a convenience function. You still need to wire it to
    LiveKit transcript callbacks (left as TODO).
    """
    if not HUB_API_BASE or not HUB_DEVICE_TOKEN or not SPACE_ID:
        return

    try:
        requests.post(
            f"{HUB_API_BASE}/v1/events",
            headers={"Authorization": f"Bearer {HUB_DEVICE_TOKEN}"},
            json={
                "space_id": SPACE_ID,
                "type": "transcript_chunk",
                "payload": {
                    "text": text,
                    "participant_identity": participant_identity,
                    "source": "livekit_agent_worker",
                },
            },
            timeout=3,
        )
    except Exception:
        # don't crash the realtime loop
        pass


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


server = AgentServer()


@server.rtc_session()
async def forge_agent(ctx: agents.JobContext):
    # Connect to LiveKit room.
    await ctx.connect()

    # Realtime model (speech-to-speech). Configure voice via env.
    voice = os.getenv("OPENAI_VOICE", "alloy")
    model = os.getenv("OPENAI_REALTIME_MODEL", "gpt-realtime")

    session = AgentSession(
        llm=openai.realtime.RealtimeModel(
            model=model,
            voice=voice,
        )
    )

    await session.start(
        room=ctx.room,
        agent=ForgeAssistant(),
        room_options=room_io.RoomOptions(
            audio_input=room_io.AudioInputOptions(
                noise_cancellation=lambda params: noise_cancellation.BVCTelephony()
                if params.participant.kind == rtc.ParticipantKind.PARTICIPANT_KIND_SIP
                else noise_cancellation.BVC(),
            ),
        ),
    )

    # Initial greeting
    await session.generate_reply(
        instructions="Greet the user and offer your assistance. Start by speaking in English."
    )

    # TODO: subscribe to transcript/turn events and forward final user utterances to the Hub:
    # - Identify participant (voice/face identity happens in the Hub)
    # - Call hub_ingest_transcript(final_text, participant_identity=...)


if __name__ == "__main__":
    agents.cli.run_app(server)
