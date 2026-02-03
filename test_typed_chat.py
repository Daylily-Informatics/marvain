#!/usr/bin/env python3
"""Test script to verify typed chat messages reach the LiveKit agent."""

import asyncio
import json
import requests
import urllib3

# Suppress InsecureRequestWarning for self-signed cert
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

from livekit import rtc

SPACE_ID = "c2e34ba8-8819-489a-b9b0-2e604a33d89b"
HUB_URL = "https://127.0.0.1:8084"


async def test_chat():
    # Get token from Hub API
    print("Getting token from Hub API...")
    resp = requests.post(
        f"{HUB_URL}/api/livekit/token",
        json={"space_id": SPACE_ID, "identity": "test-script-user"},
        verify=False,
        timeout=10,
    )
    print(f"Token response: {resp.status_code}")
    if resp.status_code != 200:
        print(resp.text)
        return

    data = resp.json()
    token = data["token"]
    url = data["url"]
    room_name = data["room"]

    print(f"Got token for room: {room_name}")
    print(f"LiveKit URL: {url}")

    room = rtc.Room()

    @room.on("data_received")
    def on_data(pkt: rtc.DataPacket):
        try:
            msg = json.loads(pkt.data.decode())
            print(f"[DATA] Received: {msg}")
        except Exception:
            print(f"[DATA] Raw: {pkt.data}")

    @room.on("participant_connected")
    def on_participant(participant: rtc.RemoteParticipant):
        print(f"[ROOM] Participant joined: {participant.identity}")

    print("Connecting to room...")
    await room.connect(url, token)
    print(f"Connected! State: {room.connection_state}")

    # List participants
    print(f"Remote participants: {[p.identity for p in room.remote_participants.values()]}")

    # Wait for agent to join
    print("Waiting 3s for agent to join...")
    await asyncio.sleep(3)

    print(f"Remote participants now: {[p.identity for p in room.remote_participants.values()]}")

    # Send a chat message
    msg = {"type": "chat", "text": "Hello from test script! What is 2+2?", "ts": 1234567890}
    payload = json.dumps(msg).encode()
    print(f"Sending chat message: {msg['text']}")
    await room.local_participant.publish_data(payload, reliable=True)

    # Wait for agent to process and respond
    print("Waiting 8s for agent response...")
    await asyncio.sleep(8)

    await room.disconnect()
    print("Disconnected. Check .marvain-agent.log for 'Received typed chat'")


if __name__ == "__main__":
    asyncio.run(test_chat())

