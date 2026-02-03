#!/usr/bin/env python3
"""Clear all LiveKit rooms.

This script connects to LiveKit Cloud and deletes all existing rooms.
Useful for resetting state during development/testing.
"""

import asyncio
import os
import sys
import boto3
import json
import yaml
from livekit.api import LiveKitAPI
from livekit import api


async def clear_all_rooms():
    """Delete all LiveKit rooms."""
    # Load config
    config_path = os.path.expanduser("~/.config/marvain/marvain-config.yaml")
    if not os.path.exists(config_path):
        print(f"ERROR: Config not found at {config_path}")
        return 1

    with open(config_path) as f:
        config = yaml.safe_load(f)

    # Get LiveKit credentials from Secrets Manager
    env_config = config.get("envs", {}).get("dev", {})
    resources = env_config.get("resources", {})
    livekit_secret_arn = resources.get("LiveKitSecretArn")
    livekit_url = env_config.get("sam", {}).get("parameter_overrides", {}).get("LiveKitUrl")

    if not livekit_secret_arn:
        print("ERROR: LiveKitSecretArn not found in config")
        return 1

    sm = boto3.client("secretsmanager", region_name="us-east-1")
    try:
        resp = sm.get_secret_value(SecretId=livekit_secret_arn)
        secret_data = json.loads(resp["SecretString"])
        livekit_api_key = secret_data.get("api_key")
        livekit_api_secret = secret_data.get("api_secret")
    except Exception as e:
        print(f"ERROR: Failed to load LiveKit credentials: {e}")
        return 1

    if not all([livekit_url, livekit_api_key, livekit_api_secret]):
        print("ERROR: Missing LiveKit credentials")
        return 1

    print(f"LiveKit URL: {livekit_url}")
    print(f"API Key: {livekit_api_key[:10]}...")
    print()

    # Connect to LiveKit
    lk = LiveKitAPI(
        url=livekit_url,
        api_key=livekit_api_key,
        api_secret=livekit_api_secret,
    )

    try:
        # List all rooms
        rooms_resp = await lk.room.list_rooms(api.ListRoomsRequest())
        rooms = rooms_resp.rooms

        if not rooms:
            print("✓ No rooms to delete")
            return 0

        print(f"Found {len(rooms)} room(s) to delete:")
        for room in rooms:
            print(f"  - {room.name} (SID: {room.sid}, {room.num_participants} participants)")

        print()
        print("Deleting rooms...")

        # Delete each room
        for room in rooms:
            try:
                await lk.room.delete_room(api.DeleteRoomRequest(room=room.name))
                print(f"  ✓ Deleted: {room.name}")
            except Exception as e:
                print(f"  ✗ Failed to delete {room.name}: {e}")

        # Verify all deleted
        print()
        print("Verifying deletion...")
        rooms_resp = await lk.room.list_rooms(api.ListRoomsRequest())
        remaining = len(rooms_resp.rooms)

        if remaining == 0:
            print("✓ All rooms deleted successfully")
            return 0
        else:
            print(f"✗ {remaining} room(s) still remain")
            return 1

    finally:
        await lk.aclose()


if __name__ == "__main__":
    exit_code = asyncio.run(clear_all_rooms())
    sys.exit(exit_code)

