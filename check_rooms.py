#!/usr/bin/env python3
"""Clear all LiveKit rooms."""
import os
import asyncio
from livekit.api import LiveKitAPI, api
from dotenv import load_dotenv

load_dotenv()

async def main():
    livekit_url = os.getenv('LIVEKIT_URL')
    livekit_api_key = os.getenv('LIVEKIT_API_KEY')
    livekit_api_secret = os.getenv('LIVEKIT_API_SECRET')

    if not all([livekit_url, livekit_api_key, livekit_api_secret]):
        print("ERROR: Missing LiveKit credentials")
        return

    lk = LiveKitAPI(url=livekit_url, api_key=livekit_api_key, api_secret=livekit_api_secret)
    try:
        # List all rooms
        rooms = await lk.room.list_rooms(api.ListRoomsRequest())
        print(f"Found {len(rooms.rooms)} rooms to delete:")

        # Delete each room
        for room in rooms.rooms:
            print(f"  Deleting: {room.name} (SID: {room.sid}, {room.num_participants} participants)")
            await lk.room.delete_room(api.DeleteRoomRequest(room=room.name))

        # Verify deletion
        rooms_after = await lk.room.list_rooms(api.ListRoomsRequest())
        print(f"\nVerification: {len(rooms_after.rooms)} rooms remaining")
        if len(rooms_after.rooms) == 0:
            print("✓ All rooms deleted successfully")
        else:
            print("⚠ Some rooms still exist:")
            for room in rooms_after.rooms:
                print(f"  - {room.name}")
    finally:
        await lk.aclose()

if __name__ == '__main__':
    asyncio.run(main())

