"""Location Node for Marvain (LiveKit AV publishing/consuming).

Extends the remote satellite concept to represent a physical location:
- joins a stable LiveKit room for a space (room == space_id)
- publishes microphone audio (and later camera video)
- subscribes to remote audio (agent speech) and plays it to speakers
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
from dataclasses import dataclass
from typing import Any

import aiohttp

logger = logging.getLogger("marvain.location_node")


@dataclass(frozen=True)
class LocationNodeConfig:
    rest_url: str
    device_token: str
    space_id: str

    mode: str = "persistent"  # triggered|persistent
    publish_audio: bool = True
    publish_video: bool = False
    subscribe_audio: bool = True

    audio_in_device: int | str | None = None
    audio_out_device: int | str | None = None

    sample_rate: int = 48000
    channels: int = 1
    frame_size_ms: int = 20


class LocationNode:
    def __init__(self, cfg: LocationNodeConfig) -> None:
        self.cfg = cfg
        self._stop = asyncio.Event()
        self._room: Any = None
        self._tasks: list[asyncio.Task] = []

    async def stop(self) -> None:
        self._stop.set()
        for t in list(self._tasks):
            t.cancel()
        self._tasks.clear()
        try:
            if self._room is not None:
                await self._room.disconnect()
        except Exception:
            pass

    async def run(self) -> None:
        mode = str(self.cfg.mode or "persistent").strip().lower()
        if mode != "persistent":
            logger.warning("LocationNode mode=%s is not implemented yet; using persistent", mode)
        await self._run_persistent()

    async def _mint_device_token(self) -> dict[str, Any]:
        url = str(self.cfg.rest_url).rstrip("/") + "/v1/livekit/device-token"
        headers = {"Authorization": f"Bearer {self.cfg.device_token}", "Content-Type": "application/json"}
        body = {
            "space_id": self.cfg.space_id,
            "room_mode": "stable",
            "capabilities": {
                "publish_audio": bool(self.cfg.publish_audio),
                "publish_video": bool(self.cfg.publish_video),
                "subscribe_audio": bool(self.cfg.subscribe_audio),
            },
        }
        async with aiohttp.ClientSession() as session:
            async with session.post(url, headers=headers, json=body, timeout=20) as resp:
                txt = await resp.text()
                if resp.status >= 400:
                    raise RuntimeError(f"device-token failed: status={resp.status} body={txt[:300]}")
                return json.loads(txt or "{}")

    async def _run_persistent(self) -> None:
        from livekit import rtc  # type: ignore

        token_out = await self._mint_device_token()
        lk_url = str(token_out.get("url") or "").strip()
        lk_token = str(token_out.get("token") or "").strip()
        room_name = str(token_out.get("room") or "").strip()
        identity = str(token_out.get("identity") or "").strip()
        if not lk_url or not lk_token or not room_name:
            raise RuntimeError("LiveKit device-token response missing url/token/room")

        logger.info("Connecting to LiveKit url=%s room=%s identity=%s", lk_url, room_name, identity)

        room = rtc.Room()
        self._room = room

        # Playback: subscribe to remote audio tracks
        if self.cfg.subscribe_audio:
            room.on("track_subscribed", self._on_track_subscribed)

        await room.connect(lk_url, lk_token, rtc.RoomOptions(auto_subscribe=True))
        logger.info("LiveKit connected")

        if self.cfg.publish_audio:
            await self._start_audio_publish(room)

        # TODO: publish_video when OpenCV/RTSP capture is available.

        # Keep alive until stop.
        while not self._stop.is_set():
            await asyncio.sleep(0.5)

        await self.stop()

    async def _start_audio_publish(self, room: Any) -> None:
        from livekit import rtc  # type: ignore

        import sounddevice as sd  # type: ignore

        sample_rate = int(self.cfg.sample_rate)
        channels = int(self.cfg.channels)

        # Use a small queue so we apply backpressure when capture is faster than publish.
        q: asyncio.Queue[bytes] = asyncio.Queue(maxsize=50)
        loop = asyncio.get_running_loop()

        def _cb(indata: bytes, frames: int, time_info: Any, status: Any) -> None:  # noqa: ARG001
            if status:
                logger.debug("audio in status: %s", status)
            try:
                loop.call_soon_threadsafe(q.put_nowait, bytes(indata))
            except Exception:
                # Drop on overload; LiveKit will recover.
                pass

        blocksize = int(sample_rate * (int(self.cfg.frame_size_ms) / 1000.0))
        stream = sd.RawInputStream(
            samplerate=sample_rate,
            channels=channels,
            dtype="int16",
            blocksize=blocksize,
            callback=_cb,
            device=self.cfg.audio_in_device,
        )
        stream.start()
        logger.info("Audio capture started (sr=%s ch=%s device=%r)", sample_rate, channels, self.cfg.audio_in_device)

        audio_source = rtc.AudioSource(sample_rate=sample_rate, num_channels=channels)
        track = rtc.LocalAudioTrack.create_audio_track("mic", audio_source)
        await room.local_participant.publish_track(track)

        async def _pump() -> None:
            try:
                while not self._stop.is_set():
                    chunk = await q.get()
                    if not chunk:
                        continue
                    samples_per_channel = int(len(chunk) / (2 * channels))
                    if samples_per_channel <= 0:
                        continue
                    frame = rtc.AudioFrame(chunk, sample_rate, channels, samples_per_channel)
                    audio_source.capture_frame(frame)
            finally:
                try:
                    stream.stop()
                    stream.close()
                except Exception:
                    pass

        self._tasks.append(asyncio.create_task(_pump(), name="location_node.audio_publish"))

    def _on_track_subscribed(self, track: Any, publication: Any, participant: Any) -> None:  # noqa: ARG002
        # Run playback loops in the main event loop.
        try:
            from livekit import rtc  # type: ignore

            if track.kind != rtc.TrackKind.KIND_AUDIO:
                return
        except Exception:
            return

        self._tasks.append(asyncio.create_task(self._play_remote_audio(track), name="location_node.audio_playback"))

    async def _play_remote_audio(self, track: Any) -> None:
        from livekit import rtc  # type: ignore

        import sounddevice as sd  # type: ignore

        sample_rate = int(self.cfg.sample_rate)
        channels = int(self.cfg.channels)

        out_stream = sd.RawOutputStream(
            samplerate=sample_rate,
            channels=channels,
            dtype="int16",
            device=self.cfg.audio_out_device,
        )
        out_stream.start()
        logger.info("Audio playback started (sr=%s ch=%s device=%r)", sample_rate, channels, self.cfg.audio_out_device)

        audio_stream = rtc.AudioStream.from_track(track=track, sample_rate=sample_rate, num_channels=channels)
        try:
            async for frame in audio_stream:
                if self._stop.is_set():
                    break
                try:
                    out_stream.write(bytes(frame.data))
                except Exception:
                    # Best-effort; don't crash playback for transient device errors.
                    pass
        finally:
            try:
                await audio_stream.aclose()
            except Exception:
                pass
            try:
                out_stream.stop()
                out_stream.close()
            except Exception:
                pass

