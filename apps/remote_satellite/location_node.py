"""Location Node for Marvain (LiveKit AV publishing/consuming).

Extends the remote satellite concept to represent a physical location:
- joins a stable LiveKit room for a space (room == space_id)
- publishes microphone audio (and later camera video)
- subscribes to remote audio (agent speech) and plays it to speakers
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import math
import time
import wave
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

    # Triggering / monitoring.
    vad_enabled: bool = True
    motion_enabled: bool = False
    idle_disconnect_seconds: int = 60
    audio_activity_rms_threshold: float = 0.02  # 0..1 (normalized int16 RMS)
    motion_activity_threshold: float = 0.03  # 0..1 (mean grayscale delta)

    # Recognition artifacts (best-effort).
    voice_sample_seconds: int = 3
    voice_sample_interval_seconds: int = 30
    face_snapshot_interval_seconds: int = 30
    sound_event_interval_seconds: int = 5
    motion_event_interval_seconds: int = 5
    enroll_person_id: str | None = None

    # Video capture.
    camera_usb_index: int | None = None
    camera_rtsp_url: str | None = None
    video_fps: int = 10
    video_width: int | None = None
    video_height: int | None = None


class LocationNode:
    def __init__(self, cfg: LocationNodeConfig) -> None:
        self.cfg = cfg
        self._stop = asyncio.Event()
        self._room: Any = None
        self._capture_tasks: list[asyncio.Task] = []
        self._session_tasks: list[asyncio.Task] = []

        self._connected = False
        self._last_activity_s: float = 0.0
        self._activity_event = asyncio.Event()

        # LiveKit publish handles (set while connected).
        self._audio_source: Any | None = None
        self._video_source: Any | None = None

    async def stop(self) -> None:
        self._stop.set()
        for t in list(self._capture_tasks) + list(self._session_tasks):
            t.cancel()
        self._capture_tasks.clear()
        self._session_tasks.clear()
        try:
            if self._room is not None:
                await self._room.disconnect()
        except Exception:
            pass
        self._connected = False
        self._room = None
        self._audio_source = None
        self._video_source = None

    async def run(self) -> None:
        mode = str(self.cfg.mode or "persistent").strip().lower()
        if mode not in {"persistent", "triggered"}:
            logger.warning("LocationNode mode=%s is not supported; using persistent", mode)
            mode = "persistent"

        # Start capture loops once. These loops can feed both monitoring and publishing.
        await self._start_capture_loops()

        if mode == "persistent":
            await self._mark_activity()
            await self._ensure_connected()
            while not self._stop.is_set():
                await asyncio.sleep(0.5)
            await self.stop()
            return

        # triggered mode
        idle_s = max(1, int(self.cfg.idle_disconnect_seconds))
        while not self._stop.is_set():
            if not self._connected:
                # Wait for activity (sound/motion) to join LiveKit.
                await self._activity_event.wait()
                self._activity_event.clear()
                if self._stop.is_set():
                    break
                await self._ensure_connected()

            # Connected: disconnect when idle.
            while self._connected and not self._stop.is_set():
                if (time.time() - self._last_activity_s) >= idle_s:
                    await self._disconnect()
                    break
                await asyncio.sleep(0.5)

        await self.stop()

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

    async def _ensure_connected(self) -> None:
        if self._connected:
            return
        await self._connect()

    async def _connect(self) -> None:
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
        self._connected = True
        await self._mark_activity()
        logger.info("LiveKit connected")

        if self.cfg.publish_audio:
            self._audio_source = rtc.AudioSource(
                sample_rate=int(self.cfg.sample_rate), num_channels=int(self.cfg.channels)
            )
            track = rtc.LocalAudioTrack.create_audio_track("mic", self._audio_source)
            await room.local_participant.publish_track(track)

        if self.cfg.publish_video:
            self._video_source = rtc.VideoSource()
            vtrack = rtc.LocalVideoTrack.create_video_track("cam", self._video_source)
            await room.local_participant.publish_track(vtrack)

        # Best-effort timeline event for visibility.
        await self._emit_simple_event(
            "location.joined",
            {"room": room_name, "identity": identity, "mode": str(self.cfg.mode or "persistent")},
        )

    async def _disconnect(self) -> None:
        if not self._connected:
            return
        # Best-effort visibility.
        await self._emit_simple_event("location.left", {"mode": str(self.cfg.mode or "persistent")})

        for t in list(self._session_tasks):
            t.cancel()
        self._session_tasks.clear()

        try:
            if self._room is not None:
                await self._room.disconnect()
        except Exception:
            pass

        self._connected = False
        self._room = None
        self._audio_source = None
        self._video_source = None

    def _on_track_subscribed(self, track: Any, publication: Any, participant: Any) -> None:  # noqa: ARG002
        # Run playback loops in the main event loop.
        try:
            from livekit import rtc  # type: ignore

            if track.kind != rtc.TrackKind.KIND_AUDIO:
                return
        except Exception:
            return

        self._session_tasks.append(
            asyncio.create_task(self._play_remote_audio(track), name="location_node.audio_playback")
        )

    async def _play_remote_audio(self, track: Any) -> None:
        import sounddevice as sd  # type: ignore
        from livekit import rtc  # type: ignore

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

    async def _start_capture_loops(self) -> None:
        """Start local A/V capture loops (best-effort).

        These loops run regardless of LiveKit connection state. When connected, they
        publish to LiveKit sources. They also drive triggered-mode activity and
        best-effort monitoring events/artifacts.
        """

        # Audio capture is needed for either publish_audio or VAD monitoring.
        if self.cfg.publish_audio or self.cfg.vad_enabled:
            self._capture_tasks.append(
                asyncio.create_task(self._audio_capture_loop(), name="location_node.audio_capture")
            )

        # Video capture is needed for either publish_video or motion monitoring.
        if self.cfg.publish_video or self.cfg.motion_enabled:
            self._capture_tasks.append(
                asyncio.create_task(self._video_capture_loop(), name="location_node.video_capture")
            )

    async def _mark_activity(self) -> None:
        self._last_activity_s = time.time()
        self._activity_event.set()

    def _rms_norm_int16(self, pcm: bytes) -> float:
        if not pcm:
            return 0.0
        # Avoid numpy dependency; int16 PCM.
        import array

        a = array.array("h")
        with contextlib.suppress(Exception):
            a.frombytes(pcm)
        if not a:
            return 0.0
        # Normalize RMS to [0,1] by dividing by int16 max.
        s = 0.0
        for v in a:
            s += float(v) * float(v)
        mean = s / float(len(a))
        rms = math.sqrt(mean) / 32768.0
        return float(rms)

    async def _emit_simple_event(self, ev_type: str, payload: dict[str, Any]) -> None:
        """Best-effort /v1/events without artifacts."""
        try:
            url = str(self.cfg.rest_url).rstrip("/") + "/v1/events"
            headers = {"Authorization": f"Bearer {self.cfg.device_token}", "Content-Type": "application/json"}
            body = {"space_id": self.cfg.space_id, "type": ev_type, "payload": payload}
            async with aiohttp.ClientSession() as session:
                async with session.post(url, headers=headers, json=body, timeout=10) as resp:
                    if resp.status >= 400:
                        txt = await resp.text()
                        logger.debug("emit_event failed: type=%s status=%s body=%s", ev_type, resp.status, txt[:200])
        except Exception as exc:
            logger.debug("emit_event failed: %s", exc)

    async def _presign_put(self, *, filename: str, content_type: str, purpose: str = "recognition") -> dict[str, Any]:
        url = str(self.cfg.rest_url).rstrip("/") + "/v1/artifacts/presign"
        headers = {"Authorization": f"Bearer {self.cfg.device_token}", "Content-Type": "application/json"}
        body = {"filename": filename, "content_type": content_type, "purpose": purpose}
        async with aiohttp.ClientSession() as session:
            async with session.post(url, headers=headers, json=body, timeout=10) as resp:
                txt = await resp.text()
                if resp.status >= 400:
                    raise RuntimeError(f"presign failed: status={resp.status} body={txt[:200]}")
                return json.loads(txt or "{}")

    async def _upload_put(self, *, upload_url: str, data: bytes, content_type: str) -> None:
        async with aiohttp.ClientSession() as session:
            async with session.put(upload_url, data=data, headers={"Content-Type": content_type}, timeout=30) as resp:
                if resp.status >= 400:
                    txt = await resp.text()
                    raise RuntimeError(f"upload failed: status={resp.status} body={txt[:200]}")

    async def _emit_artifact_event(
        self,
        *,
        ev_type: str,
        data: bytes,
        filename: str,
        content_type: str,
        extra_payload: dict[str, Any] | None = None,
    ) -> None:
        """Upload bytes to S3 via presign and ingest a hub event referencing it."""
        try:
            presign = await self._presign_put(filename=filename, content_type=content_type, purpose="recognition")
            upload_url = str(presign.get("upload_url") or "").strip()
            bucket = str(presign.get("bucket") or "").strip()
            key = str(presign.get("key") or "").strip()
            if not upload_url or not bucket or not key:
                raise RuntimeError("presign response missing upload_url/bucket/key")

            await self._upload_put(upload_url=upload_url, data=data, content_type=content_type)

            payload: dict[str, Any] = {
                "artifact_bucket": bucket,
                "artifact_key": key,
                "content_type": content_type,
            }
            if self.cfg.enroll_person_id:
                payload["enroll_person_id"] = str(self.cfg.enroll_person_id)
            if extra_payload:
                payload.update(extra_payload)
            await self._emit_simple_event(ev_type, payload)
        except Exception as exc:
            logger.debug("artifact event failed type=%s: %s", ev_type, exc)

    async def _audio_capture_loop(self) -> None:
        import sounddevice as sd  # type: ignore
        from livekit import rtc  # type: ignore

        sample_rate = int(self.cfg.sample_rate)
        channels = int(self.cfg.channels)
        blocksize = int(sample_rate * (int(self.cfg.frame_size_ms) / 1000.0))

        q: asyncio.Queue[bytes] = asyncio.Queue(maxsize=200)
        loop = asyncio.get_running_loop()

        def _cb(indata: bytes, frames: int, time_info: Any, status: Any) -> None:  # noqa: ARG001
            if status:
                logger.debug("audio in status: %s", status)
            try:
                loop.call_soon_threadsafe(q.put_nowait, bytes(indata))
            except Exception:
                pass

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

        last_sound_event_s = 0.0
        last_voice_sample_s = 0.0
        recording = False
        record_buf = bytearray()
        recorded_samples = 0
        target_samples = max(1, int(sample_rate * max(1, int(self.cfg.voice_sample_seconds))))

        try:
            while not self._stop.is_set():
                chunk = await q.get()
                if not chunk:
                    continue

                # Publish to LiveKit if connected.
                if self._connected and self._audio_source is not None and self.cfg.publish_audio:
                    samples_per_channel = int(len(chunk) / (2 * channels))
                    if samples_per_channel > 0:
                        frame = rtc.AudioFrame(chunk, sample_rate, channels, samples_per_channel)
                        self._audio_source.capture_frame(frame)

                # Drive VAD and activity.
                if self.cfg.vad_enabled:
                    rms = self._rms_norm_int16(chunk)
                    if rms >= float(self.cfg.audio_activity_rms_threshold):
                        await self._mark_activity()
                        now = time.time()
                        if (now - last_sound_event_s) >= float(self.cfg.sound_event_interval_seconds):
                            last_sound_event_s = now
                            asyncio.create_task(
                                self._emit_simple_event(
                                    "sound.detected",
                                    {"rms": rms, "threshold": float(self.cfg.audio_activity_rms_threshold)},
                                )
                            )

                        # Voice sample clip (best-effort, throttled).
                        if (not recording) and (now - last_voice_sample_s) >= float(
                            self.cfg.voice_sample_interval_seconds
                        ):
                            recording = True
                            record_buf = bytearray()
                            recorded_samples = 0
                            last_voice_sample_s = now

                    if recording:
                        record_buf.extend(chunk)
                        recorded_samples += int(len(chunk) / (2 * channels))
                        if recorded_samples >= target_samples:
                            recording = False
                            pcm_bytes = bytes(record_buf[: target_samples * channels * 2])
                            wav_bytes = self._pcm_to_wav(
                                pcm_bytes=pcm_bytes, sample_rate=sample_rate, channels=channels
                            )
                            asyncio.create_task(
                                self._emit_artifact_event(
                                    ev_type="voice.sample",
                                    data=wav_bytes,
                                    filename="voice_sample.wav",
                                    content_type="audio/wav",
                                    extra_payload={"sample_rate": sample_rate, "channels": channels},
                                )
                            )
        finally:
            with contextlib.suppress(Exception):
                stream.stop()
                stream.close()

    def _pcm_to_wav(self, *, pcm_bytes: bytes, sample_rate: int, channels: int) -> bytes:
        buf = __import__("io").BytesIO()
        with wave.open(buf, "wb") as wf:
            wf.setnchannels(int(channels))
            wf.setsampwidth(2)  # int16
            wf.setframerate(int(sample_rate))
            wf.writeframes(pcm_bytes)
        return buf.getvalue()

    async def _video_capture_loop(self) -> None:
        if not (self.cfg.publish_video or self.cfg.motion_enabled):
            return
        try:
            import cv2  # type: ignore
        except Exception:
            logger.warning("OpenCV is not installed; video capture disabled")
            return

        # Choose camera source.
        src: Any
        if self.cfg.camera_rtsp_url:
            src = str(self.cfg.camera_rtsp_url)
        else:
            src = int(self.cfg.camera_usb_index if self.cfg.camera_usb_index is not None else 0)

        cap = cv2.VideoCapture(src)
        if self.cfg.video_width:
            cap.set(cv2.CAP_PROP_FRAME_WIDTH, int(self.cfg.video_width))
        if self.cfg.video_height:
            cap.set(cv2.CAP_PROP_FRAME_HEIGHT, int(self.cfg.video_height))

        if not cap.isOpened():
            logger.warning("Failed to open camera source=%r", src)
            return

        fps = max(1, int(self.cfg.video_fps))
        frame_interval = 1.0 / float(fps)
        prev_gray = None

        last_motion_event_s = 0.0
        last_face_snapshot_s = 0.0

        try:
            while not self._stop.is_set():
                t0 = time.time()
                ok, frame_bgr = cap.read()
                if not ok or frame_bgr is None:
                    await asyncio.sleep(0.2)
                    continue

                # Motion detection.
                if self.cfg.motion_enabled:
                    gray = cv2.cvtColor(frame_bgr, cv2.COLOR_BGR2GRAY)
                    if prev_gray is not None:
                        diff = cv2.absdiff(prev_gray, gray)
                        score = float(diff.mean() / 255.0)
                        if score >= float(self.cfg.motion_activity_threshold):
                            await self._mark_activity()
                            now = time.time()
                            if (now - last_motion_event_s) >= float(self.cfg.motion_event_interval_seconds):
                                last_motion_event_s = now
                                asyncio.create_task(
                                    self._emit_simple_event(
                                        "motion.detected",
                                        {
                                            "score": score,
                                            "threshold": float(self.cfg.motion_activity_threshold),
                                        },
                                    )
                                )
                            if (now - last_face_snapshot_s) >= float(self.cfg.face_snapshot_interval_seconds):
                                last_face_snapshot_s = now
                                try:
                                    ok2, jpg = cv2.imencode(".jpg", frame_bgr, [int(cv2.IMWRITE_JPEG_QUALITY), 90])
                                    if ok2:
                                        asyncio.create_task(
                                            self._emit_artifact_event(
                                                ev_type="face.snapshot",
                                                data=bytes(jpg.tobytes()),
                                                filename="face_snapshot.jpg",
                                                content_type="image/jpeg",
                                                extra_payload={"motion_score": score},
                                            )
                                        )
                                except Exception:
                                    pass
                    prev_gray = gray

                # Publish video to LiveKit.
                if self._connected and self._video_source is not None and self.cfg.publish_video:
                    try:
                        from livekit import rtc  # type: ignore

                        rgb = cv2.cvtColor(frame_bgr, cv2.COLOR_BGR2RGB)
                        h, w = rgb.shape[:2]
                        vf = rtc.VideoFrame(int(w), int(h), rtc.VideoBufferType.RGB24, rgb.tobytes())
                        self._video_source.capture_frame(vf)
                    except Exception:
                        pass

                dt = time.time() - t0
                if dt < frame_interval:
                    await asyncio.sleep(frame_interval - dt)
        finally:
            with contextlib.suppress(Exception):
                cap.release()
