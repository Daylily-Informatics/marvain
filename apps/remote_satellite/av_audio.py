"""Audio helpers for Location Node.

Kept intentionally small so the base remote satellite daemon can still import
without heavy multimedia dependencies.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class AudioDeviceSelection:
    input_device: int | str | None = None
    output_device: int | str | None = None


def list_audio_devices() -> list[dict[str, Any]]:
    """Return sounddevice.query_devices() results (best-effort)."""
    try:
        import sounddevice as sd  # type: ignore

        devices = sd.query_devices()
        if isinstance(devices, list):
            return [dict(d) for d in devices]
        return [dict(devices)]
    except Exception:
        return []
