"""Video helpers for Location Node.

Initial implementation uses OpenCV when available. This module is optional; the
Location Node can run audio-only if OpenCV is not installed.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class CameraSource:
    type: str  # usb|rtsp
    index: int | None = None
    url: str | None = None


def has_opencv() -> bool:
    try:
        import cv2  # type: ignore  # noqa: F401

        return True
    except Exception:
        return False

