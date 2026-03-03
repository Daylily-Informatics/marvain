"""Trigger monitoring loops for Location Node (VAD/motion).

This is intentionally a stub: triggered-mode join/leave is useful but not
required for the baseline always-on (persistent) mode.
"""

from __future__ import annotations

import asyncio
import logging

logger = logging.getLogger(__name__)


async def run_noop_monitoring(stop_event: asyncio.Event) -> None:
    """Placeholder loop that does nothing."""
    while not stop_event.is_set():
        await asyncio.sleep(1.0)

