from __future__ import annotations

import logging
import os
from typing import Optional


def configure_logging(verbose_int: int = 0) -> None:
    """Configure root logging. Idempotent-ish for Lambda."""
    level = logging.DEBUG if (verbose_int or 0) >= 1 else logging.INFO

    # If AWS sets LOG_LEVEL, let it override.
    env_level = os.environ.get("LOG_LEVEL")
    if env_level:
        try:
            level = getattr(logging, env_level.upper())
        except Exception:
            pass

    root = logging.getLogger()
    if root.handlers:
        # Lambda already configured; just adjust level.
        root.setLevel(level)
        for h in root.handlers:
            h.setLevel(level)
        return

    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)s %(name)s - %(message)s",
    )
