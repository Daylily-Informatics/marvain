from __future__ import annotations

import logging
from typing import Any, Dict, List, Union

from .schema import Action

logger = logging.getLogger(__name__)


def dispatch_background_actions(actions: List[Union[Action, Dict[str, Any]]]) -> None:
    """Dispatch actions.

    Skeleton implementation: logs actions. Replace with EventBridge/SQS/etc as needed.
    """
    if not actions:
        return

    for a in actions:
        if isinstance(a, Action):
            kind = a.kind
            payload = a.payload
        elif isinstance(a, dict):
            kind = str(a.get("kind") or "LOG")
            payload = a.get("payload") or {}
        else:
            kind = "LOG"
            payload = {"value": str(a)}

        if kind.upper() in ("NOOP", "NONE"):
            logger.debug("Action NOOP")
            continue

        logger.info("Dispatch action kind=%s payload=%s", kind, payload)
