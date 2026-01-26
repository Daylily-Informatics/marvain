"""Lambda handler for Hub API.

This handler uses api_app which contains ONLY the programmatic API routes.
GUI routes are NOT deployed to Lambda - they run locally only.
"""
from __future__ import annotations

from mangum import Mangum

from api_app import api_app

handler = Mangum(api_app)
