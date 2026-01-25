"""Shared library for the Agent Hub.

This code is packaged as a Lambda Layer (Python) and imported by multiple functions.

Design goals:
- Keep dependencies minimal (stdlib + boto3).
- Enforce privacy/consent in code, not prompts.
- Keep DB access behind an RDS Data API helper.
"""
