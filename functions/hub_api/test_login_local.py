#!/usr/bin/env python3
"""Test the login flow locally without needing full AWS infrastructure.

DEPRECATED: This script requires a .env.local file which is no longer the
standard configuration approach. Configuration should be in marvain-config.yaml.
Use `marvain gui start` for local development instead.
"""

import os
import sys
from pathlib import Path
from dotenv import load_dotenv

# Load environment variables from .env.local
# DEPRECATED: New code should use marvain-config.yaml via CLI
env_file = Path(__file__).parent / ".env.local"
if not env_file.exists():
    print("ERROR: .env.local not found.", file=sys.stderr)
    print("DEPRECATED: This script is deprecated.", file=sys.stderr)
    print("Use 'marvain gui start' instead (reads from marvain-config.yaml).", file=sys.stderr)
    sys.exit(1)
load_dotenv(env_file)

# Set AWS region
if not os.getenv("AWS_REGION"):
    os.environ["AWS_REGION"] = "us-east-1"

# Now test the login URL generation
import secrets
import urllib.parse
import hashlib
import base64

def _pkce_pair():
    """Generate PKCE code_verifier and code_challenge."""
    verifier = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode("utf-8").rstrip("=")
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode("utf-8").rstrip("=")
    return verifier, challenge

def _cognito_hosted_ui_base_url() -> str:
    """Return https://<domain>.auth.<region>.amazoncognito.com (no trailing slash)."""
    dom = str(os.getenv("COGNITO_DOMAIN") or "").strip()
    if not dom:
        raise RuntimeError("COGNITO_DOMAIN not configured")

    if dom.startswith("https://") or dom.startswith("http://"):
        return dom.rstrip("/")

    # Support passing the full hostname (without scheme) or just the domain prefix.
    if ".auth." in dom and dom.endswith(".amazoncognito.com"):
        return f"https://{dom}".rstrip("/")

    region = os.getenv("AWS_REGION") or "us-west-2"
    return f"https://{dom}.auth.{region}.amazoncognito.com".rstrip("/")

# Test the login URL generation
state = secrets.token_urlsafe(24)
verifier, challenge = _pkce_pair()

# Simulate what the app does
redirect_uri = "http://localhost:8000/auth/callback"

base = _cognito_hosted_ui_base_url()
client_id = str(os.getenv("COGNITO_USER_POOL_CLIENT_ID") or "").strip()

qs = urllib.parse.urlencode(
    {
        "client_id": client_id,
        "response_type": "code",
        "scope": "openid email profile",
        "redirect_uri": redirect_uri,
        "state": state,
        "code_challenge_method": "S256",
        "code_challenge": challenge,
    }
)

login_url = f"{base}/oauth2/authorize?{qs}"

print("=" * 80)
print("LOGIN URL GENERATION TEST")
print("=" * 80)
print(f"\nCognito Domain: {os.getenv('COGNITO_DOMAIN')}")
print(f"Cognito Base URL: {base}")
print(f"Client ID: {client_id}")
print(f"Redirect URI: {redirect_uri}")
print(f"\nGenerated Login URL:")
print(login_url)
print("\n" + "=" * 80)

