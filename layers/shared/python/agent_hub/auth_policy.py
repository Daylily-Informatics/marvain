"""Verified human-email admission policy shared by browser and bearer auth."""

from __future__ import annotations

from daylily_auth_cognito.policy.email_domains import DomainValidator


def require_allowed_human_email(*, email: object, email_verified: object, allowed_domains: str) -> str:
    """Require a verified email and an explicit exact-domain allowlist."""
    if not isinstance(allowed_domains, str) or not allowed_domains.strip():
        raise RuntimeError("AUTH_ALLOWED_EMAIL_DOMAINS must be configured")
    domains = [domain.strip() for domain in allowed_domains.split(",")]
    if any(not domain or domain.lower() == "all" or "*" in domain for domain in domains):
        raise RuntimeError("AUTH_ALLOWED_EMAIL_DOMAINS must contain explicit domains")
    if not isinstance(email, str) or not email or email != email.strip() or email_verified is not True:
        raise PermissionError("A verified email address is required")
    allowed, _ = DomainValidator(allowed_domains=allowed_domains).validate_email_domain(email)
    if not allowed:
        raise PermissionError("Email domain is not permitted")
    return email
