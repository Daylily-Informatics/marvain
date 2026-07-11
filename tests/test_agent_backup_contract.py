from __future__ import annotations

import base64
import hashlib
import hmac
from dataclasses import replace
from datetime import datetime, timezone

import pytest
from agent_hub.agent_lifecycle import (
    REQUIRED_EXPORT_COMPONENTS,
    AgentLifecycleError,
    AgentLifecycleState,
    ExportManifest,
    MaturityState,
    export_component,
    sign_export_manifest,
    signed_export_manifest_payload,
    validate_restore_dry_run,
)

NOW = datetime(2026, 7, 10, 12, 0, tzinfo=timezone.utc)


class HmacTestSigner:
    algorithm = "HMAC-SHA256-TEST"
    key_id = "test-key-1"

    def __init__(self, key: bytes) -> None:
        self._key = key

    def sign(self, payload: bytes) -> bytes:
        return hmac.new(self._key, payload, hashlib.sha256).digest()


class HmacTestVerifier:
    def __init__(self, key: bytes) -> None:
        self._key = key

    def verify(self, payload: bytes, signature: bytes, *, algorithm: str, key_id: str) -> bool:
        if algorithm != "HMAC-SHA256-TEST" or key_id != "test-key-1":
            return False
        expected = hmac.new(self._key, payload, hashlib.sha256).digest()
        return hmac.compare_digest(expected, signature)


def _bundle_parts():
    payloads = {name: f'{{"component":"{name}"}}'.encode() for name in REQUIRED_EXPORT_COMPONENTS}
    components = tuple(export_component(name, payload, record_count=1) for name, payload in payloads.items())
    manifest = ExportManifest(
        export_id="export-1",
        agent_id="agent-1",
        created_at=NOW,
        source_lifecycle_state=AgentLifecycleState.STASIS,
        source_maturity_state=MaturityState.MATURE,
        components=components,
        secret_references=("arn:aws:secretsmanager:us-east-1:123456789012:secret:agent-openai",),
    )
    return manifest, payloads


def test_signed_export_manifest_validates_complete_restore_dry_run() -> None:
    key = b"test-only-signing-key"
    manifest, payloads = _bundle_parts()
    signed = sign_export_manifest(manifest, signer=HmacTestSigner(key))
    envelope = signed_export_manifest_payload(signed)

    result = validate_restore_dry_run(
        signed,
        verifier=HmacTestVerifier(key),
        expected_agent_id="agent-1",
        target_agent_exists=False,
        component_payloads=payloads,
        available_secret_references=manifest.secret_references,
    )

    assert result.valid is True
    assert envelope["signature"]["algorithm"] == "HMAC-SHA256-TEST"
    assert envelope["manifest"]["agent_id"] == "agent-1"
    assert result.dry_run is True
    assert result.signature_verified is True
    assert set(result.verified_components) == set(REQUIRED_EXPORT_COMPONENTS)
    assert result.unresolved_secret_references == ()
    assert result.errors == ()
    assert result.destructive_operations == ()
    assert "restore_agent_identity" in result.restore_plan


def test_restore_dry_run_rejects_tampered_component_without_mutation_plan_changes() -> None:
    key = b"test-only-signing-key"
    manifest, payloads = _bundle_parts()
    signed = sign_export_manifest(manifest, signer=HmacTestSigner(key))
    payloads["tapdb_subgraph"] = b'{"tampered":true}'

    result = validate_restore_dry_run(
        signed,
        verifier=HmacTestVerifier(key),
        expected_agent_id="agent-1",
        target_agent_exists=False,
        component_payloads=payloads,
        available_secret_references=manifest.secret_references,
    )

    assert result.valid is False
    assert "component_size_mismatch:tapdb_subgraph" in result.errors
    assert "tapdb_subgraph" not in result.verified_components
    assert result.dry_run is True
    assert result.destructive_operations == ()


def test_restore_dry_run_reports_signature_target_and_secret_blockers() -> None:
    key = b"test-only-signing-key"
    manifest, payloads = _bundle_parts()
    signed = sign_export_manifest(manifest, signer=HmacTestSigner(key))
    signed = replace(signed, signature_base64=base64.b64encode(b"wrong-signature").decode("ascii"))

    result = validate_restore_dry_run(
        signed,
        verifier=HmacTestVerifier(key),
        expected_agent_id="different-agent",
        target_agent_exists=True,
        component_payloads=payloads,
        available_secret_references=(),
    )

    assert result.valid is False
    assert result.signature_verified is False
    assert "manifest_signature_invalid" in result.errors
    assert "manifest_agent_id_mismatch" in result.errors
    assert "target_agent_already_exists" in result.errors
    assert result.unresolved_secret_references == manifest.secret_references
    assert any(error.startswith("secret_reference_unresolved:") for error in result.errors)


def test_signature_binds_algorithm_and_key_identity() -> None:
    key = b"test-only-signing-key"
    manifest, payloads = _bundle_parts()
    signed = sign_export_manifest(manifest, signer=HmacTestSigner(key))
    signed = replace(signed, key_id="attacker-controlled-key")

    result = validate_restore_dry_run(
        signed,
        verifier=HmacTestVerifier(key),
        expected_agent_id="agent-1",
        target_agent_exists=False,
        component_payloads=payloads,
        available_secret_references=manifest.secret_references,
    )

    assert result.valid is False
    assert result.signature_verified is False
    assert "manifest_signature_invalid" in result.errors


def test_export_manifest_must_be_complete_and_exclude_secret_values_before_signing() -> None:
    manifest, _ = _bundle_parts()
    incomplete = replace(
        manifest,
        components=tuple(component for component in manifest.components if component.name != "audit_chain"),
        secret_values_excluded=False,
    )

    with pytest.raises(AgentLifecycleError, match="secret_values_must_be_excluded") as exc:
        sign_export_manifest(incomplete, signer=HmacTestSigner(b"test-only-signing-key"))

    assert exc.value.code == "invalid_export_manifest"
    assert "required_component_missing:audit_chain" in str(exc.value)


def test_export_component_requires_exact_bytes_and_nonnegative_record_count() -> None:
    with pytest.raises(AgentLifecycleError, match="must be bytes"):
        export_component("sql_projections", "not-bytes")  # type: ignore[arg-type]
    with pytest.raises(AgentLifecycleError, match="cannot be negative"):
        export_component("sql_projections", b"{}", record_count=-1)
