"""Tests for audit hash chain verification."""

from __future__ import annotations

import hashlib
import json
from unittest.mock import MagicMock, patch


def _canon_json(obj):
    """Canonical JSON encoding for hash calculation."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _sha256_hex(s: str) -> str:
    """SHA256 hex digest."""
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


class TestAuditHashChain:
    """Tests for the audit hash chain mechanism."""

    def test_hash_chain_genesis(self):
        """First entry uses GENESIS as prev_hash."""
        # Simulate the first entry
        prev_hash = "GENESIS"
        payload = {
            "entry_id": "entry-1",
            "agent_id": "agent-1",
            "type": "test",
            "ts": "2026-02-01T00:00:00+00:00",
            "prev_hash": prev_hash,
            "data": {"test": "data"},
        }

        payload_hash = _sha256_hex(prev_hash + _canon_json(payload))

        # Hash should be deterministic
        assert len(payload_hash) == 64
        assert payload_hash == _sha256_hex("GENESIS" + _canon_json(payload))

    def test_hash_chain_links(self):
        """Subsequent entries chain from previous hash."""
        # Entry 1
        prev_hash_1 = "GENESIS"
        payload_1 = {
            "entry_id": "entry-1",
            "agent_id": "agent-1",
            "type": "test",
            "ts": "2026-02-01T00:00:00+00:00",
            "prev_hash": prev_hash_1,
            "data": {"sequence": 1},
        }
        hash_1 = _sha256_hex(prev_hash_1 + _canon_json(payload_1))

        # Entry 2 chains from entry 1
        prev_hash_2 = hash_1
        payload_2 = {
            "entry_id": "entry-2",
            "agent_id": "agent-1",
            "type": "test",
            "ts": "2026-02-01T00:00:01+00:00",
            "prev_hash": prev_hash_2,
            "data": {"sequence": 2},
        }
        hash_2 = _sha256_hex(prev_hash_2 + _canon_json(payload_2))

        # Entry 3 chains from entry 2
        prev_hash_3 = hash_2
        payload_3 = {
            "entry_id": "entry-3",
            "agent_id": "agent-1",
            "type": "test",
            "ts": "2026-02-01T00:00:02+00:00",
            "prev_hash": prev_hash_3,
            "data": {"sequence": 3},
        }
        hash_3 = _sha256_hex(prev_hash_3 + _canon_json(payload_3))

        # Verify chain is unbroken
        assert payload_2["prev_hash"] == hash_1
        assert payload_3["prev_hash"] == hash_2

        # All hashes are unique
        assert len({hash_1, hash_2, hash_3}) == 3

    def test_tamper_detection(self):
        """Tampering with data breaks the hash chain."""
        prev_hash = "GENESIS"
        payload = {
            "entry_id": "entry-1",
            "agent_id": "agent-1",
            "type": "test",
            "ts": "2026-02-01T00:00:00+00:00",
            "prev_hash": prev_hash,
            "data": {"amount": 100},
        }
        original_hash = _sha256_hex(prev_hash + _canon_json(payload))

        # Tamper with data
        tampered_payload = payload.copy()
        tampered_payload["data"] = {"amount": 1000}  # Changed!

        # Recompute hash with tampered data
        tampered_hash = _sha256_hex(prev_hash + _canon_json(tampered_payload))

        # Hash should be different
        assert tampered_hash != original_hash

    def test_canonical_json_ordering(self):
        """Canonical JSON produces deterministic output regardless of key order."""
        payload_a = {"z": 1, "a": 2, "m": 3}
        payload_b = {"a": 2, "m": 3, "z": 1}

        assert _canon_json(payload_a) == _canon_json(payload_b)
        assert _canon_json(payload_a) == '{"a":2,"m":3,"z":1}'


class TestAppendAuditEntry:
    """Tests for the append_audit_entry function."""

    @patch("agent_hub.audit.boto3")
    def test_append_audit_entry_creates_hash_chain(self, mock_boto3):
        """append_audit_entry creates proper hash chain entry."""
        from agent_hub.audit import append_audit_entry

        mock_db = MagicMock()
        mock_db.query.return_value = []  # No previous hash (genesis)
        mock_db.begin.return_value = "tx-1"

        mock_s3 = MagicMock()
        mock_boto3.client.return_value = mock_s3

        result = append_audit_entry(
            mock_db,
            bucket="test-audit-bucket",
            agent_id="agent-1",
            entry_type="test_entry",
            entry={"test": "data"},
        )

        # Verify result structure
        assert "entry_id" in result
        assert result["agent_id"] == "agent-1"
        assert result["type"] == "test_entry"
        assert result["prev_hash"] == "GENESIS"
        assert "hash" in result
        assert result["data"] == {"test": "data"}

        # Verify S3 was called
        mock_s3.put_object.assert_called_once()
        call_args = mock_s3.put_object.call_args
        assert call_args.kwargs["Bucket"] == "test-audit-bucket"
        assert "audit/agent_id=agent-1/" in call_args.kwargs["Key"]

        # Verify DB was updated with new hash
        mock_db.execute.assert_called()
