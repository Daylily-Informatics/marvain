from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_artifact_bucket_requires_explicit_browser_origins_and_checksum_headers() -> None:
    template = (ROOT / "template.yaml").read_text(encoding="utf-8")

    parameter = template.index("  ArtifactCorsAllowedOrigins:")
    conditions = template.index("\nConditions:", parameter)
    parameter_block = template[parameter:conditions]
    assert "Type: CommaDelimitedList" in parameter_block
    assert "Default:" not in parameter_block

    bucket = template.index("  ArtifactBucket:")
    audit_bucket = template.index("  AuditBucket:", bucket)
    bucket_block = template[bucket:audit_bucket]
    assert "CorsConfiguration:" in bucket_block
    assert "AllowedOrigins: !Ref ArtifactCorsAllowedOrigins" in bucket_block
    for header in (
        "Content-Type",
        "x-amz-checksum-sha256",
        "x-amz-meta-sha256",
        "x-amz-sdk-checksum-algorithm",
    ):
        assert f"- {header}" in bucket_block
    for method in ("GET", "HEAD", "PUT"):
        assert f"- {method}" in bucket_block
    assert "AllowedOrigins:\n              - '*'" not in bucket_block
