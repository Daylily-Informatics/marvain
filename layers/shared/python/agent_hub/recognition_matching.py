"""Matching against reviewed, consented projections of the exact model version."""
from __future__ import annotations

import json
import math
import os
from typing import Any


def identify_embedding(db: Any, *, agent_id: str, modality: str, model_id: str,
                       model_version: str, embedding: list[float], k: int = 2,
                       transaction_id: str | None = None) -> dict[str, Any]:
    if modality not in {"voice", "face"}:
        raise ValueError("modality must be voice or face")
    dimension = 256 if modality == "voice" else 512
    if len(embedding) != dimension or not all(math.isfinite(float(v)) for v in embedding):
        raise ValueError(f"{modality} requires {dimension} finite embedding values")
    table = "voiceprints" if modality == "voice" else "faceprints"
    threshold = float(os.getenv("VOICE_MATCH_THRESHOLD", "0.35") if modality == "voice"
                      else os.getenv("FACE_MATCH_THRESHOLD", "0.50"))
    rows = db.query(f"""
        SELECT v.person_id::text AS person_id, p.display_name,
               min(v.embedding <=> CAST(:q AS vector))::double precision AS distance
        FROM {table} v JOIN people p ON p.person_id=v.person_id AND p.agent_id=v.agent_id
        JOIN biometric_projections bp ON bp.biometric_projection_id=v.biometric_projection_id
        JOIN consent_grants cg ON cg.consent_id=bp.consent_id
        WHERE v.agent_id=:agent::uuid AND v.revoked_at IS NULL AND bp.lifecycle_state='active'
          AND bp.person_id=v.person_id AND bp.agent_id=v.agent_id AND bp.modality=:modality
          AND bp.model_id=:model AND bp.model_version=:version
          AND cg.person_id=v.person_id AND cg.agent_id=v.agent_id
          AND cg.consent_type IN (:modality,'global') AND cg.revoked_at IS NULL
          AND (cg.expires_at IS NULL OR cg.expires_at>now())
        GROUP BY v.person_id,p.display_name ORDER BY distance LIMIT :k
        """, {"agent": agent_id, "modality": modality, "model": model_id, "version": model_version,
               "q": json.dumps(embedding, allow_nan=False), "k": max(2, k)}, transaction_id=transaction_id)
    candidates = [{**r, "distance": float(r["distance"]),
                   "confidence": max(0.0, min(1.0, 1-float(r["distance"])))} for r in rows]
    passing = [r for r in candidates if r["distance"] <= threshold]
    return {"matched": len(passing) == 1, "ambiguous": len(passing) > 1,
            "threshold": threshold, "best": candidates[0] if candidates else None, "candidates": candidates}
