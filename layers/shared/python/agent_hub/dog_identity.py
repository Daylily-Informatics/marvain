"""Pinned public dog models and reference-gallery matching, independent of human biometrics."""
from __future__ import annotations

import math

MODEL_ID = "open-noodle/pet-recognition-base"
MODEL_VERSION = "fa30eb7785ceb764d5c2840c4585fb89821be385"
DETECTOR_ID = "open-noodle/rfdetr-nano"
DETECTOR_VERSION = "1618db5f22919339f4347d436da8c43afaf91926"


def match_dog(embedding, references, *, minimum_similarity: float, ambiguity_margin: float):
    """Rank distinct dogs, combining their reviewed views by best cosine match."""
    scores = {}
    for reference in references:
        vector = reference["embedding"]
        if len(embedding) != 512 or len(vector) != 512:
            raise ValueError("Dog identity requires 512-dimensional model-compatible embeddings")
        score = math.fsum(float(a) * float(b) for a, b in zip(embedding, vector))
        dog_id = reference["dog_id"]
        if dog_id not in scores or score > scores[dog_id]["similarity"]:
            scores[dog_id] = {"dog_id": dog_id, "display_name": reference["display_name"],
                              "reference_id": reference["reference_id"], "similarity": score}
    ranked = sorted(scores.values(), key=lambda item: item["similarity"], reverse=True)
    if not ranked:
        return {"result": "no_references", "candidate": None}
    if ranked[0]["similarity"] < minimum_similarity:
        return {"result": "unknown", "candidate": None}
    if len(ranked) > 1 and ranked[0]["similarity"] - ranked[1]["similarity"] < ambiguity_margin:
        return {"result": "ambiguous", "candidate": None}
    return {"result": "reference_match", "candidate": ranked[0]}
