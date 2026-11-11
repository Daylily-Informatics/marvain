"""Dog matching decisions. Source added; execution requires separate authorization."""
from agent_hub.dog_identity import match_dog


def vector(first, second=0):
    return [first, second] + [0.0] * 510


def reference(dog, image, embedding):
    return {"dog_id": dog, "display_name": dog, "reference_id": image, "embedding": embedding}


def match(references):
    return match_dog(vector(1), references, minimum_similarity=0.7, ambiguity_margin=0.05)


def test_missing_references_and_dissimilar_dogs_stay_unknown():
    assert match([]) == {"result": "no_references", "candidate": None}
    assert match([reference("fixture-dog-a", "photo-a", vector(0, 1))]) == {"result": "unknown", "candidate": None}


def test_similar_distinct_dogs_remain_ambiguous():
    result = match([reference("fixture-dog-a", "photo-a", vector(1)),
                    reference("fixture-dog-b", "photo-b", vector(0.98, 0.199))])
    assert result == {"result": "ambiguous", "candidate": None}


def test_multiple_photos_of_same_dog_do_not_create_false_ambiguity():
    result = match([reference("fixture-dog-a", "photo-a", vector(1)),
                    reference("fixture-dog-a", "photo-b", vector(0.98, 0.199)),
                    reference("fixture-dog-b", "photo-c", vector(0, 1))])
    assert result["result"] == "reference_match"
    assert result["candidate"]["dog_id"] == "fixture-dog-a"
    assert result["candidate"]["reference_id"] == "photo-a"
