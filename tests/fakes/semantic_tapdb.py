from __future__ import annotations

import copy
import uuid

from agent_hub.semantic_tapdb import SemanticEdge, SemanticObject


class InMemoryTapdbSemanticStore:
    """Deterministic test-only TapDB semantic store."""

    def __init__(self) -> None:
        self.objects: dict[str, SemanticObject] = {}
        self.edges: list[SemanticEdge] = []

    def create_object(
        self,
        *,
        template_code: str,
        name: str,
        properties: dict[str, object],
        lifecycle_state: str,
    ) -> SemanticObject:
        semantic_id = f"MVN-{uuid.uuid4()}"
        payload = copy.deepcopy(properties)
        payload["lifecycle_state"] = lifecycle_state
        obj = SemanticObject(
            semantic_id=semantic_id,
            template_code=template_code,
            name=name,
            properties=payload,
            lifecycle_state=lifecycle_state,
        )
        self.objects[semantic_id] = obj
        return obj

    def link_objects(
        self,
        *,
        parent_semantic_id: str,
        child_semantic_id: str,
        relationship_type: str,
    ) -> SemanticEdge:
        if parent_semantic_id not in self.objects:
            raise KeyError(f"unknown parent semantic object: {parent_semantic_id}")
        if child_semantic_id not in self.objects:
            raise KeyError(f"unknown child semantic object: {child_semantic_id}")
        edge = SemanticEdge(
            edge_id=f"MVN-EDGE-{uuid.uuid4()}",
            parent_semantic_id=parent_semantic_id,
            child_semantic_id=child_semantic_id,
            relationship_type=relationship_type,
        )
        self.edges.append(edge)
        return edge

    def graph_for(self, semantic_id: str, *, max_depth: int = 3) -> dict[str, object]:
        if semantic_id not in self.objects:
            raise KeyError(f"unknown semantic object: {semantic_id}")
        seen = {semantic_id}
        frontier = {semantic_id}
        selected_edges: list[SemanticEdge] = []
        for _ in range(max(0, int(max_depth))):
            next_frontier: set[str] = set()
            for edge in self.edges:
                if edge.parent_semantic_id in frontier or edge.child_semantic_id in frontier:
                    selected_edges.append(edge)
                    if edge.parent_semantic_id not in seen:
                        next_frontier.add(edge.parent_semantic_id)
                    if edge.child_semantic_id not in seen:
                        next_frontier.add(edge.child_semantic_id)
            if not next_frontier:
                break
            seen.update(next_frontier)
            frontier = next_frontier
        return {
            "nodes": [self.objects[item].__dict__ for item in sorted(seen)],
            "edges": [edge.__dict__ for edge in selected_edges],
        }
