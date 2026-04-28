# Marvain TapDB Boundary Pattern

This report records the approved TapDB usage target for Marvain.

## Decision

Marvain does not introduce a new `daylily_tapdb.semantic.SemanticTapDBClient`
facade. Marvain keeps one repository-style boundary in
`agent_hub.semantic_tapdb` and uses the same package-level TapDB/Bloom patterns
that are already used by Bloom and TapDB.

## Approved Boundary Pattern

Inside `agent_hub.semantic_tapdb`, Marvain may use:

- `TAPDBConnection` and `session_scope` for TapDB-owned sessions;
- `TemplateManager` and TapDB template loader/seed helpers for template packs;
- `InstanceFactory` for template-backed instance creation and instance links;
- TapDB ORM models for category/type/subtype/version, EUID, and name queries;
- TapDB object lookup services for EUID resolution;
- TapDB graph payload and DAG services for lineage/graph reads.

Outside the approved boundary, Marvain application code must not import
`daylily_tapdb`, query TapDB-owned tables, package copied TapDB schema, or
recreate a custom `/lineage` surface.

## Hard-Failure Rule

Production TapDB construction must require real TapDB configuration. Test fakes
belong under `tests/fakes/` or explicit test fixtures only, and cannot be
selected silently by production code.
