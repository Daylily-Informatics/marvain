# Phase 5: Rich Memory Schema & Enhanced Memory UI

> **Parent plan**: [GUI_OVERHAUL_PLAN.md](../GUI_OVERHAUL_PLAN.md)
> **Risk**: Medium — DB migration + API changes
> **Depends on**: Phase 1 (macros), Phase 4 (updated create_memory tool)

## Overview

Extend the memory schema with structured metadata (subject, tags, scene context, modality, confidence, related memories). Update the memories page with richer display, faceted search, and a memory creation form. Update the `create_memory` tool to accept new fields.

## Scope

- `sql/012_rich_memories.sql` — new migration: add `subject_person_id` (FK to people), `tags` (text[]), `scene_context` (JSONB), `modality` (text), `confidence` (float), `related_memory_ids` (uuid[])
- `layers/shared/python/agent_hub/tools/create_memory.py` — accept new fields in payload
- `functions/hub_api/api_app.py` — update `MemoryCreateIn`, `POST /v1/memories`, `GET /v1/memories` to include new fields
- `functions/hub_api/app.py` — update `gui_memories()` route with new display data; add `POST /api/memories` GUI endpoint for manual memory creation
- `functions/hub_api/templates/memories.html` — rich card layout showing tags, subject, modality icon, confidence bar; faceted filtering by tag/modality/subject; memory creation modal
- Index: `CREATE INDEX memories_tags_idx ON memories USING gin(tags);`

## Migration SQL

```sql
-- sql/012_rich_memories.sql
ALTER TABLE memories ADD COLUMN IF NOT EXISTS subject_person_id uuid REFERENCES people(person_id) ON DELETE SET NULL;
ALTER TABLE memories ADD COLUMN IF NOT EXISTS tags text[] DEFAULT '{}';
ALTER TABLE memories ADD COLUMN IF NOT EXISTS scene_context jsonb DEFAULT '{}'::jsonb;
ALTER TABLE memories ADD COLUMN IF NOT EXISTS modality text DEFAULT 'text';
ALTER TABLE memories ADD COLUMN IF NOT EXISTS confidence double precision DEFAULT 1.0;
ALTER TABLE memories ADD COLUMN IF NOT EXISTS related_memory_ids uuid[] DEFAULT '{}';

CREATE INDEX IF NOT EXISTS memories_tags_idx ON memories USING gin(tags);
CREATE INDEX IF NOT EXISTS memories_subject_idx ON memories(subject_person_id) WHERE subject_person_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS memories_modality_idx ON memories(modality);

COMMENT ON COLUMN memories.subject_person_id IS 'Who this memory is about (FK to people)';
COMMENT ON COLUMN memories.tags IS 'Freeform tags for categorization';
COMMENT ON COLUMN memories.scene_context IS 'Scene metadata: {location, activity, mood, environment}';
COMMENT ON COLUMN memories.modality IS 'Input modality: text, voice, vision, multimodal';
COMMENT ON COLUMN memories.confidence IS 'Confidence score 0.0-1.0';
COMMENT ON COLUMN memories.related_memory_ids IS 'Links to related memories';
```

## New Memory Fields

| Field | Type | Description |
|-------|------|-------------|
| `subject_person_id` | uuid FK | Who the memory is about |
| `tags` | text[] | Freeform tags (e.g., `["preference", "food", "important"]`) |
| `scene_context` | JSONB | `{location, activity, mood, environment, time_of_day}` |
| `modality` | text | `text`, `voice`, `vision`, `multimodal` |
| `confidence` | float | 0.0–1.0 confidence score |
| `related_memory_ids` | uuid[] | Links to related memories |

## Definition of Done

- Memories can store: who they're about, tags, scene context, modality, confidence, related memories
- Memory cards in GUI show subject name, tags as chips, modality icon, confidence indicator
- Filter by tag, modality, subject person
- Manual memory creation via GUI with all new fields
- Backward compatible: existing memories without new fields still display correctly

## Verification

```bash
# Create memory via API with all new fields
curl -X POST http://localhost:8443/v1/memories -H 'Authorization: Bearer ...' \
  -H 'Content-Type: application/json' \
  -d '{"content":"Prefers Earl Grey tea","tier":"semantic","tags":["preference","beverage"],"modality":"voice","confidence":0.9}'

# Filter by tag
# → GUI: select tag "preference" → only matching memories shown

# Existing memories still render
# → GUI: memories page loads without errors for memories without new fields
```

