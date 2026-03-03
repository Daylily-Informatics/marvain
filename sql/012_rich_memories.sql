-- 012_rich_memories.sql
-- Extend memories table with rich metadata columns.

ALTER TABLE memories ADD COLUMN IF NOT EXISTS subject_person_id uuid REFERENCES people(person_id) ON DELETE SET NULL;
ALTER TABLE memories ADD COLUMN IF NOT EXISTS tags text[] NOT NULL DEFAULT '{}';
ALTER TABLE memories ADD COLUMN IF NOT EXISTS scene_context text;
ALTER TABLE memories ADD COLUMN IF NOT EXISTS modality text NOT NULL DEFAULT 'text';
ALTER TABLE memories ADD COLUMN IF NOT EXISTS confidence real NOT NULL DEFAULT 1.0;
ALTER TABLE memories ADD COLUMN IF NOT EXISTS related_memory_ids uuid[] NOT NULL DEFAULT '{}';

-- Indexes for efficient querying
CREATE INDEX IF NOT EXISTS memories_subject_person_idx ON memories(subject_person_id) WHERE subject_person_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS memories_tags_gin_idx ON memories USING gin(tags);
CREATE INDEX IF NOT EXISTS memories_modality_idx ON memories(modality);

