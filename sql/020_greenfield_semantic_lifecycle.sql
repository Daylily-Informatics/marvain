-- 020_greenfield_semantic_lifecycle.sql
-- Greenfield V1 semantic projections for TapDB-backed canonical lineage.

CREATE TABLE IF NOT EXISTS locations (
  location_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  agent_id uuid NOT NULL REFERENCES agents(agent_id) ON DELETE CASCADE,
  name text NOT NULL,
  address_label text,
  metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
  tapdb_euid text,
  created_at timestamptz NOT NULL DEFAULT now(),
  disabled_at timestamptz
);

CREATE INDEX IF NOT EXISTS locations_agent_idx ON locations(agent_id);

ALTER TABLE spaces ADD COLUMN IF NOT EXISTS location_id uuid REFERENCES locations(location_id) ON DELETE SET NULL;
ALTER TABLE spaces ADD COLUMN IF NOT EXISTS room_label text;
ALTER TABLE spaces ADD COLUMN IF NOT EXISTS tapdb_euid text;
CREATE INDEX IF NOT EXISTS spaces_location_idx ON spaces(location_id) WHERE location_id IS NOT NULL;

ALTER TABLE devices ADD COLUMN IF NOT EXISTS location_id uuid REFERENCES locations(location_id) ON DELETE SET NULL;
ALTER TABLE devices ADD COLUMN IF NOT EXISTS current_space_id uuid REFERENCES spaces(space_id) ON DELETE SET NULL;
ALTER TABLE devices ADD COLUMN IF NOT EXISTS tapdb_euid text;
CREATE INDEX IF NOT EXISTS devices_current_space_idx ON devices(current_space_id) WHERE current_space_id IS NOT NULL;

CREATE TABLE IF NOT EXISTS personas (
  persona_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  agent_id uuid NOT NULL REFERENCES agents(agent_id) ON DELETE CASCADE,
  name text NOT NULL,
  instructions text NOT NULL,
  is_default boolean NOT NULL DEFAULT false,
  lifecycle_state text NOT NULL DEFAULT 'active',
  tapdb_euid text,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  disabled_at timestamptz,
  CONSTRAINT personas_lifecycle_state_chk CHECK (lifecycle_state IN ('draft', 'active', 'disabled', 'deleted'))
);

CREATE UNIQUE INDEX IF NOT EXISTS personas_one_default_idx ON personas(agent_id) WHERE is_default AND disabled_at IS NULL;
CREATE INDEX IF NOT EXISTS personas_agent_idx ON personas(agent_id);

CREATE TABLE IF NOT EXISTS sessions (
  session_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  agent_id uuid NOT NULL REFERENCES agents(agent_id) ON DELETE CASCADE,
  location_id uuid REFERENCES locations(location_id) ON DELETE SET NULL,
  space_id uuid REFERENCES spaces(space_id) ON DELETE SET NULL,
  persona_id uuid REFERENCES personas(persona_id) ON DELETE SET NULL,
  livekit_room text,
  status text NOT NULL DEFAULT 'open',
  started_at timestamptz NOT NULL DEFAULT now(),
  ended_at timestamptz,
  metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
  tapdb_euid text,
  CONSTRAINT sessions_status_chk CHECK (status IN ('open', 'paused', 'closed', 'failed'))
);

CREATE INDEX IF NOT EXISTS sessions_agent_status_idx ON sessions(agent_id, status);
CREATE INDEX IF NOT EXISTS sessions_space_started_idx ON sessions(space_id, started_at DESC) WHERE space_id IS NOT NULL;

ALTER TABLE events ADD COLUMN IF NOT EXISTS session_id uuid REFERENCES sessions(session_id) ON DELETE SET NULL;
ALTER TABLE events ADD COLUMN IF NOT EXISTS location_id uuid REFERENCES locations(location_id) ON DELETE SET NULL;
ALTER TABLE events ADD COLUMN IF NOT EXISTS artifact_id uuid;
ALTER TABLE events ADD COLUMN IF NOT EXISTS tapdb_euid text;
CREATE INDEX IF NOT EXISTS events_session_idx ON events(session_id) WHERE session_id IS NOT NULL;

CREATE TABLE IF NOT EXISTS artifact_references (
  artifact_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  agent_id uuid NOT NULL REFERENCES agents(agent_id) ON DELETE CASCADE,
  space_id uuid REFERENCES spaces(space_id) ON DELETE SET NULL,
  device_id uuid REFERENCES devices(device_id) ON DELETE SET NULL,
  session_id uuid REFERENCES sessions(session_id) ON DELETE SET NULL,
  bucket text,
  object_key text,
  uri text,
  media_type text NOT NULL,
  sha256 text,
  lifecycle_state text NOT NULL DEFAULT 'available',
  tapdb_euid text,
  created_at timestamptz NOT NULL DEFAULT now(),
  expires_at timestamptz,
  CONSTRAINT artifact_references_lifecycle_state_chk CHECK (lifecycle_state IN ('available', 'expired', 'redacted', 'deleted'))
);

CREATE INDEX IF NOT EXISTS artifact_references_agent_idx ON artifact_references(agent_id, created_at DESC);

CREATE TABLE IF NOT EXISTS memory_candidates (
  memory_candidate_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  agent_id uuid NOT NULL REFERENCES agents(agent_id) ON DELETE CASCADE,
  source_event_id uuid REFERENCES events(event_id) ON DELETE RESTRICT,
  source_action_id uuid REFERENCES actions(action_id) ON DELETE SET NULL,
  space_id uuid REFERENCES spaces(space_id) ON DELETE SET NULL,
  session_id uuid REFERENCES sessions(session_id) ON DELETE SET NULL,
  subject_person_id uuid REFERENCES people(person_id) ON DELETE SET NULL,
  tier text NOT NULL,
  content text NOT NULL,
  participants jsonb NOT NULL DEFAULT '[]'::jsonb,
  model text,
  confidence real NOT NULL DEFAULT 1.0,
  lifecycle_state text NOT NULL DEFAULT 'candidate',
  tapdb_euid text,
  created_at timestamptz NOT NULL DEFAULT now(),
  reviewed_at timestamptz,
  CONSTRAINT memory_candidates_tier_chk CHECK (
    tier IN ('episodic', 'semantic', 'procedural', 'preference', 'relationship', 'location', 'device', 'policy')
  ),
  CONSTRAINT memory_candidates_lifecycle_state_chk CHECK (lifecycle_state IN ('candidate', 'scored', 'rejected', 'committed'))
);

CREATE INDEX IF NOT EXISTS memory_candidates_agent_state_idx ON memory_candidates(agent_id, lifecycle_state, created_at DESC);
CREATE INDEX IF NOT EXISTS memory_candidates_source_event_idx ON memory_candidates(source_event_id);
CREATE INDEX IF NOT EXISTS memory_candidates_source_action_idx ON memory_candidates(source_action_id);

ALTER TABLE memories ADD COLUMN IF NOT EXISTS memory_candidate_id uuid REFERENCES memory_candidates(memory_candidate_id) ON DELETE SET NULL;
ALTER TABLE memories ADD COLUMN IF NOT EXISTS source_event_id uuid REFERENCES events(event_id) ON DELETE RESTRICT;
ALTER TABLE memories ADD COLUMN IF NOT EXISTS source_action_id uuid REFERENCES actions(action_id) ON DELETE SET NULL;
ALTER TABLE memories ADD COLUMN IF NOT EXISTS session_id uuid REFERENCES sessions(session_id) ON DELETE SET NULL;
ALTER TABLE memories ADD COLUMN IF NOT EXISTS location_id uuid REFERENCES locations(location_id) ON DELETE SET NULL;
ALTER TABLE memories ADD COLUMN IF NOT EXISTS lifecycle_state text NOT NULL DEFAULT 'committed';
ALTER TABLE memories ADD COLUMN IF NOT EXISTS tapdb_euid text;
ALTER TABLE memories ADD COLUMN IF NOT EXISTS tombstoned_at timestamptz;
ALTER TABLE memories ADD COLUMN IF NOT EXISTS recall_explanation jsonb NOT NULL DEFAULT '{}'::jsonb;

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint WHERE conname = 'memories_tier_chk'
  ) THEN
    ALTER TABLE memories
      ADD CONSTRAINT memories_tier_chk
      CHECK (tier IN ('episodic', 'semantic', 'procedural', 'preference', 'relationship', 'location', 'device', 'policy'));
  END IF;

  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint WHERE conname = 'memories_lifecycle_state_chk'
  ) THEN
    ALTER TABLE memories
      ADD CONSTRAINT memories_lifecycle_state_chk
      CHECK (lifecycle_state IN ('candidate', 'committed', 'edited', 'superseded', 'tombstoned'));
  END IF;
END $$;

CREATE INDEX IF NOT EXISTS memories_lifecycle_idx ON memories(agent_id, lifecycle_state, created_at DESC);
CREATE INDEX IF NOT EXISTS memories_source_event_idx ON memories(source_event_id) WHERE source_event_id IS NOT NULL;

CREATE TABLE IF NOT EXISTS memory_tombstones (
  memory_tombstone_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  memory_id uuid NOT NULL REFERENCES memories(memory_id) ON DELETE RESTRICT,
  agent_id uuid NOT NULL REFERENCES agents(agent_id) ON DELETE CASCADE,
  reason text,
  actor_type text NOT NULL,
  actor_id text,
  tapdb_euid text,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX IF NOT EXISTS memory_tombstones_memory_idx ON memory_tombstones(memory_id);

CREATE TABLE IF NOT EXISTS recognition_observations (
  recognition_observation_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  agent_id uuid NOT NULL REFERENCES agents(agent_id) ON DELETE CASCADE,
  space_id uuid REFERENCES spaces(space_id) ON DELETE SET NULL,
  location_id uuid REFERENCES locations(location_id) ON DELETE SET NULL,
  session_id uuid REFERENCES sessions(session_id) ON DELETE SET NULL,
  device_id uuid REFERENCES devices(device_id) ON DELETE SET NULL,
  artifact_id uuid REFERENCES artifact_references(artifact_id) ON DELETE SET NULL,
  source_event_id uuid REFERENCES events(event_id) ON DELETE SET NULL,
  modality text NOT NULL,
  lifecycle_state text NOT NULL DEFAULT 'observed',
  model text,
  tapdb_euid text,
  created_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT recognition_observations_lifecycle_state_chk CHECK (lifecycle_state IN ('observed', 'embedded', 'matched', 'no_match', 'expired'))
);

CREATE INDEX IF NOT EXISTS recognition_observations_agent_idx ON recognition_observations(agent_id, created_at DESC);

CREATE TABLE IF NOT EXISTS recognition_hypotheses (
  identity_hypothesis_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  recognition_observation_id uuid NOT NULL REFERENCES recognition_observations(recognition_observation_id) ON DELETE CASCADE,
  candidate_person_id uuid REFERENCES people(person_id) ON DELETE SET NULL,
  consent_id uuid REFERENCES consent_grants(consent_id) ON DELETE SET NULL,
  confidence real NOT NULL DEFAULT 0,
  decision text NOT NULL DEFAULT 'proposed',
  reason text,
  tapdb_euid text,
  created_at timestamptz NOT NULL DEFAULT now(),
  decided_at timestamptz,
  CONSTRAINT recognition_hypotheses_decision_chk CHECK (decision IN ('proposed', 'accepted', 'rejected', 'no_match'))
);

CREATE INDEX IF NOT EXISTS recognition_hypotheses_observation_idx ON recognition_hypotheses(recognition_observation_id);

CREATE TABLE IF NOT EXISTS presence_assertions (
  presence_assertion_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  agent_id uuid NOT NULL REFERENCES agents(agent_id) ON DELETE CASCADE,
  space_id uuid REFERENCES spaces(space_id) ON DELETE SET NULL,
  location_id uuid REFERENCES locations(location_id) ON DELETE SET NULL,
  person_id uuid REFERENCES people(person_id) ON DELETE SET NULL,
  identity_hypothesis_id uuid REFERENCES recognition_hypotheses(identity_hypothesis_id) ON DELETE SET NULL,
  confidence real NOT NULL DEFAULT 0,
  status text NOT NULL DEFAULT 'present',
  tapdb_euid text,
  asserted_at timestamptz NOT NULL DEFAULT now(),
  retracted_at timestamptz,
  CONSTRAINT presence_assertions_status_chk CHECK (status IN ('present', 'absent', 'unknown', 'retracted'))
);

CREATE INDEX IF NOT EXISTS presence_assertions_agent_space_idx ON presence_assertions(agent_id, space_id, asserted_at DESC);

ALTER TABLE voiceprints ADD COLUMN IF NOT EXISTS consent_id uuid REFERENCES consent_grants(consent_id) ON DELETE SET NULL;
ALTER TABLE voiceprints ADD COLUMN IF NOT EXISTS tapdb_euid text;
ALTER TABLE faceprints ADD COLUMN IF NOT EXISTS consent_id uuid REFERENCES consent_grants(consent_id) ON DELETE SET NULL;
ALTER TABLE faceprints ADD COLUMN IF NOT EXISTS tapdb_euid text;

ALTER TABLE actions ADD COLUMN IF NOT EXISTS tapdb_euid text;
ALTER TABLE actions ADD COLUMN IF NOT EXISTS session_id uuid REFERENCES sessions(session_id) ON DELETE SET NULL;
ALTER TABLE actions ADD COLUMN IF NOT EXISTS location_id uuid REFERENCES locations(location_id) ON DELETE SET NULL;

CREATE TABLE IF NOT EXISTS semantic_sync_status (
  semantic_sync_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  source_table text NOT NULL,
  source_id uuid NOT NULL,
  target_template_code text NOT NULL,
  tapdb_euid text,
  status text NOT NULL DEFAULT 'pending',
  attempts int NOT NULL DEFAULT 0,
  last_error text,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT semantic_sync_status_status_chk CHECK (status IN ('pending', 'written', 'failed', 'dead_lettered'))
);

CREATE UNIQUE INDEX IF NOT EXISTS semantic_sync_status_source_idx ON semantic_sync_status(source_table, source_id, target_template_code);
