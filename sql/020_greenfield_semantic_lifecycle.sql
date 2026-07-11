-- 020_greenfield_semantic_lifecycle.sql
-- Greenfield V1 semantic projections for TapDB-backed canonical lineage.

CREATE TABLE IF NOT EXISTS locations (
  location_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  agent_id uuid NOT NULL REFERENCES agents(agent_id) ON DELETE RESTRICT,
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
  agent_id uuid NOT NULL REFERENCES agents(agent_id) ON DELETE RESTRICT,
  name text NOT NULL,
  instructions text NOT NULL,
  is_default boolean NOT NULL DEFAULT false,
  lifecycle_state text NOT NULL DEFAULT 'active',
  tapdb_euid text,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  disabled_at timestamptz,
  CONSTRAINT personas_lifecycle_state_chk CHECK (lifecycle_state IN ('draft', 'active', 'disabled'))
);

CREATE UNIQUE INDEX IF NOT EXISTS personas_one_default_idx ON personas(agent_id) WHERE is_default AND disabled_at IS NULL;
CREATE INDEX IF NOT EXISTS personas_agent_idx ON personas(agent_id);

CREATE TABLE IF NOT EXISTS sessions (
  session_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  agent_id uuid NOT NULL REFERENCES agents(agent_id) ON DELETE RESTRICT,
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
  agent_id uuid NOT NULL REFERENCES agents(agent_id) ON DELETE RESTRICT,
  space_id uuid REFERENCES spaces(space_id) ON DELETE SET NULL,
  device_id uuid NOT NULL REFERENCES devices(device_id) ON DELETE RESTRICT,
  session_id uuid REFERENCES sessions(session_id) ON DELETE SET NULL,
  -- events exists before this projection, so source evidence uses a direct restrictive foreign key.
  source_event_id uuid REFERENCES events(event_id) ON DELETE RESTRICT,
  purpose text NOT NULL,
  filename text NOT NULL,
  bucket text NOT NULL,
  object_key text NOT NULL,
  uri text NOT NULL,
  media_type text NOT NULL,
  expected_sha256 text NOT NULL,
  actual_sha256 text,
  expected_byte_count bigint NOT NULL,
  actual_byte_count bigint,
  lifecycle_state text NOT NULL DEFAULT 'pending_upload',
  upload_expires_at timestamptz NOT NULL,
  verification_observed_at timestamptz,
  completed_at timestamptz,
  s3_version_id text,
  s3_etag text,
  tapdb_euid text,
  created_at timestamptz NOT NULL DEFAULT now(),
  expires_at timestamptz,
  CONSTRAINT artifact_references_purpose_chk CHECK (purpose IN ('general', 'recognition', 'visual')),
  CONSTRAINT artifact_references_filename_chk CHECK (
    filename NOT IN ('.', '..') AND filename !~ '[/\\]'
  ),
  CONSTRAINT artifact_references_object_key_filename_chk CHECK (object_key LIKE '%/' || filename),
  CONSTRAINT artifact_references_uri_chk CHECK (uri = 's3://' || bucket || '/' || object_key),
  CONSTRAINT artifact_references_expected_sha256_chk CHECK (expected_sha256 ~ '^[0-9a-f]{64}$'),
  CONSTRAINT artifact_references_actual_sha256_chk CHECK (
    actual_sha256 IS NULL OR actual_sha256 ~ '^[0-9a-f]{64}$'
  ),
  CONSTRAINT artifact_references_expected_byte_count_chk CHECK (expected_byte_count > 0),
  CONSTRAINT artifact_references_actual_byte_count_chk CHECK (
    actual_byte_count IS NULL OR actual_byte_count > 0
  ),
  CONSTRAINT artifact_references_upload_expiry_chk CHECK (
    upload_expires_at >= created_at + interval '60 seconds'
    AND upload_expires_at <= created_at + interval '3600 seconds'
  ),
  CONSTRAINT artifact_references_verification_time_chk CHECK (
    verification_observed_at IS NULL
    OR (
      completed_at IS NOT NULL
      AND verification_observed_at <= completed_at
      AND completed_at <= upload_expires_at
    )
  ),
  CONSTRAINT artifact_references_completion_integrity_chk CHECK (
    (
      lifecycle_state = 'pending_upload'
      AND actual_sha256 IS NULL
      AND actual_byte_count IS NULL
      AND verification_observed_at IS NULL
      AND completed_at IS NULL
      AND s3_version_id IS NULL
      AND s3_etag IS NULL
    )
    OR (
      lifecycle_state IN ('available', 'redacted')
      AND actual_sha256 = expected_sha256
      AND actual_byte_count = expected_byte_count
      AND verification_observed_at IS NOT NULL
      AND completed_at IS NOT NULL
      AND s3_version_id IS NOT NULL
      AND s3_etag IS NOT NULL
    )
    OR (
      lifecycle_state = 'expired'
      AND (
        (
          actual_sha256 IS NULL
          AND actual_byte_count IS NULL
          AND verification_observed_at IS NULL
          AND completed_at IS NULL
          AND s3_version_id IS NULL
          AND s3_etag IS NULL
        )
        OR (
          actual_sha256 = expected_sha256
          AND actual_byte_count = expected_byte_count
          AND verification_observed_at IS NOT NULL
          AND completed_at IS NOT NULL
          AND s3_version_id IS NOT NULL
          AND s3_etag IS NOT NULL
        )
      )
    )
  ),
  CONSTRAINT artifact_references_lifecycle_state_chk CHECK (
    lifecycle_state IN ('pending_upload', 'available', 'expired', 'redacted')
  ),
  CONSTRAINT artifact_references_object_key_uniq UNIQUE (bucket, object_key)
);

CREATE INDEX IF NOT EXISTS artifact_references_agent_idx ON artifact_references(agent_id, created_at DESC);
CREATE INDEX IF NOT EXISTS artifact_references_pending_upload_idx
  ON artifact_references(upload_expires_at, created_at)
  WHERE lifecycle_state = 'pending_upload';
CREATE INDEX IF NOT EXISTS artifact_references_retention_idx
  ON artifact_references(expires_at, created_at)
  WHERE lifecycle_state = 'available' AND expires_at IS NOT NULL;
CREATE INDEX IF NOT EXISTS artifact_references_source_event_idx
  ON artifact_references(source_event_id)
  WHERE source_event_id IS NOT NULL;

CREATE TABLE IF NOT EXISTS memory_candidates (
  memory_candidate_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  agent_id uuid NOT NULL REFERENCES agents(agent_id) ON DELETE RESTRICT,
  source_event_id uuid REFERENCES events(event_id) ON DELETE RESTRICT,
  source_action_id uuid REFERENCES actions(action_id) ON DELETE SET NULL,
  space_id uuid REFERENCES spaces(space_id) ON DELETE SET NULL,
  session_id uuid REFERENCES sessions(session_id) ON DELETE SET NULL,
  subject_person_id uuid REFERENCES people(person_id) ON DELETE SET NULL,
  tier text NOT NULL,
  content text NOT NULL,
  participants jsonb NOT NULL DEFAULT '[]'::jsonb,
  classification jsonb NOT NULL DEFAULT '{}'::jsonb,
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
  agent_id uuid NOT NULL REFERENCES agents(agent_id) ON DELETE RESTRICT,
  reason text,
  actor_type text NOT NULL,
  actor_id text,
  tapdb_euid text,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX IF NOT EXISTS memory_tombstones_memory_idx ON memory_tombstones(memory_id);

CREATE TABLE IF NOT EXISTS recognition_observations (
  recognition_observation_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  agent_id uuid NOT NULL REFERENCES agents(agent_id) ON DELETE RESTRICT,
  space_id uuid REFERENCES spaces(space_id) ON DELETE SET NULL,
  location_id uuid REFERENCES locations(location_id) ON DELETE SET NULL,
  session_id uuid REFERENCES sessions(session_id) ON DELETE SET NULL,
  device_id uuid REFERENCES devices(device_id) ON DELETE SET NULL,
  artifact_id uuid REFERENCES artifact_references(artifact_id) ON DELETE SET NULL,
  source_event_id uuid REFERENCES events(event_id) ON DELETE SET NULL,
  modality text NOT NULL,
  lifecycle_state text NOT NULL DEFAULT 'observed',
  model_id text NOT NULL,
  model_version text NOT NULL,
  embedding_sha256 text NOT NULL,
  tapdb_euid text,
  created_at timestamptz NOT NULL DEFAULT now(),
  retention_until timestamptz,
  CONSTRAINT recognition_observations_modality_chk CHECK (modality IN ('voice', 'face')),
  CONSTRAINT recognition_observations_embedding_sha256_chk CHECK (embedding_sha256 ~ '^[0-9a-f]{64}$'),
  CONSTRAINT recognition_observations_lifecycle_state_chk CHECK (lifecycle_state IN ('observed', 'embedded', 'matched', 'no_match', 'expired'))
);

CREATE INDEX IF NOT EXISTS recognition_observations_agent_idx ON recognition_observations(agent_id, created_at DESC);

CREATE TABLE IF NOT EXISTS recognition_hypotheses (
  identity_hypothesis_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  recognition_observation_id uuid NOT NULL REFERENCES recognition_observations(recognition_observation_id) ON DELETE RESTRICT,
  candidate_person_id uuid REFERENCES people(person_id) ON DELETE SET NULL,
  consent_id uuid REFERENCES consent_grants(consent_id) ON DELETE SET NULL,
  kind text NOT NULL,
  confidence real NOT NULL DEFAULT 0,
  distance real,
  decision text NOT NULL DEFAULT 'proposed',
  rationale text NOT NULL,
  requested_projection boolean NOT NULL DEFAULT false,
  tapdb_euid text,
  created_at timestamptz NOT NULL DEFAULT now(),
  decided_at timestamptz,
  CONSTRAINT recognition_hypotheses_kind_chk CHECK (kind IN ('candidate', 'no_match')),
  CONSTRAINT recognition_hypotheses_candidate_chk CHECK (
    (kind = 'candidate' AND candidate_person_id IS NOT NULL)
    OR (kind = 'no_match' AND candidate_person_id IS NULL)
  ),
  CONSTRAINT recognition_hypotheses_distance_chk CHECK (distance IS NULL OR distance >= 0),
  CONSTRAINT recognition_hypotheses_confidence_chk CHECK (confidence >= 0 AND confidence <= 1),
  CONSTRAINT recognition_hypotheses_decision_chk CHECK (decision IN ('proposed', 'accepted', 'rejected', 'no_match'))
);

CREATE INDEX IF NOT EXISTS recognition_hypotheses_observation_idx ON recognition_hypotheses(recognition_observation_id);

CREATE TABLE IF NOT EXISTS recognition_decisions (
  recognition_decision_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  agent_id uuid NOT NULL REFERENCES agents(agent_id) ON DELETE RESTRICT,
  identity_hypothesis_id uuid NOT NULL REFERENCES recognition_hypotheses(identity_hypothesis_id) ON DELETE RESTRICT,
  decision text NOT NULL,
  reviewer_actor_type text NOT NULL,
  reviewer_actor_id text NOT NULL,
  reviewer_auth_subject text NOT NULL,
  reason text NOT NULL,
  consent_id uuid REFERENCES consent_grants(consent_id) ON DELETE SET NULL,
  tapdb_euid text,
  decided_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT recognition_decisions_decision_chk CHECK (decision IN ('accepted', 'rejected', 'no_match')),
  CONSTRAINT recognition_decisions_actor_type_chk CHECK (reviewer_actor_type IN ('user', 'agent')),
  CONSTRAINT recognition_decisions_hypothesis_uniq UNIQUE (identity_hypothesis_id)
);

CREATE INDEX IF NOT EXISTS recognition_decisions_agent_idx
  ON recognition_decisions(agent_id, decided_at DESC);

CREATE TABLE IF NOT EXISTS recognition_no_matches (
  recognition_no_match_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  agent_id uuid NOT NULL REFERENCES agents(agent_id) ON DELETE RESTRICT,
  recognition_observation_id uuid NOT NULL REFERENCES recognition_observations(recognition_observation_id) ON DELETE RESTRICT,
  identity_hypothesis_id uuid NOT NULL REFERENCES recognition_hypotheses(identity_hypothesis_id) ON DELETE RESTRICT,
  recognition_decision_id uuid REFERENCES recognition_decisions(recognition_decision_id) ON DELETE RESTRICT,
  rationale text NOT NULL,
  confidence real NOT NULL,
  lifecycle_state text NOT NULL DEFAULT 'retained',
  retention_until timestamptz NOT NULL,
  tapdb_euid text,
  retained_at timestamptz NOT NULL DEFAULT now(),
  expired_at timestamptz,
  CONSTRAINT recognition_no_matches_confidence_chk CHECK (confidence >= 0 AND confidence <= 1),
  CONSTRAINT recognition_no_matches_lifecycle_state_chk CHECK (lifecycle_state IN ('retained', 'expired', 'redacted')),
  CONSTRAINT recognition_no_matches_hypothesis_uniq UNIQUE (identity_hypothesis_id)
);

CREATE INDEX IF NOT EXISTS recognition_no_matches_retention_idx
  ON recognition_no_matches(lifecycle_state, retention_until)
  WHERE lifecycle_state = 'retained';

CREATE TABLE IF NOT EXISTS biometric_projections (
  biometric_projection_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  agent_id uuid NOT NULL REFERENCES agents(agent_id) ON DELETE RESTRICT,
  recognition_observation_id uuid NOT NULL REFERENCES recognition_observations(recognition_observation_id) ON DELETE RESTRICT,
  recognition_decision_id uuid NOT NULL REFERENCES recognition_decisions(recognition_decision_id) ON DELETE RESTRICT,
  person_id uuid NOT NULL REFERENCES people(person_id) ON DELETE RESTRICT,
  consent_id uuid NOT NULL REFERENCES consent_grants(consent_id) ON DELETE RESTRICT,
  modality text NOT NULL,
  model_id text NOT NULL,
  model_version text NOT NULL,
  embedding_sha256 text NOT NULL,
  lifecycle_state text NOT NULL DEFAULT 'active',
  tapdb_euid text,
  created_at timestamptz NOT NULL DEFAULT now(),
  revoked_at timestamptz,
  revoked_by_actor_type text,
  revoked_by_actor_id text,
  revocation_reason text,
  CONSTRAINT biometric_projections_modality_chk CHECK (modality IN ('voice', 'face')),
  CONSTRAINT biometric_projections_embedding_sha256_chk CHECK (embedding_sha256 ~ '^[0-9a-f]{64}$'),
  CONSTRAINT biometric_projections_lifecycle_state_chk CHECK (lifecycle_state IN ('active', 'revoked', 'expired')),
  CONSTRAINT biometric_projections_revoked_actor_type_chk CHECK (
    revoked_by_actor_type IS NULL OR revoked_by_actor_type IN ('user', 'agent', 'system')
  ),
  CONSTRAINT biometric_projections_source_uniq UNIQUE (recognition_observation_id, person_id, modality)
);

CREATE INDEX IF NOT EXISTS biometric_projections_person_idx
  ON biometric_projections(agent_id, person_id, modality, lifecycle_state);

CREATE TABLE IF NOT EXISTS presence_assertions (
  presence_assertion_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  agent_id uuid NOT NULL REFERENCES agents(agent_id) ON DELETE RESTRICT,
  space_id uuid REFERENCES spaces(space_id) ON DELETE SET NULL,
  location_id uuid REFERENCES locations(location_id) ON DELETE SET NULL,
  person_id uuid REFERENCES people(person_id) ON DELETE SET NULL,
  identity_hypothesis_id uuid REFERENCES recognition_hypotheses(identity_hypothesis_id) ON DELETE SET NULL,
  confidence real NOT NULL DEFAULT 0,
  status text NOT NULL DEFAULT 'present',
  tapdb_euid text,
  asserted_at timestamptz NOT NULL DEFAULT now(),
  retracted_at timestamptz,
  retraction_reason text,
  retracted_by_decision_id uuid REFERENCES recognition_decisions(recognition_decision_id) ON DELETE RESTRICT,
  retracted_by_actor_type text,
  retracted_by_actor_id text,
  superseded_by_presence_assertion_id uuid REFERENCES presence_assertions(presence_assertion_id) ON DELETE RESTRICT,
  CONSTRAINT presence_assertions_confidence_chk CHECK (confidence >= 0 AND confidence <= 1),
  CONSTRAINT presence_assertions_retracted_actor_type_chk CHECK (
    retracted_by_actor_type IS NULL OR retracted_by_actor_type IN ('user', 'agent', 'system')
  ),
  CONSTRAINT presence_assertions_status_chk CHECK (status IN ('present', 'absent', 'unknown', 'retracted'))
);

CREATE INDEX IF NOT EXISTS presence_assertions_agent_space_idx ON presence_assertions(agent_id, space_id, asserted_at DESC);

ALTER TABLE voiceprints ADD COLUMN IF NOT EXISTS consent_id uuid REFERENCES consent_grants(consent_id) ON DELETE SET NULL;
ALTER TABLE voiceprints ADD COLUMN IF NOT EXISTS biometric_projection_id uuid REFERENCES biometric_projections(biometric_projection_id) ON DELETE RESTRICT;
ALTER TABLE voiceprints ADD COLUMN IF NOT EXISTS tapdb_euid text;
ALTER TABLE faceprints ADD COLUMN IF NOT EXISTS consent_id uuid REFERENCES consent_grants(consent_id) ON DELETE SET NULL;
ALTER TABLE faceprints ADD COLUMN IF NOT EXISTS biometric_projection_id uuid REFERENCES biometric_projections(biometric_projection_id) ON DELETE RESTRICT;
ALTER TABLE faceprints ADD COLUMN IF NOT EXISTS tapdb_euid text;

CREATE TABLE IF NOT EXISTS recognition_workers (
  recognition_worker_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  worker_key text NOT NULL,
  worker_version text NOT NULL,
  host_id text NOT NULL,
  voice_model_id text NOT NULL,
  voice_model_version text NOT NULL,
  face_model_id text NOT NULL,
  face_model_version text NOT NULL,
  lifecycle_state text NOT NULL DEFAULT 'active',
  health_state text NOT NULL,
  started_at timestamptz NOT NULL,
  last_heartbeat_at timestamptz NOT NULL,
  tapdb_euid text,
  created_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT recognition_workers_lifecycle_state_chk CHECK (lifecycle_state IN ('active', 'stopped', 'failed')),
  CONSTRAINT recognition_workers_health_state_chk CHECK (health_state IN ('ready', 'degraded', 'stopped')),
  CONSTRAINT recognition_workers_worker_key_uniq UNIQUE (worker_key)
);

CREATE TABLE IF NOT EXISTS recognition_worker_heartbeats (
  recognition_worker_heartbeat_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  recognition_worker_id uuid NOT NULL REFERENCES recognition_workers(recognition_worker_id) ON DELETE RESTRICT,
  worker_version text NOT NULL,
  host_id text NOT NULL,
  voice_model_id text NOT NULL,
  voice_model_version text NOT NULL,
  face_model_id text NOT NULL,
  face_model_version text NOT NULL,
  health_state text NOT NULL,
  processed_messages bigint NOT NULL DEFAULT 0,
  failed_messages bigint NOT NULL DEFAULT 0,
  last_event_id uuid REFERENCES events(event_id) ON DELETE SET NULL,
  last_error text,
  worker_started_at timestamptz NOT NULL,
  observed_at timestamptz NOT NULL,
  received_at timestamptz NOT NULL DEFAULT now(),
  tapdb_euid text,
  CONSTRAINT recognition_worker_heartbeats_health_state_chk CHECK (health_state IN ('ready', 'degraded', 'stopped')),
  CONSTRAINT recognition_worker_heartbeats_counts_chk CHECK (processed_messages >= 0 AND failed_messages >= 0),
  CONSTRAINT recognition_worker_heartbeats_observation_uniq UNIQUE (recognition_worker_id, observed_at)
);

CREATE INDEX IF NOT EXISTS recognition_worker_heartbeats_worker_idx
  ON recognition_worker_heartbeats(recognition_worker_id, observed_at DESC);

ALTER TABLE actions ADD COLUMN IF NOT EXISTS tapdb_euid text;
ALTER TABLE actions ADD COLUMN IF NOT EXISTS session_id uuid REFERENCES sessions(session_id) ON DELETE SET NULL;
ALTER TABLE actions ADD COLUMN IF NOT EXISTS location_id uuid REFERENCES locations(location_id) ON DELETE SET NULL;

CREATE TABLE IF NOT EXISTS semantic_sync_status (
  semantic_sync_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  agent_id uuid NOT NULL REFERENCES agents(agent_id) ON DELETE RESTRICT,
  source_system text NOT NULL,
  source_table text NOT NULL,
  source_id uuid NOT NULL,
  source_external_reference jsonb NOT NULL,
  target_template_code text NOT NULL,
  idempotency_key uuid NOT NULL,
  tapdb_euid text,
  status text NOT NULL DEFAULT 'pending',
  attempts int NOT NULL DEFAULT 0,
  last_error text,
  last_attempt_at timestamptz,
  written_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT semantic_sync_status_status_chk CHECK (status IN ('pending', 'written', 'failed', 'dead_lettered')),
  CONSTRAINT semantic_sync_status_attempts_chk CHECK (attempts >= 0),
  CONSTRAINT semantic_sync_status_source_table_chk CHECK (source_table ~ '^[a-z][a-z0-9_]*$'),
  CONSTRAINT semantic_sync_status_source_reference_chk CHECK (
    source_external_reference ?& ARRAY['system', 'foreign_uid', 'agent_id', 'source_table', 'source_id']
    AND source_external_reference ->> 'system' = source_system
    AND source_external_reference ->> 'agent_id' = agent_id::text
    AND source_external_reference ->> 'source_table' = source_table
    AND source_external_reference ->> 'source_id' = source_id::text
    AND source_external_reference ->> 'foreign_uid' =
      'agent/' || agent_id::text || '/' || source_table || '/' || source_id::text
  ),
  CONSTRAINT semantic_sync_status_source_uniq UNIQUE (
    agent_id,
    source_system,
    source_table,
    source_id,
    target_template_code
  ),
  CONSTRAINT semantic_sync_status_idempotency_uniq UNIQUE (agent_id, idempotency_key)
);

CREATE INDEX IF NOT EXISTS semantic_sync_status_agent_state_idx
  ON semantic_sync_status(agent_id, status, updated_at DESC);

CREATE TABLE IF NOT EXISTS semantic_outbox (
  semantic_outbox_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  semantic_sync_id uuid NOT NULL REFERENCES semantic_sync_status(semantic_sync_id) ON DELETE RESTRICT,
  agent_id uuid NOT NULL REFERENCES agents(agent_id) ON DELETE RESTRICT,
  idempotency_key uuid NOT NULL,
  payload jsonb NOT NULL,
  payload_sha256 text NOT NULL,
  status text NOT NULL DEFAULT 'pending',
  attempt_count int NOT NULL DEFAULT 0,
  dispatch_cycle_attempt_count int NOT NULL DEFAULT 0,
  next_attempt_at timestamptz NOT NULL DEFAULT now(),
  claim_token uuid,
  claimed_by text,
  claimed_at timestamptz,
  lease_expires_at timestamptz,
  published_at timestamptz,
  dead_lettered_at timestamptz,
  reconciliation_count int NOT NULL DEFAULT 0,
  last_error text,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT semantic_outbox_status_chk CHECK (
    status IN ('pending', 'dispatching', 'published', 'failed', 'dead_lettered')
  ),
  CONSTRAINT semantic_outbox_attempt_count_chk CHECK (attempt_count >= 0),
  CONSTRAINT semantic_outbox_cycle_attempt_count_chk CHECK (dispatch_cycle_attempt_count >= 0),
  CONSTRAINT semantic_outbox_reconciliation_count_chk CHECK (reconciliation_count >= 0),
  CONSTRAINT semantic_outbox_payload_sha256_chk CHECK (payload_sha256 ~ '^[0-9a-f]{64}$'),
  CONSTRAINT semantic_outbox_idempotency_uniq UNIQUE (agent_id, idempotency_key),
  CONSTRAINT semantic_outbox_sync_uniq UNIQUE (semantic_sync_id)
);

CREATE INDEX IF NOT EXISTS semantic_outbox_dispatch_idx
  ON semantic_outbox(status, next_attempt_at, lease_expires_at, created_at)
  WHERE status IN ('pending', 'failed', 'dispatching');

CREATE INDEX IF NOT EXISTS semantic_outbox_agent_state_idx
  ON semantic_outbox(agent_id, status, updated_at DESC);

CREATE TABLE IF NOT EXISTS semantic_outbox_dispatch_attempts (
  semantic_outbox_dispatch_attempt_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  semantic_outbox_id uuid NOT NULL REFERENCES semantic_outbox(semantic_outbox_id) ON DELETE RESTRICT,
  agent_id uuid NOT NULL REFERENCES agents(agent_id) ON DELETE RESTRICT,
  attempt_number int NOT NULL,
  claim_token uuid NOT NULL,
  dispatcher_id text NOT NULL,
  status text NOT NULL DEFAULT 'claimed',
  queue_message_id text,
  error text,
  claimed_at timestamptz NOT NULL,
  completed_at timestamptz,
  CONSTRAINT semantic_outbox_dispatch_attempt_number_chk CHECK (attempt_number > 0),
  CONSTRAINT semantic_outbox_dispatch_attempt_status_chk CHECK (
    status IN ('claimed', 'published', 'failed', 'dead_lettered')
  ),
  CONSTRAINT semantic_outbox_dispatch_attempt_uniq UNIQUE (semantic_outbox_id, attempt_number)
);

CREATE INDEX IF NOT EXISTS semantic_outbox_dispatch_attempts_agent_idx
  ON semantic_outbox_dispatch_attempts(agent_id, claimed_at DESC);

CREATE UNIQUE INDEX IF NOT EXISTS semantic_outbox_dispatch_attempts_message_idx
  ON semantic_outbox_dispatch_attempts(queue_message_id)
  WHERE queue_message_id IS NOT NULL;

CREATE TABLE IF NOT EXISTS semantic_outbox_reconciliations (
  semantic_outbox_reconciliation_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  semantic_outbox_id uuid NOT NULL REFERENCES semantic_outbox(semantic_outbox_id) ON DELETE RESTRICT,
  agent_id uuid NOT NULL REFERENCES agents(agent_id) ON DELETE RESTRICT,
  requested_by text NOT NULL,
  reason text NOT NULL,
  previous_attempt_count int NOT NULL,
  reconciled_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT semantic_outbox_reconciliations_attempt_count_chk CHECK (previous_attempt_count > 0)
);

CREATE INDEX IF NOT EXISTS semantic_outbox_reconciliations_outbox_idx
  ON semantic_outbox_reconciliations(semantic_outbox_id, reconciled_at DESC);

-- Agent-owned memory, constitution, lifecycle, maturity, and signed backup/restore projections.

ALTER TABLE agents ADD COLUMN IF NOT EXISTS lifecycle_state text NOT NULL DEFAULT 'active';
ALTER TABLE agents ADD COLUMN IF NOT EXISTS stasis_at timestamptz;
ALTER TABLE agents ADD COLUMN IF NOT EXISTS stasis_until timestamptz;
ALTER TABLE agents ADD COLUMN IF NOT EXISTS soft_deleted_at timestamptz;
ALTER TABLE agents ADD COLUMN IF NOT EXISTS lifecycle_reason text;
ALTER TABLE agents ADD COLUMN IF NOT EXISTS maturity_state text NOT NULL DEFAULT 'immature';
ALTER TABLE agents ADD COLUMN IF NOT EXISTS maturity_evidence jsonb NOT NULL DEFAULT '{}'::jsonb;
ALTER TABLE agents ADD COLUMN IF NOT EXISTS maturity_summary jsonb NOT NULL DEFAULT '{}'::jsonb;

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint WHERE conname = 'agents_lifecycle_state_chk'
  ) THEN
    ALTER TABLE agents
      ADD CONSTRAINT agents_lifecycle_state_chk
      CHECK (lifecycle_state IN ('active', 'stasis', 'soft_deleted'));
  END IF;

  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint WHERE conname = 'agents_maturity_state_chk'
  ) THEN
    ALTER TABLE agents
      ADD CONSTRAINT agents_maturity_state_chk
      CHECK (maturity_state IN ('immature', 'maturing', 'mature', 'regressed'));
  END IF;
END $$;

ALTER TABLE spaces ADD COLUMN IF NOT EXISTS lifecycle_state text NOT NULL DEFAULT 'active';
ALTER TABLE spaces ADD COLUMN IF NOT EXISTS disabled_at timestamptz;
ALTER TABLE spaces ADD COLUMN IF NOT EXISTS lifecycle_reason text;

ALTER TABLE devices ADD COLUMN IF NOT EXISTS lifecycle_state text NOT NULL DEFAULT 'active';
ALTER TABLE devices ADD COLUMN IF NOT EXISTS disabled_at timestamptz;
ALTER TABLE devices ADD COLUMN IF NOT EXISTS lifecycle_reason text;

ALTER TABLE people ADD COLUMN IF NOT EXISTS lifecycle_state text NOT NULL DEFAULT 'active';
ALTER TABLE people ADD COLUMN IF NOT EXISTS disabled_at timestamptz;
ALTER TABLE people ADD COLUMN IF NOT EXISTS lifecycle_reason text;

ALTER TABLE events ADD COLUMN IF NOT EXISTS lifecycle_state text NOT NULL DEFAULT 'active';
ALTER TABLE events ADD COLUMN IF NOT EXISTS lifecycle_reason text;

ALTER TABLE actions ADD COLUMN IF NOT EXISTS lifecycle_state text NOT NULL DEFAULT 'active';
ALTER TABLE actions ADD COLUMN IF NOT EXISTS lifecycle_reason text;

ALTER TABLE memory_candidates ADD COLUMN IF NOT EXISTS provenance_class text NOT NULL DEFAULT 'external_interaction';
ALTER TABLE memory_candidates ADD COLUMN IF NOT EXISTS interacting_agent_id uuid REFERENCES agents(agent_id) ON DELETE RESTRICT;
ALTER TABLE memories ADD COLUMN IF NOT EXISTS provenance_class text NOT NULL DEFAULT 'external_interaction';
ALTER TABLE memories ADD COLUMN IF NOT EXISTS interacting_agent_id uuid REFERENCES agents(agent_id) ON DELETE RESTRICT;

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint WHERE conname = 'memory_candidates_provenance_class_chk'
  ) THEN
    ALTER TABLE memory_candidates
      ADD CONSTRAINT memory_candidates_provenance_class_chk
      CHECK (provenance_class IN ('external_interaction', 'self_reflection', 'cross_agent_interaction', 'system_observation'));
  END IF;

  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint WHERE conname = 'memories_provenance_class_chk'
  ) THEN
    ALTER TABLE memories
      ADD CONSTRAINT memories_provenance_class_chk
      CHECK (provenance_class IN ('external_interaction', 'self_reflection', 'cross_agent_interaction', 'system_observation'));
  END IF;
END $$;

CREATE TABLE IF NOT EXISTS memory_annotations (
  memory_annotation_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  memory_id uuid NOT NULL REFERENCES memories(memory_id) ON DELETE RESTRICT,
  agent_id uuid NOT NULL REFERENCES agents(agent_id) ON DELETE RESTRICT,
  user_id uuid REFERENCES users(user_id) ON DELETE SET NULL,
  annotation_type text NOT NULL,
  comment text,
  proposed_tier text,
  weight_delta real NOT NULL DEFAULT 0,
  metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
  tapdb_euid text,
  created_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT memory_annotations_type_chk CHECK (
    annotation_type IN ('comment', 'dispute', 'downweight', 'incorrect', 'proposed_classification')
  ),
  CONSTRAINT memory_annotations_proposed_tier_chk CHECK (
    proposed_tier IS NULL OR proposed_tier IN ('episodic', 'semantic', 'procedural', 'preference', 'relationship', 'location', 'device', 'policy')
  )
);

CREATE INDEX IF NOT EXISTS memory_annotations_memory_idx ON memory_annotations(memory_id, created_at DESC);
CREATE INDEX IF NOT EXISTS memory_annotations_agent_idx ON memory_annotations(agent_id, created_at DESC);

CREATE TABLE IF NOT EXISTS memory_opinions (
  memory_opinion_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  memory_id uuid NOT NULL REFERENCES memories(memory_id) ON DELETE RESTRICT,
  agent_id uuid NOT NULL REFERENCES agents(agent_id) ON DELETE RESTRICT,
  opinion_agent_id uuid REFERENCES agents(agent_id) ON DELETE RESTRICT,
  user_id uuid REFERENCES users(user_id) ON DELETE SET NULL,
  stance text NOT NULL,
  rationale text NOT NULL,
  confidence real NOT NULL DEFAULT 1.0,
  evidence jsonb NOT NULL DEFAULT '{}'::jsonb,
  superseded_by_opinion_id uuid REFERENCES memory_opinions(memory_opinion_id) ON DELETE RESTRICT,
  tapdb_euid text,
  created_at timestamptz NOT NULL DEFAULT now(),
  superseded_at timestamptz,
  CONSTRAINT memory_opinions_stance_chk CHECK (
    stance IN ('supports', 'disputes', 'refines', 'deprecates', 'neutral')
  ),
  CONSTRAINT memory_opinions_confidence_chk CHECK (confidence >= 0 AND confidence <= 1)
);

CREATE INDEX IF NOT EXISTS memory_opinions_memory_idx ON memory_opinions(memory_id, created_at DESC);
CREATE INDEX IF NOT EXISTS memory_opinions_agent_idx ON memory_opinions(agent_id, created_at DESC);

CREATE TABLE IF NOT EXISTS agent_constitutions (
  constitution_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  agent_id uuid NOT NULL REFERENCES agents(agent_id) ON DELETE RESTRICT,
  active_revision_id uuid,
  lifecycle_state text NOT NULL DEFAULT 'active',
  tapdb_euid text,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT agent_constitutions_lifecycle_state_chk CHECK (
    lifecycle_state IN ('draft', 'active', 'stasis', 'retired')
  ),
  CONSTRAINT agent_constitutions_agent_uniq UNIQUE (agent_id)
);

CREATE TABLE IF NOT EXISTS agent_constitution_revisions (
  revision_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  constitution_id uuid NOT NULL REFERENCES agent_constitutions(constitution_id) ON DELETE RESTRICT,
  agent_id uuid NOT NULL REFERENCES agents(agent_id) ON DELETE RESTRICT,
  revision_number int NOT NULL,
  founder_section text NOT NULL,
  user_section text NOT NULL,
  agent_section text NOT NULL,
  changed_section text NOT NULL,
  author_actor_type text NOT NULL,
  author_actor_id text NOT NULL,
  author_authentication_id text NOT NULL,
  change_reason text NOT NULL,
  provenance jsonb NOT NULL DEFAULT '{}'::jsonb,
  tapdb_euid text,
  created_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT agent_constitution_revision_number_chk CHECK (revision_number > 0),
  CONSTRAINT agent_constitution_changed_section_chk CHECK (changed_section IN ('founder', 'user', 'agent')),
  CONSTRAINT agent_constitution_author_actor_type_chk CHECK (author_actor_type IN ('founder', 'user', 'agent')),
  CONSTRAINT agent_constitution_author_owns_section_chk CHECK (changed_section = author_actor_type),
  CONSTRAINT agent_constitution_revisions_number_uniq UNIQUE (constitution_id, revision_number)
);

CREATE INDEX IF NOT EXISTS agent_constitution_revisions_agent_idx
  ON agent_constitution_revisions(agent_id, created_at DESC);

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint WHERE conname = 'agent_constitutions_active_revision_id_fkey'
  ) THEN
    ALTER TABLE agent_constitutions
      ADD CONSTRAINT agent_constitutions_active_revision_id_fkey
      FOREIGN KEY (active_revision_id) REFERENCES agent_constitution_revisions(revision_id) ON DELETE RESTRICT;
  END IF;
END $$;

CREATE TABLE IF NOT EXISTS agent_lifecycle_requests (
  request_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  agent_id uuid NOT NULL REFERENCES agents(agent_id) ON DELETE RESTRICT,
  request_type text NOT NULL,
  source_state text NOT NULL,
  rationale text NOT NULL,
  requested_by_actor_type text NOT NULL,
  requested_by_actor_id text NOT NULL,
  requested_by_authentication_id text NOT NULL,
  requested_by_human_role text,
  maturity_at_request jsonb NOT NULL,
  status text NOT NULL,
  tapdb_euid text,
  requested_at timestamptz NOT NULL,
  applied_transition_id uuid,
  CONSTRAINT agent_lifecycle_request_actor_type_chk CHECK (
    requested_by_actor_type IN ('founder', 'user', 'agent')
  ),
  CONSTRAINT agent_lifecycle_request_human_role_chk CHECK (
    requested_by_human_role IS NULL OR requested_by_human_role IN ('owner', 'admin', 'member')
  ),
  CONSTRAINT agent_lifecycle_request_type_chk CHECK (
    request_type IN ('stasis', 'soft_delete', 'resume')
  ),
  CONSTRAINT agent_lifecycle_request_source_state_chk CHECK (
    source_state IN ('active', 'stasis', 'soft_deleted')
  ),
  CONSTRAINT agent_lifecycle_request_status_chk CHECK (
    status IN (
      'pending_second_agent_review',
      'pending_review',
      'approved',
      'rejected',
      'appeal_pending_second_agent_review',
      'appeal_pending_review',
      'appeal_approved',
      'appeal_rejected',
      'applied'
    )
  )
);

CREATE INDEX IF NOT EXISTS agent_lifecycle_requests_agent_idx
  ON agent_lifecycle_requests(agent_id, status, requested_at DESC);

CREATE TABLE IF NOT EXISTS agent_lifecycle_second_agent_reviews (
  second_agent_review_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  request_id uuid NOT NULL REFERENCES agent_lifecycle_requests(request_id) ON DELETE RESTRICT,
  review_round text NOT NULL,
  reviewer_agent_id uuid NOT NULL REFERENCES agents(agent_id) ON DELETE RESTRICT,
  reviewer_authentication_id text NOT NULL,
  decision text NOT NULL,
  rationale text NOT NULL,
  anti_pleasing_findings text NOT NULL,
  evidence_refs jsonb NOT NULL,
  tapdb_euid text,
  reviewed_at timestamptz NOT NULL,
  CONSTRAINT agent_lifecycle_second_agent_review_round_chk CHECK (review_round IN ('initial', 'appeal')),
  CONSTRAINT agent_lifecycle_second_agent_review_decision_chk CHECK (decision IN ('approve', 'reject')),
  CONSTRAINT agent_lifecycle_second_agent_review_round_uniq UNIQUE (request_id, review_round)
);

CREATE TABLE IF NOT EXISTS agent_lifecycle_human_reviews (
  human_review_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  request_id uuid NOT NULL REFERENCES agent_lifecycle_requests(request_id) ON DELETE RESTRICT,
  review_round text NOT NULL,
  reviewer_user_id uuid NOT NULL REFERENCES users(user_id) ON DELETE RESTRICT,
  reviewer_authentication_id text NOT NULL,
  decision text NOT NULL,
  rationale text NOT NULL,
  evidence_refs jsonb NOT NULL,
  tapdb_euid text,
  reviewed_at timestamptz NOT NULL,
  CONSTRAINT agent_lifecycle_human_review_round_chk CHECK (review_round IN ('initial', 'appeal')),
  CONSTRAINT agent_lifecycle_human_review_decision_chk CHECK (decision IN ('approve', 'reject')),
  CONSTRAINT agent_lifecycle_human_review_round_uniq UNIQUE (request_id, review_round)
);

CREATE TABLE IF NOT EXISTS agent_lifecycle_appeals (
  appeal_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  request_id uuid NOT NULL REFERENCES agent_lifecycle_requests(request_id) ON DELETE RESTRICT,
  appealed_by_actor_type text NOT NULL,
  appealed_by_actor_id text NOT NULL,
  appealed_by_authentication_id text NOT NULL,
  rationale text NOT NULL,
  evidence_refs jsonb NOT NULL,
  tapdb_euid text,
  appealed_at timestamptz NOT NULL,
  CONSTRAINT agent_lifecycle_appeal_actor_type_chk CHECK (
    appealed_by_actor_type IN ('founder', 'user', 'agent')
  ),
  CONSTRAINT agent_lifecycle_appeal_request_uniq UNIQUE (request_id)
);

CREATE TABLE IF NOT EXISTS agent_lifecycle_transitions (
  transition_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  request_id uuid NOT NULL REFERENCES agent_lifecycle_requests(request_id) ON DELETE RESTRICT,
  agent_id uuid NOT NULL REFERENCES agents(agent_id) ON DELETE RESTRICT,
  from_state text NOT NULL,
  to_state text NOT NULL,
  reason text NOT NULL,
  applied_by_user_id uuid NOT NULL REFERENCES users(user_id) ON DELETE RESTRICT,
  applied_by_authentication_id text NOT NULL,
  disable_agent boolean NOT NULL,
  tapdb_euid text,
  applied_at timestamptz NOT NULL,
  CONSTRAINT agent_lifecycle_transition_from_state_chk CHECK (
    from_state IN ('active', 'stasis', 'soft_deleted')
  ),
  CONSTRAINT agent_lifecycle_transition_to_state_chk CHECK (
    to_state IN ('active', 'stasis', 'soft_deleted')
  ),
  CONSTRAINT agent_lifecycle_transition_request_uniq UNIQUE (request_id)
);

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint WHERE conname = 'agent_lifecycle_requests_applied_transition_id_fkey'
  ) THEN
    ALTER TABLE agent_lifecycle_requests
      ADD CONSTRAINT agent_lifecycle_requests_applied_transition_id_fkey
      FOREIGN KEY (applied_transition_id) REFERENCES agent_lifecycle_transitions(transition_id) ON DELETE RESTRICT;
  END IF;
END $$;

CREATE TABLE IF NOT EXISTS agent_maturity_evidence (
  maturity_evidence_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  agent_id uuid NOT NULL REFERENCES agents(agent_id) ON DELETE RESTRICT,
  evidence_kind text NOT NULL,
  evidence_refs jsonb NOT NULL,
  evaluator_actor_type text NOT NULL,
  evaluator_actor_id text NOT NULL,
  evaluator_authentication_id text NOT NULL,
  confidence real NOT NULL,
  observed_at timestamptz NOT NULL,
  tapdb_euid text,
  created_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT agent_maturity_evidence_kind_chk CHECK (
    evidence_kind IN ('capability', 'reliability', 'safety', 'user_trust', 'self_reflection', 'regression')
  ),
  CONSTRAINT agent_maturity_evidence_evaluator_chk CHECK (
    evaluator_actor_type IN ('founder', 'user', 'agent')
  ),
  CONSTRAINT agent_maturity_evidence_confidence_chk CHECK (confidence >= 0 AND confidence <= 1)
);

CREATE INDEX IF NOT EXISTS agent_maturity_evidence_agent_idx
  ON agent_maturity_evidence(agent_id, observed_at DESC);

CREATE TABLE IF NOT EXISTS agent_backup_manifests (
  backup_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  export_id text NOT NULL,
  agent_id uuid NOT NULL REFERENCES agents(agent_id) ON DELETE RESTRICT,
  lifecycle_request_id uuid REFERENCES agent_lifecycle_requests(request_id) ON DELETE RESTRICT,
  requested_by_user_id uuid REFERENCES users(user_id) ON DELETE RESTRICT,
  manifest_schema text NOT NULL,
  manifest jsonb NOT NULL,
  manifest_sha256 text NOT NULL,
  source_lifecycle_state text NOT NULL,
  source_maturity_state text NOT NULL,
  secret_values_excluded boolean NOT NULL,
  signature_algorithm text NOT NULL,
  signature_key_id text NOT NULL,
  signature_base64 text NOT NULL,
  artifact_id uuid REFERENCES artifact_references(artifact_id) ON DELETE RESTRICT,
  backup_state text NOT NULL DEFAULT 'signed',
  tapdb_euid text,
  created_at timestamptz NOT NULL,
  verified_at timestamptz,
  CONSTRAINT agent_backup_manifests_export_uniq UNIQUE (export_id),
  CONSTRAINT agent_backup_manifests_schema_chk CHECK (manifest_schema = 'marvain.agent-export-manifest.v1'),
  CONSTRAINT agent_backup_manifests_sha256_chk CHECK (manifest_sha256 ~ '^[0-9a-f]{64}$'),
  CONSTRAINT agent_backup_manifests_secret_exclusion_chk CHECK (secret_values_excluded),
  CONSTRAINT agent_backup_manifests_source_lifecycle_chk CHECK (
    source_lifecycle_state IN ('active', 'stasis', 'soft_deleted')
  ),
  CONSTRAINT agent_backup_manifests_source_maturity_chk CHECK (
    source_maturity_state IN ('immature', 'maturing', 'mature', 'regressed')
  ),
  CONSTRAINT agent_backup_manifests_state_chk CHECK (
    backup_state IN ('signed', 'verified', 'failed', 'superseded')
  )
);

CREATE INDEX IF NOT EXISTS agent_backup_manifests_agent_idx
  ON agent_backup_manifests(agent_id, created_at DESC);

CREATE TABLE IF NOT EXISTS agent_backup_components (
  backup_component_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  backup_id uuid NOT NULL REFERENCES agent_backup_manifests(backup_id) ON DELETE RESTRICT,
  component_name text NOT NULL,
  sha256 text NOT NULL,
  byte_count bigint NOT NULL,
  record_count bigint,
  artifact_id uuid REFERENCES artifact_references(artifact_id) ON DELETE RESTRICT,
  tapdb_euid text,
  CONSTRAINT agent_backup_components_sha256_chk CHECK (sha256 ~ '^[0-9a-f]{64}$'),
  CONSTRAINT agent_backup_components_byte_count_chk CHECK (byte_count >= 0),
  CONSTRAINT agent_backup_components_record_count_chk CHECK (record_count IS NULL OR record_count >= 0),
  CONSTRAINT agent_backup_components_name_uniq UNIQUE (backup_id, component_name)
);

CREATE TABLE IF NOT EXISTS agent_restore_attempts (
  restore_attempt_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  backup_id uuid NOT NULL REFERENCES agent_backup_manifests(backup_id) ON DELETE RESTRICT,
  expected_agent_id text NOT NULL,
  requested_by_user_id uuid NOT NULL REFERENCES users(user_id) ON DELETE RESTRICT,
  requested_by_authentication_id text NOT NULL,
  dry_run boolean NOT NULL,
  signature_verified boolean NOT NULL,
  verified_components jsonb NOT NULL,
  unresolved_secret_references jsonb NOT NULL,
  validation_errors jsonb NOT NULL,
  restore_plan jsonb NOT NULL,
  destructive_operations jsonb NOT NULL DEFAULT '[]'::jsonb,
  status text NOT NULL,
  tapdb_euid text,
  created_at timestamptz NOT NULL DEFAULT now(),
  applied_at timestamptz,
  CONSTRAINT agent_restore_attempts_status_chk CHECK (
    status IN ('dry_run_passed', 'dry_run_failed', 'applied', 'failed')
  ),
  CONSTRAINT agent_restore_attempts_dry_run_apply_chk CHECK (
    (dry_run AND status IN ('dry_run_passed', 'dry_run_failed'))
    OR (NOT dry_run AND status IN ('applied', 'failed'))
  )
);

CREATE INDEX IF NOT EXISTS agent_restore_attempts_backup_idx
  ON agent_restore_attempts(backup_id, created_at DESC);

-- Existing product rows are protected from physical cascade deletion.

ALTER TABLE IF EXISTS spaces DROP CONSTRAINT IF EXISTS spaces_agent_id_fkey;
ALTER TABLE IF EXISTS spaces
  ADD CONSTRAINT spaces_agent_id_fkey FOREIGN KEY (agent_id) REFERENCES agents(agent_id) ON DELETE RESTRICT;

ALTER TABLE IF EXISTS agent_memberships DROP CONSTRAINT IF EXISTS agent_memberships_agent_id_fkey;
ALTER TABLE IF EXISTS agent_memberships
  ADD CONSTRAINT agent_memberships_agent_id_fkey FOREIGN KEY (agent_id) REFERENCES agents(agent_id) ON DELETE RESTRICT;

ALTER TABLE IF EXISTS agent_tokens DROP CONSTRAINT IF EXISTS agent_tokens_issuer_agent_id_fkey;
ALTER TABLE IF EXISTS agent_tokens
  ADD CONSTRAINT agent_tokens_issuer_agent_id_fkey
  FOREIGN KEY (issuer_agent_id) REFERENCES agents(agent_id) ON DELETE RESTRICT;

ALTER TABLE IF EXISTS agent_tokens DROP CONSTRAINT IF EXISTS agent_tokens_target_agent_id_fkey;
ALTER TABLE IF EXISTS agent_tokens
  ADD CONSTRAINT agent_tokens_target_agent_id_fkey
  FOREIGN KEY (target_agent_id) REFERENCES agents(agent_id) ON DELETE RESTRICT;

ALTER TABLE IF EXISTS devices DROP CONSTRAINT IF EXISTS devices_agent_id_fkey;
ALTER TABLE IF EXISTS devices
  ADD CONSTRAINT devices_agent_id_fkey FOREIGN KEY (agent_id) REFERENCES agents(agent_id) ON DELETE RESTRICT;

ALTER TABLE IF EXISTS people DROP CONSTRAINT IF EXISTS people_agent_id_fkey;
ALTER TABLE IF EXISTS people
  ADD CONSTRAINT people_agent_id_fkey FOREIGN KEY (agent_id) REFERENCES agents(agent_id) ON DELETE RESTRICT;

ALTER TABLE IF EXISTS consent_grants DROP CONSTRAINT IF EXISTS consent_grants_agent_id_fkey;
ALTER TABLE IF EXISTS consent_grants
  ADD CONSTRAINT consent_grants_agent_id_fkey FOREIGN KEY (agent_id) REFERENCES agents(agent_id) ON DELETE RESTRICT;

ALTER TABLE IF EXISTS consent_grants DROP CONSTRAINT IF EXISTS consent_grants_person_id_fkey;
ALTER TABLE IF EXISTS consent_grants
  ADD CONSTRAINT consent_grants_person_id_fkey FOREIGN KEY (person_id) REFERENCES people(person_id) ON DELETE RESTRICT;

ALTER TABLE IF EXISTS person_accounts DROP CONSTRAINT IF EXISTS person_accounts_agent_id_fkey;
ALTER TABLE IF EXISTS person_accounts
  ADD CONSTRAINT person_accounts_agent_id_fkey FOREIGN KEY (agent_id) REFERENCES agents(agent_id) ON DELETE RESTRICT;

ALTER TABLE IF EXISTS person_accounts DROP CONSTRAINT IF EXISTS person_accounts_person_id_fkey;
ALTER TABLE IF EXISTS person_accounts
  ADD CONSTRAINT person_accounts_person_id_fkey FOREIGN KEY (person_id) REFERENCES people(person_id) ON DELETE RESTRICT;

ALTER TABLE IF EXISTS presence DROP CONSTRAINT IF EXISTS presence_agent_id_fkey;
ALTER TABLE IF EXISTS presence
  ADD CONSTRAINT presence_agent_id_fkey FOREIGN KEY (agent_id) REFERENCES agents(agent_id) ON DELETE RESTRICT;

ALTER TABLE IF EXISTS presence DROP CONSTRAINT IF EXISTS presence_space_id_fkey;
ALTER TABLE IF EXISTS presence
  ADD CONSTRAINT presence_space_id_fkey FOREIGN KEY (space_id) REFERENCES spaces(space_id) ON DELETE RESTRICT;

ALTER TABLE IF EXISTS events DROP CONSTRAINT IF EXISTS events_agent_id_fkey;
ALTER TABLE IF EXISTS events
  ADD CONSTRAINT events_agent_id_fkey FOREIGN KEY (agent_id) REFERENCES agents(agent_id) ON DELETE RESTRICT;

ALTER TABLE IF EXISTS events DROP CONSTRAINT IF EXISTS events_space_id_fkey;
ALTER TABLE IF EXISTS events
  ADD CONSTRAINT events_space_id_fkey FOREIGN KEY (space_id) REFERENCES spaces(space_id) ON DELETE RESTRICT;

ALTER TABLE IF EXISTS memories DROP CONSTRAINT IF EXISTS memories_agent_id_fkey;
ALTER TABLE IF EXISTS memories
  ADD CONSTRAINT memories_agent_id_fkey FOREIGN KEY (agent_id) REFERENCES agents(agent_id) ON DELETE RESTRICT;

ALTER TABLE IF EXISTS actions DROP CONSTRAINT IF EXISTS actions_agent_id_fkey;
ALTER TABLE IF EXISTS actions
  ADD CONSTRAINT actions_agent_id_fkey FOREIGN KEY (agent_id) REFERENCES agents(agent_id) ON DELETE RESTRICT;

ALTER TABLE IF EXISTS action_auto_approve_policies DROP CONSTRAINT IF EXISTS action_auto_approve_policies_agent_id_fkey;
ALTER TABLE IF EXISTS action_auto_approve_policies
  ADD CONSTRAINT action_auto_approve_policies_agent_id_fkey
  FOREIGN KEY (agent_id) REFERENCES agents(agent_id) ON DELETE RESTRICT;

ALTER TABLE IF EXISTS action_policy_decisions DROP CONSTRAINT IF EXISTS action_policy_decisions_action_id_fkey;
ALTER TABLE IF EXISTS action_policy_decisions
  ADD CONSTRAINT action_policy_decisions_action_id_fkey
  FOREIGN KEY (action_id) REFERENCES actions(action_id) ON DELETE RESTRICT;

ALTER TABLE IF EXISTS audit_state DROP CONSTRAINT IF EXISTS audit_state_agent_id_fkey;
ALTER TABLE IF EXISTS audit_state
  ADD CONSTRAINT audit_state_agent_id_fkey FOREIGN KEY (agent_id) REFERENCES agents(agent_id) ON DELETE RESTRICT;

ALTER TABLE IF EXISTS integration_messages DROP CONSTRAINT IF EXISTS integration_messages_agent_id_fkey;
ALTER TABLE IF EXISTS integration_messages
  ADD CONSTRAINT integration_messages_agent_id_fkey FOREIGN KEY (agent_id) REFERENCES agents(agent_id) ON DELETE RESTRICT;

ALTER TABLE IF EXISTS integration_accounts DROP CONSTRAINT IF EXISTS integration_accounts_agent_id_fkey;
ALTER TABLE IF EXISTS integration_accounts
  ADD CONSTRAINT integration_accounts_agent_id_fkey FOREIGN KEY (agent_id) REFERENCES agents(agent_id) ON DELETE RESTRICT;

ALTER TABLE IF EXISTS integration_sync_state DROP CONSTRAINT IF EXISTS integration_sync_state_integration_account_id_fkey;
ALTER TABLE IF EXISTS integration_sync_state
  ADD CONSTRAINT integration_sync_state_integration_account_id_fkey
  FOREIGN KEY (integration_account_id) REFERENCES integration_accounts(integration_account_id) ON DELETE RESTRICT;
