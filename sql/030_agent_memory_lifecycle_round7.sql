-- 030_agent_memory_lifecycle_round7.sql
-- Agent-owned memory, constitution, lifecycle, maturity, and backup projections.

ALTER TABLE agents ADD COLUMN IF NOT EXISTS lifecycle_state text NOT NULL DEFAULT 'active';
ALTER TABLE agents ADD COLUMN IF NOT EXISTS stasis_at timestamptz;
ALTER TABLE agents ADD COLUMN IF NOT EXISTS soft_deleted_at timestamptz;
ALTER TABLE agents ADD COLUMN IF NOT EXISTS deleted_at timestamptz;
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
      CHECK (lifecycle_state IN ('active', 'stasis', 'soft_deleted', 'deleted'));
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
ALTER TABLE memory_candidates ADD COLUMN IF NOT EXISTS interacting_agent_id uuid REFERENCES agents(agent_id) ON DELETE SET NULL;
ALTER TABLE memory_candidates ADD COLUMN IF NOT EXISTS classification jsonb NOT NULL DEFAULT '{}'::jsonb;
ALTER TABLE memories ADD COLUMN IF NOT EXISTS provenance_class text NOT NULL DEFAULT 'external_interaction';
ALTER TABLE memories ADD COLUMN IF NOT EXISTS interacting_agent_id uuid REFERENCES agents(agent_id) ON DELETE SET NULL;

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
  opinion_agent_id uuid REFERENCES agents(agent_id) ON DELETE SET NULL,
  user_id uuid REFERENCES users(user_id) ON DELETE SET NULL,
  stance text NOT NULL,
  rationale text NOT NULL,
  confidence real NOT NULL DEFAULT 1.0,
  evidence jsonb NOT NULL DEFAULT '{}'::jsonb,
  superseded_by_opinion_id uuid REFERENCES memory_opinions(memory_opinion_id) ON DELETE SET NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  superseded_at timestamptz,
  CONSTRAINT memory_opinions_stance_chk CHECK (
    stance IN ('supports', 'disputes', 'refines', 'deprecates', 'neutral')
  )
);

CREATE INDEX IF NOT EXISTS memory_opinions_memory_idx ON memory_opinions(memory_id, created_at DESC);
CREATE INDEX IF NOT EXISTS memory_opinions_agent_idx ON memory_opinions(agent_id, created_at DESC);

CREATE TABLE IF NOT EXISTS agent_constitutions (
  constitution_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  agent_id uuid NOT NULL REFERENCES agents(agent_id) ON DELETE RESTRICT,
  active_revision_id uuid,
  lifecycle_state text NOT NULL DEFAULT 'active',
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT agent_constitutions_lifecycle_state_chk CHECK (
    lifecycle_state IN ('draft', 'active', 'stasis', 'retired')
  )
);

CREATE UNIQUE INDEX IF NOT EXISTS agent_constitutions_agent_idx ON agent_constitutions(agent_id);

CREATE TABLE IF NOT EXISTS agent_constitution_revisions (
  revision_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  constitution_id uuid NOT NULL REFERENCES agent_constitutions(constitution_id) ON DELETE RESTRICT,
  agent_id uuid NOT NULL REFERENCES agents(agent_id) ON DELETE RESTRICT,
  revision_number int NOT NULL,
  founder_section text NOT NULL DEFAULT '',
  user_section text NOT NULL DEFAULT '',
  agent_section text NOT NULL DEFAULT '',
  change_source text NOT NULL,
  change_reason text NOT NULL,
  provenance jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_by_user_id uuid REFERENCES users(user_id) ON DELETE SET NULL,
  created_by_agent_id uuid REFERENCES agents(agent_id) ON DELETE SET NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT agent_constitution_revision_number_chk CHECK (revision_number > 0),
  CONSTRAINT agent_constitution_change_source_chk CHECK (
    change_source IN ('founder', 'user', 'agent', 'governance_review')
  )
);

CREATE UNIQUE INDEX IF NOT EXISTS agent_constitution_revisions_number_idx
  ON agent_constitution_revisions(constitution_id, revision_number);

CREATE INDEX IF NOT EXISTS agent_constitution_revisions_agent_idx
  ON agent_constitution_revisions(agent_id, created_at DESC);

ALTER TABLE agent_constitutions
  DROP CONSTRAINT IF EXISTS agent_constitutions_active_revision_id_fkey;

ALTER TABLE agent_constitutions
  ADD CONSTRAINT agent_constitutions_active_revision_id_fkey
  FOREIGN KEY (active_revision_id) REFERENCES agent_constitution_revisions(revision_id) ON DELETE RESTRICT;

CREATE TABLE IF NOT EXISTS agent_lifecycle_requests (
  request_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  agent_id uuid NOT NULL REFERENCES agents(agent_id) ON DELETE RESTRICT,
  requested_by_type text NOT NULL,
  requested_by_id text,
  request_type text NOT NULL,
  rationale text NOT NULL,
  requested_stasis_until timestamptz,
  status text NOT NULL DEFAULT 'pending',
  reviewer_user_id uuid REFERENCES users(user_id) ON DELETE SET NULL,
  reviewer_agent_id uuid REFERENCES agents(agent_id) ON DELETE SET NULL,
  reviewer_findings jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_at timestamptz NOT NULL DEFAULT now(),
  reviewed_at timestamptz,
  applied_at timestamptz,
  CONSTRAINT agent_lifecycle_request_actor_chk CHECK (
    requested_by_type IN ('founder', 'user', 'agent', 'system')
  ),
  CONSTRAINT agent_lifecycle_request_type_chk CHECK (
    request_type IN ('stasis', 'resume', 'soft_delete', 'deletion')
  ),
  CONSTRAINT agent_lifecycle_request_status_chk CHECK (
    status IN ('pending', 'approved', 'rejected', 'applied', 'canceled')
  )
);

CREATE INDEX IF NOT EXISTS agent_lifecycle_requests_agent_idx
  ON agent_lifecycle_requests(agent_id, status, created_at DESC);

CREATE TABLE IF NOT EXISTS agent_maturity_evidence (
  maturity_evidence_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  agent_id uuid NOT NULL REFERENCES agents(agent_id) ON DELETE RESTRICT,
  evidence_kind text NOT NULL,
  evidence_payload jsonb NOT NULL,
  evaluator_type text NOT NULL,
  evaluator_id text,
  maturity_state text NOT NULL,
  confidence real NOT NULL DEFAULT 1.0,
  created_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT agent_maturity_evidence_kind_chk CHECK (
    evidence_kind IN ('capability', 'reliability', 'safety', 'user_trust', 'self_reflection', 'regression')
  ),
  CONSTRAINT agent_maturity_evidence_evaluator_chk CHECK (
    evaluator_type IN ('founder', 'user', 'agent', 'system')
  ),
  CONSTRAINT agent_maturity_evidence_state_chk CHECK (
    maturity_state IN ('immature', 'maturing', 'mature', 'regressed')
  )
);

CREATE INDEX IF NOT EXISTS agent_maturity_evidence_agent_idx
  ON agent_maturity_evidence(agent_id, created_at DESC);

CREATE TABLE IF NOT EXISTS agent_backup_manifests (
  backup_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  agent_id uuid NOT NULL REFERENCES agents(agent_id) ON DELETE RESTRICT,
  lifecycle_request_id uuid REFERENCES agent_lifecycle_requests(request_id) ON DELETE SET NULL,
  requested_by_user_id uuid REFERENCES users(user_id) ON DELETE SET NULL,
  manifest jsonb NOT NULL,
  checksum text NOT NULL,
  artifact_uri text,
  restore_readiness jsonb NOT NULL DEFAULT '{}'::jsonb,
  backup_state text NOT NULL DEFAULT 'recorded',
  created_at timestamptz NOT NULL DEFAULT now(),
  verified_at timestamptz,
  CONSTRAINT agent_backup_manifests_state_chk CHECK (
    backup_state IN ('recorded', 'verified', 'failed', 'superseded')
  )
);

CREATE INDEX IF NOT EXISTS agent_backup_manifests_agent_idx
  ON agent_backup_manifests(agent_id, created_at DESC);

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

ALTER TABLE IF EXISTS locations DROP CONSTRAINT IF EXISTS locations_agent_id_fkey;
ALTER TABLE IF EXISTS locations
  ADD CONSTRAINT locations_agent_id_fkey FOREIGN KEY (agent_id) REFERENCES agents(agent_id) ON DELETE RESTRICT;

ALTER TABLE IF EXISTS personas DROP CONSTRAINT IF EXISTS personas_agent_id_fkey;
ALTER TABLE IF EXISTS personas
  ADD CONSTRAINT personas_agent_id_fkey FOREIGN KEY (agent_id) REFERENCES agents(agent_id) ON DELETE RESTRICT;

ALTER TABLE IF EXISTS sessions DROP CONSTRAINT IF EXISTS sessions_agent_id_fkey;
ALTER TABLE IF EXISTS sessions
  ADD CONSTRAINT sessions_agent_id_fkey FOREIGN KEY (agent_id) REFERENCES agents(agent_id) ON DELETE RESTRICT;

ALTER TABLE IF EXISTS artifact_references DROP CONSTRAINT IF EXISTS artifact_references_agent_id_fkey;
ALTER TABLE IF EXISTS artifact_references
  ADD CONSTRAINT artifact_references_agent_id_fkey FOREIGN KEY (agent_id) REFERENCES agents(agent_id) ON DELETE RESTRICT;

ALTER TABLE IF EXISTS memory_candidates DROP CONSTRAINT IF EXISTS memory_candidates_agent_id_fkey;
ALTER TABLE IF EXISTS memory_candidates
  ADD CONSTRAINT memory_candidates_agent_id_fkey FOREIGN KEY (agent_id) REFERENCES agents(agent_id) ON DELETE RESTRICT;

ALTER TABLE IF EXISTS memory_tombstones DROP CONSTRAINT IF EXISTS memory_tombstones_agent_id_fkey;
ALTER TABLE IF EXISTS memory_tombstones
  ADD CONSTRAINT memory_tombstones_agent_id_fkey FOREIGN KEY (agent_id) REFERENCES agents(agent_id) ON DELETE RESTRICT;

ALTER TABLE IF EXISTS recognition_observations DROP CONSTRAINT IF EXISTS recognition_observations_agent_id_fkey;
ALTER TABLE IF EXISTS recognition_observations
  ADD CONSTRAINT recognition_observations_agent_id_fkey FOREIGN KEY (agent_id) REFERENCES agents(agent_id) ON DELETE RESTRICT;

ALTER TABLE IF EXISTS recognition_hypotheses DROP CONSTRAINT IF EXISTS recognition_hypotheses_recognition_observation_id_fkey;
ALTER TABLE IF EXISTS recognition_hypotheses
  ADD CONSTRAINT recognition_hypotheses_recognition_observation_id_fkey
  FOREIGN KEY (recognition_observation_id) REFERENCES recognition_observations(recognition_observation_id) ON DELETE RESTRICT;

ALTER TABLE IF EXISTS presence_assertions DROP CONSTRAINT IF EXISTS presence_assertions_agent_id_fkey;
ALTER TABLE IF EXISTS presence_assertions
  ADD CONSTRAINT presence_assertions_agent_id_fkey FOREIGN KEY (agent_id) REFERENCES agents(agent_id) ON DELETE RESTRICT;

ALTER TABLE IF EXISTS voiceprints DROP CONSTRAINT IF EXISTS voiceprints_agent_id_fkey;
ALTER TABLE IF EXISTS voiceprints
  ADD CONSTRAINT voiceprints_agent_id_fkey FOREIGN KEY (agent_id) REFERENCES agents(agent_id) ON DELETE RESTRICT;

ALTER TABLE IF EXISTS voiceprints DROP CONSTRAINT IF EXISTS voiceprints_person_id_fkey;
ALTER TABLE IF EXISTS voiceprints
  ADD CONSTRAINT voiceprints_person_id_fkey FOREIGN KEY (person_id) REFERENCES people(person_id) ON DELETE RESTRICT;

ALTER TABLE IF EXISTS faceprints DROP CONSTRAINT IF EXISTS faceprints_agent_id_fkey;
ALTER TABLE IF EXISTS faceprints
  ADD CONSTRAINT faceprints_agent_id_fkey FOREIGN KEY (agent_id) REFERENCES agents(agent_id) ON DELETE RESTRICT;

ALTER TABLE IF EXISTS faceprints DROP CONSTRAINT IF EXISTS faceprints_person_id_fkey;
ALTER TABLE IF EXISTS faceprints
  ADD CONSTRAINT faceprints_person_id_fkey FOREIGN KEY (person_id) REFERENCES people(person_id) ON DELETE RESTRICT;

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
