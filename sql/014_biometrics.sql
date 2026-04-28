-- 014_biometrics.sql
-- Store biometric embeddings (voiceprints/faceprints) for identity recognition.
-- Embeddings are stored as vectors only; raw audio/image artifacts are intended to be short-lived.

CREATE TABLE IF NOT EXISTS voiceprints (
  voiceprint_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  agent_id uuid NOT NULL REFERENCES agents(agent_id) ON DELETE RESTRICT,
  person_id uuid NOT NULL REFERENCES people(person_id) ON DELETE RESTRICT,
  embedding vector(256) NOT NULL,
  model text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  revoked_at timestamptz,
  metadata jsonb NOT NULL DEFAULT '{}'::jsonb
);

CREATE TABLE IF NOT EXISTS faceprints (
  faceprint_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  agent_id uuid NOT NULL REFERENCES agents(agent_id) ON DELETE RESTRICT,
  person_id uuid NOT NULL REFERENCES people(person_id) ON DELETE RESTRICT,
  embedding vector(512) NOT NULL,
  model text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  revoked_at timestamptz,
  metadata jsonb NOT NULL DEFAULT '{}'::jsonb
);

CREATE INDEX IF NOT EXISTS voiceprints_agent_person_idx ON voiceprints(agent_id, person_id) WHERE revoked_at IS NULL;
CREATE INDEX IF NOT EXISTS faceprints_agent_person_idx ON faceprints(agent_id, person_id) WHERE revoked_at IS NULL;
