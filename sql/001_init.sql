CREATE EXTENSION IF NOT EXISTS pgcrypto;
CREATE EXTENSION IF NOT EXISTS vector;

CREATE TABLE IF NOT EXISTS agents (
  agent_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  name text NOT NULL,
  disabled boolean NOT NULL DEFAULT false,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS spaces (
  space_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  agent_id uuid NOT NULL REFERENCES agents(agent_id) ON DELETE CASCADE,
  name text NOT NULL,
  privacy_mode boolean NOT NULL DEFAULT false,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS devices (
  device_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  agent_id uuid NOT NULL REFERENCES agents(agent_id) ON DELETE CASCADE,
  name text,
  capabilities jsonb NOT NULL DEFAULT '{}'::jsonb,
  scopes jsonb NOT NULL DEFAULT '[]'::jsonb,
  token_hash text NOT NULL UNIQUE,
  revoked_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  last_seen timestamptz
);

CREATE TABLE IF NOT EXISTS people (
  person_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  agent_id uuid NOT NULL REFERENCES agents(agent_id) ON DELETE CASCADE,
  display_name text NOT NULL,
  aliases jsonb NOT NULL DEFAULT '[]'::jsonb,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS consent_grants (
  consent_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  agent_id uuid NOT NULL REFERENCES agents(agent_id) ON DELETE CASCADE,
  person_id uuid NOT NULL REFERENCES people(person_id) ON DELETE CASCADE,
  consent_type text NOT NULL,
  scope jsonb NOT NULL DEFAULT '{}'::jsonb,
  granted_at timestamptz NOT NULL DEFAULT now(),
  expires_at timestamptz,
  revoked_at timestamptz
);

CREATE TABLE IF NOT EXISTS presence (
  presence_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  agent_id uuid NOT NULL REFERENCES agents(agent_id) ON DELETE CASCADE,
  space_id uuid NOT NULL REFERENCES spaces(space_id) ON DELETE CASCADE,
  person_id uuid REFERENCES people(person_id) ON DELETE SET NULL,
  device_id uuid REFERENCES devices(device_id) ON DELETE SET NULL,
  status text NOT NULL,
  confidence double precision NOT NULL DEFAULT 0,
  last_update timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS presence_space_idx ON presence(space_id);

CREATE TABLE IF NOT EXISTS events (
  event_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  agent_id uuid NOT NULL REFERENCES agents(agent_id) ON DELETE CASCADE,
  space_id uuid NOT NULL REFERENCES spaces(space_id) ON DELETE CASCADE,
  device_id uuid REFERENCES devices(device_id) ON DELETE SET NULL,
  person_id uuid REFERENCES people(person_id) ON DELETE SET NULL,
  type text NOT NULL,
  payload jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS events_space_time_idx ON events(space_id, created_at DESC);

CREATE TABLE IF NOT EXISTS memories (
  memory_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  agent_id uuid NOT NULL REFERENCES agents(agent_id) ON DELETE CASCADE,
  space_id uuid REFERENCES spaces(space_id) ON DELETE SET NULL,
  tier text NOT NULL,
  content text NOT NULL,
  participants jsonb NOT NULL DEFAULT '[]'::jsonb,
  provenance jsonb NOT NULL DEFAULT '{}'::jsonb,
  retention jsonb NOT NULL DEFAULT '{}'::jsonb,
  embedding vector(1536),
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS memories_agent_time_idx ON memories(agent_id, created_at DESC);

-- If your pgvector build supports HNSW, uncomment the next line.
-- CREATE INDEX IF NOT EXISTS memories_embedding_hnsw ON memories USING hnsw (embedding vector_cosine_ops);

CREATE TABLE IF NOT EXISTS actions (
  action_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  agent_id uuid NOT NULL REFERENCES agents(agent_id) ON DELETE CASCADE,
  space_id uuid REFERENCES spaces(space_id) ON DELETE SET NULL,
  kind text NOT NULL,
  payload jsonb NOT NULL DEFAULT '{}'::jsonb,
  required_scopes jsonb NOT NULL DEFAULT '[]'::jsonb,
  status text NOT NULL DEFAULT 'proposed',
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  executed_at timestamptz
);

CREATE INDEX IF NOT EXISTS actions_agent_status_idx ON actions(agent_id, status);

CREATE TABLE IF NOT EXISTS audit_state (
  agent_id uuid PRIMARY KEY REFERENCES agents(agent_id) ON DELETE CASCADE,
  last_hash text NOT NULL,
  updated_at timestamptz NOT NULL DEFAULT now()
);
