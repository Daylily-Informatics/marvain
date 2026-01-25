-- 002_users_and_memberships.sql
-- Add Cognito-backed human users and per-agent memberships.

CREATE TABLE IF NOT EXISTS users (
  user_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  cognito_sub text UNIQUE NOT NULL,
  email text,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS agent_memberships (
  agent_id uuid NOT NULL REFERENCES agents(agent_id) ON DELETE CASCADE,
  user_id uuid NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
  role text NOT NULL,
  relationship_label text,
  created_at timestamptz NOT NULL DEFAULT now(),
  revoked_at timestamptz,
  CONSTRAINT agent_memberships_role_chk CHECK (role IN ('owner','admin','member','guest','blocked')),
  CONSTRAINT agent_memberships_unique UNIQUE (agent_id, user_id)
);

CREATE INDEX IF NOT EXISTS agent_memberships_user_idx ON agent_memberships(user_id);
CREATE INDEX IF NOT EXISTS agent_memberships_agent_idx ON agent_memberships(agent_id);

