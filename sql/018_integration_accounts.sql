-- 018_integration_accounts.sql
-- Integration accounts and expanded integration message lifecycle metadata.

CREATE TABLE IF NOT EXISTS integration_accounts (
  integration_account_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  agent_id uuid NOT NULL REFERENCES agents(agent_id) ON DELETE RESTRICT,
  provider text NOT NULL,
  display_name text NOT NULL,
  external_account_id text,
  default_space_id uuid REFERENCES spaces(space_id) ON DELETE SET NULL,
  credentials_secret_arn text NOT NULL,
  scopes jsonb NOT NULL DEFAULT '[]'::jsonb,
  config jsonb NOT NULL DEFAULT '{}'::jsonb,
  status text NOT NULL DEFAULT 'active',
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT integration_accounts_status_check CHECK (status IN ('active', 'paused', 'revoked'))
);

CREATE INDEX IF NOT EXISTS integration_accounts_agent_provider_idx
  ON integration_accounts(agent_id, provider, status, created_at DESC);

ALTER TABLE integration_messages
  ADD COLUMN IF NOT EXISTS integration_account_id uuid REFERENCES integration_accounts(integration_account_id) ON DELETE SET NULL,
  ADD COLUMN IF NOT EXISTS action_id uuid REFERENCES actions(action_id) ON DELETE SET NULL,
  ADD COLUMN IF NOT EXISTS contains_phi boolean NOT NULL DEFAULT FALSE,
  ADD COLUMN IF NOT EXISTS retention_until timestamptz,
  ADD COLUMN IF NOT EXISTS processed_at timestamptz,
  ADD COLUMN IF NOT EXISTS redacted_at timestamptz;

CREATE INDEX IF NOT EXISTS integration_messages_account_time_idx
  ON integration_messages(integration_account_id, created_at DESC);

CREATE INDEX IF NOT EXISTS integration_messages_action_idx
  ON integration_messages(action_id);

CREATE INDEX IF NOT EXISTS integration_messages_thread_idx
  ON integration_messages(agent_id, provider, external_thread_id, created_at DESC);
