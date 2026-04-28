-- 017_integration_messages.sql
-- Normalized inbound/outbound provider message storage for integrations V1.

CREATE TABLE IF NOT EXISTS integration_messages (
  integration_message_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  agent_id uuid NOT NULL REFERENCES agents(agent_id) ON DELETE RESTRICT,
  space_id uuid REFERENCES spaces(space_id) ON DELETE SET NULL,
  event_id uuid REFERENCES events(event_id) ON DELETE SET NULL,
  provider text NOT NULL,
  direction text NOT NULL DEFAULT 'inbound',
  channel_type text NOT NULL,
  object_type text NOT NULL,
  external_thread_id text,
  external_message_id text,
  dedupe_key text NOT NULL,
  sender jsonb NOT NULL DEFAULT '{}'::jsonb,
  recipients jsonb NOT NULL DEFAULT '[]'::jsonb,
  subject text,
  body_text text NOT NULL DEFAULT '',
  body_html text,
  payload jsonb NOT NULL DEFAULT '{}'::jsonb,
  status text NOT NULL DEFAULT 'received',
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX IF NOT EXISTS integration_messages_agent_dedupe_idx
  ON integration_messages(agent_id, dedupe_key);

CREATE INDEX IF NOT EXISTS integration_messages_agent_time_idx
  ON integration_messages(agent_id, created_at DESC);
