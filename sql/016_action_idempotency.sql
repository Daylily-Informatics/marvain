-- 016_action_idempotency.sql
-- Add client-origin idempotency metadata to actions.

ALTER TABLE actions ADD COLUMN IF NOT EXISTS request_idempotency_key text;
ALTER TABLE actions ADD COLUMN IF NOT EXISTS request_actor_type text;
ALTER TABLE actions ADD COLUMN IF NOT EXISTS request_actor_id text;
ALTER TABLE actions ADD COLUMN IF NOT EXISTS request_origin text;

CREATE UNIQUE INDEX IF NOT EXISTS actions_request_idempotency_idx
  ON actions(agent_id, request_actor_type, request_actor_id, request_idempotency_key)
  WHERE request_idempotency_key IS NOT NULL;
