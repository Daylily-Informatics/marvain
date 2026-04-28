-- 019_integration_sync_state.sql
-- Provider sync cursors keyed by integration account.

CREATE TABLE IF NOT EXISTS integration_sync_state (
  integration_account_id uuid NOT NULL REFERENCES integration_accounts(integration_account_id) ON DELETE RESTRICT,
  sync_key text NOT NULL,
  cursor text,
  state jsonb NOT NULL DEFAULT '{}'::jsonb,
  updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (integration_account_id, sync_key)
);
