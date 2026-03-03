-- 009_action_device_execution_lifecycle.sql
-- Add async device execution lifecycle fields for correlated command results.

ALTER TABLE actions ADD COLUMN IF NOT EXISTS target_device_id uuid REFERENCES devices(device_id) ON DELETE SET NULL;
ALTER TABLE actions ADD COLUMN IF NOT EXISTS correlation_id uuid;
ALTER TABLE actions ADD COLUMN IF NOT EXISTS awaiting_result_until timestamptz;
ALTER TABLE actions ADD COLUMN IF NOT EXISTS device_acknowledged_at timestamptz;
ALTER TABLE actions ADD COLUMN IF NOT EXISTS device_response_at timestamptz;
ALTER TABLE actions ADD COLUMN IF NOT EXISTS execution_metadata jsonb NOT NULL DEFAULT '{}'::jsonb;

CREATE INDEX IF NOT EXISTS actions_status_awaiting_result_idx
  ON actions(status, awaiting_result_until)
  WHERE awaiting_result_until IS NOT NULL;

CREATE INDEX IF NOT EXISTS actions_correlation_id_idx
  ON actions(correlation_id)
  WHERE correlation_id IS NOT NULL;
