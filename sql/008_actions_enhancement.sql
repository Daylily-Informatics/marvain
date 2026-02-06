-- 008_actions_enhancement.sql
-- Add approval tracking and result storage columns to actions table.
-- Supports the full action lifecycle: proposed → approved → executing → executed/failed
--                                     proposed → rejected

-- Add approval tracking columns
ALTER TABLE actions ADD COLUMN IF NOT EXISTS approved_by uuid REFERENCES users(user_id) ON DELETE SET NULL;
ALTER TABLE actions ADD COLUMN IF NOT EXISTS approved_at timestamptz;

-- Add result storage columns
ALTER TABLE actions ADD COLUMN IF NOT EXISTS result jsonb;
ALTER TABLE actions ADD COLUMN IF NOT EXISTS error text;
ALTER TABLE actions ADD COLUMN IF NOT EXISTS completed_at timestamptz;

-- Add index for efficient querying of actions by approver
CREATE INDEX IF NOT EXISTS actions_approved_by_idx ON actions(approved_by) WHERE approved_by IS NOT NULL;

-- Add index for efficient querying of completed actions
CREATE INDEX IF NOT EXISTS actions_completed_at_idx ON actions(agent_id, completed_at) WHERE completed_at IS NOT NULL;

