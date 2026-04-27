-- 005_users_columns.sql
-- Greenfield users-table shape used by the current Marvain schema.

ALTER TABLE users ADD COLUMN IF NOT EXISTS display_name text;
ALTER TABLE users ADD COLUMN IF NOT EXISTS last_seen timestamptz;
COMMENT ON TABLE agent_memberships IS 'Primary table for user-agent membership.';
