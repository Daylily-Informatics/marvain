-- 005_users_columns_and_legacy_cleanup.sql
-- Phase 0 of Advanced Feature Plan (Spec 0)
-- 
-- Purpose:
-- 1. Add missing columns to users table (display_name, last_seen)
--    These columns are added with ADD IF NOT EXISTS for safety.
-- 2. Rename legacy 'memberships' table to 'legacy_memberships' to prevent accidental use.
--    All code should use 'agent_memberships' instead.
--
-- This migration is idempotent and can be run multiple times safely.

-- Add missing columns to users table if they don't exist
-- (sql/002 creates users without these)
ALTER TABLE users ADD COLUMN IF NOT EXISTS display_name text;
ALTER TABLE users ADD COLUMN IF NOT EXISTS last_seen timestamptz;

-- Rename legacy memberships table to prevent accidental use
-- This table is a duplicate of agent_memberships
-- with a different structure (has membership_id PK vs composite key, no revoked_at, etc.)
--
-- Note: This will fail if the table doesn't exist, which is fine - means sql/003 wasn't run.
-- We use DO block to handle this gracefully.
DO $$
BEGIN
  -- Check if memberships table exists and legacy_memberships doesn't
  IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'memberships')
     AND NOT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'legacy_memberships') THEN
    EXECUTE 'ALTER TABLE memberships RENAME TO legacy_memberships';
    RAISE NOTICE 'Renamed memberships -> legacy_memberships';
  ELSIF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'memberships')
        AND EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'legacy_memberships') THEN
    RAISE NOTICE 'Both memberships and legacy_memberships exist - manual intervention needed';
  ELSE
    RAISE NOTICE 'memberships table does not exist or already renamed';
  END IF;
END $$;

-- Comment to document the correct table to use
COMMENT ON TABLE agent_memberships IS 'Primary table for user-agent membership. Use this, not legacy_memberships.';

