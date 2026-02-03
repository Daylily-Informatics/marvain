-- 006_devices_enhancement.sql
-- Phase 1 of Advanced Feature Plan (Spec 1)
-- 
-- Purpose:
-- Add columns to devices table for better presence tracking and metadata.
--
-- This migration is idempotent and can be run multiple times safely.

-- Add metadata column for freeform device info (platform, version, labels)
ALTER TABLE devices ADD COLUMN IF NOT EXISTS metadata jsonb DEFAULT '{}'::jsonb;

-- Add last_hello_at for tracking WebSocket connection time
ALTER TABLE devices ADD COLUMN IF NOT EXISTS last_hello_at timestamptz;

-- Add last_heartbeat_at for tracking REST heartbeat time
ALTER TABLE devices ADD COLUMN IF NOT EXISTS last_heartbeat_at timestamptz;

-- Index for finding devices by agent that need heartbeat checks
CREATE INDEX IF NOT EXISTS devices_agent_heartbeat_idx ON devices(agent_id, last_heartbeat_at)
  WHERE revoked_at IS NULL;

-- Comment documenting the purpose
COMMENT ON COLUMN devices.metadata IS 'Freeform device metadata: platform, version, labels, etc.';
COMMENT ON COLUMN devices.last_hello_at IS 'Last WebSocket hello message timestamp';
COMMENT ON COLUMN devices.last_heartbeat_at IS 'Last REST heartbeat timestamp';

