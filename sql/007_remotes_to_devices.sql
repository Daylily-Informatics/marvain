-- 007_remotes_to_devices.sql
-- Phase 2 of Advanced Feature Plan (Spec 2)
--
-- Purpose:
-- Migrate existing remotes to devices table and rename remotes to legacy.
-- Remotes are now just devices with metadata.is_remote = true.
--
-- This migration is idempotent and can be run multiple times safely.

-- First, ensure devices table has the necessary columns (from migration 006)
-- These are here for safety in case migrations are run out of order
ALTER TABLE devices ADD COLUMN IF NOT EXISTS metadata jsonb DEFAULT '{}'::jsonb;
ALTER TABLE devices ADD COLUMN IF NOT EXISTS last_hello_at timestamptz;
ALTER TABLE devices ADD COLUMN IF NOT EXISTS last_heartbeat_at timestamptz;

-- Migrate existing remotes to devices
-- Each remote gets a new device entry with appropriate metadata
-- We generate a token for each migrated device (the token itself is stored as hash)
DO $$
DECLARE
    r RECORD;
    new_device_id uuid;
    new_token_hash text;
BEGIN
    -- Only migrate if remotes table exists and has data
    IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'remotes') THEN
        FOR r IN
            SELECT remote_id, agent_id, name, address, connection_type, capabilities,
                   status, last_ping, last_seen, created_at
            FROM remotes
        LOOP
            -- Check if this remote was already migrated (by checking metadata)
            IF NOT EXISTS (
                SELECT 1 FROM devices
                WHERE metadata->>'migrated_from_remote_id' = r.remote_id::text
            ) THEN
                new_device_id := gen_random_uuid();
                -- Generate a placeholder token hash (will need to be rotated on first use)
                -- Using remote_id as seed for deterministic hash during migration
                new_token_hash := encode(sha256(('migration_' || r.remote_id::text)::bytea), 'hex');

                INSERT INTO devices (
                    device_id,
                    agent_id,
                    name,
                    capabilities,
                    scopes,
                    token_hash,
                    metadata,
                    last_seen,
                    created_at
                ) VALUES (
                    new_device_id,
                    r.agent_id,
                    r.name,
                    r.capabilities,
                    '["events:write", "presence:write", "memories:read"]'::jsonb,
                    new_token_hash,
                    jsonb_build_object(
                        'is_remote', true,
                        'address', r.address,
                        'connection_type', r.connection_type,
                        'legacy_status', r.status,
                        'migrated_from_remote_id', r.remote_id::text,
                        'migration_token_needs_rotation', true
                    ),
                    COALESCE(r.last_seen, r.last_ping),
                    r.created_at
                );

                RAISE NOTICE 'Migrated remote % to device %', r.remote_id, new_device_id;
            END IF;
        END LOOP;
    END IF;
END $$;

-- Rename remotes table to legacy (only if not already renamed)
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'remotes')
       AND NOT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'legacy_remotes') THEN
        EXECUTE 'ALTER TABLE remotes RENAME TO legacy_remotes';
        RAISE NOTICE 'Renamed remotes -> legacy_remotes';
    END IF;
END $$;

-- Add comment documenting the migration
COMMENT ON TABLE devices IS 'Devices table includes migrated remotes (metadata.is_remote = true)';

