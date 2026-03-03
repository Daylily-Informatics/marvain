-- 011_device_location.sql
-- Phase 3: Location-Aware Device Provisioning
--
-- Purpose:
-- Add location tracking and provisioning metadata to devices table.
-- Supports grouping devices by location (e.g., "Kitchen", "Lab Bench 3").
--
-- This migration is idempotent and can be run multiple times safely.

-- Human-readable location label (e.g., "Kitchen", "Lab Bench 3", "Office 201")
ALTER TABLE devices ADD COLUMN IF NOT EXISTS location_label TEXT;

-- Optional geographic coordinates as JSONB (e.g., {"lat": 42.36, "lng": -71.06})
ALTER TABLE devices ADD COLUMN IF NOT EXISTS location_coords JSONB;

-- Timestamp when the device was provisioned (distinct from created_at)
ALTER TABLE devices ADD COLUMN IF NOT EXISTS provisioned_at TIMESTAMPTZ;

-- User ID of the person who provisioned the device
ALTER TABLE devices ADD COLUMN IF NOT EXISTS provisioned_by TEXT;

-- Index for grouping/filtering devices by location
CREATE INDEX IF NOT EXISTS devices_location_label_idx ON devices(location_label)
  WHERE location_label IS NOT NULL AND revoked_at IS NULL;

-- Comments documenting the purpose
COMMENT ON COLUMN devices.location_label IS 'Human-readable location label (e.g., Kitchen, Lab Bench 3)';
COMMENT ON COLUMN devices.location_coords IS 'Optional geographic coordinates as JSONB: {"lat": number, "lng": number}';
COMMENT ON COLUMN devices.provisioned_at IS 'Timestamp when the device was provisioned via the wizard';
COMMENT ON COLUMN devices.provisioned_by IS 'User ID of the person who provisioned the device';

