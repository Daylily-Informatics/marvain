-- 015_spaces_livekit_room_mode.sql
-- Add LiveKit room mode to spaces.
-- "ephemeral": join tokens create a unique room per session (current behavior).
-- "stable": room name is exactly the space_id (for always-on "location" spaces).

ALTER TABLE spaces ADD COLUMN IF NOT EXISTS livekit_room_mode text NOT NULL DEFAULT 'ephemeral';

-- Enforce allowed values at the database layer to avoid typos.
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1
    FROM pg_constraint
    WHERE conname = 'spaces_livekit_room_mode_chk'
  ) THEN
    ALTER TABLE spaces
      ADD CONSTRAINT spaces_livekit_room_mode_chk
      CHECK (livekit_room_mode IN ('ephemeral', 'stable'));
  END IF;
END $$;

CREATE INDEX IF NOT EXISTS spaces_livekit_room_mode_idx ON spaces(livekit_room_mode);
