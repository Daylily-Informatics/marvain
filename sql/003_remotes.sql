-- Remotes (Satellites) table
-- Represents network-attached or directly-connected devices that marvain connects to

CREATE TABLE IF NOT EXISTS remotes (
  remote_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  agent_id uuid NOT NULL REFERENCES agents(agent_id) ON DELETE CASCADE,
  name text NOT NULL,
  address text NOT NULL,  -- IP address, hostname, or device path
  connection_type text NOT NULL DEFAULT 'network',  -- 'network', 'usb', 'direct'
  capabilities jsonb NOT NULL DEFAULT '{}'::jsonb,  -- camera, mic, speaker, etc.
  status text NOT NULL DEFAULT 'offline',  -- 'online', 'offline', 'hibernate'
  last_ping timestamptz,
  last_seen timestamptz,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS remotes_agent_idx ON remotes(agent_id);
CREATE INDEX IF NOT EXISTS remotes_status_idx ON remotes(status);

-- Users table (for storing Cognito users locally)
CREATE TABLE IF NOT EXISTS users (
  user_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  cognito_sub text UNIQUE NOT NULL,
  email text,
  display_name text,
  created_at timestamptz NOT NULL DEFAULT now(),
  last_seen timestamptz
);

-- Memberships table (user-agent relationships)
CREATE TABLE IF NOT EXISTS memberships (
  membership_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
  agent_id uuid NOT NULL REFERENCES agents(agent_id) ON DELETE CASCADE,
  role text NOT NULL DEFAULT 'member',  -- 'owner', 'admin', 'member', 'guest', 'blocked'
  relationship_label text,  -- 'family', 'work', etc.
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE(user_id, agent_id)
);

CREATE INDEX IF NOT EXISTS memberships_user_idx ON memberships(user_id);
CREATE INDEX IF NOT EXISTS memberships_agent_idx ON memberships(agent_id);

