-- Enforce at most one active owner membership per agent.
-- This protects the "claim first owner" flow against races.

CREATE UNIQUE INDEX IF NOT EXISTS agent_memberships_one_active_owner_per_agent
ON agent_memberships (agent_id)
WHERE role = 'owner' AND revoked_at IS NULL;
