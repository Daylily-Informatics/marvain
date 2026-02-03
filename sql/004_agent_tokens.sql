-- Agent-to-Agent Authentication Tokens
-- Enables agents to authenticate to other agents with scoped permissions.
-- Used for delegation scenarios where Agent A grants Agent B specific capabilities.

CREATE TABLE IF NOT EXISTS agent_tokens (
  token_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  
  -- The agent that issued/owns this token
  issuer_agent_id uuid NOT NULL REFERENCES agents(agent_id) ON DELETE CASCADE,
  
  -- The agent that can use this token (NULL = any agent can use it)
  target_agent_id uuid REFERENCES agents(agent_id) ON DELETE CASCADE,
  
  -- Human-readable name for the token
  name text NOT NULL DEFAULT 'agent-token',
  
  -- SHA-256 hash of the bearer token (never store plaintext)
  token_hash text NOT NULL UNIQUE,
  
  -- Scopes granted to the token holder
  -- Examples: ["read_memories", "write_events", "execute_actions", "delegate"]
  scopes jsonb NOT NULL DEFAULT '[]'::jsonb,
  
  -- Optional: restrict token to specific spaces
  allowed_spaces jsonb DEFAULT NULL,  -- NULL = all spaces, or ["space-id-1", "space-id-2"]
  
  -- Token lifecycle
  expires_at timestamptz,  -- NULL = never expires
  revoked_at timestamptz,  -- Set when token is revoked
  last_used_at timestamptz,
  
  -- Audit fields
  created_at timestamptz NOT NULL DEFAULT now(),
  created_by_user_id uuid REFERENCES users(user_id) ON DELETE SET NULL
);

-- Index for token lookup during authentication
CREATE INDEX IF NOT EXISTS agent_tokens_hash_idx ON agent_tokens(token_hash) WHERE revoked_at IS NULL;

-- Index for listing tokens by issuer
CREATE INDEX IF NOT EXISTS agent_tokens_issuer_idx ON agent_tokens(issuer_agent_id);

-- Index for listing tokens by target
CREATE INDEX IF NOT EXISTS agent_tokens_target_idx ON agent_tokens(target_agent_id) WHERE target_agent_id IS NOT NULL;

COMMENT ON TABLE agent_tokens IS 'Bearer tokens for agent-to-agent authentication and delegation';
COMMENT ON COLUMN agent_tokens.issuer_agent_id IS 'The agent that created and owns this token';
COMMENT ON COLUMN agent_tokens.target_agent_id IS 'If set, only this agent can use the token';
COMMENT ON COLUMN agent_tokens.scopes IS 'JSON array of permission scopes granted to token holder';
COMMENT ON COLUMN agent_tokens.allowed_spaces IS 'If set, token only valid for these space IDs';

