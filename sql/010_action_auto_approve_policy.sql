-- 010_action_auto_approve_policy.sql
-- Add policy-driven auto-approve rules + explicit decision history.

CREATE TABLE IF NOT EXISTS action_auto_approve_policies (
  policy_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  agent_id uuid NOT NULL REFERENCES agents(agent_id) ON DELETE CASCADE,
  name text NOT NULL,
  enabled boolean NOT NULL DEFAULT true,
  priority integer NOT NULL DEFAULT 100,
  action_kind text NOT NULL DEFAULT '*',
  required_scopes jsonb NOT NULL DEFAULT '[]'::jsonb,
  time_window jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_by uuid REFERENCES users(user_id) ON DELETE SET NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  revoked_at timestamptz
);

CREATE INDEX IF NOT EXISTS action_auto_approve_policies_agent_enabled_idx
  ON action_auto_approve_policies(agent_id, enabled, priority)
  WHERE revoked_at IS NULL;

CREATE TABLE IF NOT EXISTS action_policy_decisions (
  decision_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  action_id uuid NOT NULL REFERENCES actions(action_id) ON DELETE CASCADE,
  policy_id uuid REFERENCES action_auto_approve_policies(policy_id) ON DELETE SET NULL,
  decision text NOT NULL,
  reason text,
  evaluated_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS action_policy_decisions_action_idx
  ON action_policy_decisions(action_id, evaluated_at DESC);

ALTER TABLE actions ADD COLUMN IF NOT EXISTS approval_source text;
ALTER TABLE actions ADD COLUMN IF NOT EXISTS approval_policy_id uuid REFERENCES action_auto_approve_policies(policy_id) ON DELETE SET NULL;
