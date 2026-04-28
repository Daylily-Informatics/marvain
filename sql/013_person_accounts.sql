-- 013_person_accounts.sql
-- Map authenticated Cognito users (users.user_id) to People records (people.person_id)
-- so transcripts/memories can be attributed to specific people over time.

CREATE TABLE IF NOT EXISTS person_accounts (
  person_account_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  agent_id uuid NOT NULL REFERENCES agents(agent_id) ON DELETE RESTRICT,
  user_id uuid NOT NULL REFERENCES users(user_id) ON DELETE RESTRICT,
  person_id uuid NOT NULL REFERENCES people(person_id) ON DELETE RESTRICT,
  created_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT person_accounts_unique_user UNIQUE (agent_id, user_id),
  CONSTRAINT person_accounts_unique_person UNIQUE (agent_id, person_id)
);

CREATE INDEX IF NOT EXISTS person_accounts_agent_idx ON person_accounts(agent_id);
