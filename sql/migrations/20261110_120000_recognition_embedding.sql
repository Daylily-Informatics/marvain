ALTER TABLE public.recognition_observations ADD COLUMN embedding public.vector;
ALTER TABLE public.recognition_observations ALTER COLUMN embedding_sha256 DROP NOT NULL;
ALTER TABLE public.biometric_projections ALTER COLUMN embedding_sha256 DROP NOT NULL;
CREATE TABLE public.identity_checks (
    check_id uuid PRIMARY KEY,
    agent_id uuid NOT NULL REFERENCES agents(agent_id),
    space_id uuid NOT NULL REFERENCES spaces(space_id),
    user_id uuid NOT NULL REFERENCES users(user_id),
    auth_subject text NOT NULL,
    browser_session text NOT NULL,
    person_id uuid NOT NULL REFERENCES people(person_id),
    purpose text NOT NULL CHECK (purpose IN ('private_memory_export','sensitive_action_approval')),
    target_id uuid NOT NULL,
    modalities jsonb NOT NULL,
    captures jsonb NOT NULL DEFAULT '{}',
    created_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL,
    consumed_at timestamptz,
    result text,
    tapdb_euid text
);
CREATE TABLE public.biometric_projection_revocations (
    revocation_id uuid PRIMARY KEY REFERENCES biometric_projections(biometric_projection_id),
    user_id uuid NOT NULL REFERENCES users(user_id),
    reason text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    tapdb_euid text
);

CREATE TABLE public.recognition_consent_changes (
    change_id uuid PRIMARY KEY,
    consent_id uuid NOT NULL REFERENCES consent_grants(consent_id),
    user_id uuid NOT NULL REFERENCES users(user_id),
    operation text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    tapdb_euid text
);
