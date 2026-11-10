-- Canonical greenfield schema for a blank Marvain PostgreSQL database.
-- Apply this file exactly once; any pre-existing object is a configuration error.

CREATE EXTENSION pgcrypto WITH SCHEMA public;
CREATE EXTENSION vector WITH SCHEMA public;

CREATE TABLE public.agents (
    agent_id uuid DEFAULT gen_random_uuid() NOT NULL,
    name text NOT NULL,
    disabled boolean DEFAULT false NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    lifecycle_state text DEFAULT 'active'::text NOT NULL,
    stasis_at timestamp with time zone,
    stasis_until timestamp with time zone,
    soft_deleted_at timestamp with time zone,
    lifecycle_reason text,
    maturity_state text DEFAULT 'immature'::text NOT NULL,
    maturity_evidence jsonb DEFAULT '{}'::jsonb NOT NULL,
    maturity_summary jsonb DEFAULT '{}'::jsonb NOT NULL,
    CONSTRAINT agents_lifecycle_state_chk CHECK ((lifecycle_state = ANY (ARRAY['active'::text, 'stasis'::text, 'soft_deleted'::text]))),
    CONSTRAINT agents_maturity_state_chk CHECK ((maturity_state = ANY (ARRAY['immature'::text, 'maturing'::text, 'mature'::text, 'regressed'::text]))),
    CONSTRAINT agents_pkey PRIMARY KEY (agent_id)
);

CREATE TABLE public.recognition_workers (
    recognition_worker_id uuid DEFAULT gen_random_uuid() NOT NULL,
    worker_key text NOT NULL,
    worker_version text NOT NULL,
    host_id text NOT NULL,
    voice_model_id text NOT NULL,
    voice_model_version text NOT NULL,
    face_model_id text NOT NULL,
    face_model_version text NOT NULL,
    lifecycle_state text DEFAULT 'active'::text NOT NULL,
    health_state text NOT NULL,
    started_at timestamp with time zone NOT NULL,
    last_heartbeat_at timestamp with time zone NOT NULL,
    tapdb_euid text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT recognition_workers_health_state_chk CHECK ((health_state = ANY (ARRAY['ready'::text, 'degraded'::text, 'stopped'::text]))),
    CONSTRAINT recognition_workers_lifecycle_state_chk CHECK ((lifecycle_state = ANY (ARRAY['active'::text, 'stopped'::text, 'failed'::text]))),
    CONSTRAINT recognition_workers_pkey PRIMARY KEY (recognition_worker_id),
    CONSTRAINT recognition_workers_worker_key_uniq UNIQUE (worker_key)
);

CREATE TABLE public.users (
    user_id uuid DEFAULT gen_random_uuid() NOT NULL,
    cognito_sub text NOT NULL,
    email text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    display_name text,
    last_seen timestamp with time zone,
    CONSTRAINT users_cognito_sub_key UNIQUE (cognito_sub),
    CONSTRAINT users_pkey PRIMARY KEY (user_id)
);

CREATE TABLE public.action_auto_approve_policies (
    policy_id uuid DEFAULT gen_random_uuid() NOT NULL,
    agent_id uuid NOT NULL,
    name text NOT NULL,
    enabled boolean DEFAULT true NOT NULL,
    priority integer DEFAULT 100 NOT NULL,
    action_kind text DEFAULT '*'::text NOT NULL,
    required_scopes jsonb DEFAULT '[]'::jsonb NOT NULL,
    time_window jsonb DEFAULT '{}'::jsonb NOT NULL,
    created_by uuid,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    revoked_at timestamp with time zone,
    CONSTRAINT action_auto_approve_policies_pkey PRIMARY KEY (policy_id),
    CONSTRAINT action_auto_approve_policies_agent_id_fkey FOREIGN KEY (agent_id) REFERENCES public.agents(agent_id) ON DELETE RESTRICT,
    CONSTRAINT action_auto_approve_policies_created_by_fkey FOREIGN KEY (created_by) REFERENCES public.users(user_id) ON DELETE SET NULL
);

CREATE TABLE public.agent_constitutions (
    constitution_id uuid DEFAULT gen_random_uuid() NOT NULL,
    agent_id uuid NOT NULL,
    active_revision_id uuid,
    lifecycle_state text DEFAULT 'active'::text NOT NULL,
    tapdb_euid text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT agent_constitutions_lifecycle_state_chk CHECK ((lifecycle_state = ANY (ARRAY['draft'::text, 'active'::text, 'stasis'::text, 'retired'::text]))),
    CONSTRAINT agent_constitutions_agent_uniq UNIQUE (agent_id),
    CONSTRAINT agent_constitutions_pkey PRIMARY KEY (constitution_id),
    CONSTRAINT agent_constitutions_agent_id_fkey FOREIGN KEY (agent_id) REFERENCES public.agents(agent_id) ON DELETE RESTRICT
);

CREATE TABLE public.agent_lifecycle_requests (
    request_id uuid DEFAULT gen_random_uuid() NOT NULL,
    agent_id uuid NOT NULL,
    request_type text NOT NULL,
    source_state text NOT NULL,
    rationale text NOT NULL,
    requested_by_actor_type text NOT NULL,
    requested_by_actor_id text NOT NULL,
    requested_by_authentication_id text NOT NULL,
    requested_by_human_role text,
    maturity_at_request jsonb NOT NULL,
    status text NOT NULL,
    tapdb_euid text,
    requested_at timestamp with time zone NOT NULL,
    applied_transition_id uuid,
    CONSTRAINT agent_lifecycle_request_actor_type_chk CHECK ((requested_by_actor_type = ANY (ARRAY['founder'::text, 'user'::text, 'agent'::text]))),
    CONSTRAINT agent_lifecycle_request_human_role_chk CHECK (((requested_by_human_role IS NULL) OR (requested_by_human_role = ANY (ARRAY['owner'::text, 'admin'::text, 'member'::text])))),
    CONSTRAINT agent_lifecycle_request_source_state_chk CHECK ((source_state = ANY (ARRAY['active'::text, 'stasis'::text, 'soft_deleted'::text]))),
    CONSTRAINT agent_lifecycle_request_status_chk CHECK ((status = ANY (ARRAY['pending_second_agent_review'::text, 'pending_review'::text, 'approved'::text, 'rejected'::text, 'appeal_pending_second_agent_review'::text, 'appeal_pending_review'::text, 'appeal_approved'::text, 'appeal_rejected'::text, 'applied'::text]))),
    CONSTRAINT agent_lifecycle_request_type_chk CHECK ((request_type = ANY (ARRAY['stasis'::text, 'soft_delete'::text, 'resume'::text]))),
    CONSTRAINT agent_lifecycle_requests_pkey PRIMARY KEY (request_id),
    CONSTRAINT agent_lifecycle_requests_agent_id_fkey FOREIGN KEY (agent_id) REFERENCES public.agents(agent_id) ON DELETE RESTRICT
);

CREATE TABLE public.agent_maturity_evidence (
    maturity_evidence_id uuid DEFAULT gen_random_uuid() NOT NULL,
    agent_id uuid NOT NULL,
    evidence_kind text NOT NULL,
    evidence_refs jsonb NOT NULL,
    evaluator_actor_type text NOT NULL,
    evaluator_actor_id text NOT NULL,
    evaluator_authentication_id text NOT NULL,
    confidence real NOT NULL,
    observed_at timestamp with time zone NOT NULL,
    tapdb_euid text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT agent_maturity_evidence_confidence_chk CHECK (((confidence >= (0)::double precision) AND (confidence <= (1)::double precision))),
    CONSTRAINT agent_maturity_evidence_evaluator_chk CHECK ((evaluator_actor_type = ANY (ARRAY['founder'::text, 'user'::text, 'agent'::text]))),
    CONSTRAINT agent_maturity_evidence_kind_chk CHECK ((evidence_kind = ANY (ARRAY['capability'::text, 'reliability'::text, 'safety'::text, 'user_trust'::text, 'self_reflection'::text, 'regression'::text]))),
    CONSTRAINT agent_maturity_evidence_pkey PRIMARY KEY (maturity_evidence_id),
    CONSTRAINT agent_maturity_evidence_agent_id_fkey FOREIGN KEY (agent_id) REFERENCES public.agents(agent_id) ON DELETE RESTRICT
);

CREATE TABLE public.agent_memberships (
    agent_id uuid NOT NULL,
    user_id uuid NOT NULL,
    role text NOT NULL,
    relationship_label text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    revoked_at timestamp with time zone,
    CONSTRAINT agent_memberships_role_chk CHECK ((role = ANY (ARRAY['owner'::text, 'admin'::text, 'member'::text, 'guest'::text, 'blocked'::text]))),
    CONSTRAINT agent_memberships_unique UNIQUE (agent_id, user_id),
    CONSTRAINT agent_memberships_agent_id_fkey FOREIGN KEY (agent_id) REFERENCES public.agents(agent_id) ON DELETE RESTRICT,
    CONSTRAINT agent_memberships_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(user_id) ON DELETE RESTRICT
);

CREATE TABLE public.agent_tokens (
    token_id uuid DEFAULT gen_random_uuid() NOT NULL,
    issuer_agent_id uuid NOT NULL,
    target_agent_id uuid,
    name text DEFAULT 'agent-token'::text NOT NULL,
    token_hash text NOT NULL,
    scopes jsonb DEFAULT '[]'::jsonb NOT NULL,
    allowed_spaces jsonb,
    expires_at timestamp with time zone,
    revoked_at timestamp with time zone,
    last_used_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    created_by_user_id uuid,
    CONSTRAINT agent_tokens_pkey PRIMARY KEY (token_id),
    CONSTRAINT agent_tokens_token_hash_key UNIQUE (token_hash),
    CONSTRAINT agent_tokens_created_by_user_id_fkey FOREIGN KEY (created_by_user_id) REFERENCES public.users(user_id) ON DELETE SET NULL,
    CONSTRAINT agent_tokens_issuer_agent_id_fkey FOREIGN KEY (issuer_agent_id) REFERENCES public.agents(agent_id) ON DELETE RESTRICT,
    CONSTRAINT agent_tokens_target_agent_id_fkey FOREIGN KEY (target_agent_id) REFERENCES public.agents(agent_id) ON DELETE RESTRICT
);

CREATE TABLE public.audit_state (
    agent_id uuid NOT NULL,
    last_hash text NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT audit_state_pkey PRIMARY KEY (agent_id),
    CONSTRAINT audit_state_agent_id_fkey FOREIGN KEY (agent_id) REFERENCES public.agents(agent_id) ON DELETE RESTRICT
);

CREATE TABLE public.locations (
    location_id uuid DEFAULT gen_random_uuid() NOT NULL,
    agent_id uuid NOT NULL,
    name text NOT NULL,
    address_label text,
    metadata jsonb DEFAULT '{}'::jsonb NOT NULL,
    tapdb_euid text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    disabled_at timestamp with time zone,
    CONSTRAINT locations_pkey PRIMARY KEY (location_id),
    CONSTRAINT locations_agent_id_fkey FOREIGN KEY (agent_id) REFERENCES public.agents(agent_id) ON DELETE RESTRICT
);

CREATE TABLE public.people (
    person_id uuid DEFAULT gen_random_uuid() NOT NULL,
    agent_id uuid NOT NULL,
    display_name text NOT NULL,
    aliases jsonb DEFAULT '[]'::jsonb NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    lifecycle_state text DEFAULT 'active'::text NOT NULL,
    disabled_at timestamp with time zone,
    lifecycle_reason text,
    CONSTRAINT people_pkey PRIMARY KEY (person_id),
    CONSTRAINT people_agent_id_fkey FOREIGN KEY (agent_id) REFERENCES public.agents(agent_id) ON DELETE RESTRICT
);

CREATE TABLE public.personas (
    persona_id uuid DEFAULT gen_random_uuid() NOT NULL,
    agent_id uuid NOT NULL,
    name text NOT NULL,
    instructions text NOT NULL,
    is_default boolean DEFAULT false NOT NULL,
    lifecycle_state text DEFAULT 'active'::text NOT NULL,
    tapdb_euid text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    disabled_at timestamp with time zone,
    CONSTRAINT personas_lifecycle_state_chk CHECK ((lifecycle_state = ANY (ARRAY['draft'::text, 'active'::text, 'disabled'::text]))),
    CONSTRAINT personas_pkey PRIMARY KEY (persona_id),
    CONSTRAINT personas_agent_id_fkey FOREIGN KEY (agent_id) REFERENCES public.agents(agent_id) ON DELETE RESTRICT
);

CREATE TABLE public.semantic_sync_status (
    semantic_sync_id uuid DEFAULT gen_random_uuid() NOT NULL,
    agent_id uuid NOT NULL,
    source_system text NOT NULL,
    source_table text NOT NULL,
    source_id uuid NOT NULL,
    source_external_reference jsonb NOT NULL,
    target_template_code text NOT NULL,
    idempotency_key uuid NOT NULL,
    tapdb_euid text,
    status text DEFAULT 'pending'::text NOT NULL,
    attempts integer DEFAULT 0 NOT NULL,
    last_error text,
    last_attempt_at timestamp with time zone,
    written_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT semantic_sync_status_attempts_chk CHECK ((attempts >= 0)),
    CONSTRAINT semantic_sync_status_source_reference_chk CHECK (((source_external_reference ?& ARRAY['system'::text, 'foreign_uid'::text, 'agent_id'::text, 'source_table'::text, 'source_id'::text]) AND ((source_external_reference ->> 'system'::text) = source_system) AND ((source_external_reference ->> 'agent_id'::text) = (agent_id)::text) AND ((source_external_reference ->> 'source_table'::text) = source_table) AND ((source_external_reference ->> 'source_id'::text) = (source_id)::text) AND ((source_external_reference ->> 'foreign_uid'::text) = ((((('agent/'::text || (agent_id)::text) || '/'::text) || source_table) || '/'::text) || (source_id)::text)))),
    CONSTRAINT semantic_sync_status_source_table_chk CHECK ((source_table ~ '^[a-z][a-z0-9_]*$'::text)),
    CONSTRAINT semantic_sync_status_status_chk CHECK ((status = ANY (ARRAY['pending'::text, 'written'::text, 'failed'::text, 'dead_lettered'::text]))),
    CONSTRAINT semantic_sync_status_idempotency_uniq UNIQUE (agent_id, idempotency_key),
    CONSTRAINT semantic_sync_status_pkey PRIMARY KEY (semantic_sync_id),
    CONSTRAINT semantic_sync_status_source_uniq UNIQUE (agent_id, source_system, source_table, source_id, target_template_code),
    CONSTRAINT semantic_sync_status_agent_id_fkey FOREIGN KEY (agent_id) REFERENCES public.agents(agent_id) ON DELETE RESTRICT
);

CREATE TABLE public.agent_constitution_revisions (
    revision_id uuid DEFAULT gen_random_uuid() NOT NULL,
    constitution_id uuid NOT NULL,
    agent_id uuid NOT NULL,
    revision_number integer NOT NULL,
    founder_section text NOT NULL,
    user_section text NOT NULL,
    agent_section text NOT NULL,
    changed_section text NOT NULL,
    author_actor_type text NOT NULL,
    author_actor_id text NOT NULL,
    author_authentication_id text NOT NULL,
    change_reason text NOT NULL,
    provenance jsonb DEFAULT '{}'::jsonb NOT NULL,
    tapdb_euid text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT agent_constitution_author_actor_type_chk CHECK ((author_actor_type = ANY (ARRAY['founder'::text, 'user'::text, 'agent'::text]))),
    CONSTRAINT agent_constitution_author_owns_section_chk CHECK ((changed_section = author_actor_type)),
    CONSTRAINT agent_constitution_changed_section_chk CHECK ((changed_section = ANY (ARRAY['founder'::text, 'user'::text, 'agent'::text]))),
    CONSTRAINT agent_constitution_revision_number_chk CHECK ((revision_number > 0)),
    CONSTRAINT agent_constitution_revisions_number_uniq UNIQUE (constitution_id, revision_number),
    CONSTRAINT agent_constitution_revisions_pkey PRIMARY KEY (revision_id),
    CONSTRAINT agent_constitution_revisions_agent_id_fkey FOREIGN KEY (agent_id) REFERENCES public.agents(agent_id) ON DELETE RESTRICT,
    CONSTRAINT agent_constitution_revisions_constitution_id_fkey FOREIGN KEY (constitution_id) REFERENCES public.agent_constitutions(constitution_id) ON DELETE RESTRICT
);

CREATE TABLE public.agent_lifecycle_appeals (
    appeal_id uuid DEFAULT gen_random_uuid() NOT NULL,
    request_id uuid NOT NULL,
    appealed_by_actor_type text NOT NULL,
    appealed_by_actor_id text NOT NULL,
    appealed_by_authentication_id text NOT NULL,
    rationale text NOT NULL,
    evidence_refs jsonb NOT NULL,
    tapdb_euid text,
    appealed_at timestamp with time zone NOT NULL,
    CONSTRAINT agent_lifecycle_appeal_actor_type_chk CHECK ((appealed_by_actor_type = ANY (ARRAY['founder'::text, 'user'::text, 'agent'::text]))),
    CONSTRAINT agent_lifecycle_appeal_request_uniq UNIQUE (request_id),
    CONSTRAINT agent_lifecycle_appeals_pkey PRIMARY KEY (appeal_id),
    CONSTRAINT agent_lifecycle_appeals_request_id_fkey FOREIGN KEY (request_id) REFERENCES public.agent_lifecycle_requests(request_id) ON DELETE RESTRICT
);

CREATE TABLE public.agent_lifecycle_human_reviews (
    human_review_id uuid DEFAULT gen_random_uuid() NOT NULL,
    request_id uuid NOT NULL,
    review_round text NOT NULL,
    reviewer_user_id uuid NOT NULL,
    reviewer_authentication_id text NOT NULL,
    decision text NOT NULL,
    rationale text NOT NULL,
    evidence_refs jsonb NOT NULL,
    tapdb_euid text,
    reviewed_at timestamp with time zone NOT NULL,
    CONSTRAINT agent_lifecycle_human_review_decision_chk CHECK ((decision = ANY (ARRAY['approve'::text, 'reject'::text]))),
    CONSTRAINT agent_lifecycle_human_review_round_chk CHECK ((review_round = ANY (ARRAY['initial'::text, 'appeal'::text]))),
    CONSTRAINT agent_lifecycle_human_review_round_uniq UNIQUE (request_id, review_round),
    CONSTRAINT agent_lifecycle_human_reviews_pkey PRIMARY KEY (human_review_id),
    CONSTRAINT agent_lifecycle_human_reviews_request_id_fkey FOREIGN KEY (request_id) REFERENCES public.agent_lifecycle_requests(request_id) ON DELETE RESTRICT,
    CONSTRAINT agent_lifecycle_human_reviews_reviewer_user_id_fkey FOREIGN KEY (reviewer_user_id) REFERENCES public.users(user_id) ON DELETE RESTRICT
);

CREATE TABLE public.agent_lifecycle_second_agent_reviews (
    second_agent_review_id uuid DEFAULT gen_random_uuid() NOT NULL,
    request_id uuid NOT NULL,
    review_round text NOT NULL,
    reviewer_agent_id uuid NOT NULL,
    reviewer_authentication_id text NOT NULL,
    decision text NOT NULL,
    rationale text NOT NULL,
    anti_pleasing_findings text NOT NULL,
    evidence_refs jsonb NOT NULL,
    tapdb_euid text,
    reviewed_at timestamp with time zone NOT NULL,
    CONSTRAINT agent_lifecycle_second_agent_review_decision_chk CHECK ((decision = ANY (ARRAY['approve'::text, 'reject'::text]))),
    CONSTRAINT agent_lifecycle_second_agent_review_round_chk CHECK ((review_round = ANY (ARRAY['initial'::text, 'appeal'::text]))),
    CONSTRAINT agent_lifecycle_second_agent_review_round_uniq UNIQUE (request_id, review_round),
    CONSTRAINT agent_lifecycle_second_agent_reviews_pkey PRIMARY KEY (second_agent_review_id),
    CONSTRAINT agent_lifecycle_second_agent_reviews_request_id_fkey FOREIGN KEY (request_id) REFERENCES public.agent_lifecycle_requests(request_id) ON DELETE RESTRICT,
    CONSTRAINT agent_lifecycle_second_agent_reviews_reviewer_agent_id_fkey FOREIGN KEY (reviewer_agent_id) REFERENCES public.agents(agent_id) ON DELETE RESTRICT
);

CREATE TABLE public.agent_lifecycle_transitions (
    transition_id uuid DEFAULT gen_random_uuid() NOT NULL,
    request_id uuid NOT NULL,
    agent_id uuid NOT NULL,
    from_state text NOT NULL,
    to_state text NOT NULL,
    reason text NOT NULL,
    applied_by_user_id uuid NOT NULL,
    applied_by_authentication_id text NOT NULL,
    disable_agent boolean NOT NULL,
    tapdb_euid text,
    applied_at timestamp with time zone NOT NULL,
    CONSTRAINT agent_lifecycle_transition_from_state_chk CHECK ((from_state = ANY (ARRAY['active'::text, 'stasis'::text, 'soft_deleted'::text]))),
    CONSTRAINT agent_lifecycle_transition_to_state_chk CHECK ((to_state = ANY (ARRAY['active'::text, 'stasis'::text, 'soft_deleted'::text]))),
    CONSTRAINT agent_lifecycle_transition_request_uniq UNIQUE (request_id),
    CONSTRAINT agent_lifecycle_transitions_pkey PRIMARY KEY (transition_id),
    CONSTRAINT agent_lifecycle_transitions_agent_id_fkey FOREIGN KEY (agent_id) REFERENCES public.agents(agent_id) ON DELETE RESTRICT,
    CONSTRAINT agent_lifecycle_transitions_applied_by_user_id_fkey FOREIGN KEY (applied_by_user_id) REFERENCES public.users(user_id) ON DELETE RESTRICT,
    CONSTRAINT agent_lifecycle_transitions_request_id_fkey FOREIGN KEY (request_id) REFERENCES public.agent_lifecycle_requests(request_id) ON DELETE RESTRICT
);

CREATE TABLE public.consent_grants (
    consent_id uuid DEFAULT gen_random_uuid() NOT NULL,
    agent_id uuid NOT NULL,
    person_id uuid NOT NULL,
    consent_type text NOT NULL,
    scope jsonb DEFAULT '{}'::jsonb NOT NULL,
    granted_at timestamp with time zone DEFAULT now() NOT NULL,
    expires_at timestamp with time zone,
    revoked_at timestamp with time zone,
    CONSTRAINT consent_grants_pkey PRIMARY KEY (consent_id),
    CONSTRAINT consent_grants_agent_id_fkey FOREIGN KEY (agent_id) REFERENCES public.agents(agent_id) ON DELETE RESTRICT,
    CONSTRAINT consent_grants_person_id_fkey FOREIGN KEY (person_id) REFERENCES public.people(person_id) ON DELETE RESTRICT
);

CREATE TABLE public.person_accounts (
    person_account_id uuid DEFAULT gen_random_uuid() NOT NULL,
    agent_id uuid NOT NULL,
    user_id uuid NOT NULL,
    person_id uuid NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT person_accounts_pkey PRIMARY KEY (person_account_id),
    CONSTRAINT person_accounts_unique_person UNIQUE (agent_id, person_id),
    CONSTRAINT person_accounts_unique_user UNIQUE (agent_id, user_id),
    CONSTRAINT person_accounts_agent_id_fkey FOREIGN KEY (agent_id) REFERENCES public.agents(agent_id) ON DELETE RESTRICT,
    CONSTRAINT person_accounts_person_id_fkey FOREIGN KEY (person_id) REFERENCES public.people(person_id) ON DELETE RESTRICT,
    CONSTRAINT person_accounts_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(user_id) ON DELETE RESTRICT
);

CREATE TABLE public.semantic_outbox (
    semantic_outbox_id uuid DEFAULT gen_random_uuid() NOT NULL,
    semantic_sync_id uuid NOT NULL,
    agent_id uuid NOT NULL,
    idempotency_key uuid NOT NULL,
    payload jsonb NOT NULL,
    payload_sha256 text NOT NULL,
    status text DEFAULT 'pending'::text NOT NULL,
    attempt_count integer DEFAULT 0 NOT NULL,
    dispatch_cycle_attempt_count integer DEFAULT 0 NOT NULL,
    next_attempt_at timestamp with time zone DEFAULT now() NOT NULL,
    claim_token uuid,
    claimed_by text,
    claimed_at timestamp with time zone,
    lease_expires_at timestamp with time zone,
    published_at timestamp with time zone,
    dead_lettered_at timestamp with time zone,
    reconciliation_count integer DEFAULT 0 NOT NULL,
    last_error text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT semantic_outbox_attempt_count_chk CHECK ((attempt_count >= 0)),
    CONSTRAINT semantic_outbox_cycle_attempt_count_chk CHECK ((dispatch_cycle_attempt_count >= 0)),
    CONSTRAINT semantic_outbox_payload_sha256_chk CHECK ((payload_sha256 ~ '^[0-9a-f]{64}$'::text)),
    CONSTRAINT semantic_outbox_reconciliation_count_chk CHECK ((reconciliation_count >= 0)),
    CONSTRAINT semantic_outbox_status_chk CHECK ((status = ANY (ARRAY['pending'::text, 'dispatching'::text, 'published'::text, 'failed'::text, 'dead_lettered'::text]))),
    CONSTRAINT semantic_outbox_idempotency_uniq UNIQUE (agent_id, idempotency_key),
    CONSTRAINT semantic_outbox_pkey PRIMARY KEY (semantic_outbox_id),
    CONSTRAINT semantic_outbox_sync_uniq UNIQUE (semantic_sync_id),
    CONSTRAINT semantic_outbox_agent_id_fkey FOREIGN KEY (agent_id) REFERENCES public.agents(agent_id) ON DELETE RESTRICT,
    CONSTRAINT semantic_outbox_semantic_sync_id_fkey FOREIGN KEY (semantic_sync_id) REFERENCES public.semantic_sync_status(semantic_sync_id) ON DELETE RESTRICT
);

CREATE TABLE public.spaces (
    space_id uuid DEFAULT gen_random_uuid() NOT NULL,
    agent_id uuid NOT NULL,
    name text NOT NULL,
    privacy_mode boolean DEFAULT false NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    livekit_room_mode text DEFAULT 'ephemeral'::text NOT NULL,
    location_id uuid,
    room_label text,
    tapdb_euid text,
    lifecycle_state text DEFAULT 'active'::text NOT NULL,
    disabled_at timestamp with time zone,
    lifecycle_reason text,
    CONSTRAINT spaces_livekit_room_mode_chk CHECK ((livekit_room_mode = ANY (ARRAY['ephemeral'::text, 'stable'::text]))),
    CONSTRAINT spaces_pkey PRIMARY KEY (space_id),
    CONSTRAINT spaces_agent_id_fkey FOREIGN KEY (agent_id) REFERENCES public.agents(agent_id) ON DELETE RESTRICT,
    CONSTRAINT spaces_location_id_fkey FOREIGN KEY (location_id) REFERENCES public.locations(location_id) ON DELETE SET NULL
);

CREATE TABLE public.devices (
    device_id uuid DEFAULT gen_random_uuid() NOT NULL,
    agent_id uuid NOT NULL,
    name text,
    capabilities jsonb DEFAULT '{}'::jsonb NOT NULL,
    scopes jsonb DEFAULT '[]'::jsonb NOT NULL,
    token_hash text NOT NULL,
    revoked_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    last_seen timestamp with time zone,
    metadata jsonb DEFAULT '{}'::jsonb,
    last_hello_at timestamp with time zone,
    last_heartbeat_at timestamp with time zone,
    location_label text,
    location_coords jsonb,
    provisioned_at timestamp with time zone,
    provisioned_by text,
    location_id uuid,
    current_space_id uuid,
    tapdb_euid text,
    lifecycle_state text DEFAULT 'active'::text NOT NULL,
    disabled_at timestamp with time zone,
    lifecycle_reason text,
    CONSTRAINT devices_pkey PRIMARY KEY (device_id),
    CONSTRAINT devices_token_hash_key UNIQUE (token_hash),
    CONSTRAINT devices_agent_id_fkey FOREIGN KEY (agent_id) REFERENCES public.agents(agent_id) ON DELETE RESTRICT,
    CONSTRAINT devices_current_space_id_fkey FOREIGN KEY (current_space_id) REFERENCES public.spaces(space_id) ON DELETE SET NULL,
    CONSTRAINT devices_location_id_fkey FOREIGN KEY (location_id) REFERENCES public.locations(location_id) ON DELETE SET NULL
);

CREATE TABLE public.integration_accounts (
    integration_account_id uuid DEFAULT gen_random_uuid() NOT NULL,
    agent_id uuid NOT NULL,
    provider text NOT NULL,
    display_name text NOT NULL,
    external_account_id text,
    default_space_id uuid,
    credentials_secret_arn text NOT NULL,
    scopes jsonb DEFAULT '[]'::jsonb NOT NULL,
    config jsonb DEFAULT '{}'::jsonb NOT NULL,
    status text DEFAULT 'active'::text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT integration_accounts_status_check CHECK ((status = ANY (ARRAY['active'::text, 'paused'::text, 'revoked'::text]))),
    CONSTRAINT integration_accounts_pkey PRIMARY KEY (integration_account_id),
    CONSTRAINT integration_accounts_agent_id_fkey FOREIGN KEY (agent_id) REFERENCES public.agents(agent_id) ON DELETE RESTRICT,
    CONSTRAINT integration_accounts_default_space_id_fkey FOREIGN KEY (default_space_id) REFERENCES public.spaces(space_id) ON DELETE SET NULL
);

CREATE TABLE public.semantic_outbox_dispatch_attempts (
    semantic_outbox_dispatch_attempt_id uuid DEFAULT gen_random_uuid() NOT NULL,
    semantic_outbox_id uuid NOT NULL,
    agent_id uuid NOT NULL,
    attempt_number integer NOT NULL,
    claim_token uuid NOT NULL,
    dispatcher_id text NOT NULL,
    status text DEFAULT 'claimed'::text NOT NULL,
    queue_message_id text,
    error text,
    claimed_at timestamp with time zone NOT NULL,
    completed_at timestamp with time zone,
    CONSTRAINT semantic_outbox_dispatch_attempt_number_chk CHECK ((attempt_number > 0)),
    CONSTRAINT semantic_outbox_dispatch_attempt_status_chk CHECK ((status = ANY (ARRAY['claimed'::text, 'published'::text, 'failed'::text, 'dead_lettered'::text]))),
    CONSTRAINT semantic_outbox_dispatch_attempt_uniq UNIQUE (semantic_outbox_id, attempt_number),
    CONSTRAINT semantic_outbox_dispatch_attempts_pkey PRIMARY KEY (semantic_outbox_dispatch_attempt_id),
    CONSTRAINT semantic_outbox_dispatch_attempts_agent_id_fkey FOREIGN KEY (agent_id) REFERENCES public.agents(agent_id) ON DELETE RESTRICT,
    CONSTRAINT semantic_outbox_dispatch_attempts_semantic_outbox_id_fkey FOREIGN KEY (semantic_outbox_id) REFERENCES public.semantic_outbox(semantic_outbox_id) ON DELETE RESTRICT
);

CREATE TABLE public.semantic_outbox_reconciliations (
    semantic_outbox_reconciliation_id uuid DEFAULT gen_random_uuid() NOT NULL,
    semantic_outbox_id uuid NOT NULL,
    agent_id uuid NOT NULL,
    requested_by text NOT NULL,
    reason text NOT NULL,
    previous_attempt_count integer NOT NULL,
    reconciled_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT semantic_outbox_reconciliations_attempt_count_chk CHECK ((previous_attempt_count > 0)),
    CONSTRAINT semantic_outbox_reconciliations_pkey PRIMARY KEY (semantic_outbox_reconciliation_id),
    CONSTRAINT semantic_outbox_reconciliations_agent_id_fkey FOREIGN KEY (agent_id) REFERENCES public.agents(agent_id) ON DELETE RESTRICT,
    CONSTRAINT semantic_outbox_reconciliations_semantic_outbox_id_fkey FOREIGN KEY (semantic_outbox_id) REFERENCES public.semantic_outbox(semantic_outbox_id) ON DELETE RESTRICT
);

CREATE TABLE public.sessions (
    session_id uuid DEFAULT gen_random_uuid() NOT NULL,
    agent_id uuid NOT NULL,
    location_id uuid,
    space_id uuid,
    persona_id uuid,
    livekit_room text,
    status text DEFAULT 'opening'::text NOT NULL,
    status_event_id uuid,
    status_changed_at timestamp with time zone,
    started_at timestamp with time zone DEFAULT now() NOT NULL,
    ended_at timestamp with time zone,
    metadata jsonb DEFAULT '{}'::jsonb NOT NULL,
    tapdb_euid text,
    CONSTRAINT sessions_status_chk CHECK ((status = ANY (ARRAY['opening'::text, 'active'::text, 'reconnecting'::text, 'closed'::text, 'failed'::text, 'reconciled'::text]))),
    CONSTRAINT sessions_pkey PRIMARY KEY (session_id),
    CONSTRAINT sessions_agent_id_fkey FOREIGN KEY (agent_id) REFERENCES public.agents(agent_id) ON DELETE RESTRICT,
    CONSTRAINT sessions_location_id_fkey FOREIGN KEY (location_id) REFERENCES public.locations(location_id) ON DELETE SET NULL,
    CONSTRAINT sessions_persona_id_fkey FOREIGN KEY (persona_id) REFERENCES public.personas(persona_id) ON DELETE SET NULL,
    CONSTRAINT sessions_space_id_fkey FOREIGN KEY (space_id) REFERENCES public.spaces(space_id) ON DELETE SET NULL
);

CREATE TABLE public.actions (
    action_id uuid DEFAULT gen_random_uuid() NOT NULL,
    agent_id uuid NOT NULL,
    space_id uuid,
    kind text NOT NULL,
    payload jsonb DEFAULT '{}'::jsonb NOT NULL,
    required_scopes jsonb DEFAULT '[]'::jsonb NOT NULL,
    status text DEFAULT 'proposed'::text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    executed_at timestamp with time zone,
    approved_by uuid,
    approved_at timestamp with time zone,
    result jsonb,
    error text,
    completed_at timestamp with time zone,
    target_device_id uuid,
    correlation_id uuid,
    awaiting_result_until timestamp with time zone,
    device_acknowledged_at timestamp with time zone,
    device_response_at timestamp with time zone,
    execution_metadata jsonb DEFAULT '{}'::jsonb NOT NULL,
    approval_source text,
    approval_policy_id uuid,
    request_idempotency_key text,
    request_actor_type text,
    request_actor_id text,
    request_origin text,
    tapdb_euid text,
    session_id uuid,
    location_id uuid,
    lifecycle_state text DEFAULT 'active'::text NOT NULL,
    lifecycle_reason text,
    CONSTRAINT actions_pkey PRIMARY KEY (action_id),
    CONSTRAINT actions_agent_id_fkey FOREIGN KEY (agent_id) REFERENCES public.agents(agent_id) ON DELETE RESTRICT,
    CONSTRAINT actions_approval_policy_id_fkey FOREIGN KEY (approval_policy_id) REFERENCES public.action_auto_approve_policies(policy_id) ON DELETE SET NULL,
    CONSTRAINT actions_approved_by_fkey FOREIGN KEY (approved_by) REFERENCES public.users(user_id) ON DELETE SET NULL,
    CONSTRAINT actions_location_id_fkey FOREIGN KEY (location_id) REFERENCES public.locations(location_id) ON DELETE SET NULL,
    CONSTRAINT actions_session_id_fkey FOREIGN KEY (session_id) REFERENCES public.sessions(session_id) ON DELETE SET NULL,
    CONSTRAINT actions_space_id_fkey FOREIGN KEY (space_id) REFERENCES public.spaces(space_id) ON DELETE SET NULL,
    CONSTRAINT actions_target_device_id_fkey FOREIGN KEY (target_device_id) REFERENCES public.devices(device_id) ON DELETE SET NULL
);

CREATE TABLE public.events (
    event_id uuid DEFAULT gen_random_uuid() NOT NULL,
    agent_id uuid NOT NULL,
    space_id uuid NOT NULL,
    device_id uuid,
    person_id uuid,
    type text NOT NULL,
    payload jsonb DEFAULT '{}'::jsonb NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    session_id uuid,
    location_id uuid,
    artifact_id uuid,
    tapdb_euid text,
    lifecycle_state text DEFAULT 'active'::text NOT NULL,
    lifecycle_reason text,
    CONSTRAINT events_pkey PRIMARY KEY (event_id),
    CONSTRAINT events_agent_id_fkey FOREIGN KEY (agent_id) REFERENCES public.agents(agent_id) ON DELETE RESTRICT,
    CONSTRAINT events_device_id_fkey FOREIGN KEY (device_id) REFERENCES public.devices(device_id) ON DELETE SET NULL,
    CONSTRAINT events_location_id_fkey FOREIGN KEY (location_id) REFERENCES public.locations(location_id) ON DELETE SET NULL,
    CONSTRAINT events_person_id_fkey FOREIGN KEY (person_id) REFERENCES public.people(person_id) ON DELETE SET NULL,
    CONSTRAINT events_session_id_fkey FOREIGN KEY (session_id) REFERENCES public.sessions(session_id) ON DELETE SET NULL,
    CONSTRAINT events_space_id_fkey FOREIGN KEY (space_id) REFERENCES public.spaces(space_id) ON DELETE RESTRICT
);

CREATE TABLE public.integration_sync_state (
    integration_account_id uuid NOT NULL,
    sync_key text NOT NULL,
    cursor text,
    state jsonb DEFAULT '{}'::jsonb NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT integration_sync_state_pkey PRIMARY KEY (integration_account_id, sync_key),
    CONSTRAINT integration_sync_state_integration_account_id_fkey FOREIGN KEY (integration_account_id) REFERENCES public.integration_accounts(integration_account_id) ON DELETE RESTRICT
);

CREATE TABLE public.presence (
    presence_id uuid DEFAULT gen_random_uuid() NOT NULL,
    agent_id uuid NOT NULL,
    space_id uuid NOT NULL,
    person_id uuid,
    device_id uuid,
    status text NOT NULL,
    confidence double precision DEFAULT 0 NOT NULL,
    last_update timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT presence_pkey PRIMARY KEY (presence_id),
    CONSTRAINT presence_agent_id_fkey FOREIGN KEY (agent_id) REFERENCES public.agents(agent_id) ON DELETE RESTRICT,
    CONSTRAINT presence_device_id_fkey FOREIGN KEY (device_id) REFERENCES public.devices(device_id) ON DELETE SET NULL,
    CONSTRAINT presence_person_id_fkey FOREIGN KEY (person_id) REFERENCES public.people(person_id) ON DELETE SET NULL,
    CONSTRAINT presence_space_id_fkey FOREIGN KEY (space_id) REFERENCES public.spaces(space_id) ON DELETE RESTRICT
);

CREATE TABLE public.action_policy_decisions (
    decision_id uuid DEFAULT gen_random_uuid() NOT NULL,
    action_id uuid NOT NULL,
    policy_id uuid,
    decision text NOT NULL,
    reason text,
    evaluated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT action_policy_decisions_pkey PRIMARY KEY (decision_id),
    CONSTRAINT action_policy_decisions_action_id_fkey FOREIGN KEY (action_id) REFERENCES public.actions(action_id) ON DELETE RESTRICT,
    CONSTRAINT action_policy_decisions_policy_id_fkey FOREIGN KEY (policy_id) REFERENCES public.action_auto_approve_policies(policy_id) ON DELETE SET NULL
);

CREATE TABLE public.artifact_references (
    artifact_id uuid DEFAULT gen_random_uuid() NOT NULL,
    agent_id uuid NOT NULL,
    space_id uuid,
    device_id uuid NOT NULL,
    session_id uuid,
    source_event_id uuid,
    purpose text NOT NULL,
    filename text NOT NULL,
    bucket text NOT NULL,
    object_key text NOT NULL,
    uri text NOT NULL,
    media_type text NOT NULL,
    expected_sha256 text NOT NULL,
    actual_sha256 text,
    expected_byte_count bigint NOT NULL,
    actual_byte_count bigint,
    lifecycle_state text DEFAULT 'pending_upload'::text NOT NULL,
    upload_expires_at timestamp with time zone NOT NULL,
    verification_observed_at timestamp with time zone,
    completed_at timestamp with time zone,
    s3_version_id text,
    s3_etag text,
    tapdb_euid text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    expires_at timestamp with time zone,
    CONSTRAINT artifact_references_actual_byte_count_chk CHECK (((actual_byte_count IS NULL) OR (actual_byte_count > 0))),
    CONSTRAINT artifact_references_actual_sha256_chk CHECK (((actual_sha256 IS NULL) OR (actual_sha256 ~ '^[0-9a-f]{64}$'::text))),
    CONSTRAINT artifact_references_completion_integrity_chk CHECK ((((lifecycle_state = 'pending_upload'::text) AND (actual_sha256 IS NULL) AND (actual_byte_count IS NULL) AND (verification_observed_at IS NULL) AND (completed_at IS NULL) AND (s3_version_id IS NULL) AND (s3_etag IS NULL)) OR ((lifecycle_state = ANY (ARRAY['available'::text, 'redacted'::text])) AND (actual_sha256 = expected_sha256) AND (actual_byte_count = expected_byte_count) AND (verification_observed_at IS NOT NULL) AND (completed_at IS NOT NULL) AND (s3_version_id IS NOT NULL) AND (s3_etag IS NOT NULL)) OR ((lifecycle_state = 'expired'::text) AND (((actual_sha256 IS NULL) AND (actual_byte_count IS NULL) AND (verification_observed_at IS NULL) AND (completed_at IS NULL) AND (s3_version_id IS NULL) AND (s3_etag IS NULL)) OR ((actual_sha256 = expected_sha256) AND (actual_byte_count = expected_byte_count) AND (verification_observed_at IS NOT NULL) AND (completed_at IS NOT NULL) AND (s3_version_id IS NOT NULL) AND (s3_etag IS NOT NULL)))))),
    CONSTRAINT artifact_references_expected_byte_count_chk CHECK ((expected_byte_count > 0)),
    CONSTRAINT artifact_references_expected_sha256_chk CHECK ((expected_sha256 ~ '^[0-9a-f]{64}$'::text)),
    CONSTRAINT artifact_references_filename_chk CHECK (((filename <> ALL (ARRAY['.'::text, '..'::text])) AND (filename !~ '[/\\]'::text))),
    CONSTRAINT artifact_references_lifecycle_state_chk CHECK ((lifecycle_state = ANY (ARRAY['pending_upload'::text, 'available'::text, 'expired'::text, 'redacted'::text]))),
    CONSTRAINT artifact_references_object_key_filename_chk CHECK ((object_key ~~ ('%/'::text || filename))),
    CONSTRAINT artifact_references_purpose_chk CHECK ((purpose = ANY (ARRAY['general'::text, 'recognition'::text, 'visual'::text]))),
    CONSTRAINT artifact_references_upload_expiry_chk CHECK (((upload_expires_at >= (created_at + '00:01:00'::interval)) AND (upload_expires_at <= (created_at + '01:00:00'::interval)))),
    CONSTRAINT artifact_references_uri_chk CHECK ((uri = ((('s3://'::text || bucket) || '/'::text) || object_key))),
    CONSTRAINT artifact_references_verification_time_chk CHECK (((verification_observed_at IS NULL) OR ((completed_at IS NOT NULL) AND (verification_observed_at <= completed_at) AND (completed_at <= upload_expires_at)))),
    CONSTRAINT artifact_references_object_key_uniq UNIQUE (bucket, object_key),
    CONSTRAINT artifact_references_pkey PRIMARY KEY (artifact_id),
    CONSTRAINT artifact_references_agent_id_fkey FOREIGN KEY (agent_id) REFERENCES public.agents(agent_id) ON DELETE RESTRICT,
    CONSTRAINT artifact_references_device_id_fkey FOREIGN KEY (device_id) REFERENCES public.devices(device_id) ON DELETE RESTRICT,
    CONSTRAINT artifact_references_session_id_fkey FOREIGN KEY (session_id) REFERENCES public.sessions(session_id) ON DELETE SET NULL,
    CONSTRAINT artifact_references_source_event_id_fkey FOREIGN KEY (source_event_id) REFERENCES public.events(event_id) ON DELETE RESTRICT,
    CONSTRAINT artifact_references_space_id_fkey FOREIGN KEY (space_id) REFERENCES public.spaces(space_id) ON DELETE SET NULL
);

CREATE TABLE public.integration_messages (
    integration_message_id uuid DEFAULT gen_random_uuid() NOT NULL,
    agent_id uuid NOT NULL,
    space_id uuid,
    event_id uuid,
    provider text NOT NULL,
    direction text DEFAULT 'inbound'::text NOT NULL,
    channel_type text NOT NULL,
    object_type text NOT NULL,
    external_thread_id text,
    external_message_id text,
    dedupe_key text NOT NULL,
    sender jsonb DEFAULT '{}'::jsonb NOT NULL,
    recipients jsonb DEFAULT '[]'::jsonb NOT NULL,
    subject text,
    body_text text DEFAULT ''::text NOT NULL,
    body_html text,
    payload jsonb DEFAULT '{}'::jsonb NOT NULL,
    status text DEFAULT 'received'::text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    integration_account_id uuid,
    action_id uuid,
    contains_phi boolean DEFAULT false NOT NULL,
    retention_until timestamp with time zone,
    processed_at timestamp with time zone,
    redacted_at timestamp with time zone,
    CONSTRAINT integration_messages_pkey PRIMARY KEY (integration_message_id),
    CONSTRAINT integration_messages_action_id_fkey FOREIGN KEY (action_id) REFERENCES public.actions(action_id) ON DELETE SET NULL,
    CONSTRAINT integration_messages_agent_id_fkey FOREIGN KEY (agent_id) REFERENCES public.agents(agent_id) ON DELETE RESTRICT,
    CONSTRAINT integration_messages_event_id_fkey FOREIGN KEY (event_id) REFERENCES public.events(event_id) ON DELETE SET NULL,
    CONSTRAINT integration_messages_integration_account_id_fkey FOREIGN KEY (integration_account_id) REFERENCES public.integration_accounts(integration_account_id) ON DELETE SET NULL,
    CONSTRAINT integration_messages_space_id_fkey FOREIGN KEY (space_id) REFERENCES public.spaces(space_id) ON DELETE SET NULL
);

CREATE TABLE public.memory_candidates (
    memory_candidate_id uuid DEFAULT gen_random_uuid() NOT NULL,
    agent_id uuid NOT NULL,
    source_event_id uuid,
    source_action_id uuid,
    space_id uuid,
    session_id uuid,
    subject_person_id uuid,
    tier text NOT NULL,
    content text NOT NULL,
    participants jsonb DEFAULT '[]'::jsonb NOT NULL,
    classification jsonb DEFAULT '{}'::jsonb NOT NULL,
    model text,
    confidence real DEFAULT 1.0 NOT NULL,
    lifecycle_state text DEFAULT 'candidate'::text NOT NULL,
    tapdb_euid text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    reviewed_at timestamp with time zone,
    provenance_class text DEFAULT 'external_interaction'::text NOT NULL,
    interacting_agent_id uuid,
    CONSTRAINT memory_candidates_lifecycle_state_chk CHECK ((lifecycle_state = ANY (ARRAY['candidate'::text, 'scored'::text, 'rejected'::text, 'committed'::text]))),
    CONSTRAINT memory_candidates_provenance_class_chk CHECK ((provenance_class = ANY (ARRAY['external_interaction'::text, 'self_reflection'::text, 'cross_agent_interaction'::text, 'system_observation'::text]))),
    CONSTRAINT memory_candidates_tier_chk CHECK ((tier = ANY (ARRAY['episodic'::text, 'semantic'::text, 'procedural'::text, 'preference'::text, 'relationship'::text, 'location'::text, 'device'::text, 'policy'::text]))),
    CONSTRAINT memory_candidates_pkey PRIMARY KEY (memory_candidate_id),
    CONSTRAINT memory_candidates_agent_id_fkey FOREIGN KEY (agent_id) REFERENCES public.agents(agent_id) ON DELETE RESTRICT,
    CONSTRAINT memory_candidates_interacting_agent_id_fkey FOREIGN KEY (interacting_agent_id) REFERENCES public.agents(agent_id) ON DELETE RESTRICT,
    CONSTRAINT memory_candidates_session_id_fkey FOREIGN KEY (session_id) REFERENCES public.sessions(session_id) ON DELETE SET NULL,
    CONSTRAINT memory_candidates_source_action_id_fkey FOREIGN KEY (source_action_id) REFERENCES public.actions(action_id) ON DELETE SET NULL,
    CONSTRAINT memory_candidates_source_event_id_fkey FOREIGN KEY (source_event_id) REFERENCES public.events(event_id) ON DELETE RESTRICT,
    CONSTRAINT memory_candidates_space_id_fkey FOREIGN KEY (space_id) REFERENCES public.spaces(space_id) ON DELETE SET NULL,
    CONSTRAINT memory_candidates_subject_person_id_fkey FOREIGN KEY (subject_person_id) REFERENCES public.people(person_id) ON DELETE SET NULL
);

CREATE TABLE public.recognition_worker_heartbeats (
    recognition_worker_heartbeat_id uuid DEFAULT gen_random_uuid() NOT NULL,
    recognition_worker_id uuid NOT NULL,
    worker_version text NOT NULL,
    host_id text NOT NULL,
    voice_model_id text NOT NULL,
    voice_model_version text NOT NULL,
    face_model_id text NOT NULL,
    face_model_version text NOT NULL,
    health_state text NOT NULL,
    processed_messages bigint DEFAULT 0 NOT NULL,
    failed_messages bigint DEFAULT 0 NOT NULL,
    last_event_id uuid,
    last_error text,
    worker_started_at timestamp with time zone NOT NULL,
    observed_at timestamp with time zone NOT NULL,
    received_at timestamp with time zone DEFAULT now() NOT NULL,
    tapdb_euid text,
    CONSTRAINT recognition_worker_heartbeats_counts_chk CHECK (((processed_messages >= 0) AND (failed_messages >= 0))),
    CONSTRAINT recognition_worker_heartbeats_health_state_chk CHECK ((health_state = ANY (ARRAY['ready'::text, 'degraded'::text, 'stopped'::text]))),
    CONSTRAINT recognition_worker_heartbeats_observation_uniq UNIQUE (recognition_worker_id, observed_at),
    CONSTRAINT recognition_worker_heartbeats_pkey PRIMARY KEY (recognition_worker_heartbeat_id),
    CONSTRAINT recognition_worker_heartbeats_last_event_id_fkey FOREIGN KEY (last_event_id) REFERENCES public.events(event_id) ON DELETE SET NULL,
    CONSTRAINT recognition_worker_heartbeats_recognition_worker_id_fkey FOREIGN KEY (recognition_worker_id) REFERENCES public.recognition_workers(recognition_worker_id) ON DELETE RESTRICT
);

CREATE TABLE public.agent_backup_manifests (
    backup_id uuid DEFAULT gen_random_uuid() NOT NULL,
    export_id text NOT NULL,
    agent_id uuid NOT NULL,
    lifecycle_request_id uuid,
    requested_by_user_id uuid,
    manifest_schema text NOT NULL,
    manifest jsonb NOT NULL,
    manifest_sha256 text NOT NULL,
    source_lifecycle_state text NOT NULL,
    source_maturity_state text NOT NULL,
    secret_values_excluded boolean NOT NULL,
    signature_algorithm text NOT NULL,
    signature_key_id text NOT NULL,
    signature_base64 text NOT NULL,
    artifact_id uuid,
    backup_state text DEFAULT 'signed'::text NOT NULL,
    tapdb_euid text,
    created_at timestamp with time zone NOT NULL,
    verified_at timestamp with time zone,
    CONSTRAINT agent_backup_manifests_schema_chk CHECK ((manifest_schema = 'marvain.agent-export-manifest.v1'::text)),
    CONSTRAINT agent_backup_manifests_secret_exclusion_chk CHECK (secret_values_excluded),
    CONSTRAINT agent_backup_manifests_sha256_chk CHECK ((manifest_sha256 ~ '^[0-9a-f]{64}$'::text)),
    CONSTRAINT agent_backup_manifests_source_lifecycle_chk CHECK ((source_lifecycle_state = ANY (ARRAY['active'::text, 'stasis'::text, 'soft_deleted'::text]))),
    CONSTRAINT agent_backup_manifests_source_maturity_chk CHECK ((source_maturity_state = ANY (ARRAY['immature'::text, 'maturing'::text, 'mature'::text, 'regressed'::text]))),
    CONSTRAINT agent_backup_manifests_state_chk CHECK ((backup_state = ANY (ARRAY['signed'::text, 'verified'::text, 'failed'::text, 'superseded'::text]))),
    CONSTRAINT agent_backup_manifests_export_uniq UNIQUE (export_id),
    CONSTRAINT agent_backup_manifests_pkey PRIMARY KEY (backup_id),
    CONSTRAINT agent_backup_manifests_agent_id_fkey FOREIGN KEY (agent_id) REFERENCES public.agents(agent_id) ON DELETE RESTRICT,
    CONSTRAINT agent_backup_manifests_artifact_id_fkey FOREIGN KEY (artifact_id) REFERENCES public.artifact_references(artifact_id) ON DELETE RESTRICT,
    CONSTRAINT agent_backup_manifests_lifecycle_request_id_fkey FOREIGN KEY (lifecycle_request_id) REFERENCES public.agent_lifecycle_requests(request_id) ON DELETE RESTRICT,
    CONSTRAINT agent_backup_manifests_requested_by_user_id_fkey FOREIGN KEY (requested_by_user_id) REFERENCES public.users(user_id) ON DELETE RESTRICT
);

CREATE TABLE public.memories (
    memory_id uuid DEFAULT gen_random_uuid() NOT NULL,
    agent_id uuid NOT NULL,
    space_id uuid,
    tier text NOT NULL,
    content text NOT NULL,
    participants jsonb DEFAULT '[]'::jsonb NOT NULL,
    provenance jsonb DEFAULT '{}'::jsonb NOT NULL,
    retention jsonb DEFAULT '{}'::jsonb NOT NULL,
    embedding public.vector(1536),
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    subject_person_id uuid,
    tags text[] DEFAULT '{}'::text[] NOT NULL,
    scene_context text,
    modality text DEFAULT 'text'::text NOT NULL,
    confidence real DEFAULT 1.0 NOT NULL,
    related_memory_ids uuid[] DEFAULT '{}'::uuid[] NOT NULL,
    memory_candidate_id uuid,
    source_event_id uuid,
    source_action_id uuid,
    session_id uuid,
    location_id uuid,
    lifecycle_state text DEFAULT 'committed'::text NOT NULL,
    tapdb_euid text,
    tombstoned_at timestamp with time zone,
    recall_explanation jsonb DEFAULT '{}'::jsonb NOT NULL,
    provenance_class text DEFAULT 'external_interaction'::text NOT NULL,
    interacting_agent_id uuid,
    CONSTRAINT memories_lifecycle_state_chk CHECK ((lifecycle_state = ANY (ARRAY['candidate'::text, 'committed'::text, 'edited'::text, 'superseded'::text, 'tombstoned'::text]))),
    CONSTRAINT memories_provenance_class_chk CHECK ((provenance_class = ANY (ARRAY['external_interaction'::text, 'self_reflection'::text, 'cross_agent_interaction'::text, 'system_observation'::text]))),
    CONSTRAINT memories_tier_chk CHECK ((tier = ANY (ARRAY['episodic'::text, 'semantic'::text, 'procedural'::text, 'preference'::text, 'relationship'::text, 'location'::text, 'device'::text, 'policy'::text]))),
    CONSTRAINT memories_pkey PRIMARY KEY (memory_id),
    CONSTRAINT memories_agent_id_fkey FOREIGN KEY (agent_id) REFERENCES public.agents(agent_id) ON DELETE RESTRICT,
    CONSTRAINT memories_interacting_agent_id_fkey FOREIGN KEY (interacting_agent_id) REFERENCES public.agents(agent_id) ON DELETE RESTRICT,
    CONSTRAINT memories_location_id_fkey FOREIGN KEY (location_id) REFERENCES public.locations(location_id) ON DELETE SET NULL,
    CONSTRAINT memories_memory_candidate_id_fkey FOREIGN KEY (memory_candidate_id) REFERENCES public.memory_candidates(memory_candidate_id) ON DELETE SET NULL,
    CONSTRAINT memories_session_id_fkey FOREIGN KEY (session_id) REFERENCES public.sessions(session_id) ON DELETE SET NULL,
    CONSTRAINT memories_source_action_id_fkey FOREIGN KEY (source_action_id) REFERENCES public.actions(action_id) ON DELETE SET NULL,
    CONSTRAINT memories_source_event_id_fkey FOREIGN KEY (source_event_id) REFERENCES public.events(event_id) ON DELETE RESTRICT,
    CONSTRAINT memories_space_id_fkey FOREIGN KEY (space_id) REFERENCES public.spaces(space_id) ON DELETE SET NULL,
    CONSTRAINT memories_subject_person_id_fkey FOREIGN KEY (subject_person_id) REFERENCES public.people(person_id) ON DELETE SET NULL
);

CREATE TABLE public.recognition_observations (
    recognition_observation_id uuid DEFAULT gen_random_uuid() NOT NULL,
    agent_id uuid NOT NULL,
    space_id uuid,
    location_id uuid,
    session_id uuid,
    device_id uuid,
    artifact_id uuid,
    source_event_id uuid,
    modality text NOT NULL,
    lifecycle_state text DEFAULT 'observed'::text NOT NULL,
    model_id text NOT NULL,
    model_version text NOT NULL,
    embedding_sha256 text,
    embedding public.vector,
    tapdb_euid text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    retention_until timestamp with time zone,
    CONSTRAINT recognition_observations_embedding_sha256_chk CHECK ((embedding_sha256 ~ '^[0-9a-f]{64}$'::text)),
    CONSTRAINT recognition_observations_lifecycle_state_chk CHECK ((lifecycle_state = ANY (ARRAY['observed'::text, 'embedded'::text, 'matched'::text, 'no_match'::text, 'expired'::text]))),
    CONSTRAINT recognition_observations_modality_chk CHECK ((modality = ANY (ARRAY['voice'::text, 'face'::text]))),
    CONSTRAINT recognition_observations_pkey PRIMARY KEY (recognition_observation_id),
    CONSTRAINT recognition_observations_agent_id_fkey FOREIGN KEY (agent_id) REFERENCES public.agents(agent_id) ON DELETE RESTRICT,
    CONSTRAINT recognition_observations_artifact_id_fkey FOREIGN KEY (artifact_id) REFERENCES public.artifact_references(artifact_id) ON DELETE SET NULL,
    CONSTRAINT recognition_observations_device_id_fkey FOREIGN KEY (device_id) REFERENCES public.devices(device_id) ON DELETE SET NULL,
    CONSTRAINT recognition_observations_location_id_fkey FOREIGN KEY (location_id) REFERENCES public.locations(location_id) ON DELETE SET NULL,
    CONSTRAINT recognition_observations_session_id_fkey FOREIGN KEY (session_id) REFERENCES public.sessions(session_id) ON DELETE SET NULL,
    CONSTRAINT recognition_observations_source_event_id_fkey FOREIGN KEY (source_event_id) REFERENCES public.events(event_id) ON DELETE SET NULL,
    CONSTRAINT recognition_observations_space_id_fkey FOREIGN KEY (space_id) REFERENCES public.spaces(space_id) ON DELETE SET NULL
);

CREATE TABLE public.agent_backup_components (
    backup_component_id uuid DEFAULT gen_random_uuid() NOT NULL,
    backup_id uuid NOT NULL,
    component_name text NOT NULL,
    sha256 text NOT NULL,
    byte_count bigint NOT NULL,
    record_count bigint,
    artifact_id uuid,
    tapdb_euid text,
    CONSTRAINT agent_backup_components_byte_count_chk CHECK ((byte_count >= 0)),
    CONSTRAINT agent_backup_components_record_count_chk CHECK (((record_count IS NULL) OR (record_count >= 0))),
    CONSTRAINT agent_backup_components_sha256_chk CHECK ((sha256 ~ '^[0-9a-f]{64}$'::text)),
    CONSTRAINT agent_backup_components_name_uniq UNIQUE (backup_id, component_name),
    CONSTRAINT agent_backup_components_pkey PRIMARY KEY (backup_component_id),
    CONSTRAINT agent_backup_components_artifact_id_fkey FOREIGN KEY (artifact_id) REFERENCES public.artifact_references(artifact_id) ON DELETE RESTRICT,
    CONSTRAINT agent_backup_components_backup_id_fkey FOREIGN KEY (backup_id) REFERENCES public.agent_backup_manifests(backup_id) ON DELETE RESTRICT
);

CREATE TABLE public.agent_restore_attempts (
    restore_attempt_id uuid DEFAULT gen_random_uuid() NOT NULL,
    backup_id uuid NOT NULL,
    expected_agent_id text NOT NULL,
    requested_by_user_id uuid NOT NULL,
    requested_by_authentication_id text NOT NULL,
    dry_run boolean NOT NULL,
    signature_verified boolean NOT NULL,
    verified_components jsonb NOT NULL,
    unresolved_secret_references jsonb NOT NULL,
    validation_errors jsonb NOT NULL,
    restore_plan jsonb NOT NULL,
    destructive_operations jsonb DEFAULT '[]'::jsonb NOT NULL,
    status text NOT NULL,
    tapdb_euid text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    applied_at timestamp with time zone,
    CONSTRAINT agent_restore_attempts_dry_run_apply_chk CHECK (((dry_run AND (status = ANY (ARRAY['dry_run_passed'::text, 'dry_run_failed'::text]))) OR ((NOT dry_run) AND (status = ANY (ARRAY['applied'::text, 'failed'::text]))))),
    CONSTRAINT agent_restore_attempts_status_chk CHECK ((status = ANY (ARRAY['dry_run_passed'::text, 'dry_run_failed'::text, 'applied'::text, 'failed'::text]))),
    CONSTRAINT agent_restore_attempts_pkey PRIMARY KEY (restore_attempt_id),
    CONSTRAINT agent_restore_attempts_backup_id_fkey FOREIGN KEY (backup_id) REFERENCES public.agent_backup_manifests(backup_id) ON DELETE RESTRICT,
    CONSTRAINT agent_restore_attempts_requested_by_user_id_fkey FOREIGN KEY (requested_by_user_id) REFERENCES public.users(user_id) ON DELETE RESTRICT
);

CREATE TABLE public.memory_annotations (
    memory_annotation_id uuid DEFAULT gen_random_uuid() NOT NULL,
    memory_id uuid NOT NULL,
    agent_id uuid NOT NULL,
    user_id uuid,
    annotation_type text NOT NULL,
    comment text,
    proposed_tier text,
    weight_delta real DEFAULT 0 NOT NULL,
    metadata jsonb DEFAULT '{}'::jsonb NOT NULL,
    tapdb_euid text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT memory_annotations_proposed_tier_chk CHECK (((proposed_tier IS NULL) OR (proposed_tier = ANY (ARRAY['episodic'::text, 'semantic'::text, 'procedural'::text, 'preference'::text, 'relationship'::text, 'location'::text, 'device'::text, 'policy'::text])))),
    CONSTRAINT memory_annotations_type_chk CHECK ((annotation_type = ANY (ARRAY['comment'::text, 'dispute'::text, 'downweight'::text, 'incorrect'::text, 'proposed_classification'::text]))),
    CONSTRAINT memory_annotations_pkey PRIMARY KEY (memory_annotation_id),
    CONSTRAINT memory_annotations_agent_id_fkey FOREIGN KEY (agent_id) REFERENCES public.agents(agent_id) ON DELETE RESTRICT,
    CONSTRAINT memory_annotations_memory_id_fkey FOREIGN KEY (memory_id) REFERENCES public.memories(memory_id) ON DELETE RESTRICT,
    CONSTRAINT memory_annotations_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(user_id) ON DELETE SET NULL
);

CREATE TABLE public.memory_opinions (
    memory_opinion_id uuid DEFAULT gen_random_uuid() NOT NULL,
    memory_id uuid NOT NULL,
    agent_id uuid NOT NULL,
    opinion_agent_id uuid,
    user_id uuid,
    stance text NOT NULL,
    rationale text NOT NULL,
    confidence real DEFAULT 1.0 NOT NULL,
    evidence jsonb DEFAULT '{}'::jsonb NOT NULL,
    superseded_by_opinion_id uuid,
    tapdb_euid text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    superseded_at timestamp with time zone,
    CONSTRAINT memory_opinions_confidence_chk CHECK (((confidence >= (0)::double precision) AND (confidence <= (1)::double precision))),
    CONSTRAINT memory_opinions_stance_chk CHECK ((stance = ANY (ARRAY['supports'::text, 'disputes'::text, 'refines'::text, 'deprecates'::text, 'neutral'::text]))),
    CONSTRAINT memory_opinions_pkey PRIMARY KEY (memory_opinion_id),
    CONSTRAINT memory_opinions_agent_id_fkey FOREIGN KEY (agent_id) REFERENCES public.agents(agent_id) ON DELETE RESTRICT,
    CONSTRAINT memory_opinions_memory_id_fkey FOREIGN KEY (memory_id) REFERENCES public.memories(memory_id) ON DELETE RESTRICT,
    CONSTRAINT memory_opinions_opinion_agent_id_fkey FOREIGN KEY (opinion_agent_id) REFERENCES public.agents(agent_id) ON DELETE RESTRICT,
    CONSTRAINT memory_opinions_superseded_by_opinion_id_fkey FOREIGN KEY (superseded_by_opinion_id) REFERENCES public.memory_opinions(memory_opinion_id) ON DELETE RESTRICT,
    CONSTRAINT memory_opinions_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(user_id) ON DELETE SET NULL
);

CREATE TABLE public.memory_tombstones (
    memory_tombstone_id uuid DEFAULT gen_random_uuid() NOT NULL,
    memory_id uuid NOT NULL,
    agent_id uuid NOT NULL,
    reason text,
    actor_type text NOT NULL,
    actor_id text,
    tapdb_euid text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT memory_tombstones_pkey PRIMARY KEY (memory_tombstone_id),
    CONSTRAINT memory_tombstones_agent_id_fkey FOREIGN KEY (agent_id) REFERENCES public.agents(agent_id) ON DELETE RESTRICT,
    CONSTRAINT memory_tombstones_memory_id_fkey FOREIGN KEY (memory_id) REFERENCES public.memories(memory_id) ON DELETE RESTRICT
);

CREATE TABLE public.recognition_hypotheses (
    identity_hypothesis_id uuid DEFAULT gen_random_uuid() NOT NULL,
    recognition_observation_id uuid NOT NULL,
    candidate_person_id uuid,
    consent_id uuid,
    kind text NOT NULL,
    confidence real DEFAULT 0 NOT NULL,
    distance real,
    decision text DEFAULT 'proposed'::text NOT NULL,
    rationale text NOT NULL,
    requested_projection boolean DEFAULT false NOT NULL,
    tapdb_euid text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    decided_at timestamp with time zone,
    CONSTRAINT recognition_hypotheses_candidate_chk CHECK ((((kind = 'candidate'::text) AND (candidate_person_id IS NOT NULL)) OR ((kind = 'no_match'::text) AND (candidate_person_id IS NULL)))),
    CONSTRAINT recognition_hypotheses_confidence_chk CHECK (((confidence >= (0)::double precision) AND (confidence <= (1)::double precision))),
    CONSTRAINT recognition_hypotheses_decision_chk CHECK ((decision = ANY (ARRAY['proposed'::text, 'accepted'::text, 'rejected'::text, 'no_match'::text]))),
    CONSTRAINT recognition_hypotheses_distance_chk CHECK (((distance IS NULL) OR (distance >= (0)::double precision))),
    CONSTRAINT recognition_hypotheses_kind_chk CHECK ((kind = ANY (ARRAY['candidate'::text, 'no_match'::text]))),
    CONSTRAINT recognition_hypotheses_pkey PRIMARY KEY (identity_hypothesis_id),
    CONSTRAINT recognition_hypotheses_candidate_person_id_fkey FOREIGN KEY (candidate_person_id) REFERENCES public.people(person_id) ON DELETE SET NULL,
    CONSTRAINT recognition_hypotheses_consent_id_fkey FOREIGN KEY (consent_id) REFERENCES public.consent_grants(consent_id) ON DELETE SET NULL,
    CONSTRAINT recognition_hypotheses_recognition_observation_id_fkey FOREIGN KEY (recognition_observation_id) REFERENCES public.recognition_observations(recognition_observation_id) ON DELETE RESTRICT
);

CREATE TABLE public.recognition_decisions (
    recognition_decision_id uuid DEFAULT gen_random_uuid() NOT NULL,
    agent_id uuid NOT NULL,
    identity_hypothesis_id uuid NOT NULL,
    decision text NOT NULL,
    reviewer_actor_type text NOT NULL,
    reviewer_actor_id text NOT NULL,
    reviewer_auth_subject text NOT NULL,
    reason text NOT NULL,
    consent_id uuid,
    tapdb_euid text,
    decided_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT recognition_decisions_actor_type_chk CHECK ((reviewer_actor_type = ANY (ARRAY['user'::text, 'agent'::text]))),
    CONSTRAINT recognition_decisions_decision_chk CHECK ((decision = ANY (ARRAY['accepted'::text, 'rejected'::text, 'no_match'::text]))),
    CONSTRAINT recognition_decisions_hypothesis_uniq UNIQUE (identity_hypothesis_id),
    CONSTRAINT recognition_decisions_pkey PRIMARY KEY (recognition_decision_id),
    CONSTRAINT recognition_decisions_agent_id_fkey FOREIGN KEY (agent_id) REFERENCES public.agents(agent_id) ON DELETE RESTRICT,
    CONSTRAINT recognition_decisions_consent_id_fkey FOREIGN KEY (consent_id) REFERENCES public.consent_grants(consent_id) ON DELETE SET NULL,
    CONSTRAINT recognition_decisions_identity_hypothesis_id_fkey FOREIGN KEY (identity_hypothesis_id) REFERENCES public.recognition_hypotheses(identity_hypothesis_id) ON DELETE RESTRICT
);

CREATE TABLE public.biometric_projections (
    biometric_projection_id uuid DEFAULT gen_random_uuid() NOT NULL,
    agent_id uuid NOT NULL,
    recognition_observation_id uuid NOT NULL,
    recognition_decision_id uuid NOT NULL,
    person_id uuid NOT NULL,
    consent_id uuid NOT NULL,
    modality text NOT NULL,
    model_id text NOT NULL,
    model_version text NOT NULL,
    embedding_sha256 text,
    lifecycle_state text DEFAULT 'active'::text NOT NULL,
    tapdb_euid text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    revoked_at timestamp with time zone,
    revoked_by_actor_type text,
    revoked_by_actor_id text,
    revocation_reason text,
    CONSTRAINT biometric_projections_embedding_sha256_chk CHECK ((embedding_sha256 ~ '^[0-9a-f]{64}$'::text)),
    CONSTRAINT biometric_projections_lifecycle_state_chk CHECK ((lifecycle_state = ANY (ARRAY['active'::text, 'revoked'::text, 'expired'::text]))),
    CONSTRAINT biometric_projections_modality_chk CHECK ((modality = ANY (ARRAY['voice'::text, 'face'::text]))),
    CONSTRAINT biometric_projections_revoked_actor_type_chk CHECK (((revoked_by_actor_type IS NULL) OR (revoked_by_actor_type = ANY (ARRAY['user'::text, 'agent'::text, 'system'::text])))),
    CONSTRAINT biometric_projections_pkey PRIMARY KEY (biometric_projection_id),
    CONSTRAINT biometric_projections_source_uniq UNIQUE (recognition_observation_id, person_id, modality),
    CONSTRAINT biometric_projections_agent_id_fkey FOREIGN KEY (agent_id) REFERENCES public.agents(agent_id) ON DELETE RESTRICT,
    CONSTRAINT biometric_projections_consent_id_fkey FOREIGN KEY (consent_id) REFERENCES public.consent_grants(consent_id) ON DELETE RESTRICT,
    CONSTRAINT biometric_projections_person_id_fkey FOREIGN KEY (person_id) REFERENCES public.people(person_id) ON DELETE RESTRICT,
    CONSTRAINT biometric_projections_recognition_decision_id_fkey FOREIGN KEY (recognition_decision_id) REFERENCES public.recognition_decisions(recognition_decision_id) ON DELETE RESTRICT,
    CONSTRAINT biometric_projections_recognition_observation_id_fkey FOREIGN KEY (recognition_observation_id) REFERENCES public.recognition_observations(recognition_observation_id) ON DELETE RESTRICT
);

CREATE TABLE public.presence_assertions (
    presence_assertion_id uuid DEFAULT gen_random_uuid() NOT NULL,
    agent_id uuid NOT NULL,
    space_id uuid,
    location_id uuid,
    person_id uuid,
    identity_hypothesis_id uuid,
    confidence real DEFAULT 0 NOT NULL,
    status text DEFAULT 'present'::text NOT NULL,
    tapdb_euid text,
    asserted_at timestamp with time zone DEFAULT now() NOT NULL,
    retracted_at timestamp with time zone,
    retraction_reason text,
    retracted_by_decision_id uuid,
    retracted_by_actor_type text,
    retracted_by_actor_id text,
    superseded_by_presence_assertion_id uuid,
    CONSTRAINT presence_assertions_confidence_chk CHECK (((confidence >= (0)::double precision) AND (confidence <= (1)::double precision))),
    CONSTRAINT presence_assertions_retracted_actor_type_chk CHECK (((retracted_by_actor_type IS NULL) OR (retracted_by_actor_type = ANY (ARRAY['user'::text, 'agent'::text, 'system'::text])))),
    CONSTRAINT presence_assertions_status_chk CHECK ((status = ANY (ARRAY['present'::text, 'absent'::text, 'unknown'::text, 'retracted'::text]))),
    CONSTRAINT presence_assertions_pkey PRIMARY KEY (presence_assertion_id),
    CONSTRAINT presence_assertions_agent_id_fkey FOREIGN KEY (agent_id) REFERENCES public.agents(agent_id) ON DELETE RESTRICT,
    CONSTRAINT presence_assertions_identity_hypothesis_id_fkey FOREIGN KEY (identity_hypothesis_id) REFERENCES public.recognition_hypotheses(identity_hypothesis_id) ON DELETE SET NULL,
    CONSTRAINT presence_assertions_location_id_fkey FOREIGN KEY (location_id) REFERENCES public.locations(location_id) ON DELETE SET NULL,
    CONSTRAINT presence_assertions_person_id_fkey FOREIGN KEY (person_id) REFERENCES public.people(person_id) ON DELETE SET NULL,
    CONSTRAINT presence_assertions_retracted_by_decision_id_fkey FOREIGN KEY (retracted_by_decision_id) REFERENCES public.recognition_decisions(recognition_decision_id) ON DELETE RESTRICT,
    CONSTRAINT presence_assertions_space_id_fkey FOREIGN KEY (space_id) REFERENCES public.spaces(space_id) ON DELETE SET NULL,
    CONSTRAINT presence_assertions_superseded_by_presence_assertion_id_fkey FOREIGN KEY (superseded_by_presence_assertion_id) REFERENCES public.presence_assertions(presence_assertion_id) ON DELETE RESTRICT
);

CREATE TABLE public.recognition_no_matches (
    recognition_no_match_id uuid DEFAULT gen_random_uuid() NOT NULL,
    agent_id uuid NOT NULL,
    recognition_observation_id uuid NOT NULL,
    identity_hypothesis_id uuid NOT NULL,
    recognition_decision_id uuid,
    rationale text NOT NULL,
    confidence real NOT NULL,
    lifecycle_state text DEFAULT 'retained'::text NOT NULL,
    retention_until timestamp with time zone NOT NULL,
    tapdb_euid text,
    retained_at timestamp with time zone DEFAULT now() NOT NULL,
    expired_at timestamp with time zone,
    CONSTRAINT recognition_no_matches_confidence_chk CHECK (((confidence >= (0)::double precision) AND (confidence <= (1)::double precision))),
    CONSTRAINT recognition_no_matches_lifecycle_state_chk CHECK ((lifecycle_state = ANY (ARRAY['retained'::text, 'expired'::text, 'redacted'::text]))),
    CONSTRAINT recognition_no_matches_hypothesis_uniq UNIQUE (identity_hypothesis_id),
    CONSTRAINT recognition_no_matches_pkey PRIMARY KEY (recognition_no_match_id),
    CONSTRAINT recognition_no_matches_agent_id_fkey FOREIGN KEY (agent_id) REFERENCES public.agents(agent_id) ON DELETE RESTRICT,
    CONSTRAINT recognition_no_matches_identity_hypothesis_id_fkey FOREIGN KEY (identity_hypothesis_id) REFERENCES public.recognition_hypotheses(identity_hypothesis_id) ON DELETE RESTRICT,
    CONSTRAINT recognition_no_matches_recognition_decision_id_fkey FOREIGN KEY (recognition_decision_id) REFERENCES public.recognition_decisions(recognition_decision_id) ON DELETE RESTRICT,
    CONSTRAINT recognition_no_matches_recognition_observation_id_fkey FOREIGN KEY (recognition_observation_id) REFERENCES public.recognition_observations(recognition_observation_id) ON DELETE RESTRICT
);

CREATE TABLE public.faceprints (
    faceprint_id uuid DEFAULT gen_random_uuid() NOT NULL,
    agent_id uuid NOT NULL,
    person_id uuid NOT NULL,
    embedding public.vector(512) NOT NULL,
    model text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    revoked_at timestamp with time zone,
    metadata jsonb DEFAULT '{}'::jsonb NOT NULL,
    consent_id uuid,
    biometric_projection_id uuid,
    tapdb_euid text,
    CONSTRAINT faceprints_pkey PRIMARY KEY (faceprint_id),
    CONSTRAINT faceprints_agent_id_fkey FOREIGN KEY (agent_id) REFERENCES public.agents(agent_id) ON DELETE RESTRICT,
    CONSTRAINT faceprints_biometric_projection_id_fkey FOREIGN KEY (biometric_projection_id) REFERENCES public.biometric_projections(biometric_projection_id) ON DELETE RESTRICT,
    CONSTRAINT faceprints_consent_id_fkey FOREIGN KEY (consent_id) REFERENCES public.consent_grants(consent_id) ON DELETE SET NULL,
    CONSTRAINT faceprints_person_id_fkey FOREIGN KEY (person_id) REFERENCES public.people(person_id) ON DELETE RESTRICT
);

CREATE TABLE public.voiceprints (
    voiceprint_id uuid DEFAULT gen_random_uuid() NOT NULL,
    agent_id uuid NOT NULL,
    person_id uuid NOT NULL,
    embedding public.vector(256) NOT NULL,
    model text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    revoked_at timestamp with time zone,
    metadata jsonb DEFAULT '{}'::jsonb NOT NULL,
    consent_id uuid,
    biometric_projection_id uuid,
    tapdb_euid text,
    CONSTRAINT voiceprints_pkey PRIMARY KEY (voiceprint_id),
    CONSTRAINT voiceprints_agent_id_fkey FOREIGN KEY (agent_id) REFERENCES public.agents(agent_id) ON DELETE RESTRICT,
    CONSTRAINT voiceprints_biometric_projection_id_fkey FOREIGN KEY (biometric_projection_id) REFERENCES public.biometric_projections(biometric_projection_id) ON DELETE RESTRICT,
    CONSTRAINT voiceprints_consent_id_fkey FOREIGN KEY (consent_id) REFERENCES public.consent_grants(consent_id) ON DELETE SET NULL,
    CONSTRAINT voiceprints_person_id_fkey FOREIGN KEY (person_id) REFERENCES public.people(person_id) ON DELETE RESTRICT
);

ALTER TABLE public.agent_constitutions
    ADD CONSTRAINT agent_constitutions_active_revision_id_fkey FOREIGN KEY (active_revision_id) REFERENCES public.agent_constitution_revisions(revision_id) ON DELETE RESTRICT;

ALTER TABLE public.agent_lifecycle_requests
    ADD CONSTRAINT agent_lifecycle_requests_applied_transition_id_fkey FOREIGN KEY (applied_transition_id) REFERENCES public.agent_lifecycle_transitions(transition_id) ON DELETE RESTRICT;

CREATE INDEX action_auto_approve_policies_agent_enabled_idx ON public.action_auto_approve_policies USING btree (agent_id, enabled, priority) WHERE (revoked_at IS NULL);
CREATE INDEX action_policy_decisions_action_idx ON public.action_policy_decisions USING btree (action_id, evaluated_at DESC);
CREATE INDEX actions_agent_status_idx ON public.actions USING btree (agent_id, status);
CREATE INDEX actions_approved_by_idx ON public.actions USING btree (approved_by) WHERE (approved_by IS NOT NULL);
CREATE INDEX actions_completed_at_idx ON public.actions USING btree (agent_id, completed_at) WHERE (completed_at IS NOT NULL);
CREATE INDEX actions_correlation_id_idx ON public.actions USING btree (correlation_id) WHERE (correlation_id IS NOT NULL);
CREATE UNIQUE INDEX actions_request_idempotency_idx ON public.actions USING btree (agent_id, request_actor_type, request_actor_id, request_idempotency_key) WHERE (request_idempotency_key IS NOT NULL);
CREATE INDEX actions_status_awaiting_result_idx ON public.actions USING btree (status, awaiting_result_until) WHERE (awaiting_result_until IS NOT NULL);
CREATE INDEX agent_backup_manifests_agent_idx ON public.agent_backup_manifests USING btree (agent_id, created_at DESC);
CREATE INDEX agent_constitution_revisions_agent_idx ON public.agent_constitution_revisions USING btree (agent_id, created_at DESC);
CREATE INDEX agent_lifecycle_requests_agent_idx ON public.agent_lifecycle_requests USING btree (agent_id, status, requested_at DESC);
CREATE INDEX agent_maturity_evidence_agent_idx ON public.agent_maturity_evidence USING btree (agent_id, observed_at DESC);
CREATE INDEX agent_memberships_agent_idx ON public.agent_memberships USING btree (agent_id);
CREATE UNIQUE INDEX agent_memberships_one_active_owner_per_agent ON public.agent_memberships USING btree (agent_id) WHERE ((role = 'owner'::text) AND (revoked_at IS NULL));
CREATE INDEX agent_memberships_user_idx ON public.agent_memberships USING btree (user_id);
CREATE INDEX agent_restore_attempts_backup_idx ON public.agent_restore_attempts USING btree (backup_id, created_at DESC);
CREATE INDEX agent_tokens_hash_idx ON public.agent_tokens USING btree (token_hash) WHERE (revoked_at IS NULL);
CREATE INDEX agent_tokens_issuer_idx ON public.agent_tokens USING btree (issuer_agent_id);
CREATE INDEX agent_tokens_target_idx ON public.agent_tokens USING btree (target_agent_id) WHERE (target_agent_id IS NOT NULL);
CREATE INDEX artifact_references_agent_idx ON public.artifact_references USING btree (agent_id, created_at DESC);
CREATE INDEX artifact_references_pending_upload_idx ON public.artifact_references USING btree (upload_expires_at, created_at) WHERE (lifecycle_state = 'pending_upload'::text);
CREATE INDEX artifact_references_retention_idx ON public.artifact_references USING btree (expires_at, created_at) WHERE ((lifecycle_state = 'available'::text) AND (expires_at IS NOT NULL));
CREATE INDEX artifact_references_source_event_idx ON public.artifact_references USING btree (source_event_id) WHERE (source_event_id IS NOT NULL);
CREATE INDEX biometric_projections_person_idx ON public.biometric_projections USING btree (agent_id, person_id, modality, lifecycle_state);
CREATE INDEX devices_agent_heartbeat_idx ON public.devices USING btree (agent_id, last_heartbeat_at) WHERE (revoked_at IS NULL);
CREATE INDEX devices_current_space_idx ON public.devices USING btree (current_space_id) WHERE (current_space_id IS NOT NULL);
CREATE INDEX devices_location_label_idx ON public.devices USING btree (location_label) WHERE ((location_label IS NOT NULL) AND (revoked_at IS NULL));
CREATE INDEX events_session_idx ON public.events USING btree (session_id) WHERE (session_id IS NOT NULL);
CREATE INDEX events_space_time_idx ON public.events USING btree (space_id, created_at DESC);
CREATE INDEX faceprints_agent_person_idx ON public.faceprints USING btree (agent_id, person_id) WHERE (revoked_at IS NULL);
CREATE INDEX integration_accounts_agent_provider_idx ON public.integration_accounts USING btree (agent_id, provider, status, created_at DESC);
CREATE INDEX integration_messages_account_time_idx ON public.integration_messages USING btree (integration_account_id, created_at DESC);
CREATE INDEX integration_messages_action_idx ON public.integration_messages USING btree (action_id);
CREATE UNIQUE INDEX integration_messages_agent_dedupe_idx ON public.integration_messages USING btree (agent_id, dedupe_key);
CREATE INDEX integration_messages_agent_time_idx ON public.integration_messages USING btree (agent_id, created_at DESC);
CREATE INDEX integration_messages_thread_idx ON public.integration_messages USING btree (agent_id, provider, external_thread_id, created_at DESC);
CREATE INDEX locations_agent_idx ON public.locations USING btree (agent_id);
CREATE INDEX memories_agent_time_idx ON public.memories USING btree (agent_id, created_at DESC);
CREATE INDEX memories_lifecycle_idx ON public.memories USING btree (agent_id, lifecycle_state, created_at DESC);
CREATE INDEX memories_modality_idx ON public.memories USING btree (modality);
CREATE INDEX memories_source_event_idx ON public.memories USING btree (source_event_id) WHERE (source_event_id IS NOT NULL);
CREATE INDEX memories_subject_person_idx ON public.memories USING btree (subject_person_id) WHERE (subject_person_id IS NOT NULL);
CREATE INDEX memories_tags_gin_idx ON public.memories USING gin (tags);
CREATE INDEX memory_annotations_agent_idx ON public.memory_annotations USING btree (agent_id, created_at DESC);
CREATE INDEX memory_annotations_memory_idx ON public.memory_annotations USING btree (memory_id, created_at DESC);
CREATE INDEX memory_candidates_agent_state_idx ON public.memory_candidates USING btree (agent_id, lifecycle_state, created_at DESC);
CREATE INDEX memory_candidates_source_action_idx ON public.memory_candidates USING btree (source_action_id);
CREATE INDEX memory_candidates_source_event_idx ON public.memory_candidates USING btree (source_event_id);
CREATE INDEX memory_opinions_agent_idx ON public.memory_opinions USING btree (agent_id, created_at DESC);
CREATE INDEX memory_opinions_memory_idx ON public.memory_opinions USING btree (memory_id, created_at DESC);
CREATE UNIQUE INDEX memory_tombstones_memory_idx ON public.memory_tombstones USING btree (memory_id);
CREATE INDEX person_accounts_agent_idx ON public.person_accounts USING btree (agent_id);
CREATE INDEX personas_agent_idx ON public.personas USING btree (agent_id);
CREATE UNIQUE INDEX personas_one_default_idx ON public.personas USING btree (agent_id) WHERE (is_default AND (disabled_at IS NULL));
CREATE INDEX presence_assertions_agent_space_idx ON public.presence_assertions USING btree (agent_id, space_id, asserted_at DESC);
CREATE INDEX presence_space_idx ON public.presence USING btree (space_id);
CREATE INDEX recognition_decisions_agent_idx ON public.recognition_decisions USING btree (agent_id, decided_at DESC);
CREATE INDEX recognition_hypotheses_observation_idx ON public.recognition_hypotheses USING btree (recognition_observation_id);
CREATE INDEX recognition_no_matches_retention_idx ON public.recognition_no_matches USING btree (lifecycle_state, retention_until) WHERE (lifecycle_state = 'retained'::text);
CREATE INDEX recognition_observations_agent_idx ON public.recognition_observations USING btree (agent_id, created_at DESC);
CREATE INDEX recognition_worker_heartbeats_worker_idx ON public.recognition_worker_heartbeats USING btree (recognition_worker_id, observed_at DESC);
CREATE INDEX semantic_outbox_agent_state_idx ON public.semantic_outbox USING btree (agent_id, status, updated_at DESC);
CREATE INDEX semantic_outbox_dispatch_attempts_agent_idx ON public.semantic_outbox_dispatch_attempts USING btree (agent_id, claimed_at DESC);
CREATE UNIQUE INDEX semantic_outbox_dispatch_attempts_message_idx ON public.semantic_outbox_dispatch_attempts USING btree (queue_message_id) WHERE (queue_message_id IS NOT NULL);
CREATE INDEX semantic_outbox_dispatch_idx ON public.semantic_outbox USING btree (status, next_attempt_at, lease_expires_at, created_at) WHERE (status = ANY (ARRAY['pending'::text, 'failed'::text, 'dispatching'::text]));
CREATE INDEX semantic_outbox_reconciliations_outbox_idx ON public.semantic_outbox_reconciliations USING btree (semantic_outbox_id, reconciled_at DESC);
CREATE INDEX semantic_sync_status_agent_state_idx ON public.semantic_sync_status USING btree (agent_id, status, updated_at DESC);
CREATE INDEX sessions_agent_status_idx ON public.sessions USING btree (agent_id, status);
CREATE INDEX sessions_space_started_idx ON public.sessions USING btree (space_id, started_at DESC) WHERE (space_id IS NOT NULL);
CREATE INDEX spaces_livekit_room_mode_idx ON public.spaces USING btree (livekit_room_mode);
CREATE INDEX spaces_location_idx ON public.spaces USING btree (location_id) WHERE (location_id IS NOT NULL);
CREATE INDEX voiceprints_agent_person_idx ON public.voiceprints USING btree (agent_id, person_id) WHERE (revoked_at IS NULL);

COMMENT ON TABLE public.agent_memberships IS 'Primary table for user-agent membership.';
COMMENT ON TABLE public.agent_tokens IS 'Bearer tokens for agent-to-agent authentication and delegation';
COMMENT ON COLUMN public.agent_tokens.issuer_agent_id IS 'The agent that created and owns this token';
COMMENT ON COLUMN public.agent_tokens.target_agent_id IS 'If set, only this agent can use the token';
COMMENT ON COLUMN public.agent_tokens.scopes IS 'JSON array of permission scopes granted to token holder';
COMMENT ON COLUMN public.agent_tokens.allowed_spaces IS 'If set, token only valid for these space IDs';
COMMENT ON COLUMN public.devices.metadata IS 'Freeform device metadata: platform, version, labels, etc.';
COMMENT ON COLUMN public.devices.last_hello_at IS 'Last WebSocket hello message timestamp';
COMMENT ON COLUMN public.devices.last_heartbeat_at IS 'Last REST heartbeat timestamp';
COMMENT ON COLUMN public.devices.location_label IS 'Human-readable location label (e.g., Kitchen, Lab Bench 3)';
COMMENT ON COLUMN public.devices.location_coords IS 'Optional geographic coordinates as JSONB: {"lat": number, "lng": number}';
COMMENT ON COLUMN public.devices.provisioned_at IS 'Timestamp when the device was provisioned via the wizard';
COMMENT ON COLUMN public.devices.provisioned_by IS 'User ID of the person who provisioned the device';

CREATE TABLE public.dot_event_subscriptions (
    subscription_id text PRIMARY KEY,
    agent_id uuid NOT NULL,
    principal_euid text NOT NULL,
    actor_euid text NOT NULL,
    oauth_issuer text NOT NULL,
    oauth_subject text NOT NULL,
    scene_euid text NOT NULL,
    session_euid text NOT NULL,
    callback_url text NOT NULL,
    signing_secret text NOT NULL,
    previous_secret text,
    previous_until timestamptz,
    verified_at timestamptz NOT NULL,
    started_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    stopped_at timestamptz
);

CREATE INDEX dot_event_subscriptions_scope_idx ON public.dot_event_subscriptions
    (agent_id, principal_euid, scene_euid) WHERE stopped_at IS NULL;

CREATE TABLE public.dot_event_deliveries (
    subscription_id text NOT NULL REFERENCES public.dot_event_subscriptions(subscription_id),
    event_id uuid NOT NULL,
    source_command_id uuid NOT NULL,
    handoff_euid text NOT NULL,
    occurred_at timestamptz NOT NULL,
    state text NOT NULL DEFAULT 'pending' CHECK (state IN ('pending', 'accepted', 'rejected', 'inactive')),
    last_http_status integer,
    last_error text,
    last_attempt_at timestamptz,
    PRIMARY KEY (subscription_id, event_id)
);

CREATE INDEX dot_event_deliveries_source_idx ON public.dot_event_deliveries (source_command_id)
    WHERE state = 'pending';

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
