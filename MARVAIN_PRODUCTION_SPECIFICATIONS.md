1. Purpose and Scope
1.1 Purpose

Marvain SHALL be an authoritative personal agent hub deployed on AWS that coordinates identity, memory, planning, action execution, audit, and realtime interaction for one or more intelligent agents operating on behalf of a human principal.

Marvain SHALL function both:

on behalf of a human user, and

on behalf of itself, including the ability to manage, supervise, and delegate to other agents.

1.2 Core Capabilities

Marvain MUST:

Persist identity, sessions, memory, actions, and audit state in Aurora PostgreSQL using the RDS Data API.

Support authenticated satellites (devices and other agents) that send events and receive commands over WebSocket.

Run an asynchronous planner that converts events and transcripts into memories and proposed or approved actions using the OpenAI Responses API.

Optionally operate a realtime media plane (LiveKit + OpenAI Realtime) via a containerized worker.

Maintain a tamper-evident, append-only audit log using S3 Object Lock.

Provide a repo-local CLI (./bin/marvain) as the primary developer and operator interface.

2. Goals and Non-Goals
2.1 Goals (MUST HAVES)
2.1.1 Authoritative Hub

Marvain SHALL be the single source of truth for:

agents

spaces

devices

users

memberships

events

memories

actions

audit state

2.1.2 Satellites

Multiple devices and agents SHALL be able to:

authenticate,

stream events,

receive acknowledgements and commands,

maintain presence via WebSocket connections.

2.1.3 Autonomy

Event and transcript ingestion SHALL trigger asynchronous planning without blocking ingestion.

2.1.4 Memory

Marvain SHALL store:

episodic memory (contextual, time-bound),

semantic memory (generalized, cross-context),

optional vector embeddings using pgvector.

2.1.5 Action Execution

Marvain SHALL:

record actions with required permission scopes,

support approval workflows,

execute approved actions via a tool runner.

2.1.6 Audit

All high-impact operations SHALL be recorded in an append-only audit log with cryptographic chaining.

2.1.7 Agent-of-Agents Management

Marvain MUST be capable of:

registering and managing other agents (software agents, LLM agents, service agents),

delegating tasks to those agents,

receiving results and events from them,

auditing all inter-agent delegation and execution.

Other agents SHALL be treated as first-class principals, comparable to devices, but with explicit agent-to-agent scopes and constraints.

2.2 Non-Goals (Explicitly Out of Scope for Initial Production)

A fully general, pluggable tool ecosystem.

A complete realtime voice loop fully orchestrated inside AWS.

A rich or opinionated frontend UI.

3. System Architecture Requirements
3.1 AWS Resources (MUST EXIST)

Marvain SHALL be deployable via AWS SAM and include:

API Gateway REST → Lambda (FastAPI hub)

API Gateway WebSocket → Lambda handlers

Aurora PostgreSQL Serverless v2 (with Data API)

SQS transcript queue (planner input)

SQS action queue (tool runner input)

S3 artifact bucket (non-audit)

S3 audit bucket with Object Lock (default ≥10 years)

DynamoDB table for WebSocket connection state

Amazon Cognito (hosted UI) for human authentication

3.2 Core Runtime Components
3.2.1 Hub API

MUST expose REST endpoints for:

agent and space management,

event ingestion,

memory and action inspection,

approval workflows,

LiveKit token minting.

MUST support both Lambda deployment and local development mode.

3.2.2 WebSocket Handler

MUST authenticate:

human users via Cognito access tokens,

devices via device tokens,

agents via agent credentials.

MUST persist connection metadata in DynamoDB.

3.2.3 Planner

MUST consume events from SQS.

MUST perform recall, planning, and write-back deterministically.

MUST be idempotent and failure-aware.

3.2.4 Tool Runner

MUST consume approved actions from SQS.

MUST execute at least one end-to-end “toy” action in production.

MUST record results and audit entries.

4. Data Model Requirements (PostgreSQL)
4.1 Required Tables

The following entities MUST exist:

agents

spaces

devices

people

consent_grants

presence

events

memories

actions

audit_state

users

agent_memberships

4.2 Constraints and Invariants

PostgreSQL extensions pgcrypto and vector MUST be enabled.

Schema initialization MUST be idempotent.

At most one active owner role SHALL exist per agent.

Vector columns MUST NOT be returned by default queries.

5. Authentication and Authorization
5.1 Principal Types

Marvain SHALL support:

Human users

Devices (satellites)

Agents (first-class non-human principals)

5.2 Authorization Rules

Users SHALL only operate on agents where they have active membership.

Devices SHALL only act within declared scopes.

Agents SHALL only act within delegated scopes and agent-to-agent contracts.

WebSocket connections MUST record:

principal type,

identifiers,

allowed scopes,

associated agents.

5.3 WebSocket API (MUST IMPLEMENT)

The WebSocket protocol MUST support:

hello

send_event / push_transcript

subscribe_presence

list_actions

approve_action

reject_action

ping / heartbeat

6. Event Ingestion and Planning
6.1 Event Requirements

Events MUST include agent_id, space_id, type, and payload.

Transcript events MUST include text or transcript.

6.2 Planner Output Contract

Planner output MUST be strict JSON conforming to a validated schema:

episodic memories

semantic memories

actions with approval metadata

6.3 Planner Hardening (MUST)

Strict schema validation

Length and count bounds

Deterministic idempotency

Rate limiting and retry backoff

Poison message handling

Enforced PII and privacy redaction

7. Action Lifecycle
7.1 Required States

Actions MUST support:

proposed

approved

rejected

executing

executed

failed

canceled

7.2 Required Capabilities

Action listing and filtering

Role-based approval and rejection

Scope verification before execution

Execution result persistence

Mandatory audit logging

8. Audit and Compliance
8.1 Audit Guarantees

Audit logs MUST be append-only.

Logs MUST be immutable via S3 Object Lock.

Hash chaining MUST be enforced and persisted.

8.2 Auditable Operations

At minimum:

planning outputs

action approvals and executions

membership changes

device and agent registration/revocation

bootstrap and schema initialization

9. Realtime and LiveKit Integration
9.1 Requirements

Hub MUST mint LiveKit join tokens.

Presence MUST map users, agents, and devices to spaces.

Realtime transcripts MUST be persisted as events.

Realtime transcripts MUST flow through the planner.

10. Developer Experience
10.1 CLI Contract (MUST SUPPORT)

doctor

config init|show|validate|path

build

deploy

teardown

monitor outputs|status

init db

bootstrap

logs

gui start|stop|status|restart|logs

10.2 Environment

Conda environment is primary.

Virtualenv escape hatch MUST exist.

10.3 Testing

pytest -q MUST pass in a clean environment.

Tests MUST NOT depend on wrapper scripts.

Import paths MUST be correct via packaging or pytest configuration.

11. Known Deficiencies to Be Eliminated

The following are NOT acceptable in production:

Failing test collection

Runtime NameErrors

Unvalidated planner output

Duplicate writes from retried events

Stubbed WebSocket APIs with no semantics

12. Acceptance Criteria

Marvain SHALL be considered production-ready only if:

All CLI commands function as specified.

Database initialization is repeatable and safe.

Planner is deterministic, validated, and idempotent.

At least one action executes end-to-end with audit.

Agent-to-agent delegation is supported.

pytest -q passes with no environment hacks.

End of Specification