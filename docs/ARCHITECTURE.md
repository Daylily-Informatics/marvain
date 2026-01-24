# Architecture (Rank-4+)

This repo implements a "hub + satellites" architecture by separating concerns into planes. The Hub owns **durable truth** (identity, memory, policy, audit). Realtime media is handled by an SFU (LiveKit recommended).

## Planes

### 1) Media plane (realtime A/V)

- **WebRTC SFU** (recommended: LiveKit) handles multiparty audio/video and device routing.
- Each *space* corresponds to a LiveKit room.
- Satellites publish tracks (mic/cam) and subscribe to the agent track(s).

This plane should not own identity or memory.

### 2) Control plane (sideband)

- Hub provides:
  - **REST API** (FastAPI on Lambda) for CRUD: devices, people, consent, spaces, memory inspection.
  - **WebSocket API** (API Gateway WebSocket) for push: presence updates, action approvals, agent->satellite commands.

### 3) Cognition plane

- **Realtime loop** (agent worker):
  - joins LiveKit rooms
  - uses OpenAI Realtime for low-latency speech (turn-taking, barge-in)
  - emits structured events to the Hub

- **Deliberative loop** (planner):
  - consumes transcript events (SQS)
  - calls OpenAI Responses for planning/tool proposals
  - writes memories and proposed actions

### 4) State plane (authoritative truth)

- **Aurora PostgreSQL Serverless v2** + **RDS Data API**
- pgvector extension is enabled (for embedding-based recall)
- All durable data is keyed by `agent_id`.

### 5) Execution plane

- Actions are never executed directly by the LLM.
- `tool_runner` consumes SQS and executes permission-scoped tools.
- Every action is logged to the audit log.

### 6) Observability and audit

- CloudWatch Logs for services.
- Tamper-evident audit: S3 Object Lock bucket + hash chaining.

## Event flow (speech)

1) Satellite captures speech and publishes audio into a LiveKit room.
2) Agent worker receives audio, uses OpenAI Realtime, and produces transcripts/semantic events.
3) Worker posts `transcript_chunk` events to Hub `/v1/events`.
4) Hub writes event (unless privacy mode) and pushes event reference into `TranscriptQueue`.
5) Planner consumes queue, calls OpenAI Responses, produces:
   - episodic memory updates
   - semantic memory updates
   - proposed actions
6) Tool runner consumes `ActionQueue` for approved actions.

## Privacy/consent enforcement

- **Space privacy mode** is checked at the Hub before persisting events or enqueuing them.
- Consent gates (voice/face/recording storage) are enforced in code (not in prompts).

## "Cloud hub lost" recovery

- Durable truth is in:
  - Aurora snapshots / exports
  - S3 artifacts
  - S3 Object Lock audit bucket
- Compute is disposable:
  - redeploy SAM stack
  - restore DB snapshot
  - satellites reconnect

