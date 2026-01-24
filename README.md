# Agent Hub (AWS SAM) — Multimodal Personal Agent Hub + Satellites

This repository is a **concrete starter** for a "rank‑4+" multimodal personal agent hub:

- **Authoritative Hub** (single source of truth): identity graph, memory tiers, consent/policy, presence, sessions
- **Satellites** (devices / awareness bubbles): authenticate as unique devices, send events, receive commands
- **Autonomy**: scheduled ticks + background planner
- **Tool execution**: permission-scoped, auditable
- **Tamper-evident audit**: append-only objects in S3 Object Lock (WORM)

AI components (not AWS-specific):

- **OpenAI Realtime API**: low-latency speech-to-speech + multimodal I/O
- **OpenAI Responses API**: deliberative planner + tool calling
- Optional: **OpenAI Agents SDK** tracing

Realtime media plane:

- Designed to pair with **LiveKit** (Cloud first or self-host later). The Hub provides the sideband control channel and persistent state.

## Repo layout

- `template.yaml` — SAM/CloudFormation stack (Hub REST API, WebSocket API, Aurora Postgres Serverless v2 + Data API, SQS, S3, IAM)
- `layers/shared` — shared python library (RDS Data API, auth, policy, audit)
- `functions/hub_api` — FastAPI on Lambda (REST)
- `functions/ws_*` — WebSocket handlers (connect/disconnect/message)
- `functions/planner` — consumes transcript events, calls OpenAI Responses, writes memories + proposed actions
- `functions/tool_runner` — executes approved actions (stub)
- `apps/agent_worker` — container skeleton for LiveKit Agent + OpenAI Realtime
- `sql/` — DB schema
- `scripts/` — helper scripts (DB init, backup/export)

## Deploy (AWS)

Prereqs:

- AWS CLI configured
- SAM CLI
- Docker

### 1) Build

```bash
sam build
```

### 2) Deploy (guided)

```bash
sam deploy --guided
```

### 3) Initialize the database schema (pgvector + tables)

```bash
./scripts/db_init.sh --stack <stack-name> --region <region>
```

### 4) Bootstrap your first agent/space/device

```bash
curl -sS -X POST "<API_BASE>/v1/admin/bootstrap" \
  -H "X-Admin-Key: <admin-key>" \
  -H "Content-Type: application/json" \
  -d '{"agent_name":"Forge","default_space_name":"home"}'
```

## Run the realtime agent worker (local)

This repo does not ship a full satellite app yet; it ships a worker skeleton.

```bash
cd apps/agent_worker
export LIVEKIT_URL=...
export LIVEKIT_API_KEY=...
export LIVEKIT_API_SECRET=...
export OPENAI_API_KEY=...
export HUB_API_BASE=...
python -m worker
```

## Notes

- **Privacy mode** is enforced at the Hub: when ON, events are accepted but not persisted or queued.
- Device auth uses opaque device tokens (hash stored server-side). Swap to Cognito/IoT later if desired.
- Audit is written to an S3 Object Lock bucket with a hash chain (verify offline).
