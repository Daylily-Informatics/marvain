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

## Environment (Conda; primary)

This repo uses a **Conda** env named `marvain` (Python **3.11**, matching the Lambda runtime in `template.yaml`).

```bash
conda env create -f config/marvain_conda.yaml
. ./marvain_activate
marvain doctor
```

Escape hatch (not recommended): set `MARVAIN_ALLOW_VENV=1` to bypass Conda checks.

## Deploy (AWS)

Prereqs:

- Conda (Miniconda/Mambaforge)
- AWS credentials configured (profile/region)
- SAM CLI
- Docker

### 1) Build

```bash
./bin/marvain build
./bin/marvain build --dry-run
```

### 2) Deploy (guided)

```bash
./bin/marvain config init --profile <aws-profile> --region <aws-region> --env dev
./bin/marvain deploy
./bin/marvain deploy --dry-run
```

Notes:

- `marvain config init` writes to `${XDG_CONFIG_HOME:-~/.config}/marvain/marvain.yaml` by default.
- Treat that config as **secret** once you run `marvain bootstrap` (it will store a device token).
- If you choose to write a repo-local config (e.g. `--write marvain.yaml`), it is gitignored.

### 3) Initialize the database schema (pgvector + tables)

```bash
./bin/marvain init db
```

### 4) Bootstrap your first agent/space/device

```bash
./bin/marvain bootstrap --agent-name Forge --space-name home
./bin/marvain bootstrap --dry-run --agent-name Forge --space-name home
```

### 5) Run the local GUI (legacy)

```bash
./bin/marvain gui --host 127.0.0.1 --port 8000 --reload
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
