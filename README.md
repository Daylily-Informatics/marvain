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

## Delete everything (reset) before reinstall/redeploy

If you want a true “start over”, follow `QUICKSTART.md` (full workflow). The commands below are the same idea, but inlined here for convenience.

> Safety: the commands below can delete AWS resources and local state.

### A) AWS: delete the CloudFormation stack

1) (Recommended) capture the bucket names **before** teardown:

```sh
. ./marvain_activate
./bin/marvain --profile <aws-profile> --region <aws-region> monitor outputs
# optional: write outputs into your config for later reference
./bin/marvain --profile <aws-profile> --region <aws-region> monitor outputs --write-config
```

2) Tear down the stack:

```sh
./bin/marvain --profile <aws-profile> --region <aws-region> teardown --yes --wait
```

### B) AWS: best-effort delete retained S3 buckets

In `template.yaml`, both buckets are configured with `DeletionPolicy: Retain`:

- `ArtifactBucket` (Retain)
- `AuditBucket` (Retain + **S3 Object Lock**, default 10-year governance retention)

That means stack deletion will **not** delete them.

If you captured `ArtifactBucketName` / `AuditBucketName`, try:

```sh
# Replace these with values printed by: ./bin/marvain ... monitor outputs
ARTIFACT_BUCKET="..."
AUDIT_BUCKET="..."

# Artifact bucket: usually deletable once emptied
aws s3 rb "s3://${ARTIFACT_BUCKET}" --force

# Audit bucket: may fail if it contains Object-Lock-protected objects
aws s3 rb "s3://${AUDIT_BUCKET}" --force
```

#### If you forgot to run `monitor outputs`

If the stack still exists, you can often recover the bucket names from CloudFormation outputs:

```sh
STACK_NAME="marvain-<user>-<env>"  # e.g. marvain-major-dev (from your config)
aws cloudformation describe-stacks \
  --stack-name "${STACK_NAME}" \
  --query 'Stacks[0].Outputs[?OutputKey==`ArtifactBucketName` || OutputKey==`AuditBucketName`].[OutputKey,OutputValue]' \
  --output table
```

If the stack is already deleted, you have to fall back to heuristics (less reliable). A common one is that CloudFormation-generated bucket names include the stack name, so you can list buckets and filter by substring:

```sh
STACK_NAME="marvain-<user>-<env>"  # must match the stack name you deployed
aws s3api list-buckets --query 'Buckets[].Name' --output text \
  | tr '\t' '\n' \
  | grep "${STACK_NAME}" || true
```

If you get multiple candidates, you can identify the **audit** bucket by checking whether Object Lock is enabled (it will typically succeed for the audit bucket and fail for the artifact bucket):

```sh
for b in $(aws s3api list-buckets --query 'Buckets[].Name' --output text | tr '\t' '\n' | grep "${STACK_NAME}" || true); do
  if aws s3api get-bucket-object-lock-configuration --bucket "$b" >/dev/null 2>&1; then
    echo "${b}  (ObjectLock: enabled)"
  else
    echo "${b}  (ObjectLock: not enabled / unknown)"
  fi
done
```

If `AuditBucket` deletion fails due to Object Lock retention, the practical “reset” approach is:

- leave the audit bucket alone, and/or
- deploy a new stack name (fresh resources) instead of trying to hard-delete locked audit history.

### C) Local: delete config, build artifacts, and the Conda env

1) Remove local config (this deletes your saved device token):

```sh
# OPTIONAL: backup first
cp -v "${XDG_CONFIG_HOME:-$HOME/.config}/marvain/marvain-config.yaml" \
  "${XDG_CONFIG_HOME:-$HOME/.config}/marvain/marvain-config.yaml.bak" 2>/dev/null || true

# Delete config (canonical + legacy fallbacks)
rm -f "${XDG_CONFIG_HOME:-$HOME/.config}/marvain/marvain-config.yaml" \
      "${XDG_CONFIG_HOME:-$HOME/.config}/marvain/marvain.yaml" \
      "${XDG_CONFIG_HOME:-$HOME/.config}/marvain/config.yaml" \
      "$HOME/.marvain/config.yaml"
```

2) Remove repo build artifacts:

```sh
rm -rf .aws-sam
```

3) Remove the Conda environment:

```sh
conda env remove -n marvain
```

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

- `./bin/marvain deploy` defaults to **guided** (interactive) SAM deploy.
- For a fully non-interactive deploy (no stdin prompts), use:
  - `./bin/marvain deploy --no-guided`
- `deploy` runs a `sam build --clean` first so Lambda functions include vendored dependencies.

Notes:

- `marvain config init` writes to `${XDG_CONFIG_HOME:-~/.config}/marvain/marvain-config.yaml` by default.
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

### 5) Start the Local GUI

The GUI runs locally on your machine and connects to deployed AWS resources (Aurora, Cognito, S3).

```bash
# Write stack outputs to marvain-config.yaml
./bin/marvain monitor outputs --write-config

# Start the local GUI server (background mode, default)
./bin/marvain gui start

# Or just `marvain gui` (defaults to start)
./bin/marvain gui
```

Visit `http://localhost:8084/` — you'll be redirected to Cognito for login.

#### GUI Lifecycle Commands

| Command | Description |
|---------|-------------|
| `marvain gui start` | Start GUI server (background by default) |
| `marvain gui stop` | Stop the running GUI server |
| `marvain gui restart` | Stop then start the GUI server |
| `marvain gui status` | Show whether GUI is running, PID, port |
| `marvain gui logs` | Show/tail GUI server logs |

**Options:**

```bash
# Start in foreground (blocking, Ctrl+C to stop)
./bin/marvain gui start --foreground

# Use different host/port
./bin/marvain gui start --host 0.0.0.0 --port 8080

# Disable auto-reload
./bin/marvain gui start --no-reload

# Force kill (SIGKILL instead of SIGTERM)
./bin/marvain gui stop --force

# Follow logs in real-time
./bin/marvain gui logs --follow

# Show last 100 lines of logs
./bin/marvain gui logs --lines 100
```

**Files:**
- PID file: `.marvain-gui.pid` (in repo root)
- Log file: `.marvain-gui.log` (in repo root)

## Run the realtime agent worker (local)

The agent worker is a fully functional LiveKit voice agent that connects to OpenAI's
Realtime API, ingests transcripts to the Hub, and hydrates conversation context
(recent events + recalled memories) on session start.

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
  
## AND

- I'd like marvain to be able to manage other agents on my and its behalf. 
