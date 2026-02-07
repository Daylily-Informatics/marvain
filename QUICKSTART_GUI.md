# QUICKSTART — GUI-Driven Workflow (Zero to Running Agent)

This guide walks you through the complete GUI-driven workflow for Marvain: from a fresh deployment to a running voice agent you can talk to in your browser.

## Prerequisites

| Requirement | Why | Check |
|-------------|-----|-------|
| AWS account + named profile | Hosts the Hub (Aurora, Lambda, S3, Cognito) | `aws sts get-caller-identity --profile <your-profile>` |
| Conda (Miniconda/Mambaforge) | Python 3.11 environment manager | `conda --version` |
| AWS SAM CLI | Builds and deploys the CloudFormation stack | `sam --version` |
| Docker | SAM uses it to build Lambda layers | `docker info` |
| Git | Clone the repo | `git --version` |
| LiveKit Cloud account | WebRTC media plane (free tier available) | [livekit.io](https://livekit.io) |
| OpenAI API key | Powers the voice agent (Realtime API) | [platform.openai.com](https://platform.openai.com) |

## 1) Clone and Set Up the Environment

```sh
git clone git@github.com:Daylily-Informatics/marvain.git
cd marvain

# Create the Conda environment (one-time)
conda env create -f config/marvain_conda.yaml

# Activate environment + put CLI on PATH
. ./marvain_activate

# Verify toolchain
marvain doctor
```

## 2) Configure

```sh
# Initialize config (creates ~/.config/marvain/marvain-config.yaml)
marvain config init \
  --profile <your-aws-profile> \
  --region <your-aws-region> \
  --env dev
```

> **Treat this config as secret** once you run `bootstrap` — it will contain a device token.

## 3) Build and Deploy

```sh
# Build Lambda functions + layers
marvain build

# Deploy to AWS (interactive prompts)
marvain deploy

# — OR non-interactive: —
marvain deploy --no-guided
```

SAM will create: Aurora Serverless v2, Lambda functions, API Gateway (REST + WebSocket), S3 buckets (artifact + audit with Object Lock), Cognito User Pool, SQS queues, and Secrets Manager entries.

```sh
# Write stack outputs (API URLs, ARNs) into your local config
marvain monitor outputs --write-config
```

## 4) Initialize the Database

```sh
marvain init db
```

This runs the full SQL schema: pgvector extension, all tables (agents, spaces, devices, events, memories, actions, people, consent, audit), indexes, and triggers.

## 5) Populate Secrets

The SAM stack creates placeholder Secrets Manager entries. You must fill in the real values:

```sh
# LiveKit credentials (from your LiveKit Cloud project settings)
aws secretsmanager put-secret-value \
  --profile <your-aws-profile> --region <your-aws-region> \
  --secret-id "<stack-name>/livekit" \
  --secret-string '{"api_key":"<LIVEKIT_API_KEY>","api_secret":"<LIVEKIT_API_SECRET>"}'

# OpenAI API key
aws secretsmanager put-secret-value \
  --profile <your-aws-profile> --region <your-aws-region> \
  --secret-id "<stack-name>/openai" \
  --secret-string '{"api_key":"<OPENAI_API_KEY>"}'
```

## 6) Create a Cognito User

```sh
marvain cognito create-user <your-email> --password '<YourPassword123!>'
```

This creates a user in the Cognito User Pool and sets a permanent password. You'll use this to log in to the GUI.

## 7) Bootstrap Your First Agent

```sh
marvain bootstrap --agent-name <agent-name> --space-name <space-name>
```

This creates:
- **Agent** — your AI agent identity
- **Space** — a conversation room (linked to a LiveKit room)
- **Device** — this machine, with a device token for API auth

The device token is saved to your config file automatically.

## 8) Start the GUI

```sh
# Start the local GUI server (runs in background)
marvain gui start --no-https

# Check it's running
marvain gui status
```

Open **http://localhost:8084** in your browser. You'll be redirected to Cognito for login.

### GUI Pages at a Glance

| Page | URL | What It Does |
|------|-----|-------------|
| Dashboard | `/` | Overview: agent count, device count, recent events |
| Agents | `/agents` | List agents; create new ones; click for detail |
| Agent Detail | `/agents/<id>` | Stats, worker controls (launch/stop/restart), delete |
| Spaces | `/spaces` | List spaces; create new conversation rooms |
| Devices | `/devices` | List devices; register new ones |
| Device Detail | `/devices/<id>` | Device info, launch satellite, agent worker controls |
| People | `/people` | Identity graph; create people, manage consent |
| Events | `/events` | Browse transcript events and other ingested data |
| Memories | `/memories` | Browse stored memories (episodic/semantic/procedural) |
| Actions | `/actions` | View proposed actions; approve/reject them |
| Artifacts | `/artifacts` | Upload/browse files stored in S3 |
| Audit | `/audit` | Tamper-evident audit log with hash-chain verification |
| Profile | `/profile` | Your user info, agent memberships, S3 bucket status |
| LiveKit Test | `/livekit-test` | Voice interaction test page (WebRTC) |

## 9) Launch the Agent Worker

The agent worker is a LiveKit voice agent powered by OpenAI's Realtime API. You can launch it from the **GUI** or the **CLI**.

### Option A: GUI (Device Detail Page)

1. Navigate to **Devices** → click your device
2. In the **Agent Worker** card, click **Launch**
3. The GUI calls the backend, which spawns the worker process with credentials from AWS Secrets Manager
4. Status badge updates to **running** with the worker PID

### Option B: CLI

```sh
marvain agent start
```

### Verify the Worker Is Running

```sh
marvain agent status
# Shows: running, PID, log file path

marvain agent logs --follow
# Tail the worker log in real-time
```

You should see output like:
```
INFO  worker | Registered agent worker: AW_xxxxxxxx
INFO  worker | Waiting for room dispatch...
```

## 10) Talk to Your Agent

1. Navigate to **http://localhost:8084/livekit-test**
2. Select your **space** from the dropdown
3. Click **Join Room**
4. Grant microphone permission when prompted
5. Speak — the agent will respond via voice (OpenAI Realtime API)

What happens behind the scenes:

```
┌─────────┐     WebRTC      ┌──────────┐    Realtime API   ┌────────┐
│ Browser  │ ◄────────────► │  LiveKit  │ ◄──────────────► │ OpenAI │
│ (mic/spk)│                │  Cloud    │                  │        │
└─────────┘                 └──────────┘                   └────────┘
                                 │
                           Agent Worker
                                 │
                    ┌────────────┴────────────┐
                    │ POST /v1/events          │
                    │ POST /v1/memories        │
                    ▼                          ▼
              ┌──────────┐              ┌──────────┐
              │  Aurora   │              │   SQS    │
              │ (events,  │              │ (planner │
              │  memories)│              │  queue)  │
              └──────────┘              └──────────┘
```

## 11) Monitor Activity

### Events Page (`/events`)

After a conversation, navigate to **Events**. You'll see `transcript_chunk` events for each utterance (both user and agent). Each event shows:
- Timestamp
- Type (`transcript_chunk`)
- Payload (text, role, input modality)

### Memories Page (`/memories`)

The Planner Lambda processes transcript events from SQS and creates memories. Navigate to **Memories** to see:
- **Episodic** memories (conversation summaries)
- **Semantic** memories (extracted facts)
- Tier, content, and creation timestamp

### Actions Page (`/actions`)

If the planner proposes actions (tool calls), they appear here for human-in-the-loop approval. You can:
- **Approve** — action is sent to the Tool Runner queue
- **Reject** — action is discarded with optional reason

### Audit Page (`/audit`)

Every significant operation is logged to the audit trail (S3 Object Lock). The audit page shows:
- Chronological log entries
- Hash-chain verification button (validates tamper-evidence)

## GUI-Active vs. Headless Mode

| Mode | Agent Worker | GUI | Use Case |
|------|-------------|-----|----------|
| **GUI-active** | Launched from GUI or CLI on your laptop | Running at localhost:8084 | Development, testing, interactive use |
| **Headless** | Started via CLI or systemd on a remote device | Not needed (API-only) | Raspberry Pi, always-on device, server |

### Headless Setup (Remote Device / Raspberry Pi)

On the remote device:

```sh
# 1) Clone the repo and set up Conda
git clone git@github.com:Daylily-Informatics/marvain.git
cd marvain
conda env create -f config/marvain_conda.yaml
. ./marvain_activate

# 2) Copy your config from your laptop
scp laptop:~/.config/marvain/marvain-config.yaml \
    ~/.config/marvain/marvain-config.yaml

# 3) Register this device (from the GUI on your laptop, or CLI)
marvain hub register-device --name "pi-kitchen" --agent-id <agent-id>

# 4) Start the agent worker in headless mode
marvain agent start
```

For persistent operation, create a systemd service:

```ini
# /etc/systemd/system/marvain-agent.service
[Unit]
Description=Marvain Agent Worker
After=network.target

[Service]
Type=simple
User=pi
WorkingDirectory=/home/pi/marvain
ExecStart=/bin/sh -c '. ./marvain_activate && marvain agent start --foreground'
Restart=on-failure
RestartSec=10

[Install]
WantedBy=multi-user.target
```

```sh
sudo systemctl enable --now marvain-agent.service
```

## Agent Worker Lifecycle Commands

| Command | Description |
|---------|-------------|
| `marvain agent start` | Start agent worker (background) |
| `marvain agent start --foreground` | Start in foreground (blocking) |
| `marvain agent stop` | Graceful stop (SIGTERM) |
| `marvain agent stop --force` | Force kill (SIGKILL) |
| `marvain agent restart` | Stop then start |
| `marvain agent rebuild` | Nuclear reset: stop, clear LiveKit rooms, restart |
| `marvain agent status` | Show running state, PID |
| `marvain agent logs` | Show recent logs |
| `marvain agent logs --follow` | Tail logs in real-time |

## GUI Lifecycle Commands

| Command | Description |
|---------|-------------|
| `marvain gui start` | Start GUI server (background) |
| `marvain gui start --foreground` | Start in foreground |
| `marvain gui start --no-https` | Start without TLS |
| `marvain gui start --port 9000` | Custom port |
| `marvain gui stop` | Stop GUI server |
| `marvain gui restart` | Stop then start |
| `marvain gui status` | Show running state, PID, port |
| `marvain gui logs` | Show recent logs |
| `marvain gui logs --follow` | Tail logs |

## Troubleshooting

### No memories appearing after conversation

**Symptom**: Events show up in `/events` but `/memories` stays empty.

**Likely causes**:
1. **Planner Lambda not processing**: Check CloudWatch logs for the planner function
   ```sh
   marvain logs --since 10m
   ```
2. **Missing OpenAI key**: The planner needs OpenAI to generate embeddings and summaries
   ```sh
   aws secretsmanager get-secret-value \
     --profile <profile> --region <region> \
     --secret-id "<stack-name>/openai" \
     --query SecretString --output text
   ```
3. **SQS queue empty/stuck**: Check the TranscriptQueue in AWS Console

### Agent not joining the room

**Symptom**: You join the LiveKit test page but nobody responds.

**Check**:
1. Is the agent worker running? `marvain agent status`
2. Check agent logs: `marvain agent logs --follow`
3. Verify LiveKit credentials are correct:
   ```sh
   aws secretsmanager get-secret-value \
     --profile <profile> --region <region> \
     --secret-id "<stack-name>/livekit" \
     --query SecretString --output text
   ```
4. Verify the worker registered with LiveKit (look for `Registered agent worker` in logs)

### Device shows as offline

**Symptom**: Device detail page shows device as offline.

**Check**:
1. Is the device token valid? (not revoked)
2. Is the agent worker running on that device?
3. Network connectivity to the Hub REST API:
   ```sh
   curl -s -o /dev/null -w "%{http_code}" \
     "$(marvain monitor outputs | grep HubRestApiBase | awk '{print $2}')/v1/agents"
   ```

### HTTP 502 from Hub API

**Symptom**: API calls return 502 Bad Gateway.

**Cause**: Lambda function is crashing on startup (import error or missing dependency).

**Fix**:
```sh
# Check Lambda logs
aws logs tail "/aws/lambda/<stack-name>-HubApiFunction-*" \
  --since 5m --region <region> --profile <profile>

# Common fix: redeploy
marvain build && marvain deploy --no-guided
```

### Consent update fails (red error dialog)

**Cause**: Datetime serialization issue with RDS Data API.

**Fix**: Ensure you're running the latest code. This was fixed in the `feature/gui-fixes-5-issues` branch.

## Complete CLI Reference

```sh
marvain --help                    # Top-level help
marvain doctor                    # Check toolchain
marvain config init ...           # Create config
marvain build                     # SAM build
marvain deploy                    # SAM deploy
marvain init db                   # Create DB schema
marvain bootstrap ...             # Create agent/space/device
marvain monitor outputs           # Show stack outputs
marvain monitor status            # Show stack status
marvain gui start|stop|restart|status|logs
marvain agent start|stop|restart|rebuild|status|logs
marvain cognito create-user|set-password|list-users|get-user|delete-user
marvain members invite|list|update|revoke|claim-owner
marvain hub register-device ...   # Register a new device
marvain teardown --yes --wait     # Delete CloudFormation stack
marvain info                      # Show config + env info
```
