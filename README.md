# marvain — Whaddya-Want Rank‑4 Agent Skeleton

This repository is a **reference implementation** of a Rank‑4 agent skeleton:
- **Broker Lambda** (`POST /agent`) for conversations
- **Heartbeat Lambda** (EventBridge `rate(5 minutes)`) for background work
- **Unified DynamoDB state + memory store**
- **Shared Lambda layer** (`agent_core` + deps) + **Config layer** (prompts)
- **FastAPI + Jinja2 GUI** for deploying/managing stacks and chatting with the agent

> This is intentionally a skeleton: you’re expected to adapt the toolset, prompts, planner, and action dispatch.

---

## Prereqs

### Local
- Python **3.12**
- `pip`
- AWS CLI v2
- AWS SAM CLI (`sam`)
- An AWS account with access to:
  - CloudFormation/Lambda/DynamoDB/EventBridge/IAM
  - **Amazon Bedrock** (and the chosen `MODEL_ID`)
  - (Optional) Amazon Polly

### AWS credentials
You need a configured AWS profile in `~/.aws/credentials` (or equivalent).

---

## Quickstart (macOS / Ubuntu)

### 1) Create venv + install deps
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### 2) Initialize AWS env
```bash
source initwyw <AWS_PROFILE> <AWS_REGION>
```

### 3) Deploy the SAM stack
```bash
STACK_NAME=<your stack name>
sam build --build-dir ".aws-${STACK_NAME}"
sam deploy --guided --stack-name "$STACK_NAME" --template-file ".aws-${STACK_NAME}/build/template.yaml"
```

Notes:
- `MODEL_ID` is configured via the SAM parameter `ModelIdParam`.
- Default model ID is `meta.llama3-1-8b-instruct-v1:0`.
- (Optional) set `AudioBucketName` to store Polly MP3s to S3 (requires S3 permissions).

After deployment, CloudFormation outputs `BrokerEndpointURL` like:
`https://<api-id>.execute-api.<region>.amazonaws.com/Prod/agent`

### 4) Run the GUI (optional)
```bash
uvicorn client.gui:app --reload --port 8000
```

Open:
- http://localhost:8000

From the home page you can:
- list agent stacks
- select one to chat
- delete a stack
- deploy a stack (runs `sam build` + `sam deploy`)

---

## Direct API usage

Once deployed, you can call the Broker:

```bash
curl -sS -X POST "$BROKER_URL" \
  -H "Content-Type: application/json" \
  -H "X-Session-Id: demo-session" \
  -d '{"text":"Hello. My name is Major.","channel":"text"}' | jq
```

Response schema:
```json
{
  "reply_text": "...",
  "actions": [],
  "audio": { "url": "..."}   // optional
}
```

---

## GUI usage (manual interface + chat)

The FastAPI/Jinja2 GUI exposes two major workflows:

1. **Manual interface (stack/deployment management)** — browse, create, and delete stacks, or jump to AWS consoles.
2. **Chat GUI** — talk to a deployed broker (text or voice), switch ASR modes, and inspect request/response metadata.

### 1) Manual interface

From the home page (`/`):

- **List stacks**: Fetches CloudFormation stacks matching the optional `AGENT_RESOURCE_STACK_PREFIX` (defaults to `marai-`). Stacks are grouped by status (available / creating / deleting / failed) to make it clear what you can select.
- **Select a stack**: Choosing a stack reveals the API endpoint used for chat and a direct **AWS console link** for the stack so you can debug events/outputs.
- **Delete**: Removes a selected stack (uses `cf.delete_stack` under the hood). A confirmation prompt appears in the browser before issuing the request.
- **Deploy new stack** (`/deploy`):
  1. Enter the stack name and optional `AGENT_RESOURCE_STACK_PREFIX` override.
  2. The GUI runs `sam build` + `sam deploy --guided` with the generated build directory (`.aws-<STACK_NAME>`). Output streams to the page so you can watch progress.
  3. When deployment finishes, the resulting broker endpoint is shown and the new stack is selectable on the home page.
- **Settings** (`/settings`):
  - Set `AWS_PROFILE` / `AWS_REGION` for subsequent requests.
  - Toggle “Use s3_bucket in samconfig.toml” to force/skip the `samconfig.toml` S3 bucket (handy when bootstrapping a new environment).
  - Adjust the stack prefix. The prefix is applied automatically when creating or selecting stacks.

### 2) Chat GUI

After selecting a stack, open `/chat` to talk to the broker:

- **Text chat**: Enter text and send; responses appear in the thread. If the broker returns actions, they are rendered inline for debugging.
- **Voice input**: Choose an ASR mode:
  - **Server (AWS Transcribe Streaming)**: Requires locally configured AWS credentials with `transcribe:StartStreamTranscription*` permissions. The browser streams audio to the FastAPI server, which forwards to AWS Transcribe; final transcripts are sent to the broker.
  - **Browser (Web Speech API)**: Uses the browser’s built-in recognizer; no AWS creds needed. Device selection is browser-dependent.
- **Audio output**: If the broker returns `audio.url`, the GUI provides a play button so you can listen without leaving the page.
- **Session management**: Each chat uses the `X-Session-Id` header with the current stack name by default. You can override the session ID in the UI to simulate multiple conversations.
- **Endpoint override**: Advanced users can paste a broker URL directly to test alternate deployments without switching stacks.
- **Debug panel**: Expand the request/response JSON to verify payloads, headers, and timing information when troubleshooting.

---

## Local-only development notes

- This skeleton is built for **AWS deployment**. The GUI can talk to a deployed stack.
- The chat UI supports **two ASR modes**:
  - **Server (AWS Transcribe Streaming)**: true mic selection, optional speaker routing for playback,
    push-to-talk, and continuous ambient listening. Audio is captured in the browser and streamed to the
    local FastAPI server over a websocket; the server streams to AWS Transcribe and (on final) forwards
    the transcript to the deployed Broker.
  - **Browser (Web Speech API fallback)**: uses the built-in browser recognizer (Chrome/Edge);
    device selection is not guaranteed.

### AWS permissions for server-side ASR
If you use **Server (AWS Transcribe)** mode, the AWS credentials/profile used to run the GUI must be
allowed to start a streaming transcription.

In practice that means granting (at minimum) a Transcribe streaming action to the profile/role,
e.g. `transcribe:StartStreamTranscriptionWebSocket` (some environments use `transcribe:StartStreamTranscription`).

This does **not** change the SAM-deployed stack permissions; it's purely for the local GUI.

A minimal identity policy looks like:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "transcribe:StartStreamTranscriptionWebSocket",
        "transcribe:StartStreamTranscription"
      ],
      "Resource": "*"
    }
  ]
}
```

---

## Repo layout

```text
template.yaml                # SAM template (DDB + Lambdas + layers + API + schedule)
lambda/broker/app.py         # Broker Lambda
lambda/agent_heartbeat/handler.py
layers/shared/               # Shared deps + agent_core (SAM layer with Makefile build)
layers/config/prompts/       # Prompt templates (SAM config layer)
client/                      # FastAPI + Jinja2 GUI
```

---

## Cleanup

Delete the stack (GUI “Delete” button) or via CLI:
```bash
aws cloudformation delete-stack --stack-name <STACK_NAME>
```

---

## License
MIT (see LICENSE).
