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
sam build
sam deploy --guided
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

## Local-only development notes

- This skeleton is built for **AWS deployment**. The GUI can talk to a deployed stack.
- The browser mic button uses **Web Speech API** (Chrome/Edge). It transcribes client-side.
- If you want *real* ambient listening + device selection + server-side transcription:
  - plug in AWS Transcribe (or your preferred ASR) and update the client to stream audio.

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
