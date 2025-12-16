# whaddya-want (Rank-4 agent skeleton)

This repo is a **reference implementation** of a small agent runtime on AWS:

- `POST /agent` Broker Lambda (API Gateway)
- Heartbeat Lambda (EventBridge `rate(5 minutes)`)
- Unified DynamoDB table for events + memories + voice registry
- AWS Bedrock for LLM inference (Converse API)
- Optional Amazon Polly speech synthesis (Broker)

It is intentionally **adaptable**: replace the LLM model, tool set, memory schema, or action dispatch without rewriting the whole stack.

---

## Repo layout

- `template.yaml` — AWS SAM template (deploys everything)
- `agent_core/` — core runtime code (packaged into `SharedDependenciesLayer`)
- `layers/shared/` — SAM Layer build (deps + `agent_core`)
- `layers/config/` — SAM Layer config (`agent_config` prompts)
- `lambda/broker/` — API handler
- `lambda/agent_heartbeat/` — scheduled handler
- `initwyw` — local shell bootstrap

---

## Prereqs

- Python 3.11
- AWS CLI configured (`aws configure sso` or `aws configure`)
- AWS SAM CLI installed (`sam --version`)
- An AWS account with permission to deploy CloudFormation + create IAM roles + DynamoDB + Lambda + API Gateway + EventBridge

---

## Local setup

```bash
# from repo root
./initwyw <AWS_PROFILE> <AWS_REGION>
```

This will:
- create `.venv/` if needed
- install `requirements.txt`
- set `AWS_PROFILE`, `AWS_REGION`, `AWS_DEFAULT_REGION`
- add `layers/config/python` + repo root to `PYTHONPATH` for local imports

---

## Build + deploy

```bash
sam build
sam deploy --guided
```

During `--guided` you can accept defaults from `samconfig.toml` or override.

Outputs include:
- Broker endpoint URL (`.../Prod/agent`)
- DynamoDB table name
- Broker + Heartbeat Lambda ARNs

---

## Invoke the Broker

Once deployed, call the output `BrokerEndpointUrl`:

```bash
curl -sS -X POST "$BROKER_URL" \
  -H "Content-Type: application/json" \
  -H "X-Session-Id: demo-session-1" \
  -d '{
    "text": "my name is Major. remind me to hydrate tomorrow.",
    "channel": "audio",
    "voice_id": "mic-1",
    "personality_prompt": "Be concise. Use bullet points for plans."
  }' | jq .
```

Request body supports:
- `transcript` or `text`
- `channel` (default `audio`)
- `voice_id` or `speaker_id`
- `speaker_name` or `user_name`
- `voice_embedding` (accepted, **not persisted**)
- `personality_prompt`
- `source`

Response includes:
- `reply_text`
- `actions` (array)
- optional `audio` if Polly succeeds

---

## Heartbeat

The Heartbeat Lambda is invoked by EventBridge every 5 minutes. It creates a synthetic event and can emit background actions + memories.

To test manually:

```bash
aws lambda invoke --function-name whaddya-want-heartbeat /tmp/out.json && cat /tmp/out.json
```

---

## Notes / knobs

### Bedrock model selection

Set via environment variable `MODEL_ID` (also a SAM Parameter `ModelId`).

Examples:
- `meta.llama3-1-8b-instruct-v1:0`
- `anthropic.claude-3-5-sonnet-20240620-v1:0`

### Optional: local fake LLM

If you want to run without Bedrock credentials:

```bash
export LOCAL_FAKE_LLM=1
```

The agent will return a deterministic JSON response that echoes the user input.

### Optional: speech synthesis

Broker attempts Polly synthesis automatically. To persist audio to S3:
1. Set `AUDIO_BUCKET` env var on the Broker Lambda
2. Uncomment and configure the `s3:PutObject` policy in `template.yaml`

---

## Extending the skeleton

- Add tools: `agent_core/tools.py`
- Interpret tool calls / planner output: `agent_core/planner.py`
- Dispatch actions to real systems: `agent_core/actions.py`
- Change memory schema: `agent_core/memory_store.py`
- Adjust prompts: `layers/config/python/agent_config/prompts.py`
