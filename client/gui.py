from __future__ import annotations

import asyncio
import json
import logging
import os
import subprocess
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Optional

import boto3
import requests
from fastapi import BackgroundTasks, FastAPI, Form, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import JSONResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

# Optional dependency: server-side streaming ASR via AWS Transcribe Streaming.
# Install with: pip install amazon-transcribe
try:
    from amazon_transcribe.client import TranscribeStreamingClient
    from amazon_transcribe.handlers import TranscriptResultStreamHandler
    from amazon_transcribe.model import TranscriptEvent

    _HAS_TRANSCRIBE_STREAMING = True
except Exception:
    TranscribeStreamingClient = None  # type: ignore
    TranscriptResultStreamHandler = object  # type: ignore
    TranscriptEvent = object  # type: ignore
    _HAS_TRANSCRIBE_STREAMING = False


app = FastAPI(title="marvain — Agent Manager")
templates = Jinja2Templates(directory="client/templates")

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

SAMCONFIG_PATH = Path("samconfig.toml")


def _samconfig_has_s3_bucket() -> bool:
    if not SAMCONFIG_PATH.exists():
        return False
    try:
        data = tomllib.load(SAMCONFIG_PATH.open("rb"))
    except Exception as e:  # pragma: no cover - best-effort guardrail
        logging.warning("Unable to parse samconfig.toml: %s", e)
        return False

    s3_bucket = (
        data.get("default", {})
        .get("deploy", {})
        .get("parameters", {})
        .get("s3_bucket")
    )
    return bool(s3_bucket)


@dataclass
class UiState:
    aws_profile: Optional[str] = os.environ.get("AWS_PROFILE")
    aws_region: Optional[str] = os.environ.get("AWS_REGION") or os.environ.get("AWS_DEFAULT_REGION")
    selected_stack: Optional[str] = None
    selected_endpoint: Optional[str] = None


STATE = UiState()


def boto_sess() -> boto3.Session:
    kwargs: Dict[str, Any] = {}
    if STATE.aws_profile:
        kwargs["profile_name"] = STATE.aws_profile
    if STATE.aws_region:
        kwargs["region_name"] = STATE.aws_region
    return boto3.Session(**kwargs)


def cf_client():
    return boto_sess().client("cloudformation")


@app.get("/")
def home(request: Request):
    stacks = []
    try:
        cf = cf_client()
        summaries = cf.list_stacks(
            StackStatusFilter=[
                "CREATE_COMPLETE",
                "UPDATE_COMPLETE",
                "UPDATE_ROLLBACK_COMPLETE",
                "IMPORT_COMPLETE",
                "ROLLBACK_COMPLETE",
            ]
        )["StackSummaries"]
    except Exception as e:
        logging.error("Error listing stacks: %s", e)
        summaries = []

    for s in summaries:
        stack_name = s.get("StackName")
        if not stack_name:
            continue
        try:
            detail = cf.describe_stacks(StackName=stack_name)["Stacks"][0]
            outputs = {o["OutputKey"]: o["OutputValue"] for o in detail.get("Outputs", [])}
        except Exception:
            outputs = {}

        endpoint = outputs.get("BrokerEndpointURL")
        if endpoint:
            stacks.append(
                {
                    "name": stack_name,
                    "endpoint": endpoint,
                    "table": outputs.get("AgentStateTableName", ""),
                    "api_id": outputs.get("ApiGatewayId", ""),
                }
            )

    stacks.sort(key=lambda x: x["name"])

    return templates.TemplateResponse(
        "home.html",
        {
            "request": request,
            "stacks": stacks,
            "state": STATE,
            "deploying": request.query_params.get("deploying"),
        },
    )


@app.get("/settings")
def settings_page(request: Request):
    return templates.TemplateResponse("settings.html", {"request": request, "state": STATE})


@app.post("/settings")
def update_settings(aws_profile: str = Form(""), aws_region: str = Form("")):
    STATE.aws_profile = aws_profile.strip() or None
    STATE.aws_region = aws_region.strip() or None
    # also set env so subprocess tools (sam/aws) inherit by default
    if STATE.aws_profile:
        os.environ["AWS_PROFILE"] = STATE.aws_profile
    else:
        os.environ.pop("AWS_PROFILE", None)

    if STATE.aws_region:
        os.environ["AWS_REGION"] = STATE.aws_region
        os.environ["AWS_DEFAULT_REGION"] = STATE.aws_region
    else:
        os.environ.pop("AWS_REGION", None)
        os.environ.pop("AWS_DEFAULT_REGION", None)

    return RedirectResponse(url="/", status_code=303)


@app.post("/use_endpoint")
def use_endpoint(endpoint_url: str = Form(...)):
    STATE.selected_stack = None
    STATE.selected_endpoint = endpoint_url.strip()
    logging.info("Using custom endpoint: %s", STATE.selected_endpoint)
    return RedirectResponse(url="/chat", status_code=302)


@app.get("/select_stack")
def select_stack(name: str):
    try:
        cf = cf_client()
        stack = cf.describe_stacks(StackName=name)["Stacks"][0]
        outputs = {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}
        endpoint = outputs.get("BrokerEndpointURL")
    except Exception as e:
        logging.error("Error selecting stack %s: %s", name, e)
        endpoint = None

    if not endpoint:
        return RedirectResponse(url="/", status_code=302)

    STATE.selected_stack = name
    STATE.selected_endpoint = endpoint
    return RedirectResponse(url="/chat", status_code=302)


@app.get("/delete_stack")
def delete_stack(name: str):
    try:
        cf = cf_client()
        cf.delete_stack(StackName=name)
        logging.info("Initiated deletion of stack %s", name)
    except Exception as e:
        logging.error("Failed to delete stack %s: %s", name, e)

    if STATE.selected_stack == name:
        STATE.selected_stack = None
        STATE.selected_endpoint = None

    return RedirectResponse(url="/", status_code=302)


@app.get("/deploy")
def deploy_form(request: Request):
    return templates.TemplateResponse("deploy.html", {"request": request, "state": STATE})


@app.post("/deploy")
def deploy_agent(
    background_tasks: BackgroundTasks,
    stack_name: str = Form(...),
    agent_id: str = Form("marvain-agent"),
    model_id: str = Form("meta.llama3-1-8b-instruct-v1:0"),
    polly_voice: str = Form("Matthew"),
    audio_bucket: str = Form(""),
):
    stack_name = stack_name.strip()
    agent_id = agent_id.strip() or "marvain-agent"
    model_id = model_id.strip() or "meta.llama3-1-8b-instruct-v1:0"
    polly_voice = polly_voice.strip() or "Matthew"
    audio_bucket = audio_bucket.strip()

    # Build and deploy via SAM CLI
    cmd_build = ["sam", "build"]

    cmd_deploy = [
        "sam",
        "deploy",
        "--stack-name",
        stack_name,
        "--capabilities",
        "CAPABILITY_IAM",
        "--no-confirm-changeset",
        "--no-fail-on-empty-changeset",
    ]

    if _samconfig_has_s3_bucket():
        logging.info("samconfig.toml defines s3_bucket; skipping --resolve-s3")
    else:
        cmd_deploy.append("--resolve-s3")

    if STATE.aws_region:
        cmd_deploy += ["--region", STATE.aws_region]
    if STATE.aws_profile:
        cmd_deploy += ["--profile", STATE.aws_profile]

    overrides = [
        f"AgentIdParam={agent_id}",
        f"ModelIdParam={model_id}",
        f"AgentVoiceIdParam={polly_voice}",
        f"AudioBucketName={audio_bucket}",
    ]
    cmd_deploy += ["--parameter-overrides", " ".join(overrides)]

    env = os.environ.copy()
    if STATE.aws_profile:
        env["AWS_PROFILE"] = STATE.aws_profile
    if STATE.aws_region:
        env["AWS_REGION"] = STATE.aws_region
        env["AWS_DEFAULT_REGION"] = STATE.aws_region

    def do_deploy():
        try:
            subprocess.run(cmd_build, check=True, env=env)
            subprocess.run(cmd_deploy, check=True, env=env)
            logging.info("SAM deploy succeeded for stack %s", stack_name)
        except Exception as e:
            logging.error("SAM deploy failed: %s", e)

    background_tasks.add_task(do_deploy)
    return RedirectResponse(url="/?deploying=1", status_code=303)


@app.get("/chat")
def chat_page(request: Request):
    if not STATE.selected_endpoint:
        return RedirectResponse(url="/", status_code=302)
    label = STATE.selected_stack or "Custom Agent"
    return templates.TemplateResponse("chat.html", {"request": request, "state": STATE, "stack_name": label})


@app.post("/api/send_message")
async def send_message(request: Request):
    if not STATE.selected_endpoint:
        return JSONResponse(content={"error": "No agent endpoint configured."}, status_code=400)

    data = await request.json()
    text = (data.get("text") or "").strip()
    if not text:
        return JSONResponse(content={"error": "No text provided."}, status_code=400)

    # Optional persona prompt passthrough
    personality = (data.get("personality_prompt") or "").strip() or None

    try:
        headers = {"Content-Type": "application/json", "X-Session-Id": "ui-session"}
        payload: Dict[str, Any] = {"text": text, "channel": "gui"}
        if personality:
            payload["personality_prompt"] = personality
        resp = requests.post(STATE.selected_endpoint, headers=headers, json=payload, timeout=25)
    except Exception as e:
        logging.error("Error calling agent endpoint: %s", e)
        return JSONResponse(content={"error": "Failed to reach agent endpoint."}, status_code=502)

    try:
        result = resp.json()
    except Exception:
        return JSONResponse(content={"error": "Invalid response from agent."}, status_code=500)

    return JSONResponse(content=result)


def _effective_region() -> str:
    return (
        STATE.aws_region
        or os.environ.get("AWS_REGION")
        or os.environ.get("AWS_DEFAULT_REGION")
        or "us-east-1"
    )


async def _call_agent_broker(
    *,
    transcript: str,
    session_id: str = "ui-session",
    voice_id: Optional[str] = None,
    speaker_name: Optional[str] = None,
    personality_prompt: Optional[str] = None,
    source: str = "gui-asr",
    channel: str = "audio",
) -> Dict[str, Any]:
    """Call the deployed broker endpoint. Runs in a thread to avoid blocking the event loop."""

    if not STATE.selected_endpoint:
        return {"error": "No agent endpoint configured.", "reply_text": "", "actions": []}

    payload: Dict[str, Any] = {
        "transcript": transcript,
        "channel": channel,
        "source": source,
    }
    if voice_id:
        payload["voice_id"] = voice_id
    if speaker_name:
        payload["speaker_name"] = speaker_name
    if personality_prompt:
        payload["personality_prompt"] = personality_prompt

    headers = {"Content-Type": "application/json", "X-Session-Id": session_id}

    def _do_req() -> Dict[str, Any]:
        resp = requests.post(STATE.selected_endpoint, headers=headers, json=payload, timeout=25)
        try:
            return resp.json()
        except Exception:
            return {"error": "Invalid JSON response from agent.", "raw": resp.text}

    try:
        return await asyncio.to_thread(_do_req)
    except Exception as e:
        return {"error": f"Failed to reach agent endpoint: {e}", "reply_text": "", "actions": []}


if _HAS_TRANSCRIBE_STREAMING:

    class _WsTranscriptHandler(TranscriptResultStreamHandler):
        """Transcribe streaming handler that forwards partial/final transcripts to the browser."""

        def __init__(self, output_stream, websocket: WebSocket):
            super().__init__(output_stream)
            self.websocket = websocket
            self.final_chunks: list[str] = []
            self.last_partial: str = ""

        async def handle_transcript_event(self, transcript_event: TranscriptEvent):
            results = transcript_event.transcript.results
            for res in results:
                if not res.alternatives:
                    continue
                text = (res.alternatives[0].transcript or "").strip()
                if not text:
                    continue
                if res.is_partial:
                    self.last_partial = text
                    await self.websocket.send_text(json.dumps({"type": "partial", "text": text}))
                else:
                    self.final_chunks.append(text)
                    await self.websocket.send_text(json.dumps({"type": "final_chunk", "text": text}))

        def final_text(self) -> str:
            return " ".join(self.final_chunks).strip()


@app.websocket("/ws/asr")
async def ws_asr(websocket: WebSocket):
    """Server-side streaming ASR.

    Browser sends:
      1) a JSON text frame: {type:'start', language_code, sample_rate_hz, session_id, voice_id, speaker_name, personality_prompt}
      2) binary frames containing little-endian 16-bit PCM at sample_rate_hz (default 16000)
      3) a JSON text frame: {type:'stop'}

    Server streams to AWS Transcribe Streaming, sends partial transcripts back,
    then (optionally) calls the deployed Broker and returns the agent reply.
    """

    await websocket.accept()

    if not _HAS_TRANSCRIBE_STREAMING:
        await websocket.send_text(json.dumps({"type": "error", "error": "amazon-transcribe not installed"}))
        await websocket.close()
        return

    # Read start config
    try:
        raw = await websocket.receive_text()
        cfg = json.loads(raw)
    except Exception:
        cfg = {}

    language_code = (cfg.get("language_code") or "en-US").strip()
    sample_rate_hz = int(cfg.get("sample_rate_hz") or 16000)
    session_id = (cfg.get("session_id") or "ui-session").strip()
    voice_id = (cfg.get("voice_id") or "").strip() or None
    speaker_name = (cfg.get("speaker_name") or "").strip() or None
    personality_prompt = (cfg.get("personality_prompt") or "").strip() or None
    region = _effective_region()

    await websocket.send_text(
        json.dumps(
            {
                "type": "asr_ready",
                "provider": "aws-transcribe",
                "language_code": language_code,
                "sample_rate_hz": sample_rate_hz,
                "region": region,
            }
        )
    )

    # Start transcribe stream
    try:
        client = TranscribeStreamingClient(region=region)
        stream = await client.start_stream_transcription(
            language_code=language_code,
            media_sample_rate_hz=sample_rate_hz,
            media_encoding="pcm",
        )
    except Exception as e:
        await websocket.send_text(json.dumps({"type": "error", "error": f"Failed to start Transcribe stream: {e}"}))
        await websocket.close()
        return

    handler = _WsTranscriptHandler(stream.output_stream, websocket)

    async def _recv_audio():
        try:
            while True:
                msg = await websocket.receive()
                if msg.get("type") == "websocket.disconnect":
                    break
                if msg.get("bytes") is not None:
                    chunk = msg.get("bytes")
                    if chunk:
                        await stream.input_stream.send_audio_event(audio_chunk=chunk)
                    continue
                if msg.get("text"):
                    try:
                        j = json.loads(msg["text"])
                    except Exception:
                        j = {}
                    if (j.get("type") or "").lower() == "stop":
                        break
        except WebSocketDisconnect:
            pass
        except Exception as e:
            await websocket.send_text(json.dumps({"type": "error", "error": f"Audio receive error: {e}"}))
        finally:
            try:
                await stream.input_stream.end_stream()
            except Exception:
                pass

    handler_task = asyncio.create_task(handler.handle_events())
    recv_task = asyncio.create_task(_recv_audio())

    await recv_task
    # handler completes after end_stream
    try:
        # Give AWS Transcribe time to flush the final transcript after end_stream.
        await asyncio.wait_for(handler_task, timeout=60)
    except Exception:
        # If output handler doesn't finish, cancel it.
        handler_task.cancel()

    final_text = handler.final_text()
    await websocket.send_text(json.dumps({"type": "final", "text": final_text}))

    if final_text:
        # Feed transcript into broker
        agent_resp = await _call_agent_broker(
            transcript=final_text,
            session_id=session_id,
            voice_id=voice_id,
            speaker_name=speaker_name,
            personality_prompt=personality_prompt,
            source="gui-asr",
            channel="audio",
        )
        await websocket.send_text(json.dumps({"type": "agent_reply", "payload": agent_resp}))

    await websocket.close()
