from __future__ import annotations

import asyncio
import json
import logging
import os
import subprocess
import threading
import tomllib
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Optional
from uuid import uuid4

import boto3
from botocore.exceptions import ClientError
import requests
from fastapi import FastAPI, Form, Request, WebSocket, WebSocketDisconnect
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
STACK_PREFIX_ENV_VAR = "AGENT_RESOURCE_STACK_PREFIX"
DEFAULT_STACK_PREFIX = os.environ.get(STACK_PREFIX_ENV_VAR, "marai")


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
    stack_prefix: str = DEFAULT_STACK_PREFIX
    verbose: bool = False
    selected_session: Optional[str] = None
    sessions: list[dict[str, str]] = field(default_factory=list)
    generated_session: Optional[str] = None


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


def _reset_generated_session() -> None:
    STATE.generated_session = None


def _stack_console_url(stack_id: str) -> str:
    region = _effective_region()
    return f"https://{region}.console.aws.amazon.com/cloudformation/home?region={region}#/stacks/stackinfo?stackId={stack_id}"


def _list_polly_voices() -> list[dict[str, Any]]:
    voices: list[dict[str, Any]] = []
    try:
        polly = boto_sess().client("polly", region_name=_effective_region())
        next_token: Optional[str] = None
        while True:
            kwargs: Dict[str, Any] = {}
            if next_token:
                kwargs["NextToken"] = next_token
            resp = polly.describe_voices(**kwargs)
            for v in resp.get("Voices", []):
                voices.append(
                    {
                        "id": v.get("Id"),
                        "name": v.get("Name") or v.get("Id"),
                        "language": v.get("LanguageName"),
                        "engines": v.get("SupportedEngines", []) or [],
                    }
                )
            next_token = resp.get("NextToken")
            if not next_token:
                break
        voices.sort(key=lambda v: (v.get("name") or v.get("id") or "").lower())
    except Exception as e:
        logging.warning("Unable to fetch Polly voices: %s", e)
    return voices


def _normalized_stack_prefix() -> str:
    prefix = (STATE.stack_prefix or DEFAULT_STACK_PREFIX).strip()
    if prefix and not prefix.endswith("-"):
        prefix += "-"
    return prefix


def _prefixed_stack_name(name: str) -> str:
    base = name.strip()
    prefix = _normalized_stack_prefix()
    if base.startswith(prefix):
        return base
    return f"{prefix}{base}"


def _verbose_log(msg: str, stack_name: Optional[str] = None) -> None:
    if not STATE.verbose:
        return

    safe_stack = (stack_name or STATE.selected_stack or "stack").replace("/", "-")
    timestamp = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
    line = f"[{timestamp}] {msg}"
    logging.info(line)

    log_dir = Path("logs")
    log_dir.mkdir(exist_ok=True)
    log_path = log_dir / f"{safe_stack}-local.log"
    with log_path.open("a", encoding="utf-8") as fh:
        fh.write(line + "\n")


def _redirect_back(request: Request, fallback: str = "/"):
    referer = request.headers.get("referer") or fallback
    return RedirectResponse(url=referer, status_code=303)


def _current_session_id() -> str:
    if STATE.selected_session:
        return STATE.selected_session

    if not STATE.generated_session:
        timestamp = datetime.utcnow().strftime("%Y%m%d-%H%M%S")
        STATE.generated_session = f"session-{timestamp}-{uuid4().hex[:8]}"
    return STATE.generated_session


@app.get("/")
def home(request: Request):
    stacks_available = []
    stacks_building = []
    stacks_deleting = []
    stacks_failed = []
    prefix = _normalized_stack_prefix()
    try:
        cf = cf_client()
        summaries = []
        paginator = cf.get_paginator("list_stacks")
        for page in paginator.paginate():
            summaries.extend(page.get("StackSummaries", []))
    except Exception as e:
        logging.error("Error listing stacks: %s", e)
        summaries = []

    available_statuses = {
        "CREATE_COMPLETE",
        "UPDATE_COMPLETE",
        "UPDATE_ROLLBACK_COMPLETE",
        "IMPORT_COMPLETE",
        "ROLLBACK_COMPLETE",
    }
    building_statuses = {
        "CREATE_IN_PROGRESS",
        "ROLLBACK_IN_PROGRESS",
        "UPDATE_IN_PROGRESS",
        "UPDATE_COMPLETE_CLEANUP_IN_PROGRESS",
        "UPDATE_ROLLBACK_IN_PROGRESS",
        "UPDATE_ROLLBACK_COMPLETE_CLEANUP_IN_PROGRESS",
        "REVIEW_IN_PROGRESS",
        "IMPORT_IN_PROGRESS",
        "IMPORT_ROLLBACK_IN_PROGRESS",
    }
    deleting_statuses = {
        "DELETE_IN_PROGRESS",
    }
    failed_statuses = {
        "CREATE_FAILED",
        "ROLLBACK_FAILED",
        "DELETE_FAILED",
        "UPDATE_ROLLBACK_FAILED",
        "IMPORT_ROLLBACK_FAILED",
    }

    for s in summaries:
        stack_name = s.get("StackName")
        if not stack_name or (prefix and not stack_name.startswith(prefix)):
            continue
        status = s.get("StackStatus") or ""
        stack_id = s.get("StackId") or stack_name

        if status == "DELETE_COMPLETE":
            continue

        if status in available_statuses:
            try:
                detail = cf.describe_stacks(StackName=stack_name)["Stacks"][0]
                outputs = {o["OutputKey"]: o["OutputValue"] for o in detail.get("Outputs", [])}
            except Exception:
                outputs = {}

            endpoint = outputs.get("BrokerEndpointURL")
            if endpoint:
                stacks_available.append(
                    {
                        "name": stack_name,
                        "endpoint": endpoint,
                        "table": outputs.get("AgentStateTableName", ""),
                        "api_id": outputs.get("ApiGatewayId", ""),
                        "console_url": _stack_console_url(stack_id),
                    }
                )
        elif status in building_statuses:
            stacks_building.append(
                {
                    "name": stack_name,
                    "status": status.replace("_", " ").title(),
                    "reason": s.get("StackStatusReason", ""),
                    "console_url": _stack_console_url(stack_id),
                }
            )
        elif status in deleting_statuses:
            stacks_deleting.append(
                {
                    "name": stack_name,
                    "status": status.replace("_", " ").title(),
                    "reason": s.get("StackStatusReason", ""),
                    "console_url": _stack_console_url(stack_id),
                }
            )
        elif status in failed_statuses:
            stacks_failed.append(
                {
                    "name": stack_name,
                    "status": status.replace("_", " ").title(),
                    "reason": s.get("StackStatusReason", ""),
                    "console_url": _stack_console_url(stack_id),
                }
            )

    stacks_available.sort(key=lambda x: x["name"])
    stacks_building.sort(key=lambda x: x["name"])
    stacks_deleting.sort(key=lambda x: x["name"])
    stacks_failed.sort(key=lambda x: x["name"])

    return templates.TemplateResponse(
        "home.html",
        {
            "request": request,
            "stacks": stacks_available,
            "building_stacks": stacks_building,
            "deleting_stacks": stacks_deleting,
            "failed_stacks": stacks_failed,
            "state": STATE,
            "stack_prefix": prefix,
            "deploying": request.query_params.get("deploying"),
            "sessions": STATE.sessions,
        },
    )


@app.get("/settings")
def settings_page(request: Request):
    return templates.TemplateResponse("settings.html", {"request": request, "state": STATE})


@app.post("/settings")
def update_settings(
    aws_profile: str = Form(""),
    aws_region: str = Form(""),
    stack_prefix: str = Form(""),
    verbose: bool = Form(False),
):
    STATE.aws_profile = aws_profile.strip() or None
    STATE.aws_region = aws_region.strip() or None
    STATE.stack_prefix = stack_prefix.strip() or DEFAULT_STACK_PREFIX
    STATE.verbose = bool(verbose)
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

    if STATE.stack_prefix:
        os.environ[STACK_PREFIX_ENV_VAR] = STATE.stack_prefix
    else:
        os.environ.pop(STACK_PREFIX_ENV_VAR, None)

    return RedirectResponse(url="/", status_code=303)


@app.post("/session/create")
def create_session(
    request: Request,
    session_name: str = Form(...),
    session_description: str = Form(""),
):
    name = session_name.strip()
    description = session_description.strip()

    if not name:
        return _redirect_back(request)

    existing = next((s for s in STATE.sessions if s.get("name", "").lower() == name.lower()), None)
    if existing:
        existing["description"] = description
    else:
        STATE.sessions.append(
            {
                "name": name,
                "description": description,
                "created": datetime.utcnow().isoformat(),
            }
        )

    STATE.selected_session = name
    _reset_generated_session()
    return _redirect_back(request)


@app.post("/session/select")
def select_session(request: Request, session_name: str = Form("")):
    STATE.selected_session = session_name.strip() or None
    _reset_generated_session()
    return _redirect_back(request)


@app.post("/use_endpoint")
def use_endpoint(endpoint_url: str = Form(...)):
    STATE.selected_stack = None
    STATE.selected_endpoint = endpoint_url.strip()
    _reset_generated_session()
    logging.info("Using custom endpoint: %s", STATE.selected_endpoint)
    return RedirectResponse(url="/chat", status_code=302)


@app.get("/select_stack")
def select_stack(name: str):
    name = _prefixed_stack_name(name)
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
    _reset_generated_session()
    return RedirectResponse(url="/chat", status_code=302)


def _stack_exists(name: str, already_prefixed: bool = False) -> bool:
    stack_name = name if already_prefixed else _prefixed_stack_name(name)
    try:
        cf = cf_client()
        cf.describe_stacks(StackName=stack_name)
        return True
    except ClientError as e:  # pragma: no cover - network dependency
        if e.response.get("Error", {}).get("Code") == "ValidationError":
            return False
        logging.error("Error checking stack existence for %s: %s", stack_name, e)
        return False
    except Exception as e:  # pragma: no cover - network dependency
        logging.error("Unexpected error checking stack existence for %s: %s", stack_name, e)
        return False


def _bucket_exists(bucket: str) -> bool:
    if not bucket:
        return False

    try:
        boto_sess().client("s3").head_bucket(Bucket=bucket)
        return True
    except ClientError as e:  # pragma: no cover - network dependency
        code = e.response.get("Error", {}).get("Code")
        if code in {"403", "404", "NoSuchBucket", "NotFound"}:
            return False
        logging.warning("Unexpected S3 error for bucket %s: %s", bucket, e)
        return False
    except Exception as e:  # pragma: no cover - network dependency
        logging.warning("Error checking bucket %s: %s", bucket, e)
        return False


def _model_available_in_region(model_id: str) -> tuple[bool, Optional[str]]:
    if not model_id:
        return False, None

    region = _effective_region()
    try:
        bedrock = boto_sess().client("bedrock", region_name=region)
        next_token: Optional[str] = None
        while True:
            kwargs: Dict[str, Any] = {}
            if next_token:
                kwargs["nextToken"] = next_token
            resp = bedrock.list_foundation_models(**kwargs)
            for model in resp.get("modelSummaries", []):
                if (model.get("modelId") or "").lower() == model_id.lower():
                    return True, None
            next_token = resp.get("nextToken")
            if not next_token:
                break
        return False, None
    except Exception as e:  # pragma: no cover - network dependency
        logging.warning("Unable to validate model %s in %s: %s", model_id, region, e)
        return False, str(e)


@app.get("/delete_stack")
def delete_stack(name: str):
    name = _prefixed_stack_name(name)
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
    voices = _list_polly_voices()
    return templates.TemplateResponse(
        "deploy.html",
        {
            "request": request,
            "state": STATE,
            "polly_voices": voices,
            "region": _effective_region(),
            "sessions": STATE.sessions,
        },
    )


@app.get("/api/stack_exists")
def stack_exists_api(stack_name: str):
    prefixed = _prefixed_stack_name(stack_name)
    exists = _stack_exists(prefixed, already_prefixed=True)
    return {"exists": exists, "stack_name": prefixed}


@app.get("/api/bucket_exists")
def bucket_exists_api(bucket_name: str):
    return {"exists": _bucket_exists(bucket_name)}


@app.get("/api/model_available")
def model_available_api(model_id: str):
    available, error = _model_available_in_region(model_id)
    return {"available": available, "region": _effective_region(), "error": error}


@app.post("/deploy")
def deploy_agent(
    stack_name: str = Form(...),
    agent_id: str = Form("marvain-agent"),
    model_id: str = Form("meta.llama3-1-8b-instruct-v1:0"),
    polly_voice: str = Form("Matthew"),
    polly_voice_engine: str = Form(""),
    audio_bucket: str = Form(""),
    verbose: bool = Form(False),
):
    stack_name = _prefixed_stack_name(stack_name)
    agent_id = agent_id.strip() or "marvain-agent"
    model_id = model_id.strip() or "meta.llama3-1-8b-instruct-v1:0"
    polly_voice = polly_voice.strip() or "Matthew"
    polly_voice_engine = polly_voice_engine.strip()
    audio_bucket = audio_bucket.strip()
    verbose_enabled = bool(verbose)

    if _stack_exists(stack_name, already_prefixed=True):
        logging.error("Stack already exists: %s", stack_name)
        return JSONResponse(
            status_code=400,
            content={"error": f"Stack '{stack_name}' already exists."},
        )

    if audio_bucket and not _bucket_exists(audio_bucket):
        logging.error("Audio bucket does not exist: %s", audio_bucket)
        return JSONResponse(
            status_code=400,
            content={"error": f"Audio bucket '{audio_bucket}' does not exist."},
        )

    model_available, model_error = _model_available_in_region(model_id)
    if not model_available:
        region = _effective_region()
        detail = f" ({model_error})" if model_error else ""
        logging.error("Model %s is unavailable in %s%s", model_id, region, detail)
        return JSONResponse(
            status_code=400,
            content={
                "error": f"Model '{model_id}' is not available in region {region}.{detail}",
            },
        )

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
        f"AgentVoiceEngineParam={polly_voice_engine}",
        f"AudioBucketName={audio_bucket}",
        f"VerboseLogging={1 if verbose_enabled else 0}",
    ]
    cmd_deploy += ["--parameter-overrides", " ".join(overrides)]

    env = os.environ.copy()
    if STATE.aws_profile:
        env["AWS_PROFILE"] = STATE.aws_profile
    if STATE.aws_region:
        env["AWS_REGION"] = STATE.aws_region
        env["AWS_DEFAULT_REGION"] = STATE.aws_region

    log_path: Optional[Path] = None
    if verbose_enabled:
        deploy_ts = datetime.utcnow().strftime("%Y%m%d-%H%M%S")
        log_dir = Path("logfs")
        log_dir.mkdir(exist_ok=True)
        safe_stack = stack_name.replace("/", "-")
        log_path = log_dir / f"{safe_stack}-deploy-{deploy_ts}.log"

    def _stream_and_log(cmd):
        if not log_path:
            subprocess.run(cmd, check=True, env=env)
            return

        with log_path.open("a", encoding="utf-8") as fh:
            fh.write(f"Running: {' '.join(cmd)}\n")
            fh.flush()
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                env=env,
            )
            assert process.stdout is not None
            for line in process.stdout:
                fh.write(line)
                fh.flush()
                logging.info(line.rstrip())
            process.wait()
            if process.returncode != 0:
                raise subprocess.CalledProcessError(process.returncode, cmd)

    def do_deploy():
        try:
            _stream_and_log(cmd_build)
            _stream_and_log(cmd_deploy)
            logging.info("SAM deploy succeeded for stack %s", stack_name)
        except Exception as e:
            logging.error("SAM deploy failed: %s", e)

    thread = threading.Thread(target=do_deploy, daemon=True)
    thread.start()
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
    verbose_logs: list[str] = []
    if STATE.verbose:
        verbose_logs.append(f"Sending message to {STATE.selected_endpoint}: {text}")
        _verbose_log(verbose_logs[-1])

    try:
        headers = {
            "Content-Type": "application/json",
            "X-Session-Id": _current_session_id(),
        }
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

    if STATE.verbose:
        reply_txt = result.get("reply_text") or ""
        if reply_txt:
            verbose_logs.append(f"Agent reply: {reply_txt}")
            _verbose_log(verbose_logs[-1])
        if result.get("actions"):
            verbose_logs.append(f"Actions: {result['actions']}")
            _verbose_log(verbose_logs[-1])

    if verbose_logs:
        result["verbose_logs"] = verbose_logs

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
    session_id: Optional[str] = None,
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

    headers = {
        "Content-Type": "application/json",
        "X-Session-Id": session_id or _current_session_id(),
    }
    if STATE.verbose:
        _verbose_log(
            f"Calling broker at {STATE.selected_endpoint or 'custom endpoint'} with channel={channel}"
        )

    def _do_req() -> Dict[str, Any]:
        resp = requests.post(STATE.selected_endpoint, headers=headers, json=payload, timeout=25)
        try:
            return resp.json()
        except Exception:
            return {"error": "Invalid JSON response from agent.", "raw": resp.text}

    try:
        result = await asyncio.to_thread(_do_req)
        if STATE.verbose:
            summary = result.get("reply_text") or result.get("error") or "(no reply)"
            _verbose_log(f"Broker response: {summary}")
        return result
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
    session_id = (cfg.get("session_id") or STATE.selected_session or _current_session_id()).strip()
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
