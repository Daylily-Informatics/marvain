from __future__ import annotations

import asyncio
import json
import logging
import os
import shlex
import subprocess
import threading
import tomllib
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Optional

import boto3
import re
from botocore.exceptions import ClientError
import requests
from fastapi import FastAPI, Form, HTTPException, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import JSONResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

# Optional dependency: server-side streaming ASR via AWS Transcribe Streaming.
# Install with: pip install amazon-transcribe

def _secure_log_filename(name: str) -> str:
    """
    Sanitize stack name for log file usage. Allows only alphanum, dash, and underscore.
    """
    # Remove any directory traversal or weird chars
    name = str(name)
    # Remove path separators and restrict to safe chars
    name = re.sub(r"[^A-Za-z0-9_.-]", "_", name)
    # Defensive: collapse repeated underscores/dots/dashes
    name = re.sub(r"[_\.\-]+", "_", name)
    # Prevent issues with empty names
    return name or "stack"
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


STATE = UiState()


@dataclass
class DebugTool:
    id: str
    label: str
    description: str
    param_key: Optional[str] = None
    param_label: Optional[str] = None
    default_param: Optional[str] = None
    options: Optional[list[str]] = None


DEBUG_TOOLS: list[DebugTool] = [
    DebugTool(
        id="dump_memories",
        label="Dump memories",
        description="Run bin/dump_memory.py (short/long tables). Optional target: both, short, long.",
        param_key="target",
        param_label="target (both|short|long)",
        default_param="both",
    ),
    DebugTool(
        id="dump_transcript",
        label="Dump recent transcript",
        description="Shortcut for bin/dump_memory.py --target short to view short-term conversation items.",
        default_param="short",
        param_key="target",
        param_label="target",
    ),
    DebugTool(
        id="dump_voice_profiles",
        label="Dump voice registry",
        description="List voice profiles using bin/dump_voice_profiles.py --json.",
    ),
    DebugTool(
        id="dump_face_profiles",
        label="Dump face registry",
        description="List face profiles using bin/dump_face_profiles.py --json.",
    ),
    DebugTool(
        id="delete_voice",
        label="Delete voice profile",
        description="Remove a voice profile via bin/remove_voice_from_registry.py --name.",
        param_key="name",
        param_label="voice name",
    ),
    DebugTool(
        id="delete_face",
        label="Delete face profile",
        description="Remove a face profile via bin/remove_face_from_registry.py --name.",
        param_key="name",
        param_label="face name",
    ),
    DebugTool(
        id="purge_registry",
        label="Delete all registry entries",
        description="Reset the local identity registry using bin/unenroll_profiles.py --name '*' --type both.",
        default_param="*",
        param_key="name",
        param_label="name (use '*' for all)",
    ),
    DebugTool(
        id="tail_cloud_logs",
        label="Tail cloud logs",
        description="Run bin/tail_cloud_logs.sh for the selected stack (up to 20 seconds).",
        param_key="stack",
        param_label="stack name (optional)",
    ),
    DebugTool(
        id="print_stack_outputs",
        label="Print stack outputs",
        description="Show CloudFormation Output Key, Description, and Value entries for a stack.",
        param_key="stack",
        param_label="stack name (optional)",
    ),
]


def boto_sess() -> boto3.Session:
    kwargs: Dict[str, Any] = {}
    if STATE.aws_profile:
        kwargs["profile_name"] = STATE.aws_profile
    if STATE.aws_region:
        kwargs["region_name"] = STATE.aws_region
    return boto3.Session(**kwargs)


def cf_client():
    return boto_sess().client("cloudformation")


def _stack_console_url(stack_id: str) -> str:
    region = _effective_region()
    return f"https://{region}.console.aws.amazon.com/cloudformation/home?region={region}#/stacks/stackinfo?stackId={stack_id}"


def _list_polly_voices() -> list[dict[str, Any]]:
    voices: list[dict[str, Any]] = []
    try:
        polly = boto_sess().client("polly")
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

    safe_stack = _secure_log_filename(stack_name or STATE.selected_stack or "stack")
    timestamp = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
    line = f"[{timestamp}] {msg}"
    logging.info(line)

    log_dir = Path("logs")
    log_dir.mkdir(exist_ok=True)
    log_path = (log_dir / f"{safe_stack}-local.log").resolve()
    # Check that log_path is within log_dir
    if not str(log_path).startswith(str(log_dir.resolve())):
        logging.error("Attempted to write log outside of logs directory: %s", log_path)
        return
    with log_path.open("a", encoding="utf-8") as fh:
        fh.write(line + "\n")


def _current_verbose_log_path() -> Optional[Path]:
    safe_stack = _secure_log_filename(STATE.selected_stack or "stack")
    log_dir = Path("logs").resolve()
    log_path = (log_dir / f"{safe_stack}-local.log").resolve()
    # Check that log_path is within log_dir (prevents path traversal)
    if not str(log_path).startswith(str(log_dir)):
        logging.error("Attempted to access log outside of logs directory: %s", log_path)
        return None
    return log_path if log_path.exists() else None


def _debug_env() -> Dict[str, str]:
    env = os.environ.copy()
    if STATE.aws_profile:
        env["AWS_PROFILE"] = STATE.aws_profile
    if STATE.aws_region:
        env["AWS_REGION"] = STATE.aws_region
        env["AWS_DEFAULT_REGION"] = STATE.aws_region
    return env


def _build_debug_command(tool_id: str, params: Dict[str, Any]) -> list[str]:
    if tool_id == "dump_memories":
        target = (params.get("target") or "both").strip()
        cmd = ["python3", "bin/dump_memory.py", "--target", target]
        if params.get("conversation_table"):
            cmd += ["--conversation-table", str(params["conversation_table"])]
        if params.get("ais_table"):
            cmd += ["--ais-table", str(params["ais_table"])]
        return cmd

    if tool_id == "dump_transcript":
        return ["python3", "bin/dump_memory.py", "--target", (params.get("target") or "short").strip()]

    if tool_id == "dump_voice_profiles":
        return ["python3", "bin/dump_voice_profiles.py", "--json"]

    if tool_id == "dump_face_profiles":
        return ["python3", "bin/dump_face_profiles.py", "--json"]

    if tool_id == "delete_voice":
        name = (params.get("name") or "").strip()
        if not name:
            raise HTTPException(status_code=400, detail="Voice name is required")
        return ["python3", "bin/remove_voice_from_registry.py", "--name", name]

    if tool_id == "delete_face":
        name = (params.get("name") or "").strip()
        if not name:
            raise HTTPException(status_code=400, detail="Face name is required")
        return ["python3", "bin/remove_face_from_registry.py", "--name", name]

    if tool_id == "purge_registry":
        name = (params.get("name") or "*").strip() or "*"
        return ["python3", "bin/unenroll_profiles.py", "--name", name, "--type", "both"]

    if tool_id == "tail_cloud_logs":
        stack = (params.get("stack") or STATE.selected_stack or "").strip()
        if not stack:
            raise HTTPException(status_code=400, detail="Provide a stack name or select one on the home page")
        region_flag = f" --region {shlex.quote(STATE.aws_region)}" if STATE.aws_region else ""
        cmd_str = f"timeout 20 bin/tail_cloud_logs.sh {shlex.quote(stack)}{region_flag}"
        return ["bash", "-lc", cmd_str]

    if tool_id == "print_stack_outputs":
        stack = (params.get("stack") or STATE.selected_stack or "").strip()
        if not stack:
            raise HTTPException(status_code=400, detail="Provide a stack name or select one on the home page")
        cmd = ["python3", "bin/print_stack_outputs.py", stack]
        if STATE.aws_region:
            cmd += ["--region", STATE.aws_region]
        return cmd

    raise HTTPException(status_code=400, detail=f"Unsupported debug tool: {tool_id}")


def _debug_tool_metadata() -> list[dict[str, Any]]:
    prefix = _normalized_stack_prefix()
    stacks_available, _, _, _ = _list_stacks_by_status(prefix)
    stack_options = [s["name"] for s in stacks_available]

    tools: list[dict[str, Any]] = []
    for tool in DEBUG_TOOLS:
        meta = tool.__dict__.copy()
        if tool.id in {"tail_cloud_logs", "print_stack_outputs"}:
            meta["options"] = stack_options
            if not meta.get("default_param"):
                meta["default_param"] = STATE.selected_stack or None
            meta["selected_stack"] = STATE.selected_stack
        tools.append(meta)
    return tools


def _list_stacks_by_status(prefix: str):
    stacks_available: list[dict[str, Any]] = []
    stacks_building: list[dict[str, Any]] = []
    stacks_deleting: list[dict[str, Any]] = []
    stacks_failed: list[dict[str, Any]] = []
    try:
        cf = cf_client()
        summaries: list[dict[str, Any]] = []
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

    try:
        cf = cf_client()
    except Exception:
        cf = None

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
                detail = cf.describe_stacks(StackName=stack_name)["Stacks"][0] if cf else {}
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
    return stacks_available, stacks_building, stacks_deleting, stacks_failed


@app.get("/")
def home(request: Request):
    prefix = _normalized_stack_prefix()
    stacks_available, stacks_building, stacks_deleting, stacks_failed = _list_stacks_by_status(prefix)

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


@app.post("/use_endpoint")
def use_endpoint(endpoint_url: str = Form(...)):
    STATE.selected_stack = None
    STATE.selected_endpoint = endpoint_url.strip()
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
        "deploy.html", {"request": request, "state": STATE, "polly_voices": voices}
    )


@app.get("/api/stack_exists")
def stack_exists_api(stack_name: str):
    prefixed = _prefixed_stack_name(stack_name)
    exists = _stack_exists(prefixed, already_prefixed=True)
    return {"exists": exists, "stack_name": prefixed}


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

    if audio_bucket:
        try:
            boto_sess().client("s3").head_bucket(Bucket=audio_bucket)
        except Exception:
            logging.error("Audio bucket does not exist: %s", audio_bucket)
            return JSONResponse(
                status_code=400,
                content={"error": f"Audio bucket '{audio_bucket}' does not exist."},
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


@app.get("/api/debug/tools")
def list_debug_tools():
    logs: list[str] = []
    log_path = _current_verbose_log_path()
    if log_path:
        logs = log_path.read_text(encoding="utf-8").splitlines()[-100:]
    return {"tools": _debug_tool_metadata(), "logs": logs}


@app.get("/api/debug/logs")
def debug_logs():
    path = _current_verbose_log_path()
    if not path:
        return {"lines": []}
    return {"lines": path.read_text(encoding="utf-8").splitlines()[-200:]}


@app.post("/api/debug/run_tool")
async def run_debug_tool(request: Request):
    data = await request.json()
    tool_id = (data.get("tool") or "").strip()
    params = data.get("params") or {}
    cmd = _build_debug_command(tool_id, params)

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            env=_debug_env(),
            timeout=120,
        )
    except FileNotFoundError:
        return JSONResponse(status_code=400, content={"ok": False, "error": "Script not found", "output": ""})
    except subprocess.TimeoutExpired as e:
        output = (e.stdout or "") + (e.stderr or "")
        return JSONResponse(
            status_code=504,
            content={"ok": False, "error": "Debug tool timed out", "output": output},
        )

    combined_output = (proc.stdout or "") + (proc.stderr or "")
    return {"ok": proc.returncode == 0, "output": combined_output, "returncode": proc.returncode}


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
