from __future__ import annotations

import logging
import os
import subprocess
from dataclasses import dataclass
from typing import Any, Dict, Optional

import boto3
import requests
from fastapi import BackgroundTasks, FastAPI, Form, Request
from fastapi.responses import JSONResponse, RedirectResponse
from fastapi.templating import Jinja2Templates


app = FastAPI(title="marvain — Agent Manager")
templates = Jinja2Templates(directory="client/templates")

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")


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
        "--resolve-s3",
        "--no-confirm-changeset",
        "--no-fail-on-empty-changeset",
    ]

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
