FROM python:3.12-slim

WORKDIR /app

ARG MARVAIN_WORKER_VERSION
RUN test -n "${MARVAIN_WORKER_VERSION}"
ENV MARVAIN_WORKER_VERSION=${MARVAIN_WORKER_VERSION}

# System deps (minimal)
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
  && rm -rf /var/lib/apt/lists/*

COPY apps/agent_worker/requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

COPY layers/shared/python/agent_hub /app/agent_hub
COPY apps/agent_worker/worker.py /app/worker.py
COPY apps/agent_worker/.env.example /app/.env.example
RUN python -c "import agent_hub.livekit_tokens, agent_hub.memory_classifier, agent_hub.personas"

ENV PYTHONUNBUFFERED=1

CMD ["python", "/app/worker.py", "start"]
