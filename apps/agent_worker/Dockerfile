FROM python:3.12-slim

WORKDIR /app

ARG MARVAIN_WORKER_VERSION
RUN test -n "${MARVAIN_WORKER_VERSION}"
ENV MARVAIN_WORKER_VERSION=${MARVAIN_WORKER_VERSION}

# System deps (minimal)
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
  && rm -rf /var/lib/apt/lists/*

COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

COPY worker.py /app/worker.py
COPY .env.example /app/.env.example

ENV PYTHONUNBUFFERED=1

CMD ["python", "/app/worker.py", "start"]
