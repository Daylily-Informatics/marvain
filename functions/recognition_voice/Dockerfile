FROM python:3.12-slim
ARG MARVAIN_RELEASE_VERSION
ENV MARVAIN_RELEASE_VERSION=${MARVAIN_RELEASE_VERSION} PYTHONUNBUFFERED=1 NUMBA_CACHE_DIR=/tmp/numba
WORKDIR /var/task
RUN apt-get update && apt-get install -y --no-install-recommends ffmpeg g++ make cmake libcurl4-openssl-dev && rm -rf /var/lib/apt/lists/*
RUN pip install --no-cache-dir torch==2.6.0 --index-url https://download.pytorch.org/whl/cpu
RUN pip install --no-cache-dir awslambdaric boto3 'numpy<2' resemblyzer==0.1.4 soundfile pydantic requests daylily-tapdb==7.0.13
COPY layers/shared/python/agent_hub /var/task/agent_hub
COPY functions/hub_api/recognition_repository.py /var/task/recognition_repository.py
COPY functions/recognition_voice/handler.py /var/task/handler.py
ENTRYPOINT ["python", "-m", "awslambdaric"]
CMD ["handler.handler"]
