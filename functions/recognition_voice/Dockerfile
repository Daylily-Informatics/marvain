FROM python:3.12-slim
ENV PYTHONUNBUFFERED=1 NUMBA_DISABLE_JIT=1 OMP_NUM_THREADS=1 OPENBLAS_NUM_THREADS=1 MKL_NUM_THREADS=1
WORKDIR /var/task
RUN apt-get update && apt-get install -y --no-install-recommends ffmpeg g++ make cmake libcurl4-openssl-dev && rm -rf /var/lib/apt/lists/*
RUN pip install --no-cache-dir torch==2.6.0 --index-url https://download.pytorch.org/whl/cpu
RUN pip install --no-cache-dir awslambdaric boto3 'numpy<2' resemblyzer==0.1.4 soundfile pydantic requests daylily-tapdb==7.0.13 onnxruntime pillow
COPY functions/recognition_voice/download_dog_models.py /opt/download_dog_models.py
RUN python /opt/download_dog_models.py
COPY docs/licenses/dog-recognition.md /opt/dog-models/ATTRIBUTION.md
ARG MARVAIN_RELEASE_VERSION
ENV MARVAIN_RELEASE_VERSION=${MARVAIN_RELEASE_VERSION}
COPY layers/shared/python/agent_hub /var/task/agent_hub
COPY functions/hub_api/recognition_repository.py /var/task/recognition_repository.py
COPY functions/recognition_voice/handler.py /var/task/handler.py
COPY functions/recognition_voice/dog_handler.py /var/task/dog_handler.py
ENTRYPOINT ["python", "-m", "awslambdaric"]
CMD ["handler.handler"]
