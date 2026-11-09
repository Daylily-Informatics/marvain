FROM debian:bookworm-slim

WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/* \
    && curl -fsSL -o /tmp/miniforge.sh https://github.com/conda-forge/miniforge/releases/download/26.9.4-1/Miniforge3-26.9.4-1-Linux-x86_64.sh \
    && bash /tmp/miniforge.sh -b -p /opt/conda \
    && rm /tmp/miniforge.sh \
    && /opt/conda/bin/conda create --yes --name marvain python=3.12 pip \
    && /opt/conda/bin/conda clean --all --yes

ENV PATH=/opt/conda/bin:${PATH} \
    PYTHONUNBUFFERED=1 \
    MARVAIN_TAPDB_TEMPLATE_ROOT=/app/tapdb_templates

COPY apps/dot_service/requirements.txt /app/dot-requirements.txt
RUN conda run -n marvain python -m pip install --no-cache-dir -r /app/dot-requirements.txt

COPY pyproject.toml README.md activate /app/
COPY marvain_cli /app/marvain_cli
COPY layers/shared/python/agent_hub /app/layers/shared/python/agent_hub
COPY tapdb_templates /app/tapdb_templates

ARG MARVAIN_RELEASE_VERSION
RUN SETUPTOOLS_SCM_PRETEND_VERSION_FOR_MARVAIN="${MARVAIN_RELEASE_VERSION:?set the final Marvain release tag}" \
    conda run -n marvain python -m pip install --no-cache-dir --no-deps /app \
    && useradd --create-home --uid 10001 --user-group marvain

USER marvain
EXPOSE 8000

CMD ["/bin/bash", "-c", "source ./activate && exec marvain dot serve --binding-secret-arn \"${MARVAIN_DOT_BINDING_SECRET_ARN:?required}\" --resource-uri \"${MARVAIN_DOT_RESOURCE_URI:?required}\" --host 0.0.0.0 --port 8000"]
