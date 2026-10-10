# syntax=docker/dockerfile:1
# One image runs both processes:
#   api:    uvicorn api.main:create_app --factory --host 0.0.0.0 --port 8000
#   worker: python -m core.worker
ARG PYTHON_IMAGE=python:3.12-slim
FROM ${PYTHON_IMAGE} AS base

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# git is needed by the archaeology runbook to clone client repositories.
RUN apt-get update \
    && apt-get install -y --no-install-recommends git ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.lock ./
RUN pip install -r requirements.lock

RUN useradd --create-home --uid 10001 agency \
    && mkdir -p /data \
    && chown agency:agency /data

COPY --chown=agency:agency api ./api
COPY --chown=agency:agency core ./core
COPY --chown=agency:agency vendor/agency-agents ./vendor/agency-agents
COPY --chown=agency:agency pyproject.toml ./

USER agency
ENV AGENCY_STORAGE_ROOT=/data \
    AGENCY_DATABASE_PATH=/data/database.db
VOLUME ["/data"]
EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/readyz', timeout=4).status == 200 else 1)"

CMD ["uvicorn", "api.main:create_app", "--factory", "--host", "0.0.0.0", "--port", "8000", "--proxy-headers"]
