# syntax=docker/dockerfile:1.7

FROM python:3.12-slim AS build

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /build
COPY security-engine-python/pyproject.toml ./security-engine-python/pyproject.toml
COPY security-engine-python/agentshield ./security-engine-python/agentshield

RUN python -m pip wheel \
    --wheel-dir /wheels \
    "/build/security-engine-python[api,kafka,otel,graph,mcp,llm,langfuse]"

FROM python:3.12-slim AS runtime

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    AGENTSHIELD_DATASETS=/app/datasets

RUN groupadd --gid 10001 agentshield \
    && useradd --uid 10001 --gid agentshield --create-home --shell /usr/sbin/nologin agentshield

COPY --from=build /wheels /wheels
RUN python -m pip install \
    --no-index \
    --find-links=/wheels \
    "agentshield-engine[api,kafka,otel,graph,mcp,llm,langfuse]==0.1.0" \
    && rm -rf /wheels

WORKDIR /app
COPY --chown=agentshield:agentshield datasets /app/datasets

USER agentshield

EXPOSE 8081

HEALTHCHECK --interval=10s --timeout=3s --start-period=10s --retries=10 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8081/health', timeout=2)"

CMD ["python", "-m", "agentshield.api.app"]
