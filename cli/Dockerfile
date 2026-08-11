# syntax=docker/dockerfile:1.7

FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    AGENTSHIELD_DATASETS=/app/datasets

WORKDIR /app

COPY security-engine-python/pyproject.toml /app/security-engine-python/pyproject.toml
COPY security-engine-python/agentshield /app/security-engine-python/agentshield
COPY cli/pyproject.toml /app/cli/pyproject.toml
COPY cli/agentshield_cli /app/cli/agentshield_cli
COPY datasets /app/datasets

RUN python -m pip install /app/security-engine-python /app/cli \
    && groupadd --gid 10001 agentshield \
    && useradd --uid 10001 --gid agentshield --create-home --shell /usr/sbin/nologin agentshield \
    && chown -R agentshield:agentshield /app

USER agentshield

ENTRYPOINT ["agentshield"]
CMD ["--help"]
