# Demo targets.
#
# These applications are intentionally vulnerable. The image runs as a non-root user with no
# outbound network dependencies and every dangerous action mocked — but it is still a
# deliberately insecure application, so the compose file binds it to 127.0.0.1 only.

FROM python:3.12-slim AS base

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

COPY demo-targets/pyproject.toml /app/demo-targets/pyproject.toml
COPY demo-targets/demo_targets /app/demo-targets/demo_targets

RUN pip install --no-cache-dir /app/demo-targets \
    && useradd --create-home --uid 10001 demo

USER demo

EXPOSE 8090

HEALTHCHECK --interval=10s --timeout=3s --retries=5 \
    CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8090/health').status==200 else 1)"

CMD ["python", "-m", "demo_targets.vulnerable_support_agent", "--host", "0.0.0.0", "--port", "8090"]
