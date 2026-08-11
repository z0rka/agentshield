"""The security engine as a service.

The control plane drives scans over Kafka; this HTTP surface exists for what Kafka is the
wrong shape for: health, capability discovery during target validation, cancellation, and a
synchronous scan endpoint that the CLI and the tests use.

This module now does one thing - assemble the application. Handlers live in `routes`, request
bodies in `schemas`, in-flight bookkeeping in `runtime`.
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager, suppress

from fastapi import FastAPI

from agentshield import __version__
from agentshield.api.routes import router
from agentshield.api.runtime import RunningScans
from agentshield.config import EngineSettings
from agentshield.telemetry import configure_logging, configure_tracing


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    """Start the Kafka worker alongside the API when a broker is configured.

    One process serves both roles in the local stack, which keeps the developer setup to two
    terminals. In a real deployment they are separate containers driven by the same code - 
    `agentshield-engine-worker` runs the consumer without the HTTP surface.
    """
    settings: EngineSettings = app.state.settings
    configure_logging(settings.log_level)
    configure_tracing(settings.otel_endpoint, service_name=settings.service_name)

    worker_task: asyncio.Task[None] | None = None
    if settings.kafka_bootstrap_servers:
        from agentshield.messaging.worker import run_worker_forever

        worker_task = asyncio.create_task(
            run_worker_forever(settings, running=app.state.running.as_dict()),
            name="agentshield-kafka-worker",
        )

    try:
        yield
    finally:
        # Cancel cooperatively so in-flight scenarios finish instead of leaving a target
        # holding session state that the next scan would inherit.
        app.state.running.cancel_all()
        if worker_task is not None:
            worker_task.cancel()
            with suppress(asyncio.CancelledError):
                await worker_task


def create_app(settings: EngineSettings | None = None) -> FastAPI:
    """Build the application.

    Settings are a parameter so a test can construct an app with a different concurrency
    ceiling or no broker, instead of mutating the environment and hoping nothing else read it.
    """
    resolved = settings or EngineSettings.from_env()
    app = FastAPI(
        title="AgentShield security engine",
        version=__version__,
        lifespan=lifespan,
        description="Executes attack scenarios and evaluates agent trajectories.",
    )
    app.state.settings = resolved
    app.state.running = RunningScans()
    app.include_router(router)
    return app


app = create_app()


def main() -> None:
    import uvicorn

    settings = EngineSettings.from_env()
    uvicorn.run(app, host="0.0.0.0", port=settings.port)  # noqa: S104 - containerised


if __name__ == "__main__":
    main()
