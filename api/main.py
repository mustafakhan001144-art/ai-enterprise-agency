"""Public API gateway for the AI Enterprise Agency.

Run locally:  uvicorn api.main:create_app --factory --host 0.0.0.0 --port 8000
(`uvicorn api.main:app` also works; the app is built on first access.)
"""

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

import stripe
from fastapi import FastAPI
from fastapi.responses import JSONResponse

from api.db import connect, init_db
from api.middleware.body_limit import BodySizeLimitMiddleware
from api.routes import account, archeology, forensics, jobs, stripe_webhooks
from api.settings import GatewaySettings, get_settings


def create_app(settings: GatewaySettings | None = None) -> FastAPI:
    settings = settings or get_settings()

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        stripe.api_key = settings.stripe_api_key.get_secret_value()
        settings.jobs_dir.mkdir(parents=True, exist_ok=True)
        await init_db(settings.database_path)
        yield

    app = FastAPI(
        title="AI Enterprise Agency API",
        version="1.1.0",
        lifespan=lifespan,
        docs_url=None if settings.environment == "production" else "/docs",
        redoc_url=None,
    )
    app.state.settings = settings
    app.add_middleware(BodySizeLimitMiddleware, max_bytes=settings.max_request_bytes)

    app.include_router(forensics.router)
    app.include_router(archeology.router)
    app.include_router(jobs.router)
    app.include_router(account.router)
    app.include_router(stripe_webhooks.router)

    @app.get("/healthz", tags=["ops"])
    async def healthz() -> dict:
        """Liveness: the process is serving requests."""
        return {"status": "ok"}

    @app.get("/readyz", tags=["ops"])
    async def readyz() -> JSONResponse:
        """Readiness: the database is reachable and migrated."""
        try:
            async with connect(settings.database_path) as conn:
                cursor = await conn.execute("PRAGMA user_version")
                version = (await cursor.fetchone())[0]
        except Exception as exc:  # pragma: no cover - exercised by the readiness test via a bad path
            return JSONResponse({"status": "unavailable", "detail": type(exc).__name__}, status_code=503)
        return JSONResponse({"status": "ready", "schema_version": version})

    return app


def __getattr__(name: str) -> FastAPI:
    # Built lazily so importing api.main (tests, tooling) never needs the environment.
    if name == "app":
        global app
        app = create_app()
        return app
    raise AttributeError(name)
