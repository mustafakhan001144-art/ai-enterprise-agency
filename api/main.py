"""Public API gateway for the AI Enterprise Agency.

Run locally:  uvicorn api.main:app --host 0.0.0.0 --port 8000
"""

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

import stripe
from fastapi import FastAPI

from api.db import init_db
from api.middleware.body_limit import BodySizeLimitMiddleware
from api.routes import archeology, forensics, jobs, stripe_webhooks
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
        version="1.0.0",
        lifespan=lifespan,
        docs_url=None if settings.environment == "production" else "/docs",
        redoc_url=None,
    )
    app.state.settings = settings
    app.add_middleware(BodySizeLimitMiddleware, max_bytes=settings.max_request_bytes)

    app.include_router(forensics.router)
    app.include_router(archeology.router)
    app.include_router(jobs.router)
    app.include_router(stripe_webhooks.router)

    @app.get("/healthz", tags=["ops"])
    async def healthz() -> dict:
        return {"status": "ok"}

    return app


app = create_app()
