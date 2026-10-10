"""POST /api/v1/archeology/audit: queue a static audit of a client repository."""

from urllib.parse import urlsplit

from fastapi import APIRouter, HTTPException, Request, status

from api.middleware.auth import Subscriber
from api.routes.jobs import enqueue_job
from api.schemas import ArcheologyAuditRequest, JobAccepted

router = APIRouter(prefix="/api/v1/archeology", tags=["archeology"])


@router.post("/audit", response_model=JobAccepted, status_code=status.HTTP_202_ACCEPTED)
async def audit(body: ArcheologyAuditRequest, request: Request, principal: Subscriber) -> JobAccepted:
    """Queue a dependency cartography + archaeology sweep.

    Only HTTPS URLs on allow-listed git hosts are accepted. Local filesystem
    paths are refused: the engine clones into its own sandbox and never reads
    paths on the server.
    """
    settings = request.app.state.settings
    host = (urlsplit(body.repo_url).hostname or "").lower()
    if host not in settings.allowed_git_hosts:
        raise HTTPException(
            status_code=422,
            detail=f"repo host '{host}' is not allowed; allowed: {sorted(settings.allowed_git_hosts)}",
        )
    return await enqueue_job(
        request,
        principal,
        kind="archeology_audit",
        runbook="legacy_archeology_sweep",
        credits=settings.archeology_audit_credits,
        payload=body.model_dump(mode="json"),
    )
