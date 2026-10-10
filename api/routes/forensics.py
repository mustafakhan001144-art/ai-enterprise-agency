"""POST /api/v1/forensics/contain: accept raw telemetry from a third-party agent."""

from fastapi import APIRouter, Request, status

from api.middleware.auth import Subscriber
from api.routes.jobs import credits_for_bytes, enqueue_job
from api.schemas import ForensicsContainRequest, JobAccepted

router = APIRouter(prefix="/api/v1/forensics", tags=["forensics"])


@router.post("/contain", response_model=JobAccepted, status_code=status.HTTP_202_ACCEPTED)
async def contain(body: ForensicsContainRequest, request: Request, principal: Subscriber) -> JobAccepted:
    """Queue a trace analysis + containment plan for the submitted logs.

    The result is a recommended plan only: every action requires a human
    operator's approval and nothing is executed against the client's systems.
    """
    size = int(request.headers["content-length"])
    credits = credits_for_bytes(size, request.app.state.settings.forensics_bytes_per_credit)
    return await enqueue_job(
        request,
        principal,
        kind="forensics_contain",
        runbook="forensic_incident_response",
        credits=credits,
        payload=body.model_dump(mode="json"),
    )
