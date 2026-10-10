"""Job intake shared by the forensics and archeology routes, plus job status lookup.

The gateway only meters, persists and queues work. Execution belongs to the
orchestrator (Phase 3), which picks up `queued` jobs and runs their runbook.
"""

import json
import math
from typing import Annotated

from fastapi import APIRouter, HTTPException, Query, Request, status

from api.db import connect, debit_credits, new_id, now_iso
from api.middleware.auth import Principal, Subscriber
from api.schemas import JobAccepted, JobPage, JobStatus, JobSummary

router = APIRouter(prefix="/api/v1/jobs", tags=["jobs"])


def credits_for_bytes(size: int, bytes_per_credit: int) -> int:
    return max(1, math.ceil(size / bytes_per_credit))


async def enqueue_job(
    request: Request,
    principal: Principal,
    *,
    kind: str,
    runbook: str,
    credits: int,
    payload: dict,
) -> JobAccepted:
    settings = request.app.state.settings
    job_id = new_id()
    job_dir = settings.jobs_dir / job_id
    request_path = job_dir / "request.json"

    async with connect(settings.database_path) as conn:
        await conn.execute("BEGIN IMMEDIATE")
        timestamp = now_iso()
        await conn.execute(
            "INSERT INTO jobs (id, account_id, kind, runbook, status, credits_charged, "
            "request_path, created_at, updated_at) VALUES (?, ?, ?, ?, 'queued', ?, ?, ?, ?)",
            (job_id, principal.account_id, kind, runbook, credits, str(request_path), timestamp, timestamp),
        )
        if not await debit_credits(conn, principal.account_id, credits, job_id=job_id):
            await conn.rollback()
            raise HTTPException(
                status_code=status.HTTP_402_PAYMENT_REQUIRED,
                detail=f"insufficient credits: request needs {credits}, "
                f"{principal.credits_remaining} remaining this period",
            )
        job_dir.mkdir(parents=True, exist_ok=False)
        request_path.write_text(json.dumps(payload, sort_keys=True), encoding="utf-8")
        cursor = await conn.execute(
            "SELECT credit_quota - credits_used AS remaining FROM accounts WHERE id = ?",
            (principal.account_id,),
        )
        remaining = (await cursor.fetchone())["remaining"]
        await conn.commit()

    return JobAccepted(
        job_id=job_id,
        status="queued",
        runbook=runbook,
        credits_charged=credits,
        credits_remaining=remaining,
        status_url=f"/api/v1/jobs/{job_id}",
    )


@router.get("", response_model=JobPage)
async def list_jobs(
    request: Request,
    principal: Subscriber,
    limit: Annotated[int, Query(ge=1, le=100)] = 20,
    job_status: Annotated[str | None, Query(alias="status", pattern="^[a-z_]{1,20}$")] = None,
) -> JobPage:
    """This account's jobs, newest first. Other tenants' jobs are never visible."""
    async with connect(request.app.state.settings.database_path) as conn:
        rows = await (
            await conn.execute(
                "SELECT id, kind, runbook, status, credits_charged, created_at FROM jobs "
                "WHERE account_id = ? AND (? IS NULL OR status = ?) ORDER BY created_at DESC, id LIMIT ?",
                (principal.account_id, job_status, job_status, limit),
            )
        ).fetchall()
    return JobPage(jobs=[JobSummary(job_id=row["id"], **{k: row[k] for k in row.keys() if k != "id"}) for row in rows])


@router.get("/{job_id}", response_model=JobStatus)
async def get_job(job_id: str, request: Request, principal: Subscriber) -> JobStatus:
    async with connect(request.app.state.settings.database_path) as conn:
        cursor = await conn.execute(
            "SELECT id, kind, runbook, status, credits_charged, created_at, updated_at "
            "FROM jobs WHERE id = ? AND account_id = ?",
            (job_id, principal.account_id),
        )
        row = await cursor.fetchone()
    if row is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="job not found")
    return JobStatus(job_id=row["id"], **{k: row[k] for k in row.keys() if k != "id"})
