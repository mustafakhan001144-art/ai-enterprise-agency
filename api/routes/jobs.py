"""Job intake shared by the forensics and archeology routes, plus job status lookup.

The gateway only meters, persists and queues work. The worker (core/worker.py)
claims `queued` jobs and runs their runbook through core/orchestrator.py.
"""

import json
import math
from pathlib import Path
from typing import Annotated

from fastapi import APIRouter, HTTPException, Query, Request, status
from fastapi.responses import JSONResponse, PlainTextResponse

from api.db import connect, debit_credits, new_id, now_iso
from api.middleware.auth import Principal, Subscriber
from api.schemas import JobAccepted, JobPage, JobStatus, JobSummary
from core.evidence import verify_manifest

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


JOB_COLUMNS = (
    "id, kind, runbook, status, credits_charged, attempts, error, result_digest, result_path, evidence_head, "
    "created_at, updated_at, started_at, finished_at"
)


async def _own_job(request: Request, principal: Principal, job_id: str):
    async with connect(request.app.state.settings.database_path) as conn:
        cursor = await conn.execute(
            f"SELECT {JOB_COLUMNS} FROM jobs WHERE id = ? AND account_id = ?",
            (job_id, principal.account_id),
        )
        row = await cursor.fetchone()
    if row is None:
        # Another tenant's job is indistinguishable from a missing one.
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="job not found")
    return row


@router.get("/{job_id}", response_model=JobStatus)
async def get_job(job_id: str, request: Request, principal: Subscriber) -> JobStatus:
    row = await _own_job(request, principal, job_id)
    fields = {k: row[k] for k in row.keys() if k not in ("id", "result_path", "evidence_head")}
    result_url = f"/api/v1/jobs/{job_id}/result" if row["status"] == "succeeded" else None
    return JobStatus(job_id=row["id"], result_url=result_url, **fields)


def _finished_job_dir(request: Request, row, job_id: str) -> Path:
    if row["status"] != "succeeded" or not row["result_path"]:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=f"job is {row['status']}, no result yet")
    jobs_root = request.app.state.settings.jobs_dir.resolve()
    job_dir = Path(row["result_path"]).resolve().parent
    if job_dir != (jobs_root / job_id).resolve() or not job_dir.is_dir():
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="result files missing")
    return job_dir


@router.get("/{job_id}/result")
async def get_job_result(job_id: str, request: Request, principal: Subscriber) -> JSONResponse:
    """The JobResult/v1 document for a succeeded job: every stage report plus their digests."""
    row = await _own_job(request, principal, job_id)
    path = _finished_job_dir(request, row, job_id) / "result.json"
    if not path.is_file():
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="result file missing")
    body = json.loads(path.read_text(encoding="utf-8"))
    return JSONResponse(body, headers={"X-Result-Digest": row["result_digest"] or ""})


@router.get("/{job_id}/report", response_class=PlainTextResponse)
async def get_job_report(job_id: str, request: Request, principal: Subscriber) -> PlainTextResponse:
    """The human-readable Markdown report rendered from the job result."""
    row = await _own_job(request, principal, job_id)
    path = _finished_job_dir(request, row, job_id) / "report.md"
    if not path.is_file():
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="report missing")
    return PlainTextResponse(path.read_text(encoding="utf-8"), media_type="text/markdown; charset=utf-8")


@router.get("/{job_id}/evidence")
async def get_job_evidence(job_id: str, request: Request, principal: Subscriber) -> JSONResponse:
    """The hash-chained evidence manifest, re-verified against the files on disk."""
    row = await _own_job(request, principal, job_id)
    job_dir = _finished_job_dir(request, row, job_id)
    verification = verify_manifest(job_dir, expected_head=row["evidence_head"])
    manifest_path = job_dir / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8")) if manifest_path.is_file() else None
    return JSONResponse(
        {"job_id": job_id, "recorded_head": row["evidence_head"], "verification": verification, "manifest": manifest}
    )
