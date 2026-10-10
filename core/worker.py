"""Durable job worker.

Jobs live in SQLite. A worker claims one job at a time with a single atomic
UPDATE ... RETURNING, so two workers never run the same job. The claim takes a
lease that the worker renews while the job runs; if the worker dies, the lease
expires and another worker picks the job up. Every claim counts as an attempt.
When attempts run out the job is marked ``failed`` and its credits are refunded
in the same transaction.

Completion and failure writes are fenced on ``lease_owner``: a worker that lost
its lease cannot overwrite the outcome recorded by the worker that took over.

Run with ``python -m core.worker`` (loop) or ``python -m core.worker --once``.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import os
import signal
import socket
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path

from api.db import connect, init_db, now_iso, refund_credits
from api.settings import CoreSettings, get_core_settings
from core.orchestrator import Fetcher, PermanentJobError, run_job
from core.registry import AgentRegistry, default_registry
from core.workflows import archaeology
from core.workflows.common import excerpt

log = logging.getLogger("agency.worker")

CLAIM_SQL = """
UPDATE jobs
SET status = 'running', attempts = attempts + 1, lease_owner = :owner, lease_expires_at = :expires,
    started_at = COALESCE(started_at, :now), updated_at = :now, error = NULL
WHERE id = (
    SELECT id FROM jobs
    WHERE status = 'queued' OR (status = 'running' AND lease_expires_at < :now)
    ORDER BY created_at, id
    LIMIT 1
)
RETURNING id, account_id, kind, runbook, request_path, attempts, credits_charged
"""


def _iso(moment: datetime) -> str:
    return moment.isoformat(timespec="seconds")


class Worker:
    def __init__(
        self,
        settings: CoreSettings,
        registry: AgentRegistry | None = None,
        *,
        worker_id: str | None = None,
        fetcher: Fetcher = archaeology.git_fetch,
    ):
        self.settings = settings
        self.registry = registry or default_registry()
        self.worker_id = worker_id or f"{socket.gethostname()}:{os.getpid()}:{uuid.uuid4().hex[:8]}"
        self.fetcher = fetcher

    def _expiry(self) -> str:
        return _iso(datetime.now(UTC) + timedelta(seconds=self.settings.worker_lease_seconds))

    async def claim(self) -> dict | None:
        async with connect(self.settings.database_path) as conn:
            await conn.execute("BEGIN IMMEDIATE")
            cursor = await conn.execute(
                CLAIM_SQL, {"owner": self.worker_id, "expires": self._expiry(), "now": now_iso()}
            )
            row = await cursor.fetchone()
            await cursor.close()
            await conn.commit()
        return dict(row) if row else None

    async def _heartbeat(self, job_id: str, stop: asyncio.Event) -> None:
        interval = max(1.0, self.settings.worker_lease_seconds / 3)
        while not stop.is_set():
            try:
                await asyncio.wait_for(stop.wait(), timeout=interval)
            except TimeoutError:
                async with connect(self.settings.database_path) as conn:
                    await conn.execute(
                        "UPDATE jobs SET lease_expires_at = ?, updated_at = ? WHERE id = ? AND lease_owner = ?",
                        (self._expiry(), now_iso(), job_id, self.worker_id),
                    )
                    await conn.commit()

    async def _finish(self, job: dict, *, result_path: Path, digest: str, evidence_head: str) -> bool:
        async with connect(self.settings.database_path) as conn:
            cursor = await conn.execute(
                "UPDATE jobs SET status = 'succeeded', result_path = ?, result_digest = ?, evidence_head = ?, "
                "finished_at = ?, "
                "updated_at = ?, lease_owner = NULL, lease_expires_at = NULL, error = NULL "
                "WHERE id = ? AND lease_owner = ? AND status = 'running'",
                (str(result_path), digest, evidence_head, now_iso(), now_iso(), job["id"], self.worker_id),
            )
            await conn.commit()
            return cursor.rowcount == 1

    async def _fail(self, job: dict, error: str, *, permanent: bool) -> str:
        """Requeue the job, or fail it and refund its credits. Returns the new status ('' if lease was lost)."""
        exhausted = permanent or job["attempts"] >= self.settings.worker_max_attempts
        new_status = "failed" if exhausted else "queued"
        timestamp = now_iso()
        async with connect(self.settings.database_path) as conn:
            await conn.execute("BEGIN IMMEDIATE")
            cursor = await conn.execute(
                "UPDATE jobs SET status = ?, error = ?, updated_at = ?, lease_owner = NULL, lease_expires_at = NULL, "
                "finished_at = CASE WHEN ? = 'failed' THEN ? ELSE finished_at END "
                "WHERE id = ? AND lease_owner = ? AND status = 'running'",
                (new_status, excerpt(error, 500), timestamp, new_status, timestamp, job["id"], self.worker_id),
            )
            if cursor.rowcount != 1:
                await conn.rollback()
                return ""
            if exhausted and job["credits_charged"]:
                await refund_credits(conn, job["account_id"], job["credits_charged"], job_id=job["id"])
            await conn.commit()
        return new_status

    async def process(self, job: dict) -> str:
        if job["attempts"] > self.settings.worker_max_attempts:
            # A previous worker died holding this job on its final attempt.
            return await self._fail(job, "attempts exhausted after lease expiry", permanent=True)
        stop = asyncio.Event()
        beat = asyncio.create_task(self._heartbeat(job["id"], stop))
        try:
            request_path = Path(job["request_path"])
            request = json.loads(request_path.read_text(encoding="utf-8"))
            outcome = await asyncio.to_thread(
                run_job, job["runbook"], request, request_path.parent, job["id"], self.registry, self.fetcher
            )
        except PermanentJobError as exc:
            log.warning("job %s failed permanently: %s", job["id"], exc)
            return await self._fail(job, str(exc), permanent=True)
        except Exception as exc:  # noqa: BLE001 - any engine error is recorded and retried
            log.exception("job %s attempt %s failed", job["id"], job["attempts"])
            return await self._fail(job, f"{type(exc).__name__}: {exc}", permanent=False)
        finally:
            stop.set()
            await beat
        if await self._finish(
            job, result_path=outcome.result_path, digest=outcome.result_digest, evidence_head=outcome.evidence_head
        ):
            return "succeeded"
        log.warning("job %s finished after its lease was taken over; result discarded", job["id"])
        return ""

    async def run_once(self) -> str | None:
        """Claim and run at most one job. Returns its new status, or None if nothing was queued."""
        job = await self.claim()
        if job is None:
            return None
        log.info("claimed job %s (%s, attempt %s)", job["id"], job["runbook"], job["attempts"])
        return await self.process(job)

    async def run_forever(self, stop: asyncio.Event) -> None:
        while not stop.is_set():
            outcome = await self.run_once()
            if outcome is None:
                try:
                    await asyncio.wait_for(stop.wait(), timeout=self.settings.worker_poll_seconds)
                except TimeoutError:
                    pass


async def _main(once: bool) -> int:
    settings = get_core_settings()
    await init_db(settings.database_path)
    worker = Worker(settings)
    snapshot = worker.registry.snapshot()
    for warning in snapshot.warnings:
        log.warning("registry: %s", warning)
    log.info("worker %s ready with %d agents", worker.worker_id, len(snapshot.agents))
    if once:
        await worker.run_once()
        return 0
    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGTERM, signal.SIGINT):
        try:
            loop.add_signal_handler(sig, stop.set)
        except NotImplementedError:
            # Windows event loops have no signal handlers; Ctrl+C raises KeyboardInterrupt instead.
            pass
    try:
        await worker.run_forever(stop)
    except (KeyboardInterrupt, asyncio.CancelledError):
        pass
    log.info("worker %s stopped", worker.worker_id)
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Run queued AI Audit Agency jobs.")
    parser.add_argument("--once", action="store_true", help="run at most one job and exit")
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    try:
        return asyncio.run(_main(args.once))
    except KeyboardInterrupt:
        log.info("worker interrupted")
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
