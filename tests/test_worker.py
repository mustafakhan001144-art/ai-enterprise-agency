"""The durable job worker: claiming, leases, retries, refunds and result access."""

import asyncio
import shutil
import sqlite3
from datetime import UTC, datetime, timedelta

import pytest

from core.registry import AgentRegistry, default_registry
from core.worker import Worker
from core.workflows.archaeology import FetchError
from tests.fixtures.samples import FORENSICS_INCIDENT, write_legacy_repo


def auth(key: str) -> dict:
    return {"Authorization": f"Bearer {key}"}


def job_row(settings, job_id: str) -> dict:
    with sqlite3.connect(settings.database_path) as conn:
        conn.row_factory = sqlite3.Row
        return dict(conn.execute("SELECT * FROM jobs WHERE id = ?", (job_id,)).fetchone())


def ledger(settings, job_id: str) -> list[tuple[str, int]]:
    with sqlite3.connect(settings.database_path) as conn:
        return conn.execute(
            "SELECT reason, delta FROM credit_ledger WHERE job_id = ? ORDER BY id", (job_id,)
        ).fetchall()


def submit_forensics(client, key: str) -> str:
    response = client.post("/api/v1/forensics/contain", json=FORENSICS_INCIDENT, headers=auth(key))
    assert response.status_code == 202, response.text
    return response.json()["job_id"]


def submit_audit(client, key: str) -> str:
    body = {"repo_url": "https://github.com/example/legacy.git"}
    response = client.post("/api/v1/archeology/audit", json=body, headers=auth(key))
    assert response.status_code == 202, response.text
    return response.json()["job_id"]


def fixture_fetcher(tmp_path):
    source = write_legacy_repo(tmp_path / "upstream-repo")

    def fetch(repo_url, ref, dest):
        shutil.copytree(source, dest)
        return "0" * 40

    return fetch


def failing_fetcher(repo_url, ref, dest):
    raise FetchError("git failed: could not resolve host")


@pytest.fixture
def worker(settings):
    return Worker(settings, default_registry(), worker_id="w1")


def run(coro):
    return asyncio.run(coro)


def test_worker_runs_forensics_job_and_result_is_served(client, make_account, settings, worker):
    _, key = make_account()
    job_id = submit_forensics(client, key)
    assert run(worker.run_once()) == "succeeded"
    assert run(worker.run_once()) is None  # queue is empty

    status = client.get(f"/api/v1/jobs/{job_id}", headers=auth(key)).json()
    assert status["status"] == "succeeded"
    assert status["attempts"] == 1
    assert status["result_url"] == f"/api/v1/jobs/{job_id}/result"

    result = client.get(status["result_url"], headers=auth(key))
    assert result.status_code == 200
    assert result.headers["X-Result-Digest"] == status["result_digest"]
    body = result.json()
    assert body["schema_version"] == "JobResult/v1"
    assert [s["stage_id"] for s in body["stages"]] == ["trace_analysis", "containment_plan"]
    assert body["outputs"]["trace_analysis"]["primary_class"] == "DATA_EXFILTRATION"
    assert body["outputs"]["containment_plan"]["tier"] == "T1_KILL"
    assert {a["agent_id"] for a in body["agents"]} == {
        "forensics.ai-trace-analyst",
        "forensics.agent-containment-specialist",
    }
    assert all(not s["self_validation_failed"] for s in body["stages"])
    job_dir = settings.jobs_dir / job_id
    assert (job_dir / "stages" / "01_trace_analysis.json").is_file()
    assert (job_dir / "stages" / "02_containment_plan.json").is_file()


def test_worker_runs_archaeology_job_and_deletes_client_source(client, make_account, settings, tmp_path):
    _, key = make_account()
    job_id = submit_audit(client, key)
    worker = Worker(settings, default_registry(), worker_id="w1", fetcher=fixture_fetcher(tmp_path))
    assert run(worker.run_once()) == "succeeded"
    body = client.get(f"/api/v1/jobs/{job_id}/result", headers=auth(key)).json()
    assert [s["stage_id"] for s in body["stages"]] == ["dependency_cartography", "code_archaeology"]
    units = {u["unit_id"] for u in body["outputs"]["code_archaeology"]["units"]}
    assert "app/main.py::fetch" in units
    assert body["outputs"]["dependency_cartography"]["repository"]["commit"] == "0" * 40
    assert not (settings.jobs_dir / job_id / "checkout").exists()


def test_result_is_not_available_before_the_job_runs(client, make_account):
    _, key = make_account()
    job_id = submit_forensics(client, key)
    response = client.get(f"/api/v1/jobs/{job_id}/result", headers=auth(key))
    assert response.status_code == 409


def test_other_tenant_cannot_read_status_or_result(client, make_account, worker):
    _, owner_key = make_account()
    _, other_key = make_account()
    job_id = submit_forensics(client, owner_key)
    assert run(worker.run_once()) == "succeeded"
    assert client.get(f"/api/v1/jobs/{job_id}", headers=auth(other_key)).status_code == 404
    assert client.get(f"/api/v1/jobs/{job_id}/result", headers=auth(other_key)).status_code == 404


def test_transient_failure_is_retried_then_failed_and_refunded(client, make_account, settings, account_row):
    account_id, key = make_account(quota=100)
    job_id = submit_audit(client, key)
    assert account_row(account_id)["credits_used"] == settings.archeology_audit_credits
    worker = Worker(settings, default_registry(), worker_id="w1", fetcher=failing_fetcher)

    for attempt in range(1, settings.worker_max_attempts):
        assert run(worker.run_once()) == "queued"
        row = job_row(settings, job_id)
        assert row["attempts"] == attempt
        assert "could not resolve host" in row["error"]

    assert run(worker.run_once()) == "failed"
    row = job_row(settings, job_id)
    assert row["status"] == "failed"
    assert row["finished_at"] is not None
    assert account_row(account_id)["credits_used"] == 0
    assert ledger(settings, job_id) == [
        ("job_debit", -settings.archeology_audit_credits),
        ("job_refund", settings.archeology_audit_credits),
    ]


def test_missing_agent_fails_permanently_on_first_attempt(client, make_account, settings, account_row, tmp_path):
    account_id, key = make_account()
    job_id = submit_forensics(client, key)
    empty = tmp_path / "no-agents"
    empty.mkdir()
    worker = Worker(settings, AgentRegistry(empty, None), worker_id="w1")
    assert run(worker.run_once()) == "failed"
    row = job_row(settings, job_id)
    assert row["attempts"] == 1
    assert "not found in registry" in row["error"]
    assert account_row(account_id)["credits_used"] == 0


def test_only_one_worker_claims_a_job(client, make_account, settings):
    _, key = make_account()
    submit_forensics(client, key)
    workers = [Worker(settings, default_registry(), worker_id=f"w{i}") for i in range(5)]

    async def claim_all():
        return await asyncio.gather(*(w.claim() for w in workers))

    claims = [c for c in run(claim_all()) if c is not None]
    assert len(claims) == 1


def test_expired_lease_is_taken_over_and_old_worker_is_fenced(client, make_account, settings):
    _, key = make_account()
    job_id = submit_forensics(client, key)
    dead = Worker(settings, default_registry(), worker_id="dead")
    claimed = run(dead.claim())
    assert claimed["id"] == job_id

    live = Worker(settings, default_registry(), worker_id="live")
    assert run(live.claim()) is None  # lease still valid

    past = (datetime.now(UTC) - timedelta(seconds=1)).isoformat(timespec="seconds")
    with sqlite3.connect(settings.database_path) as conn:
        conn.execute("UPDATE jobs SET lease_expires_at = ? WHERE id = ?", (past, job_id))

    taken = run(live.claim())
    assert taken["id"] == job_id and taken["attempts"] == 2
    assert run(live.process(taken)) == "succeeded"
    # The dead worker wakes up and tries to record an outcome: it no longer owns the lease.
    assert run(dead.process(claimed)) == ""
    row = job_row(settings, job_id)
    assert row["status"] == "succeeded" and row["lease_owner"] is None


def test_job_abandoned_on_its_last_attempt_is_failed_and_refunded(client, make_account, settings, account_row):
    account_id, key = make_account()
    job_id = submit_forensics(client, key)
    with sqlite3.connect(settings.database_path) as conn:
        conn.execute(
            "UPDATE jobs SET status = 'running', attempts = ?, lease_owner = 'gone', lease_expires_at = ? WHERE id = ?",
            (settings.worker_max_attempts, "2000-01-01T00:00:00+00:00", job_id),
        )
    worker = Worker(settings, default_registry(), worker_id="w1")
    assert run(worker.run_once()) == "failed"
    assert account_row(account_id)["credits_used"] == 0
    assert ("job_refund", job_row(settings, job_id)["credits_charged"]) in ledger(settings, job_id)


def test_jobs_are_claimed_oldest_first(client, make_account, settings, worker):
    _, key = make_account()
    first = submit_forensics(client, key)
    second = submit_forensics(client, key)
    with sqlite3.connect(settings.database_path) as conn:
        conn.execute("UPDATE jobs SET created_at = '2026-01-01T00:00:00+00:00' WHERE id = ?", (first,))
        conn.execute("UPDATE jobs SET created_at = '2026-01-02T00:00:00+00:00' WHERE id = ?", (second,))
    assert run(worker.claim())["id"] == first
