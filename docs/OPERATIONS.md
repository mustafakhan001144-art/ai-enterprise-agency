# Operations

## Processes

| Process | Command | Scales |
|---|---|---|
| API gateway | `uvicorn api.main:create_app --factory --host 0.0.0.0 --port 8000` | one per host (SQLite) |
| Job worker | `python -m core.worker` | several per host; each claims one job at a time |

Both read the same `AGENCY_*` settings and the same SQLite file. The worker
needs no Stripe keys. With Docker, `docker compose up --build` runs one API and
one worker sharing the `agency-data` volume; `docker compose up --scale worker=3`
adds workers.

## Health

- `GET /healthz`: the process is up.
- `GET /readyz`: the database opens and reports `schema_version`; returns 503 otherwise.
  The Docker image's `HEALTHCHECK` uses it.

## Configuration

| Setting | Default | Notes |
|---|---|---|
| `AGENCY_ENVIRONMENT` | `development` | `production` disables `/docs` and is the only mode that accepts live Stripe keys |
| `AGENCY_STORAGE_ROOT` | `storage` | job directories live in `<root>/code_sandboxes/<job_id>` |
| `AGENCY_DATABASE_PATH` | `storage/database.db` | WAL mode, migrated on startup |
| `AGENCY_STRIPE_API_KEY`, `AGENCY_STRIPE_WEBHOOK_SECRET` | required for the API | see [Stripe test mode](STRIPE_TEST_MODE.md) |
| `AGENCY_PLAN_CREDITS` | `{}` | JSON map of Stripe Price ID to monthly credits |
| `AGENCY_WORKER_LEASE_SECONDS` | `300` | a worker that stops renewing loses the job after this |
| `AGENCY_WORKER_MAX_ATTEMPTS` | `3` | then the job fails and its credits are refunded |
| `AGENCY_WORKER_POLL_SECONDS` | `2.0` | idle wait between queue checks |
| `AGENCY_ALLOWED_GIT_HOSTS` | github.com, gitlab.com, bitbucket.org | hosts accepted for archaeology audits |

## Job lifecycle

`queued` → `running` (claimed, lease held) → `succeeded` or back to `queued`
(transient error, attempts left) → `failed` (attempts exhausted or a permanent
error such as a missing agent). Credits are debited at submission and refunded
in the same transaction that marks a job `failed`; both appear in
`GET /api/v1/account/ledger`.

A worker killed mid-job leaves the job `running` until its lease expires; the
next worker then takes it over and counts a new attempt. A worker that comes
back after losing its lease cannot overwrite the newer outcome.

## Schema migrations

Migrations are numbered in `api/db.py` and applied on API and worker startup
inside one transaction each. A database newer than the code is refused. Back
up the database file (and its `-wal` file) before upgrading:

```
sqlite3 /data/database.db ".backup '/backups/database-$(date +%F).db'"
```

## Evidence and retention

Each job directory holds `request.json`, `stages/*.json`, `result.json`,
`report.md` and `manifest.json`. Cloned client repositories are deleted as soon
as the archaeology stage has read them. `GET /api/v1/jobs/{id}/evidence`
re-hashes the files and compares the chain head with the value stored when the
job finished.

Job directories contain client data. Delete them on the schedule your
contracts require; deleting a directory makes that job's result and report
return 404 but leaves its billing history intact.

## Accounts and keys

```
python -m api.admin create-account --email ops@example.com --quota 100 --status active
python -m api.admin issue-key --account <account_id> --label laptop   # prints the key once
python -m api.admin revoke-key --prefix aea_XXXXXX
python -m api.admin list-accounts
```

Only the SHA-256 of a key is stored. A lost key cannot be recovered; issue a
new one and revoke the old prefix.

## CI

`.github/workflows/ci.yml` runs ruff and the test suite on Python 3.11 and
3.12, refuses tracked secrets and databases, then builds the Docker image and
runs `scripts/docker_smoke.sh`: the API and a worker container process a real
job and the evidence must verify.
