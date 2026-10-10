# AI Enterprise Agency

Subscription API for AI-agent forensics and legacy-code archaeology. A FastAPI
gateway authenticates API keys, meters credits against Stripe subscription
state and queues jobs. A separate worker process runs each job's runbook and
stores a result, a readable report and a hash-chained evidence manifest.

## What is here

| Path | Contents |
|---|---|
| `api/main.py` | App factory, lifespan (DB migrations, Stripe key), `/healthz`, `/readyz` |
| `api/settings.py` | `AGENCY_*` settings; live Stripe keys refused outside production |
| `api/db.py` | Versioned SQLite schema, hashed API keys, atomic credit debit, credit ledger |
| `api/admin.py` | CLI: create accounts, issue and revoke keys, set subscriptions |
| `api/routes/` | `forensics/contain`, `archeology/audit`, `jobs` (status, result, report, evidence), `agents`, `account`, `webhooks/stripe` |
| `core/registry.py` | Agent registry: the custom personas plus the vendored upstream library |
| `core/workflows/` | Deterministic implementations of the four custom agents' procedures |
| `core/orchestrator.py`, `core/worker.py` | Runbooks and the durable, lease-based job worker |
| `core/evidence.py` | `report.md` and the hash-chained `manifest.json` for each finished job |
| `core/agents/` | Personas: forensics (2), archaeology (2); management and marketing are empty |
| `vendor/agency-agents/` | Upstream agent library ([msitarzewski/agency-agents](https://github.com/msitarzewski/agency-agents), MIT), pinned git submodule |
| `tests/` | Unit, API, worker, evidence, Stripe and adversarial tests |

Known limits: the workflows are deterministic rule implementations and call no
language model; the management and marketing divisions have no agents yet.

## Quick start

Requires **Python 3.11 or 3.12** (CI tests both).

Linux / macOS:

```bash
git submodule update --init --recursive
python3.11 -m venv .venv && source .venv/bin/activate
pip install -r requirements.lock
cp .env.example .env          # then edit with Stripe TEST keys
pytest -q
uvicorn api.main:app --reload --port 8000
python -m core.worker          # in a second terminal: runs queued jobs
```

Windows PowerShell:

```powershell
git submodule update --init --recursive
py -3.11 -m venv .venv; .\.venv\Scripts\Activate.ps1
pip install -r requirements.lock
Copy-Item .env.example .env   # then edit with Stripe TEST keys
pytest -q
uvicorn api.main:app --reload --port 8000
python -m core.worker          # in a second terminal: runs queued jobs
```

With Docker: `docker compose up --build` (API on http://127.0.0.1:8000 plus one worker).

Open http://localhost:8000/docs (disabled when `AGENCY_ENVIRONMENT=production`).

More: [operations](docs/OPERATIONS.md),
[Stripe test mode](docs/STRIPE_TEST_MODE.md),
[development workflow](docs/DEVELOPMENT_WORKFLOW.md),
[Windows recovery](docs/WINDOWS_RECOVERY.md),
[upstream agents](docs/UPSTREAM_AGENTS.md).
