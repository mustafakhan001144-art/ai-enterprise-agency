# AI Enterprise Agency

Subscription API for AI-agent forensics and legacy-code archaeology. A FastAPI
gateway authenticates API keys, meters credits against Stripe subscription
state and queues jobs. A separate worker process runs each job's runbook and
stores a result, a readable report and a hash-chained evidence manifest. A web
dashboard served by the API at http://127.0.0.1:8000/ lets you run audits and
read the results.

Every job runs the specialists' stages, then three governance stages shared by
all runbooks: the management division's **quality review** (RELEASE,
RELEASE_WITH_CAVEATS or HOLD) and **executive brief**, and the marketing
division's **follow-up proposal**. With an Anthropic key configured, a fourth
optional stage asks Claude for a plain-language client summary.

## What is here

| Path | Contents |
|---|---|
| `api/main.py` | App factory, lifespan (DB migrations, Stripe key), `/healthz`, `/readyz` |
| `api/settings.py` | `AGENCY_*` settings; live Stripe keys refused outside production |
| `api/db.py` | Versioned SQLite schema, hashed API keys, atomic credit debit, credit ledger |
| `api/admin.py` | CLI: create accounts, issue and revoke keys, set subscriptions |
| `api/routes/` | `forensics/contain`, `archeology/audit`, `jobs` (status, result, report, evidence), `agents`, `account`, `webhooks/stripe` |
| `core/registry.py` | Agent registry: the custom personas plus the vendored upstream library |
| `core/workflows/` | Deterministic implementations of the custom agents' procedures (forensics, archaeology, management, marketing) |
| `core/llm.py` | Optional Claude-written client summary; off unless `AGENCY_LLM_PROVIDER=anthropic` |
| `api/dashboard/`, `api/routes/dashboard.py` | The web dashboard (plain HTML/JS, no build step) |
| `core/orchestrator.py`, `core/worker.py` | Runbooks and the durable, lease-based job worker |
| `core/evidence.py` | `report.md` and the hash-chained `manifest.json` for each finished job |
| `core/agents/` | Personas: forensics (2), archaeology (2), management (2), marketing (2) |
| `vendor/agency-agents/` | Upstream agent library ([msitarzewski/agency-agents](https://github.com/msitarzewski/agency-agents), MIT), pinned git submodule |
| `tests/` | Unit, API, worker, evidence, Stripe and adversarial tests |

Known limits: the technical findings come from deterministic rule implementations,
not a language model. The only model call is the optional client summary, which
rewords the executive brief and proposal and adds no findings.

## See it running (Windows, one command)

From the repository folder, e.g. `D:\ai-enterprise-agency`:

```powershell
git submodule update --init --recursive
powershell -ExecutionPolicy Bypass -File scripts\run-local.ps1
```

It creates `.venv` and `.env` if they are missing, makes a demo account with 500
credits, opens the API and the worker in two windows and opens the dashboard. The
demo API key is copied to the clipboard (and saved in `storage\demo-key.txt`):
paste it, press **Connect**, then **Run forensics** on the sample incident. The
brief, full report and evidence verification appear within a few seconds.

## Quick start

Requires **Python 3.11 or 3.12** (CI tests both).

Linux / macOS:

```bash
git submodule update --init --recursive
python3.11 -m venv .venv && source .venv/bin/activate
pip install -r requirements.lock
cp .env.example .env          # then edit with Stripe TEST keys
pytest -q
python -m api.admin demo       # prints an API key for an account with 500 credits
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
python -m api.admin demo       # prints an API key for an account with 500 credits
uvicorn api.main:app --reload --port 8000
python -m core.worker          # in a second terminal: runs queued jobs
```

With Docker: `docker compose up --build` (API on http://127.0.0.1:8000 plus one worker),
then `docker compose exec api python -m api.admin demo` for a key.

Open http://127.0.0.1:8000/ for the dashboard and http://127.0.0.1:8000/docs for the
API reference (docs are disabled when `AGENCY_ENVIRONMENT=production`).

To add the Claude-written client summary, set `AGENCY_LLM_PROVIDER=anthropic` and
`ANTHROPIC_API_KEY` in `.env` and restart the worker.

More: [operations](docs/OPERATIONS.md),
[Stripe test mode](docs/STRIPE_TEST_MODE.md),
[development workflow](docs/DEVELOPMENT_WORKFLOW.md),
[Windows recovery](docs/WINDOWS_RECOVERY.md),
[upstream agents](docs/UPSTREAM_AGENTS.md).
