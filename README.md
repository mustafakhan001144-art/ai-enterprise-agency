# AI Enterprise Agency

Subscription API for AI-agent forensics and legacy-code archaeology. A FastAPI
gateway authenticates API keys, meters credits against Stripe subscription
state, and queues jobs that the core engine's orchestrator will execute.

## What is here

| Path | Contents |
|---|---|
| `api/main.py` | App factory, lifespan (DB init, Stripe key), `/healthz` |
| `api/settings.py` | `AGENCY_*` environment settings (pydantic-settings) |
| `api/db.py` | SQLite schema: accounts, hashed API keys, Stripe events, jobs; atomic credit debit |
| `api/middleware/` | API-key + subscription gate, request body size limit |
| `api/routes/` | `forensics/contain`, `archeology/audit`, `jobs/{id}`, `webhooks/stripe` |
| `vendor/agency-agents/` | Upstream agent library ([msitarzewski/agency-agents](https://github.com/msitarzewski/agency-agents), MIT), pinned git submodule |
| `core/agents/` | Specialist personas: forensics (2), archaeology (2); management and marketing divisions are placeholders |
| `tests/` | Gateway, auth, tenant isolation, metering, validation and Stripe webhook tests |

Not yet implemented: the orchestrator that executes queued jobs, the dynamic
agent registry, and the management and marketing personas.

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
```

Windows PowerShell:

```powershell
git submodule update --init --recursive
py -3.11 -m venv .venv; .\.venv\Scripts\Activate.ps1
pip install -r requirements.lock
Copy-Item .env.example .env   # then edit with Stripe TEST keys
pytest -q
uvicorn api.main:app --reload --port 8000
```

Open http://localhost:8000/docs (disabled when `AGENCY_ENVIRONMENT=production`).

More: [development workflow](docs/DEVELOPMENT_WORKFLOW.md),
[Windows recovery](docs/WINDOWS_RECOVERY.md),
[upstream agents](docs/UPSTREAM_AGENTS.md).
