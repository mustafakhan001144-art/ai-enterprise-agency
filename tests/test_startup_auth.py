"""Startup, schema migrations, the admin CLI, API key handling and tenant isolation."""

import json
import sqlite3
import subprocess
import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from api import admin
from api.db import SCHEMA_VERSION, hash_api_key
from api.main import create_app

REPO_ROOT = Path(__file__).resolve().parents[1]
FORENSICS_BODY = {
    "subject": {"agent_name": "billing-bot", "runtime": "langgraph"},
    "artifacts": [{"artifact_id": "a1", "kind": "tool_log", "content": "tool=http_get url=https://x"}],
}

# The v1 schema exactly as databases created before versioning have it.
LEGACY_V1_SCHEMA = """
CREATE TABLE accounts (id TEXT PRIMARY KEY, email TEXT NOT NULL, stripe_customer_id TEXT UNIQUE,
  subscription_status TEXT NOT NULL DEFAULT 'inactive', stripe_price_id TEXT,
  credit_quota INTEGER NOT NULL DEFAULT 0, credits_used INTEGER NOT NULL DEFAULT 0, updated_at TEXT NOT NULL);
CREATE TABLE api_keys (key_hash TEXT PRIMARY KEY, account_id TEXT NOT NULL REFERENCES accounts(id),
  revoked INTEGER NOT NULL DEFAULT 0, created_at TEXT NOT NULL);
CREATE TABLE stripe_events (event_id TEXT PRIMARY KEY, event_type TEXT NOT NULL, processed_at TEXT NOT NULL);
CREATE TABLE jobs (id TEXT PRIMARY KEY, account_id TEXT NOT NULL REFERENCES accounts(id), kind TEXT NOT NULL,
  runbook TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'queued', credits_charged INTEGER NOT NULL,
  request_path TEXT NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL);
INSERT INTO accounts VALUES ('acct-old', 'old@example.test', NULL, 'active', NULL, 50, 5, '2026-01-01T00:00:00+00:00');
"""


def auth(key: str) -> dict:
    return {"Authorization": f"Bearer {key}"}


def user_version(path: Path) -> int:
    with sqlite3.connect(path) as conn:
        return conn.execute("PRAGMA user_version").fetchone()[0]


def test_importing_api_main_needs_no_environment():
    env = {"PATH": "/usr/bin:/bin", "PYTHONPATH": str(REPO_ROOT)}
    result = subprocess.run(
        [sys.executable, "-c", "import api.main; print('ok')"],
        cwd="/", env=env, capture_output=True, text=True, check=False,
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "ok"


def test_missing_stripe_settings_fail_with_named_fields():
    env = {"PATH": "/usr/bin:/bin", "PYTHONPATH": str(REPO_ROOT)}
    result = subprocess.run(
        [sys.executable, "-c", "from api.main import app"],
        cwd="/", env=env, capture_output=True, text=True, check=False,
    )
    assert result.returncode != 0
    assert "stripe_api_key" in result.stderr
    assert "stripe_webhook_secret" in result.stderr


def test_fresh_database_is_fully_migrated(client, settings):
    assert user_version(settings.database_path) == SCHEMA_VERSION
    assert client.get("/readyz").json() == {"status": "ready", "schema_version": SCHEMA_VERSION}


def test_restart_is_idempotent(settings):
    for _ in range(3):
        with TestClient(create_app(settings)) as c:
            assert c.get("/healthz").status_code == 200
    assert user_version(settings.database_path) == SCHEMA_VERSION


def test_unversioned_legacy_database_is_upgraded_in_place(settings):
    settings.database_path.parent.mkdir(parents=True)
    with sqlite3.connect(settings.database_path) as conn:
        conn.executescript(LEGACY_V1_SCHEMA)
    with TestClient(create_app(settings)) as c:
        assert c.get("/readyz").json()["schema_version"] == SCHEMA_VERSION
    with sqlite3.connect(settings.database_path) as conn:
        assert conn.execute("SELECT credits_used FROM accounts WHERE id = 'acct-old'").fetchone() == (5,)
        columns = {row[1] for row in conn.execute("PRAGMA table_info(jobs)")}
        assert {"attempts", "lease_expires_at", "result_path"} <= columns


def test_database_newer_than_code_refuses_to_start(settings):
    settings.database_path.parent.mkdir(parents=True)
    with sqlite3.connect(settings.database_path) as conn:
        conn.execute(f"PRAGMA user_version = {SCHEMA_VERSION + 1}")
    with pytest.raises(RuntimeError, match="newer than this code"):
        with TestClient(create_app(settings)):
            pass


@pytest.fixture
def cli_env(settings, monkeypatch):
    monkeypatch.setenv("AGENCY_DATABASE_PATH", str(settings.database_path))
    monkeypatch.setenv("AGENCY_STORAGE_ROOT", str(settings.storage_root))
    monkeypatch.setenv("AGENCY_STRIPE_API_KEY", "sk_test_cli")
    monkeypatch.setenv("AGENCY_STRIPE_WEBHOOK_SECRET", "whsec_cli")
    admin.get_settings.cache_clear()
    yield
    admin.get_settings.cache_clear()


def run_cli(capsys, *args) -> dict | list:
    assert admin.main(list(args)) == 0
    return json.loads(capsys.readouterr().out)


def test_admin_cli_issues_working_key_and_stores_only_hash(cli_env, client, settings, capsys):
    account = run_cli(capsys, "create-account", "--email", "ops@example.test", "--quota", "40", "--status", "active")
    issued = run_cli(capsys, "issue-key", "--account", account["account_id"], "--label", "ci")
    raw_key = issued["api_key"]
    assert raw_key.startswith("aea_") and len(raw_key) > 40

    with sqlite3.connect(settings.database_path) as conn:
        stored = conn.execute("SELECT key_hash, key_prefix FROM api_keys").fetchall()
        dump = "\n".join(conn.iterdump())
    assert stored == [(hash_api_key(raw_key), issued["key_prefix"])]
    assert raw_key not in dump

    summary = client.get("/api/v1/account", headers=auth(raw_key)).json()
    assert summary["credit_quota"] == 40 and summary["credits_remaining"] == 40

    assert run_cli(capsys, "revoke-key", "--prefix", issued["key_prefix"]) == {
        "key_prefix": issued["key_prefix"],
        "revoked": 1,
    }
    assert client.get("/api/v1/account", headers=auth(raw_key)).status_code == 401


def test_admin_cli_rejects_negative_quota(cli_env):
    with pytest.raises(SystemExit):
        admin.main(["create-account", "--email", "x@example.test", "--quota", "-1"])


def test_tenant_cannot_list_or_read_other_tenants_jobs(client, make_account):
    _, key_a = make_account()
    _, key_b = make_account()
    job_a = client.post("/api/v1/forensics/contain", json=FORENSICS_BODY, headers=auth(key_a)).json()["job_id"]

    assert [j["job_id"] for j in client.get("/api/v1/jobs", headers=auth(key_a)).json()["jobs"]] == [job_a]
    assert client.get("/api/v1/jobs", headers=auth(key_b)).json()["jobs"] == []
    assert client.get(f"/api/v1/jobs/{job_a}", headers=auth(key_b)).status_code == 404


def test_ledger_records_debits_for_own_account_only(client, make_account):
    _, key_a = make_account(quota=100)
    _, key_b = make_account(quota=100)
    accepted = client.post(
        "/api/v1/archeology/audit", json={"repo_url": "https://github.com/acme/legacy"}, headers=auth(key_a)
    ).json()

    entries = client.get("/api/v1/account/ledger", headers=auth(key_a)).json()["entries"]
    assert [(e["delta"], e["reason"], e["job_id"]) for e in entries] == [(-10, "job_debit", accepted["job_id"])]
    assert client.get("/api/v1/account/ledger", headers=auth(key_b)).json()["entries"] == []


def test_failed_debit_leaves_no_job_or_ledger_row(client, make_account, settings):
    _, key = make_account(quota=5)
    response = client.post(
        "/api/v1/archeology/audit", json={"repo_url": "https://github.com/acme/legacy"}, headers=auth(key)
    )
    assert response.status_code == 402
    with sqlite3.connect(settings.database_path) as conn:
        assert conn.execute("SELECT COUNT(*) FROM jobs").fetchone() == (0,)
        assert conn.execute("SELECT COUNT(*) FROM credit_ledger").fetchone() == (0,)
    assert list(settings.jobs_dir.iterdir()) == []


@pytest.mark.parametrize(
    "header",
    [
        {"Authorization": "Basic dXNlcjpwYXNz"},
        {"Authorization": "Bearer "},
        {"Authorization": "Bearer ' OR 1=1 --"},
        {"X-API-Key": "x" * 5000},
    ],
)
def test_malformed_credentials_are_401(client, header):
    assert client.get("/api/v1/account", headers=header).status_code == 401


def test_revoked_key_is_rejected_even_with_active_subscription(client, make_account, settings):
    _, key = make_account()
    with sqlite3.connect(settings.database_path) as conn:
        conn.execute("UPDATE api_keys SET revoked = 1")
    assert client.get("/api/v1/account", headers=auth(key)).status_code == 401
