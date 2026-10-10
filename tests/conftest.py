"""Shared fixtures: an isolated app instance per test with its own SQLite file."""

import hashlib
import hmac
import json
import os
import sqlite3
import time
import uuid

import pytest

# api.main builds a module-level app from the environment at import time, so
# placeholder values must exist before any test imports it.
os.environ.setdefault("AGENCY_STRIPE_API_KEY", "sk_test_placeholder")
os.environ.setdefault("AGENCY_STRIPE_WEBHOOK_SECRET", "whsec_placeholder")

from fastapi.testclient import TestClient  # noqa: E402

from api.db import hash_api_key, now_iso  # noqa: E402
from api.main import create_app  # noqa: E402
from api.settings import GatewaySettings  # noqa: E402

WEBHOOK_SECRET = "whsec_test_secret"
PRICE_ID = "price_test_basic"


@pytest.fixture
def settings(tmp_path) -> GatewaySettings:
    return GatewaySettings(
        _env_file=None,
        storage_root=tmp_path / "storage",
        database_path=tmp_path / "storage" / "test.db",
        stripe_api_key="sk_test_dummy",
        stripe_webhook_secret=WEBHOOK_SECRET,
        plan_credits={PRICE_ID: 100},
        max_request_bytes=64 * 1024,
        forensics_bytes_per_credit=1024,
        archeology_audit_credits=10,
    )


@pytest.fixture
def client(settings):
    with TestClient(create_app(settings)) as test_client:
        yield test_client


@pytest.fixture
def make_account(settings, client):
    """Insert an account plus one API key; returns (account_id, raw_key)."""

    def _make(status: str = "active", quota: int = 100, used: int = 0, customer: str | None = None):
        account_id = str(uuid.uuid4())
        raw_key = f"test_{uuid.uuid4().hex}"
        with sqlite3.connect(settings.database_path) as conn:
            conn.execute(
                "INSERT INTO accounts (id, email, stripe_customer_id, subscription_status, "
                "credit_quota, credits_used, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (account_id, f"{account_id}@example.test", customer, status, quota, used, now_iso()),
            )
            conn.execute(
                "INSERT INTO api_keys (key_hash, account_id, created_at) VALUES (?, ?, ?)",
                (hash_api_key(raw_key), account_id, now_iso()),
            )
        return account_id, raw_key

    return _make


@pytest.fixture
def account_row(settings):
    def _get(account_id: str) -> dict:
        with sqlite3.connect(settings.database_path) as conn:
            conn.row_factory = sqlite3.Row
            return dict(conn.execute("SELECT * FROM accounts WHERE id = ?", (account_id,)).fetchone())

    return _get


def sign_stripe_payload(payload: bytes, secret: str = WEBHOOK_SECRET) -> str:
    timestamp = int(time.time())
    signed = f"{timestamp}.".encode() + payload
    signature = hmac.new(secret.encode(), signed, hashlib.sha256).hexdigest()
    return f"t={timestamp},v1={signature}"


def stripe_event(event_type: str, obj: dict, event_id: str | None = None) -> bytes:
    return json.dumps(
        {
            "id": event_id or f"evt_{uuid.uuid4().hex}",
            "object": "event",
            "type": event_type,
            "data": {"object": obj},
        }
    ).encode()
