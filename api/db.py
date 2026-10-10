"""SQLite persistence for API keys, credit balances, Stripe state and jobs.

API keys are stored only as SHA-256 digests. Credit debits are a single
conditional UPDATE so concurrent requests can never overdraw an account.
"""

import hashlib
import uuid
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from pathlib import Path

import aiosqlite

SCHEMA = """
PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS accounts (
    id                  TEXT PRIMARY KEY,
    email               TEXT NOT NULL,
    stripe_customer_id  TEXT UNIQUE,
    subscription_status TEXT NOT NULL DEFAULT 'inactive',
    stripe_price_id     TEXT,
    credit_quota        INTEGER NOT NULL DEFAULT 0 CHECK (credit_quota >= 0),
    credits_used        INTEGER NOT NULL DEFAULT 0 CHECK (credits_used >= 0),
    updated_at          TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS api_keys (
    key_hash   TEXT PRIMARY KEY,
    account_id TEXT NOT NULL REFERENCES accounts(id),
    revoked    INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS stripe_events (
    event_id     TEXT PRIMARY KEY,
    event_type   TEXT NOT NULL,
    processed_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS jobs (
    id             TEXT PRIMARY KEY,
    account_id     TEXT NOT NULL REFERENCES accounts(id),
    kind           TEXT NOT NULL CHECK (kind IN ('forensics_contain', 'archeology_audit')),
    runbook        TEXT NOT NULL,
    status         TEXT NOT NULL DEFAULT 'queued',
    credits_charged INTEGER NOT NULL,
    request_path   TEXT NOT NULL,
    created_at     TEXT NOT NULL,
    updated_at     TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS jobs_account_idx ON jobs(account_id, created_at);
"""

ACTIVE_STATUSES = ("active", "trialing")


def now_iso() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


def hash_api_key(raw_key: str) -> str:
    return hashlib.sha256(raw_key.encode("utf-8")).hexdigest()


def new_id() -> str:
    return str(uuid.uuid4())


async def init_db(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    async with aiosqlite.connect(path) as conn:
        await conn.executescript(SCHEMA)
        await conn.commit()


@asynccontextmanager
async def connect(path: Path) -> AsyncIterator[aiosqlite.Connection]:
    conn = await aiosqlite.connect(path)
    conn.row_factory = aiosqlite.Row
    await conn.execute("PRAGMA foreign_keys = ON")
    try:
        yield conn
    finally:
        await conn.close()


async def debit_credits(conn: aiosqlite.Connection, account_id: str, credits: int) -> bool:
    """Atomically reserve credits. Returns False when the quota would be exceeded."""
    cursor = await conn.execute(
        "UPDATE accounts SET credits_used = credits_used + ?, updated_at = ? "
        "WHERE id = ? AND credits_used + ? <= credit_quota",
        (credits, now_iso(), account_id, credits),
    )
    return cursor.rowcount == 1
