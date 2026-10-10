"""SQLite persistence for API keys, credit balances, Stripe state and jobs.

API keys are stored only as SHA-256 digests. Credit debits are a single
conditional UPDATE so concurrent requests can never overdraw an account.
"""

import hashlib
import secrets
import uuid
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from pathlib import Path

import aiosqlite

# Migrations are append-only. Each entry upgrades the schema by one version and
# PRAGMA user_version records the version reached. Never edit a released entry;
# add a new one instead, and keep every change additive so older code keeps working.
MIGRATIONS: list[str] = [
    # 1: baseline gateway schema
    """
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
    """,
    # 2: key metadata, durable job execution columns, credit ledger
    """
    ALTER TABLE api_keys ADD COLUMN key_prefix TEXT;
    ALTER TABLE api_keys ADD COLUMN label TEXT;

    ALTER TABLE jobs ADD COLUMN attempts INTEGER NOT NULL DEFAULT 0;
    ALTER TABLE jobs ADD COLUMN lease_owner TEXT;
    ALTER TABLE jobs ADD COLUMN lease_expires_at TEXT;
    ALTER TABLE jobs ADD COLUMN started_at TEXT;
    ALTER TABLE jobs ADD COLUMN finished_at TEXT;
    ALTER TABLE jobs ADD COLUMN error TEXT;
    ALTER TABLE jobs ADD COLUMN result_path TEXT;
    ALTER TABLE jobs ADD COLUMN result_digest TEXT;

    CREATE INDEX IF NOT EXISTS jobs_status_idx ON jobs(status, created_at);

    CREATE TABLE IF NOT EXISTS credit_ledger (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        account_id  TEXT NOT NULL REFERENCES accounts(id),
        delta       INTEGER NOT NULL,
        reason      TEXT NOT NULL CHECK (reason IN ('job_debit', 'job_refund', 'period_reset', 'admin_adjust')),
        job_id      TEXT REFERENCES jobs(id),
        reference   TEXT,
        created_at  TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS credit_ledger_account_idx ON credit_ledger(account_id, id);
    """,
]

SCHEMA_VERSION = len(MIGRATIONS)

ACTIVE_STATUSES = ("active", "trialing")


def now_iso() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


def hash_api_key(raw_key: str) -> str:
    return hashlib.sha256(raw_key.encode("utf-8")).hexdigest()


def new_id() -> str:
    return str(uuid.uuid4())


BUSY_TIMEOUT_MS = 5000


async def init_db(path: Path) -> int:
    """Create the database if needed and apply pending migrations. Returns the schema version."""
    path.parent.mkdir(parents=True, exist_ok=True)
    async with aiosqlite.connect(path) as conn:
        await conn.execute(f"PRAGMA busy_timeout = {BUSY_TIMEOUT_MS}")
        await conn.execute("PRAGMA journal_mode = WAL")
        current = (await (await conn.execute("PRAGMA user_version")).fetchone())[0]
        if current > SCHEMA_VERSION:
            raise RuntimeError(
                f"database {path} is at schema version {current}, newer than this code ({SCHEMA_VERSION})"
            )
        if current == 0 and await _has_table(conn, "accounts"):
            # Databases created before versioning carry the baseline schema already.
            current = 1
            await conn.execute("PRAGMA user_version = 1")
        for version in range(current + 1, SCHEMA_VERSION + 1):
            await conn.executescript(f"BEGIN;\n{MIGRATIONS[version - 1]}\nPRAGMA user_version = {version};\nCOMMIT;")
        await conn.commit()
        return SCHEMA_VERSION


async def _has_table(conn: aiosqlite.Connection, name: str) -> bool:
    cursor = await conn.execute("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?", (name,))
    return await cursor.fetchone() is not None


@asynccontextmanager
async def connect(path: Path) -> AsyncIterator[aiosqlite.Connection]:
    conn = await aiosqlite.connect(path)
    conn.row_factory = aiosqlite.Row
    await conn.execute(f"PRAGMA busy_timeout = {BUSY_TIMEOUT_MS}")
    await conn.execute("PRAGMA foreign_keys = ON")
    try:
        yield conn
    finally:
        await conn.close()


async def debit_credits(
    conn: aiosqlite.Connection, account_id: str, credits: int, *, job_id: str | None = None
) -> bool:
    """Atomically reserve credits. Returns False when the quota would be exceeded.

    The caller owns the transaction; the ledger row is written in the same one.
    """
    timestamp = now_iso()
    cursor = await conn.execute(
        "UPDATE accounts SET credits_used = credits_used + ?, updated_at = ? "
        "WHERE id = ? AND credits_used + ? <= credit_quota",
        (credits, timestamp, account_id, credits),
    )
    if cursor.rowcount != 1:
        return False
    await record_ledger(conn, account_id, -credits, "job_debit", job_id=job_id, created_at=timestamp)
    return True


async def refund_credits(conn: aiosqlite.Connection, account_id: str, credits: int, *, job_id: str) -> None:
    """Return credits for a job that failed permanently. Never drives credits_used below zero."""
    timestamp = now_iso()
    await conn.execute(
        "UPDATE accounts SET credits_used = MAX(0, credits_used - ?), updated_at = ? WHERE id = ?",
        (credits, timestamp, account_id),
    )
    await record_ledger(conn, account_id, credits, "job_refund", job_id=job_id, created_at=timestamp)


async def record_ledger(
    conn: aiosqlite.Connection,
    account_id: str,
    delta: int,
    reason: str,
    *,
    job_id: str | None = None,
    reference: str | None = None,
    created_at: str | None = None,
) -> None:
    await conn.execute(
        "INSERT INTO credit_ledger (account_id, delta, reason, job_id, reference, created_at) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        (account_id, delta, reason, job_id, reference, created_at or now_iso()),
    )


API_KEY_PREFIX = "aea_"


def generate_api_key() -> str:
    """A new random API key. Only its hash is stored; show the raw value to the user once."""
    return API_KEY_PREFIX + secrets.token_urlsafe(32)


def display_prefix(raw_key: str) -> str:
    """The non-secret leading characters kept for identifying a key in listings."""
    return raw_key[: len(API_KEY_PREFIX) + 6]
