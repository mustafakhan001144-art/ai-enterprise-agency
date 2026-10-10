"""Operator CLI for accounts and API keys.

    python -m api.admin create-account --email ops@example.com [--quota 100]
    python -m api.admin issue-key --account <id> [--label laptop]
    python -m api.admin revoke-key --prefix aea_AbCdEf
    python -m api.admin list-accounts
    python -m api.admin set-subscription --account <id> --status active --quota 500 [--customer cus_123]
    python -m api.admin demo [--email demo@localhost] [--quota 500]

Normally Stripe webhooks set subscription status and quota; set-subscription exists
for local development and support cases. `demo` does create-account (active, with
credits) plus issue-key in one step, for trying the dashboard locally; it refuses to
run when AGENCY_ENVIRONMENT=production. Every quota change is written to the credit
ledger. A raw API key is printed exactly once and never stored.
"""

import argparse
import asyncio
import json
import sys

from api.db import (
    connect,
    display_prefix,
    generate_api_key,
    hash_api_key,
    init_db,
    new_id,
    now_iso,
    record_ledger,
)
from api.settings import get_settings

SUBSCRIPTION_STATUSES = ("active", "trialing", "past_due", "canceled", "inactive", "incomplete", "unpaid")


async def create_account(email: str, quota: int, status: str) -> dict:
    settings = get_settings()
    await init_db(settings.database_path)
    account_id = new_id()
    async with connect(settings.database_path) as conn:
        await conn.execute("BEGIN IMMEDIATE")
        await conn.execute(
            "INSERT INTO accounts (id, email, subscription_status, credit_quota, updated_at) VALUES (?, ?, ?, ?, ?)",
            (account_id, email, status, quota, now_iso()),
        )
        if quota:
            await record_ledger(conn, account_id, quota, "admin_adjust", reference="initial quota")
        await conn.commit()
    return {"account_id": account_id, "email": email, "subscription_status": status, "credit_quota": quota}


async def issue_key(account_id: str, label: str | None) -> dict:
    settings = get_settings()
    await init_db(settings.database_path)
    raw_key = generate_api_key()
    async with connect(settings.database_path) as conn:
        exists = await (await conn.execute("SELECT 1 FROM accounts WHERE id = ?", (account_id,))).fetchone()
        if exists is None:
            raise SystemExit(f"no account {account_id}")
        await conn.execute(
            "INSERT INTO api_keys (key_hash, account_id, key_prefix, label, created_at) VALUES (?, ?, ?, ?, ?)",
            (hash_api_key(raw_key), account_id, display_prefix(raw_key), label, now_iso()),
        )
        await conn.commit()
    return {"account_id": account_id, "api_key": raw_key, "key_prefix": display_prefix(raw_key), "label": label}


async def revoke_key(prefix: str) -> dict:
    settings = get_settings()
    await init_db(settings.database_path)
    async with connect(settings.database_path) as conn:
        cursor = await conn.execute("UPDATE api_keys SET revoked = 1 WHERE key_prefix = ? AND revoked = 0", (prefix,))
        await conn.commit()
    return {"key_prefix": prefix, "revoked": cursor.rowcount}


async def list_accounts() -> list[dict]:
    settings = get_settings()
    await init_db(settings.database_path)
    async with connect(settings.database_path) as conn:
        rows = await (
            await conn.execute(
                "SELECT a.id, a.email, a.subscription_status, a.credit_quota, a.credits_used, "
                "(SELECT COUNT(*) FROM api_keys k WHERE k.account_id = a.id AND k.revoked = 0) AS active_keys "
                "FROM accounts a ORDER BY a.email"
            )
        ).fetchall()
    return [dict(row) for row in rows]


async def set_subscription(account_id: str, status: str, quota: int | None, customer: str | None) -> dict:
    settings = get_settings()
    await init_db(settings.database_path)
    async with connect(settings.database_path) as conn:
        await conn.execute("BEGIN IMMEDIATE")
        row = await (await conn.execute("SELECT credit_quota FROM accounts WHERE id = ?", (account_id,))).fetchone()
        if row is None:
            await conn.rollback()
            raise SystemExit(f"no account {account_id}")
        new_quota = row["credit_quota"] if quota is None else quota
        await conn.execute(
            "UPDATE accounts SET subscription_status = ?, credit_quota = ?, "
            "stripe_customer_id = COALESCE(?, stripe_customer_id), updated_at = ? WHERE id = ?",
            (status, new_quota, customer, now_iso(), account_id),
        )
        if new_quota != row["credit_quota"]:
            await record_ledger(
                conn, account_id, new_quota - row["credit_quota"], "admin_adjust", reference="set-subscription"
            )
        await conn.commit()
    return {"account_id": account_id, "subscription_status": status, "credit_quota": new_quota}


async def demo(email: str, quota: int) -> dict:
    if get_settings().environment == "production":
        raise SystemExit("refusing to create a demo account with AGENCY_ENVIRONMENT=production")
    account = await create_account(email, quota, "active")
    key = await issue_key(account["account_id"], "demo")
    return {
        **account,
        "api_key": key["api_key"],
        "dashboard": "http://127.0.0.1:8000/",
        "next": "Paste api_key into the dashboard. Keep the worker running so jobs complete.",
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m api.admin", description=__doc__.split("\n")[0])
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("create-account")
    p.add_argument("--email", required=True)
    p.add_argument("--quota", type=int, default=0)
    p.add_argument("--status", choices=SUBSCRIPTION_STATUSES, default="inactive")

    p = sub.add_parser("issue-key")
    p.add_argument("--account", required=True)
    p.add_argument("--label")

    p = sub.add_parser("revoke-key")
    p.add_argument("--prefix", required=True)

    sub.add_parser("list-accounts")

    p = sub.add_parser("set-subscription")
    p.add_argument("--account", required=True)
    p.add_argument("--status", choices=SUBSCRIPTION_STATUSES, required=True)
    p.add_argument("--quota", type=int)
    p.add_argument("--customer")

    p = sub.add_parser("demo", help="create an active account with credits and print an API key")
    p.add_argument("--email", default="demo@localhost")
    p.add_argument("--quota", type=int, default=500)

    args = parser.parse_args(argv)
    if getattr(args, "quota", None) is not None and args.quota < 0:
        parser.error("--quota must be >= 0")

    match args.command:
        case "create-account":
            result = asyncio.run(create_account(args.email, args.quota, args.status))
        case "issue-key":
            result = asyncio.run(issue_key(args.account, args.label))
        case "revoke-key":
            result = asyncio.run(revoke_key(args.prefix))
        case "list-accounts":
            result = asyncio.run(list_accounts())
        case "set-subscription":
            result = asyncio.run(set_subscription(args.account, args.status, args.quota, args.customer))
        case "demo":
            result = asyncio.run(demo(args.email, args.quota))
    json.dump(result, sys.stdout, indent=2)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
