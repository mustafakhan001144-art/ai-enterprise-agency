"""POST /api/v1/webhooks/stripe: keep local subscription state and quotas in sync.

Every event is signature-verified against the raw body, and processed at most
once (event ids are recorded in the same transaction as the state change).

Handled events:
  customer.subscription.created / updated -> status + plan quota from the price id
  customer.subscription.deleted           -> status 'canceled', quota 0
  invoice.paid                            -> new billing period: credits_used reset to 0,
                                             recorded in the ledger as period_reset
  invoice.payment_failed                  -> status 'past_due' (API returns 402)
Anything else is acknowledged and ignored.
"""

import logging

import aiosqlite
import stripe
from fastapi import APIRouter, Header, HTTPException, Request, status

from api.db import connect, now_iso, record_ledger

router = APIRouter(prefix="/api/v1/webhooks", tags=["webhooks"])
log = logging.getLogger("api.stripe")


def _quota_for_subscription(subscription: dict, plan_credits: dict[str, int]) -> tuple[str | None, int]:
    """Sum the quotas of every recognised price on the subscription."""
    price_ids = [item["price"]["id"] for item in subscription.get("items", {}).get("data", [])]
    known = [p for p in price_ids if p in plan_credits]
    if price_ids and not known:
        log.warning("subscription %s has no price in plan_credits: %s", subscription.get("id"), price_ids)
    return (known[0] if known else None), sum(plan_credits[p] for p in known)


async def _apply_event(conn: aiosqlite.Connection, event: dict, plan_credits: dict[str, int]) -> str:
    obj = event["data"]["object"]
    customer = obj.get("customer")
    if not customer:
        return "ignored: no customer"
    timestamp = now_iso()

    match event["type"]:
        case "customer.subscription.created" | "customer.subscription.updated":
            price_id, quota = _quota_for_subscription(obj, plan_credits)
            cursor = await conn.execute(
                "UPDATE accounts SET subscription_status = ?, stripe_price_id = ?, credit_quota = ?, "
                "updated_at = ? WHERE stripe_customer_id = ?",
                (obj["status"], price_id, quota, timestamp, customer),
            )
        case "customer.subscription.deleted":
            cursor = await conn.execute(
                "UPDATE accounts SET subscription_status = 'canceled', credit_quota = 0, "
                "updated_at = ? WHERE stripe_customer_id = ?",
                (timestamp, customer),
            )
        case "invoice.paid":
            row = await (
                await conn.execute("SELECT id, credits_used FROM accounts WHERE stripe_customer_id = ?", (customer,))
            ).fetchone()
            cursor = await conn.execute(
                "UPDATE accounts SET credits_used = 0, subscription_status = 'active', "
                "updated_at = ? WHERE stripe_customer_id = ?",
                (timestamp, customer),
            )
            if row is not None:
                # The ledger records the credits returned by the new period, so its
                # running total stays equal to -credits_used.
                await record_ledger(
                    conn,
                    row["id"],
                    row["credits_used"],
                    "period_reset",
                    reference=obj.get("id") or event["id"],
                    created_at=timestamp,
                )
        case "invoice.payment_failed":
            cursor = await conn.execute(
                "UPDATE accounts SET subscription_status = 'past_due', updated_at = ? WHERE stripe_customer_id = ?",
                (timestamp, customer),
            )
        case _:
            return "ignored: unhandled type"

    if cursor.rowcount == 0:
        log.warning("stripe event %s for unknown customer %s", event["id"], customer)
        return "ignored: unknown customer"
    return "applied"


@router.post("/stripe", status_code=status.HTTP_200_OK)
async def stripe_webhook(
    request: Request,
    stripe_signature: str = Header(alias="Stripe-Signature"),
) -> dict:
    settings = request.app.state.settings
    payload = await request.body()
    try:
        event = stripe.Webhook.construct_event(
            payload, stripe_signature, settings.stripe_webhook_secret.get_secret_value()
        )
    except ValueError:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="invalid payload")
    except stripe.SignatureVerificationError:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="invalid signature")

    event = event.to_dict()
    async with connect(settings.database_path) as conn:
        await conn.execute("BEGIN IMMEDIATE")
        cursor = await conn.execute(
            "INSERT OR IGNORE INTO stripe_events (event_id, event_type, processed_at) VALUES (?, ?, ?)",
            (event["id"], event["type"], now_iso()),
        )
        if cursor.rowcount == 0:
            await conn.rollback()
            return {"received": True, "result": "duplicate"}
        result = await _apply_event(conn, event, settings.plan_credits)
        await conn.commit()

    log.info("stripe event %s (%s): %s", event["id"], event["type"], result)
    return {"received": True, "result": result}
