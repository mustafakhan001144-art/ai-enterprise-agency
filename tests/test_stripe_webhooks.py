"""Stripe webhook verification, idempotency and quota updates (no network calls)."""

from tests.conftest import PRICE_ID, sign_stripe_payload, stripe_event

URL = "/api/v1/webhooks/stripe"


def post_event(client, payload: bytes, signature: str | None = None):
    return client.post(
        URL,
        content=payload,
        headers={"Stripe-Signature": signature or sign_stripe_payload(payload), "Content-Type": "application/json"},
    )


def test_bad_signature_is_400(client):
    payload = stripe_event("invoice.paid", {"customer": "cus_1"})
    response = post_event(client, payload, signature=sign_stripe_payload(payload, secret="whsec_wrong"))
    assert response.status_code == 400


def test_subscription_update_sets_quota(client, make_account, account_row):
    account_id, _ = make_account(status="inactive", quota=0, customer="cus_sub")
    subscription = {
        "id": "sub_1",
        "customer": "cus_sub",
        "status": "active",
        "items": {"data": [{"price": {"id": PRICE_ID}}]},
    }
    response = post_event(client, stripe_event("customer.subscription.updated", subscription))
    assert response.json()["result"] == "applied"
    row = account_row(account_id)
    assert row["subscription_status"] == "active"
    assert row["credit_quota"] == 100
    assert row["stripe_price_id"] == PRICE_ID


def test_invoice_paid_resets_usage_and_is_idempotent(client, make_account, account_row):
    account_id, _ = make_account(used=40, customer="cus_paid")
    payload = stripe_event("invoice.paid", {"customer": "cus_paid"}, event_id="evt_fixed")
    assert post_event(client, payload).json()["result"] == "applied"
    assert account_row(account_id)["credits_used"] == 0

    assert post_event(client, payload).json()["result"] == "duplicate"


def test_payment_failed_blocks_api(client, make_account, account_row):
    account_id, key = make_account(customer="cus_fail")
    post_event(client, stripe_event("invoice.payment_failed", {"customer": "cus_fail"}))
    assert account_row(account_id)["subscription_status"] == "past_due"
    response = client.get("/api/v1/jobs/whatever", headers={"Authorization": f"Bearer {key}"})
    assert response.status_code == 402


def test_subscription_deleted_zeroes_quota(client, make_account, account_row):
    account_id, _ = make_account(customer="cus_del")
    post_event(client, stripe_event("customer.subscription.deleted", {"customer": "cus_del"}))
    row = account_row(account_id)
    assert row["subscription_status"] == "canceled"
    assert row["credit_quota"] == 0


def test_unknown_customer_ignored(client):
    response = post_event(client, stripe_event("invoice.paid", {"customer": "cus_nobody"}))
    assert response.json()["result"] == "ignored: unknown customer"


def test_invoice_paid_writes_one_period_reset_to_the_ledger(client, make_account, settings):
    import sqlite3

    account_id, key = make_account(used=40, customer="cus_ledger")
    payload = stripe_event("invoice.paid", {"id": "in_123", "customer": "cus_ledger"}, event_id="evt_ledger")
    post_event(client, payload)
    post_event(client, payload)  # replay is ignored
    with sqlite3.connect(settings.database_path) as conn:
        rows = conn.execute(
            "SELECT reason, delta, reference FROM credit_ledger WHERE account_id = ?", (account_id,)
        ).fetchall()
    assert rows == [("period_reset", 40, "in_123")]
    entries = client.get("/api/v1/account/ledger", headers={"Authorization": f"Bearer {key}"}).json()["entries"]
    assert [(e["reason"], e["delta"]) for e in entries] == [("period_reset", 40)]


def test_replayed_event_with_a_new_signature_is_still_a_duplicate(client, make_account, account_row):
    account_id, _ = make_account(used=10, customer="cus_replay")
    payload = stripe_event("invoice.paid", {"customer": "cus_replay"}, event_id="evt_replay")
    assert post_event(client, payload).json()["result"] == "applied"
    # An attacker cannot reset usage twice by re-signing: the event id is recorded.
    post_event(client, stripe_event("invoice.payment_failed", {"customer": "cus_replay"}))
    assert post_event(client, payload, signature=sign_stripe_payload(payload)).json()["result"] == "duplicate"
    assert account_row(account_id)["subscription_status"] == "past_due"
