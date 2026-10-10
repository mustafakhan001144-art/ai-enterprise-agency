# Stripe in test mode

Billing runs against Stripe **test mode** everywhere except production. The
gateway refuses to start with a live key (`sk_live_…` / `rk_live_…`) unless
`AGENCY_ENVIRONMENT=production`, and it rejects anything that is not a secret
or restricted key, or a webhook secret that does not start with `whsec_`. The
error names the setting but never prints its value.

## 1. Configure test keys

In your local `.env` (never committed):

```
AGENCY_ENVIRONMENT=development
AGENCY_STRIPE_API_KEY=sk_test_...          # Dashboard > Developers > API keys (test mode)
AGENCY_STRIPE_WEBHOOK_SECRET=whsec_...     # printed by `stripe listen`, see below
AGENCY_PLAN_CREDITS={"price_...": 1000}    # test-mode Price ID -> monthly credits
```

## 2. Forward webhooks with the Stripe CLI

```
stripe login
stripe listen --forward-to localhost:8000/api/v1/webhooks/stripe
```

`stripe listen` prints a `whsec_…` signing secret; put it in
`AGENCY_STRIPE_WEBHOOK_SECRET` and restart the gateway.

## 3. Link a local account to a Stripe customer

```
python -m api.admin create-account --email you@example.test --quota 0
stripe customers create --email you@example.test          # note the cus_... id
python -m api.admin set-subscription --account <account_id> --customer cus_... --status inactive
python -m api.admin issue-key --account <account_id> --label local
```

## 4. Drive the lifecycle

| Command | Effect on the account |
|---|---|
| `stripe trigger customer.subscription.created` (with your price) | status and credit quota set from `AGENCY_PLAN_CREDITS` |
| `stripe trigger invoice.paid` | `credits_used` reset to 0; a `period_reset` row appears in `GET /api/v1/account/ledger` |
| `stripe trigger invoice.payment_failed` | status `past_due`; API calls return 402 |
| `stripe trigger customer.subscription.deleted` | status `canceled`, quota 0 |

`stripe trigger` creates its own fixture customer. To hit your account, either
link that customer id with `set-subscription`, or use
`stripe trigger invoice.paid --override invoice:customer=cus_...`.

Every event is signature-checked and recorded by id, so replaying the same
event (`stripe events resend evt_…`) is acknowledged as `duplicate` and changes
nothing.
