"""GET /api/v1/account and /api/v1/account/ledger: the caller's own balance and usage history."""

from typing import Annotated

from fastapi import APIRouter, Query, Request

from api.db import connect
from api.middleware.auth import Subscriber
from api.schemas import AccountSummary, LedgerEntry, LedgerPage

router = APIRouter(prefix="/api/v1/account", tags=["account"])


@router.get("", response_model=AccountSummary)
async def get_account(principal: Subscriber) -> AccountSummary:
    return AccountSummary(
        account_id=principal.account_id,
        subscription_status=principal.subscription_status,
        credit_quota=principal.credit_quota,
        credits_used=principal.credits_used,
        credits_remaining=principal.credits_remaining,
    )


@router.get("/ledger", response_model=LedgerPage)
async def get_ledger(
    request: Request,
    principal: Subscriber,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    before_id: Annotated[int | None, Query(ge=1)] = None,
) -> LedgerPage:
    """Credit movements for this account, newest first. Page with `before_id`."""
    async with connect(request.app.state.settings.database_path) as conn:
        rows = await (
            await conn.execute(
                "SELECT id, delta, reason, job_id, reference, created_at FROM credit_ledger "
                "WHERE account_id = ? AND (? IS NULL OR id < ?) ORDER BY id DESC LIMIT ?",
                (principal.account_id, before_id, before_id, limit),
            )
        ).fetchall()
    entries = [LedgerEntry(**dict(row)) for row in rows]
    next_before = entries[-1].id if len(entries) == limit else None
    return LedgerPage(entries=entries, next_before_id=next_before)
