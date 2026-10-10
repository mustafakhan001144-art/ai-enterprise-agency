"""API key authentication and subscription gate.

Keys arrive as `Authorization: Bearer <key>` or `X-API-Key: <key>`. A request
passes only if the key exists, is not revoked, and its account's Stripe
subscription is active or trialing. Credit debits happen per route, because
the cost depends on the payload.
"""

from dataclasses import dataclass
from typing import Annotated

from fastapi import Depends, Header, HTTPException, Request, status

from api.db import ACTIVE_STATUSES, connect, hash_api_key


@dataclass(frozen=True)
class Principal:
    account_id: str
    subscription_status: str
    credit_quota: int
    credits_used: int

    @property
    def credits_remaining(self) -> int:
        return self.credit_quota - self.credits_used


def _extract_key(authorization: str | None, x_api_key: str | None) -> str:
    if x_api_key:
        return x_api_key.strip()
    if authorization and authorization.lower().startswith("bearer "):
        return authorization[7:].strip()
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="missing API key",
        headers={"WWW-Authenticate": "Bearer"},
    )


async def require_subscriber(
    request: Request,
    authorization: Annotated[str | None, Header()] = None,
    x_api_key: Annotated[str | None, Header()] = None,
) -> Principal:
    raw_key = _extract_key(authorization, x_api_key)
    settings = request.app.state.settings
    async with connect(settings.database_path) as conn:
        cursor = await conn.execute(
            "SELECT a.id, a.subscription_status, a.credit_quota, a.credits_used "
            "FROM api_keys k JOIN accounts a ON a.id = k.account_id "
            "WHERE k.key_hash = ? AND k.revoked = 0",
            (hash_api_key(raw_key),),
        )
        row = await cursor.fetchone()

    if row is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="invalid API key")
    if row["subscription_status"] not in ACTIVE_STATUSES:
        raise HTTPException(
            status_code=status.HTTP_402_PAYMENT_REQUIRED,
            detail=f"subscription is {row['subscription_status']}",
        )
    return Principal(
        account_id=row["id"],
        subscription_status=row["subscription_status"],
        credit_quota=row["credit_quota"],
        credits_used=row["credits_used"],
    )


Subscriber = Annotated[Principal, Depends(require_subscriber)]
