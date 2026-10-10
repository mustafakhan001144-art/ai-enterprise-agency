"""Gateway settings, validated from the environment at startup.

Engine-level settings (LLM endpoints, model parameters) live in core/config.py
(Phase 3). Only what the gateway needs to accept, meter and persist requests is here.
"""

from functools import lru_cache
from pathlib import Path

from pydantic import Field, SecretStr, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class GatewaySettings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="AGENCY_", env_file=".env", extra="ignore")

    environment: str = Field(default="development", pattern="^(development|staging|production)$")

    storage_root: Path = Path("storage")
    database_path: Path = Path("storage/database.db")

    stripe_api_key: SecretStr
    stripe_webhook_secret: SecretStr
    # Maps a Stripe Price ID to the monthly credit quota it grants, e.g.
    # AGENCY_PLAN_CREDITS='{"price_123": 1000, "price_456": 10000}'
    plan_credits: dict[str, int] = Field(default_factory=dict)

    max_request_bytes: int = Field(default=5 * 1024 * 1024, gt=0)
    forensics_bytes_per_credit: int = Field(default=64 * 1024, gt=0)
    archeology_audit_credits: int = Field(default=10, gt=0)
    allowed_git_hosts: frozenset[str] = frozenset({"github.com", "gitlab.com", "bitbucket.org"})

    @field_validator("plan_credits")
    @classmethod
    def _quotas_positive(cls, value: dict[str, int]) -> dict[str, int]:
        bad = [price for price, credits in value.items() if credits < 0]
        if bad:
            raise ValueError(f"negative credit quota for prices: {bad}")
        return value

    @property
    def jobs_dir(self) -> Path:
        return self.storage_root / "code_sandboxes"


@lru_cache
def get_settings() -> GatewaySettings:
    return GatewaySettings()
