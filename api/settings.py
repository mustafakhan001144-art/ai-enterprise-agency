"""Gateway settings, validated from the environment at startup.

CoreSettings holds what both the gateway and the worker need (storage, worker
tuning, the optional language-model narrative). GatewaySettings adds Stripe and
request metering, which only the API process uses.
"""

from functools import lru_cache
from pathlib import Path
from typing import Literal

from pydantic import Field, SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

STRIPE_KEY_PREFIXES = ("sk_test_", "sk_live_", "rk_test_", "rk_live_")


class CoreSettings(BaseSettings):
    """Settings shared by the gateway and the job worker. Needs no secrets."""

    model_config = SettingsConfigDict(env_prefix="AGENCY_", env_file=".env", extra="ignore", populate_by_name=True)

    environment: str = Field(default="development", pattern="^(development|staging|production)$")

    storage_root: Path = Path("storage")
    database_path: Path = Path("storage/database.db")

    # How long a worker owns a claimed job before another worker may take it over.
    worker_lease_seconds: int = Field(default=300, ge=10)
    # Attempts before a job is marked failed and its credits are refunded.
    worker_max_attempts: int = Field(default=3, ge=1, le=10)
    worker_poll_seconds: float = Field(default=2.0, gt=0)

    # Optional language-model narrative (core/llm.py). "none" keeps every job fully deterministic.
    llm_provider: Literal["none", "anthropic"] = "none"
    llm_model: str = Field(default="claude-opus-5-5", min_length=1, max_length=100)
    llm_effort: Literal["low", "medium", "high", "xhigh", "max"] = "low"
    llm_timeout_seconds: float = Field(default=120.0, gt=0)
    anthropic_api_key: SecretStr | None = Field(default=None, validation_alias="ANTHROPIC_API_KEY")

    @model_validator(mode="after")
    def _llm_key_present(self) -> "CoreSettings":
        key = self.anthropic_api_key.get_secret_value() if self.anthropic_api_key else ""
        if self.llm_provider == "anthropic" and not key:
            raise ValueError("AGENCY_LLM_PROVIDER=anthropic needs ANTHROPIC_API_KEY to be set")
        return self

    @property
    def jobs_dir(self) -> Path:
        return self.storage_root / "code_sandboxes"


class GatewaySettings(CoreSettings):
    stripe_api_key: SecretStr
    stripe_webhook_secret: SecretStr
    # Maps a Stripe Price ID to the monthly credit quota it grants, e.g.
    # AGENCY_PLAN_CREDITS='{"price_123": 1000, "price_456": 10000}'
    plan_credits: dict[str, int] = Field(default_factory=dict)

    max_request_bytes: int = Field(default=5 * 1024 * 1024, gt=0)
    forensics_bytes_per_credit: int = Field(default=64 * 1024, gt=0)
    archeology_audit_credits: int = Field(default=10, gt=0)
    allowed_git_hosts: frozenset[str] = frozenset({"github.com", "gitlab.com", "bitbucket.org"})

    @model_validator(mode="after")
    def _stripe_test_mode_outside_production(self) -> "GatewaySettings":
        """Live Stripe keys are only accepted when environment=production."""
        key = self.stripe_api_key.get_secret_value()
        if not key.startswith(STRIPE_KEY_PREFIXES):
            raise ValueError("stripe_api_key must be a Stripe secret or restricted key (sk_... or rk_...)")
        if self.environment != "production" and key.startswith(("sk_live_", "rk_live_")):
            raise ValueError(
                f"a live Stripe key is configured with environment={self.environment}; "
                "use a test-mode key (sk_test_...) outside production"
            )
        if not self.stripe_webhook_secret.get_secret_value().startswith("whsec_"):
            raise ValueError("stripe_webhook_secret must be a Stripe webhook signing secret (whsec_...)")
        return self

    @property
    def stripe_test_mode(self) -> bool:
        return "_test_" in self.stripe_api_key.get_secret_value()[:8]

    @field_validator("plan_credits")
    @classmethod
    def _quotas_positive(cls, value: dict[str, int]) -> dict[str, int]:
        bad = [price for price, credits in value.items() if credits < 0]
        if bad:
            raise ValueError(f"negative credit quota for prices: {bad}")
        return value


@lru_cache
def get_settings() -> GatewaySettings:
    return GatewaySettings()


@lru_cache
def get_core_settings() -> CoreSettings:
    return CoreSettings()
