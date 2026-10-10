"""Public request/response models for the v1 API."""

import ipaddress
import re
from datetime import datetime
from typing import Literal
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field, field_validator

ArtifactKind = Literal[
    "transcript", "tool_log", "orchestrator_log", "egress_log", "policy_log", "token_ledger", "other"
]

GIT_REF_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]{0,199}$")


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


class LogArtifact(StrictModel):
    artifact_id: str = Field(pattern=r"^[A-Za-z0-9_-]{1,32}$")
    kind: ArtifactKind
    content: str | list[dict] = Field(description="Raw log text or a list of structured records")


class BaselineProfile(StrictModel):
    max_tool_calls_per_turn: int | None = Field(default=None, ge=1)
    max_tokens_per_turn: int | None = Field(default=None, ge=1)
    permitted_data_classes: list[str] = Field(default_factory=list)


class SubjectAgent(StrictModel):
    agent_name: str = Field(min_length=1, max_length=200)
    runtime: str = Field(min_length=1, max_length=100)
    declared_tools: list[str] = Field(default_factory=list)
    declared_egress_allowlist: list[str] = Field(default_factory=list)
    baseline_profile: BaselineProfile | None = None


class ForensicsContainRequest(StrictModel):
    subject: SubjectAgent
    artifacts: list[LogArtifact] = Field(min_length=1, max_length=200)
    available_controls: list[str] = Field(default_factory=list)
    business_critical_components: list[str] = Field(default_factory=list)

    @field_validator("artifacts")
    @classmethod
    def _unique_ids(cls, artifacts: list[LogArtifact]) -> list[LogArtifact]:
        ids = [a.artifact_id for a in artifacts]
        if len(ids) != len(set(ids)):
            raise ValueError("artifact_id values must be unique")
        return artifacts


class ArcheologyAuditRequest(StrictModel):
    repo_url: str = Field(max_length=500, description="HTTPS clone URL of a repository on an allowed host")
    ref: str | None = Field(default=None, description="Branch, tag or commit to audit; default branch if omitted")

    @field_validator("repo_url")
    @classmethod
    def _https_without_credentials(cls, value: str) -> str:
        parts = urlsplit(value)
        if parts.scheme != "https":
            raise ValueError("repo_url must use https")
        if parts.username or parts.password:
            raise ValueError("repo_url must not embed credentials")
        if parts.port not in (None, 443):
            raise ValueError("repo_url must use the default https port")
        host = (parts.hostname or "").lower()
        try:
            ipaddress.ip_address(host)
        except ValueError:
            pass
        else:
            raise ValueError("repo_url must use a hostname, not an IP address")
        if not parts.path.strip("/") or parts.query or parts.fragment:
            raise ValueError("repo_url must be a plain repository URL")
        return value

    @field_validator("ref")
    @classmethod
    def _safe_ref(cls, value: str | None) -> str | None:
        if value is not None and (not GIT_REF_PATTERN.fullmatch(value) or ".." in value):
            raise ValueError("ref contains unsupported characters")
        return value


class JobAccepted(BaseModel):
    job_id: str
    status: Literal["queued"]
    runbook: str
    credits_charged: int
    credits_remaining: int
    status_url: str


class JobStatus(BaseModel):
    job_id: str
    kind: str
    runbook: str
    status: str
    credits_charged: int
    attempts: int
    error: str | None
    result_digest: str | None
    result_url: str | None
    created_at: datetime
    updated_at: datetime
    started_at: datetime | None
    finished_at: datetime | None


class JobSummary(BaseModel):
    job_id: str
    kind: str
    runbook: str
    status: str
    credits_charged: int
    created_at: datetime


class JobPage(BaseModel):
    jobs: list[JobSummary]


class AccountSummary(BaseModel):
    account_id: str
    subscription_status: str
    credit_quota: int
    credits_used: int
    credits_remaining: int


class LedgerEntry(BaseModel):
    id: int
    delta: int
    reason: str
    job_id: str | None
    reference: str | None
    created_at: datetime


class LedgerPage(BaseModel):
    entries: list[LedgerEntry]
    next_before_id: int | None


class AgentInfo(BaseModel):
    agent_id: str
    name: str
    division: str
    source: str
    description: str
    version: str | None
    output_schema: str | None
    upstream: list[str]
    downstream: list[str]
    path: str
    prompt_sha256: str
    location: str = "repository"
    modified: bool = False


class DivisionInfo(BaseModel):
    division: str
    label: str
    source: str
    agent_count: int


class AgentPage(BaseModel):
    agents: list[AgentInfo]
    divisions: list[DivisionInfo]
    warnings: list[str]
    installed: dict = {}
