"""Evidence bundles, the report endpoints and the Stripe test-mode guard."""

import asyncio
import json

import pytest
from pydantic import ValidationError

from api.settings import GatewaySettings
from core.registry import default_registry
from core.worker import Worker
from tests.fixtures.samples import FORENSICS_INCIDENT


def auth(key: str) -> dict:
    return {"Authorization": f"Bearer {key}"}


@pytest.fixture
def finished_job(client, make_account, settings):
    _, key = make_account()
    response = client.post("/api/v1/forensics/contain", json=FORENSICS_INCIDENT, headers=auth(key))
    job_id = response.json()["job_id"]
    assert asyncio.run(Worker(settings, default_registry(), worker_id="w1").run_once()) == "succeeded"
    return job_id, key, settings.jobs_dir / job_id


def test_report_is_markdown_and_states_how_it_was_produced(client, finished_job):
    job_id, key, _ = finished_job
    response = client.get(f"/api/v1/jobs/{job_id}/report", headers=auth(key))
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/markdown")
    text = response.text
    assert "DATA_EXFILTRATION" in text and "T1_KILL" in text
    assert "No language model was called" in text
    assert "nothing has been executed against your systems" in text
    assert "paste.example.net" in text


def test_evidence_manifest_covers_every_file_and_verifies(client, finished_job):
    job_id, key, _ = finished_job
    body = client.get(f"/api/v1/jobs/{job_id}/evidence", headers=auth(key)).json()
    assert body["verification"] == {"valid": True, "problems": [], "head": body["recorded_head"]}
    paths = [e["path"] for e in body["manifest"]["entries"]]
    assert paths == [
        "request.json",
        "stages/01_trace_analysis.json",
        "stages/02_containment_plan.json",
        "result.json",
        "report.md",
    ]


def test_tampered_report_is_detected(client, finished_job):
    job_id, key, job_dir = finished_job
    report = job_dir / "stages" / "02_containment_plan.json"
    data = json.loads(report.read_text())
    data["tier"] = "T4_MONITOR"
    report.write_text(json.dumps(data))
    verification = client.get(f"/api/v1/jobs/{job_id}/evidence", headers=auth(key)).json()["verification"]
    assert not verification["valid"]
    assert "stages/02_containment_plan.json: content changed" in verification["problems"]


def test_rewritten_manifest_is_detected_by_the_recorded_head(client, finished_job):
    job_id, key, job_dir = finished_job
    (job_dir / "report.md").write_text("# nothing to see\n")
    # Rebuilding the manifest makes it self-consistent, but its head no longer matches the database.
    from core.evidence import build_manifest

    build_manifest(job_dir, job_id)
    verification = client.get(f"/api/v1/jobs/{job_id}/evidence", headers=auth(key)).json()["verification"]
    assert not verification["valid"]
    assert any("recorded when the job finished" in p for p in verification["problems"])


def test_extra_file_is_reported(client, finished_job):
    job_id, key, job_dir = finished_job
    (job_dir / "stages" / "03_injected.json").write_text("{}")
    verification = client.get(f"/api/v1/jobs/{job_id}/evidence", headers=auth(key)).json()["verification"]
    assert "stages/03_injected.json: not in manifest" in verification["problems"]


def test_other_tenant_cannot_read_report_or_evidence(client, finished_job, make_account):
    job_id, _, _ = finished_job
    _, other = make_account()
    for suffix in ("report", "evidence", "result"):
        assert client.get(f"/api/v1/jobs/{job_id}/{suffix}", headers=auth(other)).status_code == 404


def test_report_before_completion_is_409(client, make_account):
    _, key = make_account()
    job_id = client.post("/api/v1/forensics/contain", json=FORENSICS_INCIDENT, headers=auth(key)).json()["job_id"]
    assert client.get(f"/api/v1/jobs/{job_id}/report", headers=auth(key)).status_code == 409


def _settings(**overrides):
    values = {"_env_file": None, "stripe_api_key": "sk_test_x", "stripe_webhook_secret": "whsec_x"}
    values.update(overrides)
    return GatewaySettings(**values)


@pytest.mark.parametrize("environment", ["development", "staging"])
def test_live_stripe_key_is_refused_outside_production(environment):
    with pytest.raises(ValidationError, match="test-mode key"):
        _settings(environment=environment, stripe_api_key="sk_live_abc")


def test_live_stripe_key_is_allowed_in_production():
    settings = _settings(environment="production", stripe_api_key="sk_live_abc")
    assert settings.stripe_test_mode is False


def test_test_key_reports_test_mode():
    assert _settings().stripe_test_mode is True


@pytest.mark.parametrize(
    ("field", "value"),
    [("stripe_api_key", "pk_test_publishable"), ("stripe_webhook_secret", "not_a_secret")],
)
def test_malformed_stripe_credentials_are_refused(field, value):
    with pytest.raises(ValidationError):
        _settings(**{field: value})


def test_validation_error_never_echoes_the_key():
    with pytest.raises(ValidationError) as excinfo:
        _settings(environment="development", stripe_api_key="sk_live_SUPERSECRETVALUE")
    assert "SUPERSECRETVALUE" not in str(excinfo.value)
