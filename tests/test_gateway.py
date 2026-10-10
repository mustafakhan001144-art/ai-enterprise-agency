"""Startup, authentication, tenant isolation, metering and input validation."""

FORENSICS_BODY = {
    "subject": {"agent_name": "billing-bot", "runtime": "langgraph"},
    "artifacts": [{"artifact_id": "a1", "kind": "tool_log", "content": "tool=http_get url=https://x"}],
}


def auth(key: str) -> dict:
    return {"Authorization": f"Bearer {key}"}


def test_healthz_and_database_created(client, settings):
    assert client.get("/healthz").json() == {"status": "ok"}
    assert settings.database_path.exists()
    assert settings.jobs_dir.is_dir()


def test_missing_key_is_401(client):
    response = client.post("/api/v1/forensics/contain", json=FORENSICS_BODY)
    assert response.status_code == 401


def test_unknown_key_is_401(client):
    response = client.post("/api/v1/forensics/contain", json=FORENSICS_BODY, headers=auth("nope"))
    assert response.status_code == 401


def test_x_api_key_header_accepted(client, make_account):
    _, key = make_account()
    response = client.post("/api/v1/forensics/contain", json=FORENSICS_BODY, headers={"X-API-Key": key})
    assert response.status_code == 202


def test_inactive_subscription_is_402(client, make_account):
    _, key = make_account(status="past_due")
    response = client.post("/api/v1/forensics/contain", json=FORENSICS_BODY, headers=auth(key))
    assert response.status_code == 402


def test_forensics_job_is_queued_and_metered(client, make_account, account_row):
    account_id, key = make_account(quota=100)
    response = client.post("/api/v1/forensics/contain", json=FORENSICS_BODY, headers=auth(key))
    assert response.status_code == 202
    body = response.json()
    assert body["status"] == "queued"
    assert body["runbook"] == "forensic_incident_response"
    assert body["credits_charged"] >= 1
    assert body["credits_remaining"] == 100 - body["credits_charged"]
    assert account_row(account_id)["credits_used"] == body["credits_charged"]


def test_insufficient_credits_is_402_and_not_charged(client, make_account, account_row):
    account_id, key = make_account(quota=15, used=10)
    response = client.post(
        "/api/v1/archeology/audit", json={"repo_url": "https://github.com/acme/legacy"}, headers=auth(key)
    )
    assert response.status_code == 402
    assert account_row(account_id)["credits_used"] == 10


def test_job_status_is_tenant_isolated(client, make_account):
    _, key_a = make_account()
    _, key_b = make_account()
    job = client.post("/api/v1/forensics/contain", json=FORENSICS_BODY, headers=auth(key_a)).json()

    own = client.get(job["status_url"], headers=auth(key_a))
    assert own.status_code == 200
    assert own.json()["job_id"] == job["job_id"]

    other = client.get(job["status_url"], headers=auth(key_b))
    assert other.status_code == 404


def test_oversized_body_is_413(client, make_account):
    _, key = make_account()
    big = dict(FORENSICS_BODY, artifacts=[{"artifact_id": "a1", "kind": "other", "content": "x" * 70_000}])
    response = client.post("/api/v1/forensics/contain", json=big, headers=auth(key))
    assert response.status_code == 413


def test_duplicate_artifact_ids_rejected(client, make_account):
    _, key = make_account()
    artifact = FORENSICS_BODY["artifacts"][0]
    response = client.post(
        "/api/v1/forensics/contain",
        json=dict(FORENSICS_BODY, artifacts=[artifact, artifact]),
        headers=auth(key),
    )
    assert response.status_code == 422


def test_unknown_fields_rejected(client, make_account):
    _, key = make_account()
    response = client.post("/api/v1/forensics/contain", json=dict(FORENSICS_BODY, surprise=True), headers=auth(key))
    assert response.status_code == 422


def test_archeology_rejects_disallowed_and_unsafe_urls(client, make_account):
    _, key = make_account()
    for url in [
        "https://evil.example/acme/repo",
        "http://github.com/acme/repo",
        "https://user:pw@github.com/acme/repo",
        "https://140.82.112.3/acme/repo",
        "file:///etc/passwd",
        "https://github.com/",
    ]:
        response = client.post("/api/v1/archeology/audit", json={"repo_url": url}, headers=auth(key))
        assert response.status_code == 422, url


def test_archeology_rejects_path_traversal_ref(client, make_account):
    _, key = make_account()
    response = client.post(
        "/api/v1/archeology/audit",
        json={"repo_url": "https://github.com/acme/repo", "ref": "../../etc"},
        headers=auth(key),
    )
    assert response.status_code == 422


def test_archeology_job_queued(client, make_account):
    _, key = make_account()
    response = client.post(
        "/api/v1/archeology/audit",
        json={"repo_url": "https://github.com/acme/repo", "ref": "main"},
        headers=auth(key),
    )
    assert response.status_code == 202
    assert response.json()["credits_charged"] == 10
