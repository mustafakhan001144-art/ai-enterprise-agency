"""The dashboard is served by the API with a strict content security policy."""

import json

from tests.fixtures.samples import FORENSICS_INCIDENT


def test_root_redirects_to_dashboard(client):
    response = client.get("/", follow_redirects=False)
    assert response.status_code == 307 and response.headers["location"] == "/dashboard/"


def test_dashboard_page_and_assets_are_served_with_csp(client):
    page = client.get("/dashboard/")
    assert page.status_code == 200 and page.headers["content-type"].startswith("text/html")
    assert "script-src 'self'" in page.headers["content-security-policy"]
    assert "frame-ancestors 'none'" in page.headers["content-security-policy"]
    assert '<script src="/dashboard/app.js"' in page.text
    script = client.get("/dashboard/app.js")
    assert script.status_code == 200 and script.headers["content-type"].startswith("text/javascript")
    assert client.get("/dashboard/app.css").status_code == 200


def test_sample_incident_matches_the_tested_fixture(client):
    assert client.get("/dashboard/sample-incident.json").json() == json.loads(json.dumps(FORENSICS_INCIDENT))


def test_only_known_dashboard_files_are_served(client):
    for name in ("index.html.bak", "..%2Fmain.py", "%2E%2E%2Fsettings.py", "nope.js"):
        assert client.get(f"/dashboard/{name}").status_code == 404


def test_dashboard_is_not_in_the_api_schema(client):
    assert not [p for p in client.get("/openapi.json").json()["paths"] if p.startswith("/dashboard") or p == "/"]
