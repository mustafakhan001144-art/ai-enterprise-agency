"""The dynamic agent registry and the /api/v1/agents endpoints."""

import os
import time

import pytest

from core.registry import AgentRegistry, RegistryError, default_registry

CUSTOM_IDS = {
    "forensics.ai-trace-analyst",
    "forensics.agent-containment-specialist",
    "archaeology.dependency-cartographer",
    "archaeology.legacy-code-archaeologist",
}

VALID_AGENT = """---
name: Test Agent
agent_id: management.test-agent
version: 0.1.0
output_schema: Test/v1
description: A test agent.
---
Do the thing.
"""


def auth(key: str) -> dict:
    return {"Authorization": f"Bearer {key}"}


def test_default_registry_loads_custom_and_upstream_agents():
    snapshot = default_registry().snapshot()
    custom = {a.agent_id for a in snapshot.agents.values() if a.source == "custom"}
    assert custom == CUSTOM_IDS
    upstream = [a for a in snapshot.agents.values() if a.source == "upstream"]
    assert upstream, "vendored upstream agents should load"
    assert all(a.agent_id.startswith("upstream.") for a in upstream)


def test_empty_custom_divisions_are_reported_not_invented():
    snapshot = default_registry().snapshot()
    assert snapshot.divisions["management"]["agent_count"] == 0
    assert snapshot.divisions["marketing"]["agent_count"] == 0
    assert "custom division 'management' has no agents" in snapshot.warnings
    assert "custom division 'marketing' has no agents" in snapshot.warnings


def test_public_metadata_never_contains_the_prompt_body():
    agent = default_registry().get("forensics.ai-trace-analyst")
    public = agent.public()
    assert len(public["prompt_sha256"]) == 64
    assert "body" not in public and "prompt" not in public
    assert all(len(str(v)) < 2000 for v in public.values())


@pytest.mark.parametrize(
    ("content", "message"),
    [
        ("no front matter\n", "missing YAML front matter"),
        (VALID_AGENT.replace("version: 0.1.0\n", ""), "missing required fields"),
        (VALID_AGENT.replace("management.test-agent", "forensics.test-agent"), "must start with 'management.'"),
        (VALID_AGENT.replace("Do the thing.\n", ""), "prompt body is empty"),
    ],
)
def test_invalid_custom_agents_are_rejected(tmp_path, content, message):
    (tmp_path / "management").mkdir()
    (tmp_path / "management" / "bad.md").write_text(content)
    with pytest.raises(RegistryError, match=message):
        AgentRegistry(tmp_path, None).snapshot()


def test_unknown_division_is_rejected(tmp_path):
    (tmp_path / "sales").mkdir()
    (tmp_path / "sales" / "x.md").write_text(VALID_AGENT)
    with pytest.raises(RegistryError, match="not a custom division"):
        AgentRegistry(tmp_path, None).snapshot()


def test_registry_reloads_when_an_agent_file_is_added(tmp_path):
    (tmp_path / "management").mkdir()
    registry = AgentRegistry(tmp_path, None)
    assert registry.get("management.test-agent") is None
    path = tmp_path / "management" / "test.md"
    path.write_text(VALID_AGENT)
    future = time.time() + 5
    os.utime(path, (future, future))
    assert registry.get("management.test-agent") is not None
    with pytest.raises(RegistryError, match="not found in registry"):
        registry.require(["management.missing"])


def test_agents_endpoint_requires_a_key(client):
    assert client.get("/api/v1/agents").status_code == 401


def test_agents_endpoint_lists_and_filters(client, make_account):
    _, key = make_account()
    body = client.get("/api/v1/agents?source=custom", headers=auth(key)).json()
    assert {a["agent_id"] for a in body["agents"]} == CUSTOM_IDS
    divisions = {d["division"]: d for d in body["divisions"]}
    assert divisions["management"]["agent_count"] == 0
    assert any("management" in w for w in body["warnings"])
    forensics = client.get("/api/v1/agents?division=forensics", headers=auth(key)).json()["agents"]
    assert {a["agent_id"] for a in forensics} == {i for i in CUSTOM_IDS if i.startswith("forensics.")}


def test_agent_detail_and_missing_agent(client, make_account):
    _, key = make_account()
    detail = client.get("/api/v1/agents/archaeology.dependency-cartographer", headers=auth(key))
    assert detail.status_code == 200
    assert detail.json()["output_schema"] == "DependencyMap/v1"
    assert client.get("/api/v1/agents/nope.nothing", headers=auth(key)).status_code == 404
