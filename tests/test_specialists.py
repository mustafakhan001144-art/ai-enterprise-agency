"""Routing jobs to the Agency Agents catalog, installed copies, and specialist consults."""

import copy
import json
from pathlib import Path
from types import SimpleNamespace

from api.settings import CoreSettings
from core.llm import CONSULT_RULES, narrator_from_settings
from core.orchestrator import run_job
from core.registry import REPO_ROOT, AgentRegistry, default_registry
from core.workflows import specialists
from tests.fixtures.samples import FORENSICS_INCIDENT

CATALOG = REPO_ROOT / "vendor" / "agency-agents"
RESPONDER = "upstream.security.security-incident-responder"


def _run(tmp_path: Path, registry=None, **kwargs):
    job_dir = tmp_path / "job"
    job_dir.mkdir(parents=True)
    (job_dir / "request.json").write_text(json.dumps(FORENSICS_INCIDENT))
    outcome = run_job(
        "forensic_incident_response",
        copy.deepcopy(FORENSICS_INCIDENT),
        job_dir,
        "job-1",
        registry or default_registry(),
        **kwargs,
    )
    return outcome, job_dir


def test_forensics_job_is_staffed_from_the_catalog(tmp_path):
    outcome, job_dir = _run(tmp_path)
    roster = outcome.result["outputs"]["specialist_roster"]
    assert roster["schema_version"] == "SpecialistRoster/v1"
    assert roster["status"] == "STAFFED" and roster["not_found"] == []
    assert roster["catalog"]["agents_available"] >= 282
    by_name = {a["catalog_name"]: a for a in roster["assignments"]}
    assert by_name["security-incident-responder"]["role"] == "lead"
    assert by_name["security-incident-responder"]["agent_id"] == RESPONDER
    # The sample incident is a data exfiltration, so the egress specialist is routed in.
    assert "security-cloud-security-architect" in by_name
    assert {"testing-reality-checker", "support-executive-summary-generator", "sales-proposal-strategist"} <= set(
        by_name
    )
    assert all(a["triggered_by"] for a in roster["assignments"])
    assert all(c["passed"] for c in roster["self_validation"])
    assert len(by_name) == len(roster["assignments"])  # each specialist once
    assert "## Specialist team" in (job_dir / "report.md").read_text()


def test_roster_is_deterministic(tmp_path):
    first, _ = _run(tmp_path / "a")
    second, _ = _run(tmp_path / "b")
    assert first.result["outputs"]["specialist_roster"] == second.result["outputs"]["specialist_roster"]


def test_archaeology_findings_route_to_matching_specialists():
    outputs = {
        "code_archaeology": {
            "units": [{}, {}],
            "portfolio_summary": {
                "by_gate": {"CHARACTERISATION_TESTS_REQUIRED_BEFORE_CHANGE": 2},
                "hazard_counts": {"H02_HARDCODED_SECRET": 1, "H03_UNPARAMETERISED_QUERY": 3},
            },
        },
        "dependency_cartography": {"evidence_gaps": [{"gap_id": "G1", "type": "MISSING_LOCKFILE"}]},
        "follow_up_proposal": {"status": "WITHHELD"},
    }
    roster = specialists.specialist_roster("legacy_archeology_sweep", outputs, default_registry().snapshot(), "r")
    names = [a["catalog_name"] for a in roster["assignments"]]
    assert names[0] == "specialized-codebase-archaeologist"
    assert {
        "security-secrets-credential-engineer",
        "security-appsec-engineer",
        "testing-test-automation-engineer",
        "engineering-devops-automator",
    } <= set(names)
    # A withheld proposal brings in no sales or delivery specialists.
    assert "sales-proposal-strategist" not in names and "project-manager-senior" not in names
    appsec = next(a for a in roster["assignments"] if a["catalog_name"] == "security-appsec-engineer")
    assert appsec["triggered_by"] == ["portfolio_summary.hazard_counts.H03_UNPARAMETERISED_QUERY=3"]


def test_job_still_runs_without_the_catalog(tmp_path):
    registry = AgentRegistry(REPO_ROOT / "core" / "agents", None)
    outcome, _ = _run(tmp_path, registry)
    roster = outcome.result["outputs"]["specialist_roster"]
    assert roster["status"] == "CATALOG_UNAVAILABLE" and roster["assignments"] == []
    assert "security-incident-responder" in roster["not_found"]


def _installed_folder(tmp_path: Path) -> Path:
    folder = tmp_path / "claude-agents"
    folder.mkdir()
    source = (CATALOG / "security" / "security-incident-responder.md").read_text(encoding="utf-8")
    (folder / "security-incident-responder.md").write_text(source + "\nLocal house rule: page the CISO first.\n")
    unchanged = (CATALOG / "testing" / "testing-reality-checker.md").read_text(encoding="utf-8")
    (folder / "testing-reality-checker.md").write_text(unchanged)
    (folder / "my-own-agent.md").write_text("---\nname: My Agent\ndescription: Mine.\n---\nDo things.\n")
    (folder / "notes.md").write_text("# not an agent\n")
    return folder


def test_installed_copy_replaces_the_vendored_agent(tmp_path):
    registry = default_registry(_installed_folder(tmp_path))
    snapshot = registry.snapshot()
    responder = snapshot.agents[RESPONDER]
    assert responder.location == "installed" and responder.modified is True
    assert responder.path == "installed:security-incident-responder.md"
    assert str(tmp_path) not in json.dumps(responder.public())  # local paths are not published
    checker = snapshot.agents["upstream.testing.testing-reality-checker"]
    assert checker.location == "installed" and checker.modified is False
    assert snapshot.agents["installed.my-own-agent"].division == "installed"
    assert snapshot.installed == {
        "configured": True,
        "found": 3,
        "matched_catalog": 2,
        "modified": 1,
        "not_in_catalog": 1,
    }
    assert "page the CISO first" in registry.prompt_body(RESPONDER)
    assert not registry.prompt_body(RESPONDER).startswith("---")

    outcome, _ = _run(tmp_path, registry)
    roster = outcome.result["outputs"]["specialist_roster"]
    assert roster["catalog"]["installed_copies_used"] == 2
    lead = roster["assignments"][0]
    assert lead["location"] == "installed" and lead["prompt_sha256"] == responder.prompt_sha256
    assert {
        "agent_id": RESPONDER,
        "version": None,
        "prompt_sha256": responder.prompt_sha256,
        "location": "installed",
    } in (outcome.result["agents"])


def test_installed_folder_from_environment_and_missing_folder(tmp_path, monkeypatch):
    monkeypatch.setenv("AGENCY_INSTALLED_AGENTS_DIR", str(_installed_folder(tmp_path)))
    assert default_registry().get(RESPONDER).location == "installed"
    missing = default_registry(tmp_path / "nope").snapshot()
    assert missing.agents[RESPONDER].location == "repository"
    assert any("does not exist" in w for w in missing.warnings)


def test_agents_api_reports_installed_copies(client, make_account, tmp_path):
    client.app.state.registry = default_registry(_installed_folder(tmp_path))
    _, key = make_account()
    page = client.get("/api/v1/agents?source=installed", headers={"Authorization": f"Bearer {key}"}).json()
    assert [a["agent_id"] for a in page["agents"]] == ["installed.my-own-agent"]
    assert page["installed"]["matched_catalog"] == 2
    one = client.get(f"/api/v1/agents/{RESPONDER}", headers={"Authorization": f"Bearer {key}"}).json()
    assert one["location"] == "installed" and one["modified"] is True


def test_consults_use_each_specialists_catalog_prompt(tmp_path):
    seen = []

    def consultant(assignment, persona, material):
        seen.append((assignment["agent_id"], persona, material.get("schema_version")))
        return {
            "agent_id": assignment["agent_id"],
            "name": assignment["name"],
            "prompt_sha256": assignment["prompt_sha256"],
            "works_from_stage": assignment["works_from_stage"],
            "source_digest": "x",
            "status": "COMPLETE",
            "model": "fake",
            "notes_markdown": f"- Notes from {assignment['name']}",
            "detail": None,
        }

    outcome, job_dir = _run(tmp_path, consultant=consultant, max_consults=2)
    consults = outcome.result["outputs"]["specialist_consults"]
    assert [s["stage_id"] for s in outcome.result["stages"]][-2:] == ["specialist_roster", "specialist_consults"]
    assert len(seen) == 2 and seen[0][0] == RESPONDER
    assert seen[0][1].startswith("# Incident Responder") and "You are **Incident Responder**" in seen[0][1]
    assert seen[0][2] == "ContainmentPlan/v1"
    roster = outcome.result["outputs"]["specialist_roster"]
    assert consults["not_consulted"] == [a["agent_id"] for a in roster["assignments"][2:]]
    assert "specialist_consults" in outcome.result["generated_by"]
    assert "Notes from Incident Responder" in (job_dir / "report.md").read_text()


def test_a_failing_consult_never_fails_the_job(tmp_path):
    def consultant(assignment, persona, material):
        raise ConnectionError("down")

    outcome, _ = _run(tmp_path, consultant=consultant, max_consults=1)
    consults = outcome.result["outputs"]["specialist_consults"]
    assert consults["status"] == "PARTIAL"
    assert consults["consults"][0]["status"] == "FAILED" and consults["consults"][0]["detail"] == "ConnectionError"


def test_no_consults_without_a_model(tmp_path):
    outcome, _ = _run(tmp_path)
    assert "specialist_consults" not in outcome.result["outputs"]
    assert "no language model was called" in outcome.result["generated_by"]


def test_anthropic_consult_sends_persona_rules_and_redacted_report(monkeypatch):
    settings = CoreSettings(_env_file=None, llm_provider="anthropic", ANTHROPIC_API_KEY="sk-ant-test")
    narrator = narrator_from_settings(settings)
    calls = []

    def create(**kwargs):
        calls.append(kwargs)
        text = SimpleNamespace(type="text", text="1. Revoke the token (AN-001).")
        return SimpleNamespace(stop_reason="end_turn", model="claude-opus-5-5", content=[text])

    monkeypatch.setattr(narrator.client.beta.messages, "create", create)
    assignment = {
        "agent_id": RESPONDER,
        "name": "Incident Responder",
        "prompt_sha256": "abc",
        "works_from_stage": "containment_plan",
        "task": "Lead the response.",
        "triggered_by": ["trace_analysis.severity=SEV1_CRITICAL"],
    }
    material = {"schema_version": "ContainmentPlan/v1", "note": "api_key=supersecretvalue123"}
    entry = narrator.consult(assignment, "# Incident Responder\nYou are the responder.", material)
    assert entry["status"] == "COMPLETE" and entry["notes_markdown"].startswith("1. Revoke")
    sent = calls[0]
    assert sent["system"].startswith("# Incident Responder") and sent["system"].endswith(CONSULT_RULES)
    assert "supersecretvalue123" not in sent["messages"][0]["content"]
    assert "Lead the response." in sent["messages"][0]["content"]


def test_max_consults_setting_defaults_to_three():
    assert CoreSettings(_env_file=None).llm_max_consults == 3
    assert CoreSettings(_env_file=None).installed_agents_dir is None
