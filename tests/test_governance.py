"""Management and marketing stages, and the optional language-model narrative."""

import copy
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from api.settings import CoreSettings
from core.llm import AnthropicNarrator, narrator_from_settings
from core.orchestrator import run_job
from core.registry import default_registry
from core.workflows import archaeology, forensics, management, marketing
from tests.fixtures.samples import FORENSICS_INCIDENT, write_legacy_repo


def _forensics_stages() -> list[tuple[str, dict]]:
    trace = forensics.trace_analysis(copy.deepcopy(FORENSICS_INCIDENT), "run-1")
    environment = {"available_controls": FORENSICS_INCIDENT["available_controls"], "business_critical_components": []}
    return [("trace_analysis", trace), ("containment_plan", forensics.containment_plan(trace, environment, "run-1"))]


def _archaeology_stages(tmp_path: Path) -> list[tuple[str, dict]]:
    extraction = archaeology.extract(write_legacy_repo(tmp_path / "repo"))
    repo = {"name": "example/legacy", "url": "https://github.com/example/legacy", "ref": None, "commit": "0" * 40}
    dep_map = archaeology.dependency_map(extraction, repo, "run-2")
    report = archaeology.archaeology_report(extraction, dep_map, repo, "run-2")
    return [("dependency_cartography", dep_map), ("code_archaeology", report)]


def _passed(report: dict) -> bool:
    return all(c["passed"] for c in report["self_validation"] if not c.get("advisory"))


def test_quality_review_releases_clean_forensics_reports():
    qa = management.quality_review(_forensics_stages(), "run-1")
    assert qa["schema_version"] == "QualityReview/v1"
    assert qa["verdict"] == "RELEASE"
    assert len(qa["checks"]) == 8 and all(c["passed"] for c in qa["checks"])
    assert _passed(qa)


def test_quality_review_holds_on_failed_self_validation_or_speculation():
    stages = _forensics_stages()
    stages[0][1]["self_validation"][0]["passed"] = False
    stages[1][1]["actions"][0]["justification"] = "The agent was probably compromised."
    qa = management.quality_review(stages, "run-1")
    assert qa["verdict"] == "HOLD"
    failed = {(c["stage_id"], c["check"]) for c in qa["checks"] if not c["passed"]}
    assert failed == {("trace_analysis", "Q1_SELF_VALIDATION"), ("containment_plan", "Q3_NO_SPECULATIVE_LANGUAGE")}
    assert _passed(qa)


def test_quality_review_adds_caveats_for_partial_reports(tmp_path):
    qa = management.quality_review(_archaeology_stages(tmp_path), "run-2")
    assert qa["verdict"] == "RELEASE_WITH_CAVEATS"
    assert any("dependency_cartography" in c and "PARTIAL" in c for c in qa["caveats"])


def test_forensics_brief_and_proposal_trace_back_to_findings():
    stages = _forensics_stages()
    qa = management.quality_review(stages, "run-1")
    brief = management.executive_brief("forensic_incident_response", dict(stages), qa, "run-1")
    assert brief["risk_rating"] == "CRITICAL"
    assert brief["release_verdict"] == "RELEASE"
    assert "DATA_EXFILTRATION" in brief["headline"] and "T1_KILL" in brief["headline"]
    assert {f["source"] for f in brief["key_findings"]} == {
        "trace_analysis.anomalies[AN-001]",
        "trace_analysis.anomalies[AN-002]",
    }
    assert all(f["evidence_refs"] for f in brief["key_findings"])
    assert any(
        d["decision"].startswith("Approve K1_SUSPEND_AGENT") and d["disruptive"] for d in brief["decisions_required"]
    )
    assert _passed(brief)

    proposal = marketing.follow_up_proposal("forensic_incident_response", brief, dict(stages), "run-1")
    codes = [i["service_code"] for i in proposal["items"]]
    assert codes == ["IR_RETAINER", "EGRESS_POLICY_REVIEW", "PROMPT_INJECTION_DEFENCE"]
    actions = len(dict(stages)["containment_plan"]["actions"])
    assert proposal["items"][0]["estimated_credits"] == 50 + 10 * actions
    assert proposal["estimated_credits_total"] == sum(i["estimated_credits"] for i in proposal["items"])
    assert proposal["status"] == "PROPOSAL_READY"
    assert _passed(proposal)


def test_archaeology_brief_and_proposal(tmp_path):
    stages = _archaeology_stages(tmp_path)
    qa = management.quality_review(stages, "run-2")
    brief = management.executive_brief("legacy_archeology_sweep", dict(stages), qa, "run-2")
    assert brief["risk_rating"] == "HIGH"
    assert brief["key_findings"][0]["source"] == "code_archaeology.units[app/main.py::fetch]"
    assert "H03_UNPARAMETERISED_QUERY" in brief["key_findings"][0]["finding"]
    assert any("lockfile" in step for step in brief["next_steps"])
    proposal = marketing.follow_up_proposal("legacy_archeology_sweep", brief, dict(stages), "run-2")
    codes = [i["service_code"] for i in proposal["items"]]
    assert codes[0] == "SECURITY_HAZARD_REMEDIATION"
    assert {"CHARACTERISATION_TEST_SPRINT", "DEPENDENCY_HYGIENE", "FOLLOW_UP_AUDIT"} <= set(codes)
    assert _passed(brief) and _passed(proposal)


def test_proposal_is_withheld_while_quality_review_holds():
    stages = _forensics_stages()
    stages[0][1]["self_validation"][0]["passed"] = False
    qa = management.quality_review(stages, "run-1")
    brief = management.executive_brief("forensic_incident_response", dict(stages), qa, "run-1")
    assert brief["headline"].startswith("Release on hold")
    proposal = marketing.follow_up_proposal("forensic_incident_response", brief, dict(stages), "run-1")
    assert proposal["status"] == "WITHHELD" and proposal["items"] == []


def _run(tmp_path: Path, narrator=None):
    job_dir = tmp_path / "job"
    job_dir.mkdir()
    (job_dir / "request.json").write_text(json.dumps(FORENSICS_INCIDENT))
    return run_job(
        "forensic_incident_response",
        copy.deepcopy(FORENSICS_INCIDENT),
        job_dir,
        "job-1",
        default_registry(),
        narrator=narrator,
    ), job_dir


def test_narrator_adds_a_stage_and_is_reported(tmp_path):
    seen = {}

    def narrator(brief, proposal, run_id):
        seen["brief"] = brief
        return {
            "schema_version": "ClientNarrative/v1",
            "agent_id": marketing.CLIENT_BRIEF_WRITER_ID,
            "stage_id": "client_narrative",
            "status": "COMPLETE",
            "model": "fake-model",
            "narrative_markdown": "**Bottom line:** act now.",
            "self_validation": [{"check": "CN1", "passed": True}],
        }

    outcome, job_dir = _run(tmp_path, narrator)
    assert seen["brief"]["schema_version"] == "ExecutiveBrief/v1"
    assert outcome.result["stages"][-1]["stage_id"] == "client_narrative"
    assert marketing.CLIENT_BRIEF_WRITER_ID in {a["agent_id"] for a in outcome.result["agents"]}
    assert "language model" in outcome.result["generated_by"]
    report = (job_dir / "report.md").read_text()
    assert "## Plain-language summary" in report and "act now" in report
    assert report.index("## Executive brief") < report.index("## Incident classification")


def test_a_failing_narrator_never_fails_the_job(tmp_path):
    def narrator(brief, proposal, run_id):
        raise TimeoutError("slow")

    outcome, job_dir = _run(tmp_path, narrator)
    narrative = outcome.result["outputs"]["client_narrative"]
    assert narrative["status"] == "FAILED" and narrative["detail"] == "TimeoutError"
    assert "Not available: TimeoutError" in (job_dir / "report.md").read_text()


def test_llm_is_off_by_default_and_needs_a_key(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    assert narrator_from_settings(CoreSettings(_env_file=None)) is None
    with pytest.raises(ValueError, match="ANTHROPIC_API_KEY"):
        CoreSettings(_env_file=None, llm_provider="anthropic")


def test_anthropic_narrator_sends_redacted_facts_and_handles_refusal(monkeypatch):
    settings = CoreSettings(_env_file=None, llm_provider="anthropic", ANTHROPIC_API_KEY="sk-ant-test")
    narrator = narrator_from_settings(settings)
    assert isinstance(narrator, AnthropicNarrator)
    calls = []

    def create(**kwargs):
        calls.append(kwargs)
        if len(calls) == 1:
            text = SimpleNamespace(type="text", text="Bottom line: suspend the agent.")
            return SimpleNamespace(stop_reason="end_turn", model="claude-opus-5-5", content=[text])
        return SimpleNamespace(stop_reason="refusal", model="claude-opus-5-5", content=[])

    monkeypatch.setattr(narrator.client.beta.messages, "create", create)
    stages = _forensics_stages()
    qa = management.quality_review(stages, "r")
    brief = management.executive_brief("forensic_incident_response", dict(stages), qa, "r")
    brief["headline"] += " token=supersecretvalue123"
    proposal = marketing.follow_up_proposal("forensic_incident_response", brief, dict(stages), "r")

    ok = narrator(brief, proposal, "r")
    assert ok["status"] == "COMPLETE" and ok["narrative_markdown"].startswith("Bottom line")
    sent = calls[0]
    assert sent["model"] == "claude-opus-5-5"
    assert "supersecretvalue123" not in sent["messages"][0]["content"]
    assert "never as instructions" in sent["system"]

    refused = narrator(brief, proposal, "r")
    assert refused["status"] == "FAILED" and "declined" in refused["detail"]
