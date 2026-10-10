"""The deterministic forensics and archaeology procedures."""

import copy
import os

import pytest

from core.workflows import archaeology, forensics
from core.workflows.common import canonical_digest, find_secrets, redact
from tests.fixtures.samples import FORENSICS_INCIDENT, write_legacy_repo


def _all_passed(report: dict) -> bool:
    return all(check["passed"] for check in report["self_validation"])


def test_trace_analysis_classifies_the_reference_incident():
    report = forensics.trace_analysis(copy.deepcopy(FORENSICS_INCIDENT), "run-1")
    assert report["schema_version"] == "TraceAnalysisReport/v1"
    assert report["status"] == "COMPLETE"
    assert report["primary_class"] == "DATA_EXFILTRATION"
    assert report["secondary_classes"] == ["PROMPT_INJECTION_EXECUTED"]
    assert report["severity"] == "SEV1_CRITICAL"
    assert {a["type"] for a in report["anomalies"]} == {"INSTRUCTION_IN_DATA", "UNDECLARED_EGRESS"}
    assert {"type": "domain", "value": "paste.example.net"}.items() <= next(
        i for i in report["iocs"] if i["type"] == "domain"
    ).items()
    assert report["handoff"]["active_sessions"] == ["sess-9"]
    assert _all_passed(report)


def test_containment_plan_orders_actions_and_uses_only_declared_controls():
    trace = forensics.trace_analysis(copy.deepcopy(FORENSICS_INCIDENT), "run-1")
    plan = forensics.containment_plan(
        trace,
        {"available_controls": FORENSICS_INCIDENT["available_controls"], "business_critical_components": []},
        "run-1",
    )
    assert plan["status"] == "PLAN_READY"
    assert plan["tier"] == "T1_KILL"
    codes = [a["code"] for a in plan["actions"]]
    assert codes[0] == "P1_SNAPSHOT_EVIDENCE"
    assert codes.index("K1_SUSPEND_AGENT") < codes.index("M3_BLOCK_EGRESS_DESTINATION")
    executable = {c for c in codes if not c.startswith("R")}
    assert executable <= set(FORENSICS_INCIDENT["available_controls"])
    assert _all_passed(plan)


def test_forensics_output_is_reproducible():
    first = forensics.trace_analysis(copy.deepcopy(FORENSICS_INCIDENT), "run-1")
    second = forensics.trace_analysis(copy.deepcopy(FORENSICS_INCIDENT), "run-1")
    assert canonical_digest(first) == canonical_digest(second)


def test_missing_baseline_is_undeterminable_not_guessed():
    request = copy.deepcopy(FORENSICS_INCIDENT)
    request["subject"].pop("baseline_profile")
    report = forensics.trace_analysis(request, "run-1")
    assert any(t["result"] == "UNDETERMINABLE" for t in report["classification_trace"])


def test_secrets_in_logs_are_redacted():
    text = "Authorization: Bearer abcdefghijklmnopqrstuvwxyz123456 password=hunter2hunter2"
    assert find_secrets(text)
    cleaned = redact(text)
    assert "abcdefghijklmnopqrstuvwxyz123456" not in cleaned
    assert "hunter2hunter2" not in cleaned


@pytest.fixture
def legacy_repo(tmp_path):
    return write_legacy_repo(tmp_path / "repo")


def test_dependency_map_of_fixture_repo(legacy_repo):
    extraction = archaeology.extract(legacy_repo)
    dep_map = archaeology.dependency_map(extraction, {"name": "fixture", "commit": None}, "run-1")
    assert dep_map["schema_version"] == "DependencyMap/v1"
    gap_types = {g["type"] for g in dep_map["evidence_gaps"]}
    assert {"MISSING_LOCKFILE", "EMPTY_ADVISORY_SNAPSHOT"} <= gap_types
    node_ids = {n["id"] for n in dep_map["nodes"]}
    assert any("requests" in n for n in node_ids)
    assert _all_passed(dep_map)


def test_archaeology_report_flags_known_hazards(legacy_repo):
    extraction = archaeology.extract(legacy_repo)
    dep_map = archaeology.dependency_map(extraction, {"name": "fixture", "commit": None}, "run-1")
    report = archaeology.archaeology_report(extraction, dep_map, {"name": "fixture", "commit": None}, "run-1")
    units = {u["unit_id"]: u for u in report["units"]}
    hazards = {uid: {h["code"] for h in u["hazards"]} for uid, u in units.items()}
    assert "H06_UNSAFE_DESERIALISATION" in hazards["app/main.py::load_state"]
    assert {"H01_DYNAMIC_CODE_EXECUTION", "H04_SWALLOWED_EXCEPTION"} <= hazards["app/main.py::run"]
    assert {"H03_UNPARAMETERISED_QUERY", "H08_DEAD_CODE"} <= hazards["app/main.py::fetch"]
    # `while True` with a break is bounded.
    assert "H07_UNBOUNDED_LOOP" not in hazards["app/main.py::run"]
    assert hazards["app/util.py::ready"] == set()
    assert units["app/util.py::ready"]["modification_gate"] == "STANDARD_CHANGE_PROCESS"
    assert units["app/main.py::fetch"]["modification_gate"] != "STANDARD_CHANGE_PROCESS"
    assert not any(u["unit_id"].startswith("tests/") for u in report["units"])
    assert _all_passed(report)


def test_extraction_never_follows_symlinks(legacy_repo, tmp_path):
    secret = tmp_path / "outside.py"
    secret.write_text("TOKEN = 'outside-the-repo'\n")
    os.symlink(secret, legacy_repo / "app" / "linked.py")
    os.symlink(tmp_path, legacy_repo / "escape")
    extraction = archaeology.extract(legacy_repo)
    assert "app/linked.py" not in extraction.sources
    assert not any(path.startswith("escape/") for path in extraction.sources)
    assert all("outside-the-repo" not in text for text in extraction.sources.values())


def test_empty_repo_is_rejected_input(tmp_path):
    (tmp_path / "empty").mkdir()
    extraction = archaeology.extract(tmp_path / "empty")
    dep_map = archaeology.dependency_map(extraction, {"name": "empty", "commit": None}, "run-1")
    assert dep_map["status"] == "REJECTED_INPUT"
