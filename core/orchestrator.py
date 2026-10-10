"""Runbooks: the ordered stages a job runs, each bound to an agent in the registry.

The orchestrator is deterministic. Every stage is a Python implementation of the
procedure its agent persona defines (see core/agents), so the same input always
produces the same report and digest. No LLM is called.

Stage outputs are written to ``<job_dir>/stages/NN_<stage_id>.json`` and the
combined result to ``<job_dir>/result.json``.
"""

from __future__ import annotations

import json
import shutil
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

from core.registry import AgentRegistry, RegistryError
from core.workflows import archaeology, forensics
from core.workflows.common import canonical_digest

RESULT_SCHEMA = "JobResult/v1"

Fetcher = Callable[[str, "str | None", Path], "str | None"]


class PermanentJobError(RuntimeError):
    """The job can never succeed as submitted (unknown runbook, missing agent, bad request)."""


@dataclass(frozen=True)
class RunOutcome:
    result_path: Path
    result_digest: str
    result: dict


def _write_stage(job_dir: Path, index: int, stage_id: str, report: dict) -> dict:
    stages = job_dir / "stages"
    stages.mkdir(parents=True, exist_ok=True)
    path = stages / f"{index:02d}_{stage_id}.json"
    path.write_text(json.dumps(report, sort_keys=True, indent=2), encoding="utf-8")
    checks = report.get("self_validation") or []
    failed = [c.get("check") for c in checks if isinstance(c, dict) and c.get("passed") is False]
    return {
        "index": index,
        "stage_id": stage_id,
        "agent_id": report.get("agent_id"),
        "status": report.get("status"),
        "self_validation_failed": failed,
        "digest": canonical_digest(report),
        "path": str(path.relative_to(job_dir)),
    }


def _forensics(request: dict, job_dir: Path, run_id: str, fetcher: Fetcher) -> list[tuple[str, dict]]:
    trace = forensics.trace_analysis(request, run_id)
    environment = {
        "available_controls": request.get("available_controls") or [],
        "business_critical_components": request.get("business_critical_components") or [],
    }
    plan = forensics.containment_plan(trace, environment, run_id)
    return [("trace_analysis", trace), ("containment_plan", plan)]


def _archaeology(request: dict, job_dir: Path, run_id: str, fetcher: Fetcher) -> list[tuple[str, dict]]:
    repo_url = request.get("repo_url")
    if not isinstance(repo_url, str) or not repo_url:
        raise PermanentJobError("request has no repo_url")
    ref = request.get("ref")
    checkout = job_dir / "checkout"
    if checkout.exists():
        shutil.rmtree(checkout)
    try:
        commit = fetcher(repo_url, ref, checkout)
        extraction = archaeology.extract(checkout)
    finally:
        # Client source is not retained after analysis; only the reports are kept.
        shutil.rmtree(checkout, ignore_errors=True)
    name = urlsplit(repo_url).path.strip("/").removesuffix(".git") or repo_url
    repository = {"name": name, "url": repo_url, "ref": ref, "commit": commit}
    dep_map = archaeology.dependency_map(extraction, repository, run_id)
    report = archaeology.archaeology_report(extraction, dep_map, repository, run_id)
    return [("dependency_cartography", dep_map), ("code_archaeology", report)]


@dataclass(frozen=True)
class Runbook:
    runbook_id: str
    agents: tuple[str, ...]
    run: Callable[[dict, Path, str, Fetcher], list[tuple[str, dict]]]


RUNBOOKS: dict[str, Runbook] = {
    "forensic_incident_response": Runbook(
        "forensic_incident_response",
        (forensics.TRACE_AGENT_ID, forensics.CONTAINMENT_AGENT_ID),
        _forensics,
    ),
    "legacy_archeology_sweep": Runbook(
        "legacy_archeology_sweep",
        (archaeology.CARTOGRAPHER_ID, archaeology.ARCHAEOLOGIST_ID),
        _archaeology,
    ),
}


def run_job(
    runbook_id: str,
    request: dict,
    job_dir: Path,
    run_id: str,
    registry: AgentRegistry,
    fetcher: Fetcher = archaeology.git_fetch,
) -> RunOutcome:
    runbook = RUNBOOKS.get(runbook_id)
    if runbook is None:
        raise PermanentJobError(f"unknown runbook {runbook_id!r}")
    try:
        agents = registry.require(list(runbook.agents))
    except RegistryError as exc:
        raise PermanentJobError(str(exc)) from exc

    stages_dir = job_dir / "stages"
    if stages_dir.exists():
        shutil.rmtree(stages_dir)  # a retried attempt starts clean
    reports = runbook.run(request, job_dir, run_id, fetcher)
    stage_index = [_write_stage(job_dir, i, stage_id, report) for i, (stage_id, report) in enumerate(reports, 1)]

    result = {
        "schema_version": RESULT_SCHEMA,
        "runbook": runbook_id,
        "run_id": run_id,
        "agents": [{"agent_id": a.agent_id, "version": a.version, "prompt_sha256": a.prompt_sha256} for a in agents],
        "stages": stage_index,
        "outputs": {stage_id: report for stage_id, report in reports},
        "generated_by": "deterministic procedure implementations; no language model was called",
    }
    digest = canonical_digest(result)
    result_path = job_dir / "result.json"
    tmp = result_path.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(result, sort_keys=True, indent=2), encoding="utf-8")
    tmp.replace(result_path)
    return RunOutcome(result_path=result_path, result_digest=digest, result=result)
