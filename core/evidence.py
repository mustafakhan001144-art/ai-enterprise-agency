"""Evidence bundle for a finished job: a hash-chained manifest and a readable report.

``manifest.json`` lists every file the job produced (request, stage reports,
result, report) with its SHA-256 and size. Entries are chained: each entry's
``chain`` is SHA-256 over the previous chain value, the path and the file hash,
so removing, reordering or editing any file breaks verification. The manifest's
``head`` is the last chain value and is stored alongside the job in the database.

``report.md`` is rendered from the JobResult only. It restates findings with
their evidence references; it adds no new conclusions.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

MANIFEST_SCHEMA = "EvidenceManifest/v1"
GENESIS = "0" * 64


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(65536), b""):
            digest.update(block)
    return digest.hexdigest()


def _chain(previous: str, rel_path: str, file_hash: str) -> str:
    return hashlib.sha256(f"{previous}\n{rel_path}\n{file_hash}".encode()).hexdigest()


def _bundle_paths(job_dir: Path) -> list[str]:
    """request.json, then stage reports in order, then result.json and report.md."""
    stages = sorted(p.relative_to(job_dir).as_posix() for p in (job_dir / "stages").glob("*.json"))
    ordered = ["request.json", *stages, "result.json", "report.md"]
    return [rel for rel in ordered if (job_dir / rel).is_file()]


def build_manifest(job_dir: Path, job_id: str) -> dict:
    entries = []
    previous = GENESIS
    for rel in _bundle_paths(job_dir):
        path = job_dir / rel
        file_hash = _sha256_file(path)
        previous = _chain(previous, rel, file_hash)
        entries.append({"path": rel, "sha256": file_hash, "bytes": path.stat().st_size, "chain": previous})
    manifest = {
        "schema_version": MANIFEST_SCHEMA,
        "job_id": job_id,
        "algorithm": "sha256(previous_chain + '\\n' + path + '\\n' + file_sha256)",
        "genesis": GENESIS,
        "entries": entries,
        "head": previous,
    }
    (job_dir / "manifest.json").write_text(json.dumps(manifest, sort_keys=True, indent=2), encoding="utf-8")
    return manifest


def verify_manifest(job_dir: Path, expected_head: str | None = None) -> dict:
    """Recompute every hash. Returns {'valid': bool, 'problems': [...], 'head': str|None}."""
    path = job_dir / "manifest.json"
    if not path.is_file():
        return {"valid": False, "problems": ["manifest.json is missing"], "head": None}
    manifest = json.loads(path.read_text(encoding="utf-8"))
    problems: list[str] = []
    previous = manifest.get("genesis", GENESIS)
    listed = []
    for entry in manifest.get("entries", []):
        rel = entry["path"]
        listed.append(rel)
        file_path = (job_dir / rel).resolve()
        if not file_path.is_relative_to(job_dir.resolve()) or not file_path.is_file():
            problems.append(f"{rel}: missing")
            continue
        actual = _sha256_file(file_path)
        if actual != entry["sha256"]:
            problems.append(f"{rel}: content changed")
        previous = _chain(previous, rel, actual)
        if previous != entry["chain"]:
            problems.append(f"{rel}: chain mismatch")
    unlisted = sorted(set(_bundle_paths(job_dir)) - set(listed))
    problems += [f"{rel}: not in manifest" for rel in unlisted]
    if previous != manifest.get("head"):
        problems.append("manifest head does not match its entries")
    if expected_head is not None and manifest.get("head") != expected_head:
        problems.append("manifest head does not match the value recorded when the job finished")
    return {"valid": not problems, "problems": problems, "head": manifest.get("head")}


# ---------------------------------------------------------------------------
# report.md
# ---------------------------------------------------------------------------
def _refs(refs: list | None) -> str:
    out = []
    for ref in refs or []:
        if isinstance(ref, dict):
            if "artifact_id" in ref:
                out.append(f"{ref['artifact_id']}:{ref.get('locator', '')}")
            elif "file" in ref:
                out.append(f"{ref['file']}:{ref.get('line', '')}")
    return ", ".join(out) or "none"


def _cell(value) -> str:
    return str(value if value is not None else "").replace("|", "\\|").replace("\n", " ")[:200]


def _forensics_section(outputs: dict) -> list[str]:
    trace = outputs.get("trace_analysis") or {}
    plan = outputs.get("containment_plan") or {}
    lines = [
        "## Incident classification",
        "",
        f"- Status: **{trace.get('status')}**",
        f"- Primary class: **{trace.get('primary_class')}**",
        f"- Secondary classes: {', '.join(trace.get('secondary_classes') or []) or 'none'}",
        f"- Severity: **{trace.get('severity')}**",
        "",
        "### Anomalies",
        "",
        "| Type | Detail | Evidence |",
        "|---|---|---|",
    ]
    for anomaly in trace.get("anomalies") or []:
        lines.append(
            f"| {_cell(anomaly.get('type'))} | {_cell(anomaly.get('detail'))} | {_refs(anomaly.get('evidence_refs'))} |"
        )
    lines += ["", "### Indicators of compromise", "", "| Type | Value | Evidence |", "|---|---|---|"]
    for ioc in trace.get("iocs") or []:
        lines.append(f"| {_cell(ioc.get('type'))} | `{_cell(ioc.get('value'))}` | {_refs(ioc.get('evidence_refs'))} |")
    lines += [
        "",
        "## Recommended containment plan",
        "",
        f"Tier **{plan.get('tier')}**, status **{plan.get('status')}**. Every action needs a human operator's "
        "approval; nothing has been executed against your systems.",
        "",
        "| # | Action | Target |",
        "|---|---|---|",
    ]
    for action in plan.get("actions") or []:
        lines.append(f"| {action.get('order')} | {_cell(action.get('code'))} | {_cell(action.get('target'))} |")
    gaps = (plan.get("control_gaps") or []) + (trace.get("evidence_gaps") or [])
    lines += ["", "## Gaps", ""]
    lines += [f"- {_cell(g.get('detail') or g.get('type') or g)}" for g in gaps] or ["- none recorded"]
    return lines


def _archaeology_section(outputs: dict) -> list[str]:
    dep_map = outputs.get("dependency_cartography") or {}
    report = outputs.get("code_archaeology") or {}
    summary = report.get("portfolio_summary") or {}
    metrics = dep_map.get("graph_metrics") or {}
    lines = [
        "## Repository",
        "",
        f"- Repository: `{_cell((dep_map.get('repository') or {}).get('name'))}`",
        f"- Commit: `{_cell((dep_map.get('repository') or {}).get('commit'))}`",
        f"- Dependency map status: **{dep_map.get('status')}**, archaeology status: **{report.get('status')}**",
        f"- Internal modules: {metrics.get('internal_modules', 'n/a')}",
        "",
        "## Risk by tier",
        "",
        "| Tier | Units |",
        "|---|---|",
    ]
    for tier, count in (summary.get("by_tier") or {}).items():
        lines.append(f"| {tier} | {count} |")
    lines += ["", "## Modification gates", "", "| Gate | Units |", "|---|---|"]
    for gate, count in (summary.get("by_gate") or {}).items():
        lines.append(f"| {gate} | {count} |")
    units = sorted(report.get("units") or [], key=lambda u: -((u.get("risk") or {}).get("score") or 0))[:15]
    lines += ["", "## Highest-risk units", "", "| Unit | Score | Gate | Hazards |", "|---|---|---|---|"]
    for unit in units:
        hazards = ", ".join(sorted(h.get("code", "") for h in unit.get("hazards") or [])) or "none"
        lines.append(
            f"| `{_cell(unit.get('unit_id'))}` | {(unit.get('risk') or {}).get('score')} | "
            f"{_cell(unit.get('modification_gate'))} | {_cell(hazards)} |"
        )
    lines += ["", "## Gaps", ""]
    gaps = (dep_map.get("evidence_gaps") or []) + (report.get("evidence_gaps") or [])
    lines += [f"- {_cell(g.get('detail') or g.get('type'))}" for g in gaps] or ["- none recorded"]
    return lines


def render_report(result: dict, job_id: str) -> str:
    lines = [
        f"# Job report: {result.get('runbook')}",
        "",
        f"- Job: `{job_id}`",
        f"- Result schema: {result.get('schema_version')}",
        "- Produced by deterministic implementations of the agent procedures listed below. "
        "No language model was called.",
        "",
        "## Agents",
        "",
        "| Agent | Version | Prompt SHA-256 |",
        "|---|---|---|",
    ]
    for agent in result.get("agents") or []:
        lines.append(f"| {agent['agent_id']} | {agent.get('version')} | `{agent.get('prompt_sha256')}` |")
    lines += ["", "## Stages", "", "| # | Stage | Status | Failed checks | Digest |", "|---|---|---|---|---|"]
    for stage in result.get("stages") or []:
        failed = ", ".join(stage.get("self_validation_failed") or []) or "none"
        lines.append(
            f"| {stage['index']} | {stage['stage_id']} | {stage.get('status')} | {failed} | `{stage['digest']}` |"
        )
    lines.append("")
    outputs = result.get("outputs") or {}
    if result.get("runbook") == "forensic_incident_response":
        lines += _forensics_section(outputs)
    elif result.get("runbook") == "legacy_archeology_sweep":
        lines += _archaeology_section(outputs)
    lines += [
        "",
        "## Verifying this report",
        "",
        "`manifest.json` lists the SHA-256 of every file in this bundle in a hash chain. "
        "`GET /api/v1/jobs/{id}/evidence` recomputes it and reports whether anything changed.",
        "",
    ]
    return "\n".join(lines)


def write_bundle(job_dir: Path, job_id: str, result: dict) -> dict:
    (job_dir / "report.md").write_text(render_report(result, job_id), encoding="utf-8")
    return build_manifest(job_dir, job_id)
