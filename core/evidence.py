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
        detail = _cell(anomaly.get("description") or anomaly.get("detail"))
        lines.append(f"| {_cell(anomaly.get('type'))} | {detail} | {_refs(anomaly.get('evidence_refs'))} |")
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
        "| # | Action | Target | Justification |",
        "|---|---|---|---|",
    ]
    for action in plan.get("actions") or []:
        lines.append(
            f"| {action.get('order')} | {_cell(action.get('code'))} | {_cell(action.get('target'))} "
            f"| {_cell(action.get('justification'))} |"
        )
    lines += ["", "## Gaps", ""]
    gap_lines = [
        f"- Missing control {g.get('missing_control')} (mandated by {g.get('mandated_by')})"
        for g in plan.get("control_gaps") or []
    ]
    gap_lines += [
        f"- {_cell(g.get('detail') or g.get('description') or g.get('type'))}" for g in trace.get("evidence_gaps") or []
    ]
    lines += gap_lines or ["- none recorded"]
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


def _brief_section(outputs: dict) -> list[str]:
    brief = outputs.get("executive_brief")
    if not brief:
        return []
    lines = [
        "## Executive brief",
        "",
        f"- Risk rating: **{brief.get('risk_rating')}**",
        f"- Release verdict: **{brief.get('release_verdict')}**",
        "",
        _cell(brief.get("headline")),
        "",
    ]
    if brief.get("key_findings"):
        lines += ["### Key findings", "", "| Finding | Source | Evidence |", "|---|---|---|"]
        for finding in brief["key_findings"]:
            lines.append(
                f"| {_cell(finding.get('finding'))} | `{_cell(finding.get('source'))}` "
                f"| {_refs(finding.get('evidence_refs'))} |"
            )
        lines.append("")
    if brief.get("decisions_required"):
        lines += ["### Decisions required", ""]
        for decision in brief["decisions_required"]:
            flag = " (disruptive)" if decision.get("disruptive") else ""
            lines.append(f"- {_cell(decision.get('decision'))}{flag}: {_cell(decision.get('why'))}")
        lines.append("")
    if brief.get("next_steps"):
        lines += ["### Next steps", ""] + [f"- {_cell(step)}" for step in brief["next_steps"]] + [""]
    if brief.get("caveats"):
        lines += ["### Caveats", ""] + [f"- {_cell(c)}" for c in brief["caveats"]] + [""]
    return lines


def _narrative_section(outputs: dict) -> list[str]:
    narrative = outputs.get("client_narrative")
    if not narrative:
        return []
    lines = ["## Plain-language summary", ""]
    if narrative.get("status") == "COMPLETE" and narrative.get("narrative_markdown"):
        lines += [
            f"_Written by a language model ({_cell(narrative.get('model'))}) from the executive brief and "
            "proposal only. The findings above are authoritative._",
            "",
            str(narrative["narrative_markdown"]).replace("\r", ""),
            "",
        ]
    else:
        lines += [f"Not available: {_cell(narrative.get('detail'))}.", ""]
    return lines


def _governance_section(outputs: dict) -> list[str]:
    lines: list[str] = []
    qa = outputs.get("quality_review")
    if qa:
        failed = [c for c in qa.get("checks") or [] if not c.get("passed")]
        lines += [
            "## Quality review",
            "",
            f"Verdict **{qa.get('verdict')}**: {len(qa.get('checks') or [])} checks, {len(failed)} failed.",
            "",
        ]
        if failed:
            lines += ["| Stage | Check | Detail |", "|---|---|---|"]
            lines += [f"| {c['stage_id']} | {c['check']} | {_cell(c.get('detail'))} |" for c in failed]
            lines.append("")
    proposal = outputs.get("follow_up_proposal")
    if proposal:
        lines += ["## Follow-up proposal", "", f"Status **{proposal.get('status')}**. {proposal.get('terms')}", ""]
        if proposal.get("items"):
            lines += ["| Priority | Service | Triggered by | Credits | Basis |", "|---|---|---|---|---|"]
            for item in proposal["items"]:
                lines.append(
                    f"| {item['priority']} | {_cell(item['title'])} | {_cell(', '.join(item['triggered_by']))} "
                    f"| {item['estimated_credits']} | {_cell(item['estimate_basis'])} |"
                )
            lines += ["", f"Estimated total: **{proposal.get('estimated_credits_total')} credits**.", ""]
    return lines


def render_report(result: dict, job_id: str) -> str:
    lines = [
        f"# Job report: {result.get('runbook')}",
        "",
        f"- Job: `{job_id}`",
        f"- Result schema: {result.get('schema_version')}",
        f"- Produced by {result.get('generated_by') or 'deterministic procedure implementations'}.",
        "",
    ]
    outputs = result.get("outputs") or {}
    lines += _brief_section(outputs)
    lines += _narrative_section(outputs)
    lines += [
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
    if result.get("runbook") == "forensic_incident_response":
        lines += _forensics_section(outputs)
    elif result.get("runbook") == "legacy_archeology_sweep":
        lines += _archaeology_section(outputs)
    lines += [""] + _governance_section(outputs)
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
