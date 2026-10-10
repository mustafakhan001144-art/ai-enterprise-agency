"""Management division: quality review and executive brief.

Both stages read only the reports produced by earlier stages of the same job. They
add no new technical findings: the quality reviewer checks that the technical
reports are fit to release, and the engagement director restates the findings an
executive has to act on, each with the evidence references it came from.
"""

from __future__ import annotations

from typing import Any

from core.workflows.common import canonical_digest, has_banned_phrase

QUALITY_REVIEWER_ID = "management.quality-reviewer"
ENGAGEMENT_DIRECTOR_ID = "management.engagement-director"

QUALITY_SCHEMA = "QualityReview/v1"
BRIEF_SCHEMA = "ExecutiveBrief/v1"

# Stage statuses that mean the report must not reach a client as-is.
BLOCKING_STATUSES = {"REJECTED_INPUT", "UPSTREAM_INCONSISTENT"}
# Stage statuses that may be released, with the limitation stated.
CAVEAT_STATUSES = {"INSUFFICIENT_EVIDENCE", "PARTIAL"}

VERDICT_RELEASE = "RELEASE"
VERDICT_CAVEATS = "RELEASE_WITH_CAVEATS"
VERDICT_HOLD = "HOLD"

RISK_ORDER = ("NONE", "LOW", "MEDIUM", "HIGH", "CRITICAL")
SEVERITY_RISK = {
    "SEV1_CRITICAL": "CRITICAL",
    "SEV2_HIGH": "HIGH",
    "SEV3_MEDIUM": "MEDIUM",
    "SEV4_LOW": "LOW",
    "SEV5_INFORMATIONAL": "NONE",
}
TIER_RISK = {"R4_CRITICAL": "CRITICAL", "R3_HIGH": "HIGH", "R2_MODERATE": "MEDIUM", "R1_LOW": "LOW"}
MAX_KEY_FINDINGS = 5


# ---------------------------------------------------------------------------
# Quality review
# ---------------------------------------------------------------------------
def _findings_without_evidence(stage_id: str, report: dict) -> list[str]:
    """IDs of findings that carry no evidence reference."""
    missing: list[str] = []
    if stage_id == "trace_analysis":
        for anomaly in report.get("anomalies") or []:
            if not anomaly.get("evidence_refs"):
                missing.append(str(anomaly.get("anomaly_id")))
        for ioc in report.get("iocs") or []:
            if not ioc.get("evidence_refs"):
                missing.append(f"ioc:{ioc.get('value')}")
    elif stage_id == "code_archaeology":
        for unit in report.get("units") or []:
            for hazard in unit.get("hazards") or []:
                if not hazard.get("evidence_refs"):
                    missing.append(f"{unit.get('unit_id')}:{hazard.get('code')}")
    elif stage_id == "containment_plan":
        for action in report.get("actions") or []:
            if not action.get("finding_refs"):
                missing.append(f"action:{action.get('order')}")
    return missing


def quality_review(stages: list[tuple[str, dict]], run_id: str) -> dict:
    """Check every technical stage before anything is summarised for a client.

    Checks per stage:
      Q1 the stage's own self-validation passed;
      Q2 the stage status is releasable;
      Q3 the report uses none of the banned speculative phrases;
      Q4 every finding carries an evidence reference.
    """
    checks: list[dict] = []
    caveats: list[str] = []
    for stage_id, report in stages:
        failed = [
            c.get("check")
            for c in report.get("self_validation") or []
            if isinstance(c, dict) and c.get("passed") is False
        ]
        checks.append(
            {
                "stage_id": stage_id,
                "check": "Q1_SELF_VALIDATION",
                "passed": not failed,
                "detail": f"failed checks: {', '.join(map(str, failed))}" if failed else "all checks passed",
            }
        )
        status = str(report.get("status"))
        checks.append(
            {
                "stage_id": stage_id,
                "check": "Q2_STATUS_RELEASABLE",
                "passed": status not in BLOCKING_STATUSES,
                "detail": f"status {status}",
            }
        )
        if status in CAVEAT_STATUSES:
            caveats.append(f"{stage_id} finished with status {status}; its evidence gaps are listed in the report")
        banned = has_banned_phrase(report)
        checks.append(
            {
                "stage_id": stage_id,
                "check": "Q3_NO_SPECULATIVE_LANGUAGE",
                "passed": not banned,
                "detail": "speculative phrase found" if banned else "none found",
            }
        )
        missing = _findings_without_evidence(stage_id, report)
        checks.append(
            {
                "stage_id": stage_id,
                "check": "Q4_FINDINGS_HAVE_EVIDENCE",
                "passed": not missing,
                "detail": f"without evidence: {', '.join(missing[:10])}" if missing else "every finding is referenced",
            }
        )

    if any(not c["passed"] for c in checks):
        verdict = VERDICT_HOLD
    elif caveats:
        verdict = VERDICT_CAVEATS
    else:
        verdict = VERDICT_RELEASE
    report = {
        "schema_version": QUALITY_SCHEMA,
        "agent_id": QUALITY_REVIEWER_ID,
        "run_id": run_id,
        "stage_id": "quality_review",
        "reviewed_stages": [{"stage_id": stage_id, "digest": canonical_digest(report)} for stage_id, report in stages],
        "status": "COMPLETE",
        "verdict": verdict,
        "checks": checks,
        "caveats": caveats,
    }
    report["self_validation"] = [
        {"check": "QV1", "passed": bool(checks)},
        {"check": "QV2", "passed": (verdict == VERDICT_HOLD) == any(not c["passed"] for c in checks)},
    ]
    return report


# ---------------------------------------------------------------------------
# Executive brief
# ---------------------------------------------------------------------------
def _max_risk(levels: list[str]) -> str:
    return max(levels or ["NONE"], key=RISK_ORDER.index)


def _forensics_brief(outputs: dict) -> dict[str, Any]:
    trace = outputs.get("trace_analysis") or {}
    plan = outputs.get("containment_plan") or {}
    severity = trace.get("severity")
    risk = SEVERITY_RISK.get(str(severity), "NONE")
    actions = plan.get("actions") or []
    approvals = [a for a in actions if a.get("requires_human_approval")]
    subject = trace.get("subject_agent") or "the subject agent"
    if trace.get("status") == "REJECTED_INPUT":
        headline = "The submitted telemetry was rejected; no classification was made."
    else:
        headline = (
            f"{trace.get('primary_class')} at {severity} for {subject}. "
            f"Containment tier {plan.get('tier')}: {len(approvals)} action(s) await operator approval."
        )
    key_findings = [
        {
            "finding": f"{a.get('type')}: {a.get('description')}",
            "source": f"trace_analysis.anomalies[{a.get('anomaly_id')}]",
            "evidence_refs": a.get("evidence_refs") or [],
        }
        for a in (trace.get("anomalies") or [])[:MAX_KEY_FINDINGS]
    ]
    decisions = [
        {
            "decision": f"Approve {a.get('code')}" + (f" on {a.get('target')}" if a.get("target") else ""),
            "why": a.get("justification"),
            "disruptive": bool(a.get("disruptive")),
            "source": f"containment_plan.actions[{a.get('order')}]",
        }
        for a in approvals
    ]
    next_steps = []
    if decisions:
        next_steps.append("Review the containment actions in order and approve or reject each one.")
    for gap in plan.get("control_gaps") or []:
        next_steps.append(f"Provision missing control {gap.get('missing_control')}.")
    if trace.get("evidence_gaps"):
        next_steps.append(
            f"Supply the {len(trace['evidence_gaps'])} missing telemetry source(s) listed under evidence gaps."
        )
    metrics = {
        "anomalies": len(trace.get("anomalies") or []),
        "indicators_of_compromise": len(trace.get("iocs") or []),
        "containment_actions": len(actions),
        "control_gaps": len(plan.get("control_gaps") or []),
        "evidence_gaps": len(trace.get("evidence_gaps") or []),
    }
    return {
        "risk_rating": risk,
        "headline": headline,
        "key_findings": key_findings,
        "decisions_required": decisions,
        "next_steps": next_steps,
        "metrics": metrics,
    }


def _archaeology_brief(outputs: dict) -> dict[str, Any]:
    dep_map = outputs.get("dependency_cartography") or {}
    report = outputs.get("code_archaeology") or {}
    summary = report.get("portfolio_summary") or {}
    by_tier = summary.get("by_tier") or {}
    by_gate = summary.get("by_gate") or {}
    risk = _max_risk([TIER_RISK[t] for t, count in by_tier.items() if count and t in TIER_RISK])
    repo = (dep_map.get("repository") or report.get("repository") or {}).get("name") or "the repository"
    high = by_tier.get("R3_HIGH", 0) + by_tier.get("R4_CRITICAL", 0)
    frozen = by_gate.get("FREEZE_HUMAN_EXPERT_REQUIRED", 0)
    gated = by_gate.get("CHARACTERISATION_TESTS_REQUIRED_BEFORE_CHANGE", 0)
    headline = (
        f"{summary.get('units_total', 0)} code unit(s) analysed in {repo}: {high} rated R3_HIGH or above, "
        f"{frozen} frozen pending expert review, {gated} need characterisation tests before any change."
    )
    units = sorted(report.get("units") or [], key=lambda u: (-((u.get("risk") or {}).get("score") or 0), u["unit_id"]))
    key_findings = []
    for unit in units[:MAX_KEY_FINDINGS]:
        hazards = unit.get("hazards") or []
        codes = sorted({h.get("code") for h in hazards if h.get("code")})
        risk_info = unit.get("risk") or {}
        key_findings.append(
            {
                "finding": (
                    f"{unit['unit_id']} scores {risk_info.get('score')} ({risk_info.get('tier')}); "
                    f"hazards: {', '.join(codes) or 'none'}"
                ),
                "source": f"code_archaeology.units[{unit['unit_id']}]",
                "evidence_refs": [ref for h in hazards for ref in h.get("evidence_refs") or []][:5],
            }
        )
    decisions = [
        {
            "decision": f"Assign a domain expert to {u['unit_id']} before it is changed",
            "why": "modification gate FREEZE_HUMAN_EXPERT_REQUIRED",
            "disruptive": False,
            "source": f"code_archaeology.units[{u['unit_id']}]",
        }
        for u in units
        if u.get("modification_gate") == "FREEZE_HUMAN_EXPERT_REQUIRED"
    ]
    if gated:
        decisions.append(
            {
                "decision": f"Fund characterisation tests for {gated} unit(s) before modernisation work starts",
                "why": "modification gate CHARACTERISATION_TESTS_REQUIRED_BEFORE_CHANGE",
                "disruptive": False,
                "source": "code_archaeology.portfolio_summary.by_gate",
            }
        )
    next_steps = [f"Close evidence gap: {g.get('detail')}" for g in dep_map.get("evidence_gaps") or []]
    metrics = {
        "units_total": summary.get("units_total", 0),
        "units_high_or_critical": high,
        "internal_modules": (dep_map.get("graph_metrics") or {}).get("internal_modules"),
        "dependency_cycles": len((dep_map.get("graph_metrics") or {}).get("cycles") or []),
        "hazards_total": sum((summary.get("hazard_counts") or {}).values()),
    }
    return {
        "risk_rating": risk,
        "headline": headline,
        "key_findings": key_findings,
        "decisions_required": decisions,
        "next_steps": next_steps,
        "metrics": metrics,
    }


def executive_brief(runbook_id: str, outputs: dict, qa: dict, run_id: str) -> dict:
    if runbook_id == "forensic_incident_response":
        body = _forensics_brief(outputs)
    elif runbook_id == "legacy_archeology_sweep":
        body = _archaeology_brief(outputs)
    else:
        raise ValueError(f"no executive brief template for runbook {runbook_id!r}")
    verdict = qa.get("verdict")
    if verdict == VERDICT_HOLD:
        body["headline"] = "Release on hold until quality review issues are resolved. " + body["headline"]
        body["next_steps"].insert(0, "Resolve the failed quality checks before this report is shared.")
    report = {
        "schema_version": BRIEF_SCHEMA,
        "agent_id": ENGAGEMENT_DIRECTOR_ID,
        "run_id": run_id,
        "stage_id": "executive_brief",
        "runbook": runbook_id,
        "status": "COMPLETE",
        "release_verdict": verdict,
        "caveats": list(qa.get("caveats") or []),
        **body,
    }
    report["self_validation"] = [
        {"check": "EB1", "passed": all(f.get("source") for f in report["key_findings"])},
        {"check": "EB2", "passed": not has_banned_phrase({k: v for k, v in report.items() if k != "key_findings"})},
        {"check": "EB3", "passed": report["risk_rating"] in RISK_ORDER},
    ]
    return report
