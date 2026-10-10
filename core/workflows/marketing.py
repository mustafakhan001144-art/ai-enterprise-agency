"""Marketing division: the follow-up proposal.

The proposal writer maps findings in the executive brief and technical reports to
entries in a fixed service catalogue. Every recommendation names the findings that
triggered it and a credit estimate computed from a published formula, so the client
can see why it was proposed and check the arithmetic. It is a proposal only: nothing
is booked or charged.
"""

from __future__ import annotations

from core.workflows.common import has_banned_phrase

PROPOSAL_WRITER_ID = "marketing.engagement-proposal-writer"
CLIENT_BRIEF_WRITER_ID = "marketing.client-brief-writer"
PROPOSAL_SCHEMA = "EngagementProposal/v1"

# code -> (title, what is delivered)
SERVICE_CATALOGUE: dict[str, tuple[str, str]] = {
    "IR_RETAINER": (
        "Incident response retainer",
        "On-call forensic examiners who run each approved containment step with your operators and re-run trace "
        "analysis after each step.",
    ),
    "CONTROL_GAP_REMEDIATION": (
        "Containment control build-out",
        "Design and test the containment controls your environment is missing, so the next plan can use them.",
    ),
    "TELEMETRY_HARDENING": (
        "Agent telemetry hardening",
        "Add the logging sources the trace analysis could not see, so future incidents are classified with full "
        "evidence.",
    ),
    "EGRESS_POLICY_REVIEW": (
        "Agent egress policy review",
        "Review and enforce each agent's declared network allowlist at the network layer.",
    ),
    "PROMPT_INJECTION_DEFENCE": (
        "Prompt-injection defence review",
        "Review the data paths that fed instructions to the agent and add input isolation and tool-call policy checks.",
    ),
    "CHARACTERISATION_TEST_SPRINT": (
        "Characterisation test sprint",
        "Write tests that pin the current behaviour of gated units, so modernisation can start safely.",
    ),
    "EXPERT_FREEZE_REVIEW": (
        "Expert review of frozen units",
        "A senior engineer documents each frozen unit's behaviour and signs off a change plan.",
    ),
    "SECURITY_HAZARD_REMEDIATION": (
        "Security hazard remediation",
        "Fix dynamic execution, unparameterised queries, unsafe deserialisation and hard-coded secrets, with tests.",
    ),
    "DEPENDENCY_HYGIENE": (
        "Dependency hygiene",
        "Add lockfiles, remove unused declarations and replace deprecated dependency use.",
    ),
    "FOLLOW_UP_AUDIT": (
        "Follow-up audit",
        "Re-run this audit after the fixes land and report the change in risk.",
    ),
}

SECURITY_HAZARDS = (
    "H01_DYNAMIC_CODE_EXECUTION",
    "H02_HARDCODED_SECRET",
    "H03_UNPARAMETERISED_QUERY",
    "H06_UNSAFE_DESERIALISATION",
)
PRIORITY_ORDER = {"P1": 0, "P2": 1, "P3": 2}


def _item(code: str, priority: str, triggered_by: list[str], credits: int, basis: str) -> dict:
    title, scope = SERVICE_CATALOGUE[code]
    return {
        "service_code": code,
        "title": title,
        "scope": scope,
        "priority": priority,
        "triggered_by": triggered_by,
        "estimated_credits": credits,
        "estimate_basis": basis,
    }


def _forensics_items(brief: dict, outputs: dict) -> list[dict]:
    trace = outputs.get("trace_analysis") or {}
    plan = outputs.get("containment_plan") or {}
    items: list[dict] = []
    severity = str(trace.get("severity"))
    actions = plan.get("actions") or []
    if severity in ("SEV1_CRITICAL", "SEV2_HIGH"):
        n = len(actions)
        items.append(
            _item(
                "IR_RETAINER",
                "P1",
                [f"trace_analysis.severity={severity}"],
                50 + 10 * n,
                f"50 base + 10 per containment action ({n})",
            )
        )
    gaps = plan.get("control_gaps") or []
    if gaps:
        items.append(
            _item(
                "CONTROL_GAP_REMEDIATION",
                "P1",
                [f"containment_plan.control_gaps[{g.get('missing_control')}]" for g in gaps],
                20 * len(gaps),
                f"20 per missing control ({len(gaps)})",
            )
        )
    anomaly_types = {a.get("type") for a in trace.get("anomalies") or []}
    classes = {trace.get("primary_class"), *(trace.get("secondary_classes") or [])}
    if "UNDECLARED_EGRESS" in anomaly_types or "DATA_EXFILTRATION" in classes:
        refs = [
            f"trace_analysis.anomalies[{a.get('anomaly_id')}]"
            for a in trace.get("anomalies") or []
            if a.get("type") == "UNDECLARED_EGRESS"
        ] or ["trace_analysis.primary_class=DATA_EXFILTRATION"]
        items.append(_item("EGRESS_POLICY_REVIEW", "P2", refs, 30, "fixed scope"))
    if "INSTRUCTION_IN_DATA" in anomaly_types or "PROMPT_INJECTION_EXECUTED" in classes:
        refs = [
            f"trace_analysis.anomalies[{a.get('anomaly_id')}]"
            for a in trace.get("anomalies") or []
            if a.get("type") == "INSTRUCTION_IN_DATA"
        ] or ["trace_analysis.classes=PROMPT_INJECTION_EXECUTED"]
        items.append(_item("PROMPT_INJECTION_DEFENCE", "P2", refs, 40, "fixed scope"))
    evidence_gaps = trace.get("evidence_gaps") or []
    if evidence_gaps:
        items.append(
            _item(
                "TELEMETRY_HARDENING",
                "P3",
                [f"trace_analysis.evidence_gaps ({len(evidence_gaps)})"],
                15 * len(evidence_gaps),
                f"15 per missing telemetry source ({len(evidence_gaps)})",
            )
        )
    return items


def _archaeology_items(brief: dict, outputs: dict) -> list[dict]:
    dep_map = outputs.get("dependency_cartography") or {}
    report = outputs.get("code_archaeology") or {}
    summary = report.get("portfolio_summary") or {}
    by_gate = summary.get("by_gate") or {}
    hazards = summary.get("hazard_counts") or {}
    items: list[dict] = []
    frozen = by_gate.get("FREEZE_HUMAN_EXPERT_REQUIRED", 0)
    if frozen:
        items.append(
            _item(
                "EXPERT_FREEZE_REVIEW",
                "P1",
                [f"portfolio_summary.by_gate.FREEZE_HUMAN_EXPERT_REQUIRED={frozen}"],
                25 * frozen,
                f"25 per frozen unit ({frozen})",
            )
        )
    security = {h: hazards.get(h, 0) for h in SECURITY_HAZARDS if hazards.get(h, 0)}
    if security:
        total = sum(security.values())
        items.append(
            _item(
                "SECURITY_HAZARD_REMEDIATION",
                "P1",
                [f"portfolio_summary.hazard_counts.{h}={n}" for h, n in security.items()],
                8 * total,
                f"8 per security hazard ({total})",
            )
        )
    gated = by_gate.get("CHARACTERISATION_TESTS_REQUIRED_BEFORE_CHANGE", 0)
    if gated:
        items.append(
            _item(
                "CHARACTERISATION_TEST_SPRINT",
                "P2",
                [f"portfolio_summary.by_gate.CHARACTERISATION_TESTS_REQUIRED_BEFORE_CHANGE={gated}"],
                12 * gated,
                f"12 per gated unit ({gated})",
            )
        )
    dep_gaps = [g for g in dep_map.get("evidence_gaps") or [] if g.get("type") == "MISSING_LOCKFILE"]
    deprecated = hazards.get("H12_DEPRECATED_DEPENDENCY_USE", 0)
    if dep_gaps or deprecated:
        refs = [f"dependency_cartography.evidence_gaps[{g.get('gap_id')}]" for g in dep_gaps]
        if deprecated:
            refs.append(f"portfolio_summary.hazard_counts.H12_DEPRECATED_DEPENDENCY_USE={deprecated}")
        items.append(
            _item(
                "DEPENDENCY_HYGIENE", "P3", refs, 15 + 5 * deprecated, f"15 base + 5 per deprecated use ({deprecated})"
            )
        )
    if items:
        items.append(_item("FOLLOW_UP_AUDIT", "P3", ["proposal.items"], 10, "standard audit price"))
    return items


def follow_up_proposal(runbook_id: str, brief: dict, outputs: dict, run_id: str) -> dict:
    if runbook_id == "forensic_incident_response":
        items = _forensics_items(brief, outputs)
    elif runbook_id == "legacy_archeology_sweep":
        items = _archaeology_items(brief, outputs)
    else:
        raise ValueError(f"no proposal template for runbook {runbook_id!r}")
    items.sort(key=lambda i: (PRIORITY_ORDER[i["priority"]], i["service_code"]))
    on_hold = brief.get("release_verdict") == "HOLD"
    report = {
        "schema_version": PROPOSAL_SCHEMA,
        "agent_id": PROPOSAL_WRITER_ID,
        "run_id": run_id,
        "stage_id": "follow_up_proposal",
        "runbook": runbook_id,
        "status": "WITHHELD" if on_hold else ("PROPOSAL_READY" if items else "NO_FOLLOW_UP_NEEDED"),
        "risk_rating": brief.get("risk_rating"),
        "items": [] if on_hold else items,
        "estimated_credits_total": 0 if on_hold else sum(i["estimated_credits"] for i in items),
        "terms": "Proposal only. Nothing is booked or charged until you accept it.",
    }
    report["self_validation"] = [
        {"check": "PR1", "passed": all(i["triggered_by"] for i in report["items"])},
        {"check": "PR2", "passed": all(i["service_code"] in SERVICE_CATALOGUE for i in report["items"])},
        {"check": "PR3", "passed": not has_banned_phrase(report)},
    ]
    return report
