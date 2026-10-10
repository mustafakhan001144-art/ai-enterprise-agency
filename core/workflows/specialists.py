"""Specialist routing: staff each job with agents from the Agency Agents catalog.

The engagement director reads the finished reports and assigns specialists from the
msitarzewski/agency-agents catalog (vendored in ``vendor/agency-agents``, or the copy
installed on this machine when ``AGENCY_INSTALLED_AGENTS_DIR`` is set). Every
assignment comes from a fixed routing table and names the findings that triggered it,
so the same reports always produce the same roster.

Agents are looked up by their catalog file name (for example
``security-incident-responder``), which is the same name the Agency Agents installer
uses in ``~/.claude/agents``. A routed agent that is missing from the registry is listed
under ``not_found`` instead of failing the job.
"""

from __future__ import annotations

from core.registry import Agent, Snapshot
from core.workflows.common import has_banned_phrase
from core.workflows.management import ENGAGEMENT_DIRECTOR_ID
from core.workflows.marketing import SECURITY_HAZARDS

ROSTER_SCHEMA = "SpecialistRoster/v1"

# Each route: (catalog file name, stage the specialist works from, role, task)
Route = tuple[str, str, str, str]


def _route(slug: str, stage: str, task: str, role: str = "specialist") -> Route:
    return (slug, stage, role, task)


def _forensics_routes(outputs: dict) -> list[tuple[Route, list[str]]]:
    trace = outputs.get("trace_analysis") or {}
    plan = outputs.get("containment_plan") or {}
    anomalies = trace.get("anomalies") or []
    classes = {trace.get("primary_class"), *(trace.get("secondary_classes") or [])}

    def refs(*types: str) -> list[str]:
        return [f"trace_analysis.anomalies[{a.get('anomaly_id')}]" for a in anomalies if a.get("type") in types]

    routes: list[tuple[Route, list[str]]] = [
        (
            _route(
                "security-incident-responder",
                "containment_plan",
                "Lead the response: confirm the timeline in the trace analysis and run each approved containment "
                "action with the client's operators.",
                role="lead",
            ),
            [f"trace_analysis.severity={trace.get('severity')}"],
        ),
        (
            _route(
                "testing-evidence-collector",
                "trace_analysis",
                "Check that every finding cites its evidence references and keep the evidence bundle intact for "
                "hand-off.",
            ),
            [f"trace_analysis.anomalies ({len(anomalies)})"],
        ),
    ]
    egress = refs("UNDECLARED_EGRESS") or (
        ["trace_analysis.primary_class=DATA_EXFILTRATION"] if "DATA_EXFILTRATION" in classes else []
    )
    if egress:
        routes.append(
            (
                _route(
                    "security-cloud-security-architect",
                    "containment_plan",
                    "Enforce the agent's declared egress allowlist at the network layer for the listed destinations.",
                ),
                egress,
            )
        )
    injection = refs("INSTRUCTION_IN_DATA") or (
        ["trace_analysis.classes=PROMPT_INJECTION_EXECUTED"] if "PROMPT_INJECTION_EXECUTED" in classes else []
    )
    if injection:
        routes.append(
            (
                _route(
                    "engineering-prompt-engineer",
                    "trace_analysis",
                    "Review the data paths that carried instructions into the agent and design input isolation for "
                    "them.",
                ),
                injection,
            )
        )
    secrets = refs("SECRET_IN_OUTPUT")
    if secrets:
        routes.append(
            (
                _route(
                    "security-secrets-credential-engineer",
                    "containment_plan",
                    "Rotate every credential that appeared in agent output and add leak detection on that path.",
                ),
                secrets,
            )
        )
    access = refs("AUTH_SCOPE_CHANGE", "DENIED_SCOPE_EXECUTED", "POLICY_BYPASS")
    if access:
        routes.append(
            (
                _route(
                    "engineering-identity-access-engineer",
                    "containment_plan",
                    "Reduce the agent's credentials to the declared scopes and close the policy bypass paths listed.",
                ),
                access,
            )
        )
    runaway = refs("LOOP_THRESHOLD", "TOKEN_THRESHOLD")
    if runaway:
        routes.append(
            (
                _route(
                    "engineering-sre",
                    "trace_analysis",
                    "Add loop and token budgets with alerts so a runaway agent is stopped automatically.",
                ),
                runaway,
            )
        )
    gaps = plan.get("control_gaps") or []
    boundary = [f"containment_plan.control_gaps[{g.get('missing_control')}]" for g in gaps] + refs("UNDECLARED_TOOL")
    if boundary:
        routes.append(
            (
                _route(
                    "security-architect",
                    "containment_plan",
                    "Design the missing containment controls and the trust boundary around the agent's tools.",
                ),
                boundary,
            )
        )
    evidence_gaps = trace.get("evidence_gaps") or []
    if evidence_gaps:
        routes.append(
            (
                _route(
                    "security-threat-detection-engineer",
                    "trace_analysis",
                    "Add detection rules and the missing telemetry sources so the next incident is fully evidenced.",
                ),
                [f"trace_analysis.evidence_gaps ({len(evidence_gaps)})"],
            )
        )
    return routes


def _archaeology_routes(outputs: dict) -> list[tuple[Route, list[str]]]:
    dep_map = outputs.get("dependency_cartography") or {}
    report = outputs.get("code_archaeology") or {}
    summary = report.get("portfolio_summary") or {}
    by_gate = summary.get("by_gate") or {}
    hazards = summary.get("hazard_counts") or {}

    def counted(*codes: str) -> list[str]:
        return [f"portfolio_summary.hazard_counts.{c}={hazards[c]}" for c in codes if hazards.get(c)]

    routes: list[tuple[Route, list[str]]] = [
        (
            _route(
                "specialized-codebase-archaeologist",
                "code_archaeology",
                "Lead the modernisation review: walk the unit inventory and confirm each change gate with the "
                "client's engineers.",
                role="lead",
            ),
            [f"code_archaeology.units ({len(report.get('units') or [])})"],
        ),
        (
            _route(
                "engineering-code-reviewer",
                "code_archaeology",
                "Review the highest-risk units first and turn each hazard into a reviewed change request.",
            ),
            [f"portfolio_summary.hazard_counts ({sum(hazards.values()) if hazards else 0})"],
        ),
    ]
    appsec = counted(*(h for h in SECURITY_HAZARDS if h != "H02_HARDCODED_SECRET"))
    if appsec:
        routes.append(
            (
                _route(
                    "security-appsec-engineer",
                    "code_archaeology",
                    "Fix the dynamic execution, unparameterised query and unsafe deserialisation hazards, with tests.",
                ),
                appsec,
            )
        )
    secrets = counted("H02_HARDCODED_SECRET")
    if secrets:
        routes.append(
            (
                _route(
                    "security-secrets-credential-engineer",
                    "code_archaeology",
                    "Move hard-coded secrets into a vault, rotate them and add a pre-commit secret scan.",
                ),
                secrets,
            )
        )
    injected = counted("H11_INSTRUCTION_IN_SOURCE")
    if injected:
        routes.append(
            (
                _route(
                    "security-ai-generated-code-auditor",
                    "code_archaeology",
                    "Review the source files that contain instructions aimed at AI tools and remove them.",
                ),
                injected,
            )
        )
    gated = by_gate.get("CHARACTERISATION_TESTS_REQUIRED_BEFORE_CHANGE", 0)
    if gated:
        routes.append(
            (
                _route(
                    "testing-test-automation-engineer",
                    "code_archaeology",
                    "Write characterisation tests that pin the current behaviour of each gated unit.",
                ),
                [f"portfolio_summary.by_gate.CHARACTERISATION_TESTS_REQUIRED_BEFORE_CHANGE={gated}"],
            )
        )
    frozen = by_gate.get("FREEZE_HUMAN_EXPERT_REQUIRED", 0)
    if frozen:
        routes.append(
            (
                _route(
                    "engineering-software-architect",
                    "code_archaeology",
                    "Document each frozen unit's behaviour and sign off a change plan for it.",
                ),
                [f"portfolio_summary.by_gate.FREEZE_HUMAN_EXPERT_REQUIRED={frozen}"],
            )
        )
    dep_refs = [
        f"dependency_cartography.evidence_gaps[{g.get('gap_id')}]"
        for g in dep_map.get("evidence_gaps") or []
        if g.get("type") == "MISSING_LOCKFILE"
    ] + counted("H12_DEPRECATED_DEPENDENCY_USE")
    if dep_refs:
        routes.append(
            (
                _route(
                    "engineering-devops-automator",
                    "dependency_cartography",
                    "Add lockfiles and a CI dependency check, and replace deprecated dependency use.",
                ),
                dep_refs,
            )
        )
    docs = counted("H10_DOC_BEHAVIOUR_CONTRADICTION")
    if docs:
        routes.append(
            (
                _route(
                    "engineering-technical-writer",
                    "code_archaeology",
                    "Correct the documentation that contradicts the code's behaviour.",
                ),
                docs,
            )
        )
    return routes


def _governance_routes(outputs: dict) -> list[tuple[Route, list[str]]]:
    qa = outputs.get("quality_review") or {}
    brief = outputs.get("executive_brief") or {}
    proposal = outputs.get("follow_up_proposal") or {}
    routes: list[tuple[Route, list[str]]] = [
        (
            _route(
                "testing-reality-checker",
                "quality_review",
                "Give the release verdict a second, evidence-first check before the client sees it.",
            ),
            [f"quality_review.verdict={qa.get('verdict')}"],
        ),
        (
            _route(
                "support-executive-summary-generator",
                "executive_brief",
                "Present the executive brief to the client's leadership and answer their questions on it.",
            ),
            [f"executive_brief.risk_rating={brief.get('risk_rating')}"],
        ),
    ]
    if proposal.get("status") == "PROPOSAL_READY":
        items = [f"follow_up_proposal.items[{i.get('service_code')}]" for i in proposal.get("items") or []]
        routes.append(
            (
                _route(
                    "sales-proposal-strategist",
                    "follow_up_proposal",
                    "Walk the client through the follow-up proposal and record which items they accept.",
                ),
                items,
            )
        )
        routes.append(
            (
                _route(
                    "project-manager-senior",
                    "follow_up_proposal",
                    "Turn the accepted proposal items into a delivery plan with owners and dates.",
                ),
                items,
            )
        )
    return routes


ROUTERS = {
    "forensic_incident_response": _forensics_routes,
    "legacy_archeology_sweep": _archaeology_routes,
}


def _by_slug(snapshot: Snapshot) -> dict[str, Agent]:
    return {a.slug: a for a in snapshot.agents.values() if a.source in ("upstream", "installed")}


def specialist_roster(runbook_id: str, outputs: dict, snapshot: Snapshot, run_id: str) -> dict:
    router = ROUTERS.get(runbook_id)
    if router is None:
        raise ValueError(f"no specialist routing for runbook {runbook_id!r}")
    catalog = _by_slug(snapshot)
    assignments: list[dict] = []
    not_found: list[str] = []
    seen: set[str] = set()
    for (slug, stage, role, task), triggered_by in router(outputs) + _governance_routes(outputs):
        if slug in seen:
            continue
        seen.add(slug)
        agent = catalog.get(slug)
        if agent is None:
            not_found.append(slug)
            continue
        assignments.append(
            {
                "agent_id": agent.agent_id,
                "catalog_name": slug,
                "name": agent.name,
                "division": agent.division,
                "location": agent.location,
                "role": role,
                "works_from_stage": stage,
                "task": task,
                "triggered_by": triggered_by,
                "prompt_sha256": agent.prompt_sha256,
            }
        )
    if not catalog:
        status = "CATALOG_UNAVAILABLE"
    elif not_found:
        status = "PARTIAL"
    else:
        status = "STAFFED"
    report = {
        "schema_version": ROSTER_SCHEMA,
        "agent_id": ENGAGEMENT_DIRECTOR_ID,
        "run_id": run_id,
        "stage_id": "specialist_roster",
        "runbook": runbook_id,
        "status": status,
        "catalog": {
            "source": "msitarzewski/agency-agents",
            "agents_available": len(catalog),
            "installed_copies_used": sum(1 for a in assignments if a["location"] == "installed"),
        },
        "assignments": assignments,
        "not_found": not_found,
    }
    report["self_validation"] = [
        {"check": "SR1", "passed": all(a["triggered_by"] for a in assignments)},
        {"check": "SR2", "passed": all(a["catalog_name"] in catalog for a in assignments)},
        {"check": "SR3", "passed": not has_banned_phrase(report)},
    ]
    return report
