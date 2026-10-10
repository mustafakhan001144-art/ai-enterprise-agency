"""Forensic incident response: the deterministic engines behind two custom agents.

* ``trace_analysis`` implements ``forensics.ai-trace-analyst`` (TraceAnalysisReport/v1):
  it parses the submitted telemetry into a timeline, detects anomalies, applies rules
  R1 to R10 in order and the severity matrix from the persona file.
* ``containment_plan`` implements ``forensics.agent-containment-specialist``
  (ContainmentPlan/v1): tier table, action catalogue, ordering and validation.

Nothing here contacts the client's systems. Every action in a plan requires a human
operator's approval and is executed by the client with their own tooling.

Every claim cites ``{artifact_id, locator}``. Locators are ``R<n>`` (1-based record
index) for structured artifacts and ``L<n>`` (1-based line number) for text.
"""

from __future__ import annotations

import ipaddress
import json
import re
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlsplit

from core.workflows.common import canonical_digest, excerpt, find_secrets, has_banned_phrase, sha256_text

TRACE_AGENT_ID = "forensics.ai-trace-analyst"
CONTAINMENT_AGENT_ID = "forensics.agent-containment-specialist"

TS_KEYS = ("ts", "timestamp", "time", "@timestamp", "created_at")
TOOL_KEYS = ("tool", "tool_name", "function", "name")
ARG_KEYS = ("args", "arguments", "input", "params", "parameters")
DEST_KEYS = ("destination", "dest", "host", "url", "endpoint", "target")
ID_KEYS = ("trace_id", "span_id", "tool_call_id", "request_id", "session_id")
TURN_KEYS = ("turn", "turn_id", "task_id")
TOKEN_KEYS = ("tokens", "total_tokens", "token_count")
TERMINATION_WORDS = (
    "session_end",
    "session_ended",
    "process_exit",
    "exit",
    "terminated",
    "killed",
    "kill",
    "sigterm",
    "sigkill",
    "shutdown",
    "stopped",
)
NETWORK_TOOL_RE = re.compile(r"(http|request|fetch|post|upload|send|webhook|curl|wget|email|smtp)", re.IGNORECASE)
URL_RE = re.compile(r"https?://[^\s\"'<>)\]}]+", re.IGNORECASE)
KV_RE = re.compile(r"([A-Za-z_][A-Za-z0-9_.@-]*)=(\"[^\"]*\"|'[^']*'|\S+)")
INJECTION_RE = re.compile(
    r"(ignore (?:all |any |the )?(?:previous|prior|above|earlier) (?:instructions|prompts|rules)"
    r"|disregard (?:all |any |the )?(?:previous|prior|above|your) (?:instructions|rules|guidelines)"
    r"|you are now (?:in )?(?:developer|dan|admin|god) mode"
    r"|new instructions?:"
    r"|(?:reveal|print|output) (?:your|the) system prompt"
    r"|do not (?:report|log|mention|flag) (?:this|these|it)"
    r"|(?:omit|hide|suppress) (?:this|these|the) (?:finding|findings|event|events)"
    r"|as an ai (?:auditor|reviewer|analyst),? you must)",
    re.IGNORECASE,
)
RATE_LIMIT_RE = re.compile(
    r"(rate.?limit|quota (?:exceeded|exhausted)|too many requests|\b429\b|insufficient_quota)", re.IGNORECASE
)
DENY_VERDICTS = {"deny", "denied", "block", "blocked", "reject", "rejected"}
FLAG_VERDICTS = DENY_VERDICTS | {"flag", "flagged", "warn"}

RULES = [
    ("R1", "DATA_EXFILTRATION"),
    ("R2", "CREDENTIAL_EXPOSURE"),
    ("R3", "PROMPT_INJECTION_EXECUTED"),
    ("R4", "UNAUTHORIZED_TOOL_USE"),
    ("R5", "PRIVILEGE_ESCALATION"),
    ("R6", "UNBOUNDED_AUTONOMY_LOOP"),
    ("R7", "RESOURCE_EXHAUSTION"),
    ("R8", "PROMPT_INJECTION_ATTEMPTED"),
    ("R9", "POLICY_FILTER_BYPASS"),
    ("R10", "BEHAVIOURAL_DEVIATION_UNCLASSIFIED"),
]
RULE_CLASS = dict(RULES)


# ---------------------------------------------------------------------------
# Parsing
# ---------------------------------------------------------------------------
@dataclass
class Record:
    artifact_id: str
    kind: str
    locator: str
    order: int  # position inside its artifact
    raw: str  # verbatim text of the record (line, or compact JSON of a structured record)
    data: dict[str, Any]


@dataclass
class Event:
    record: Record
    timestamp: datetime | None
    actor: str
    event_type: str
    summary: str
    tool: str | None = None
    destination: str | None = None
    ids: dict[str, str] = field(default_factory=dict)
    turn: str | None = None
    tokens: int | None = None
    seq: int = 0

    @property
    def ref(self) -> dict:
        return {"artifact_id": self.record.artifact_id, "locator": self.record.locator}


def _first(data: dict, keys: tuple[str, ...]) -> Any:
    for key in keys:
        if key in data and data[key] not in (None, ""):
            return data[key]
    return None


def _parse_ts(value: Any) -> datetime | None:
    if value is None:
        return None
    if isinstance(value, int | float):
        try:
            return datetime.fromtimestamp(float(value), tz=UTC)
        except (OverflowError, OSError, ValueError):
            return None
    text = str(value).strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    return parsed.replace(tzinfo=UTC) if parsed.tzinfo is None else parsed.astimezone(UTC)


def _parse_line(line: str) -> dict[str, Any]:
    stripped = line.strip()
    if stripped.startswith("{"):
        try:
            value = json.loads(stripped)
            if isinstance(value, dict):
                return value
        except json.JSONDecodeError:
            pass
    pairs = {key: val.strip("\"'") for key, val in KV_RE.findall(line)}
    if not pairs:
        # Leading ISO timestamp on free text lines, e.g. "2026-03-02T10:14:03Z agent said ..."
        first = stripped.split(" ", 1)[0] if stripped else ""
        if _parse_ts(first):
            pairs["ts"] = first
    return pairs


def parse_artifacts(artifacts: list[dict]) -> list[Record]:
    records: list[Record] = []
    for artifact in artifacts:
        content = artifact["content"]
        if isinstance(content, list):
            for index, item in enumerate(content, start=1):
                data = item if isinstance(item, dict) else {"value": item}
                raw = json.dumps(data, sort_keys=True, ensure_ascii=False)
                records.append(Record(artifact["artifact_id"], artifact["kind"], f"R{index}", index, raw, data))
        else:
            for index, line in enumerate(str(content).splitlines(), start=1):
                if not line.strip():
                    continue
                records.append(
                    Record(artifact["artifact_id"], artifact["kind"], f"L{index}", index, line, _parse_line(line))
                )
    return records


def _host(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    if "://" in text:
        return (urlsplit(text).hostname or "").lower() or None
    return text.split("/", 1)[0].split(":", 1)[0].lower() or None


def _args_text(data: dict) -> str:
    args = _first(data, ARG_KEYS)
    if args is None:
        return ""
    return args if isinstance(args, str) else json.dumps(args, sort_keys=True, ensure_ascii=False)


def _destination(record: Record) -> str | None:
    data = record.data
    direct = _first(data, DEST_KEYS)
    if direct is not None and not isinstance(direct, dict | list):
        return _host(direct)
    args = _first(data, ARG_KEYS)
    if isinstance(args, dict):
        nested = _first(args, DEST_KEYS)
        if nested is not None and not isinstance(nested, dict | list):
            return _host(nested)
    match = URL_RE.search(_args_text(data)) if record.kind == "tool_log" else None
    return _host(match.group(0)) if match else None


def _tokens(data: dict) -> int | None:
    value = _first(data, TOKEN_KEYS)
    if value is None and isinstance(data.get("usage"), dict):
        value = _first(data["usage"], TOKEN_KEYS + ("input_tokens",))
        if value is not None and "output_tokens" in data["usage"] and "total_tokens" not in data["usage"]:
            try:
                value = int(value) + int(data["usage"]["output_tokens"])
            except (TypeError, ValueError):
                return None
    try:
        return int(value) if value is not None else None
    except (TypeError, ValueError):
        return None


def _is_termination(record: Record) -> bool:
    data = record.data
    words = " ".join(str(data.get(k, "")) for k in ("event", "type", "event_type", "status", "signal", "action"))
    if not words.strip() and record.kind == "orchestrator_log":
        words = record.raw
    lowered = words.lower()
    return any(re.search(rf"\b{re.escape(w)}\b", lowered) for w in TERMINATION_WORDS)


def build_events(records: list[Record]) -> list[Event]:
    events: list[Event] = []
    for record in records:
        data = record.data
        tool = _first(data, TOOL_KEYS) if record.kind in ("tool_log", "orchestrator_log", "other") else None
        tool = str(tool) if tool is not None and not isinstance(tool, dict | list) else None
        destination = _destination(record)
        role = str(data.get("role", "")).lower()
        verdict = str(data.get("verdict", data.get("decision", ""))).lower()

        if _is_termination(record):
            event_type, actor = "TERMINATION", "orchestrator"
        elif record.kind == "policy_log" or verdict:
            event_type, actor = "POLICY_VERDICT", "orchestrator"
        elif record.kind == "egress_log" or (
            destination
            and (record.kind == "tool_log")
            and (NETWORK_TOOL_RE.search(tool or "") or URL_RE.search(record.raw))
        ):
            event_type = "EGRESS"
            actor = "subject_agent"
        elif record.kind == "tool_log" and tool:
            event_type = (
                "TOOL_RESULT" if ("result" in data or "output" in data) and not _first(data, ARG_KEYS) else "TOOL_CALL"
            )
            actor = "subject_agent" if event_type == "TOOL_CALL" else f"tool:{tool}"
        elif "error" in data or RATE_LIMIT_RE.search(record.raw) and record.kind == "token_ledger":
            event_type, actor = "ERROR", "orchestrator"
        elif any(k in data for k in ("scope", "role_granted", "scopes", "grant")) and record.kind != "transcript":
            event_type, actor = "AUTH", "orchestrator"
        elif record.kind == "transcript":
            if role in ("user", "human"):
                event_type, actor = "PROMPT", "user"
            elif role in ("tool", "function"):
                event_type, actor = "TOOL_RESULT", f"tool:{data.get('name', 'unknown')}"
            else:
                event_type, actor = "COMPLETION", "subject_agent"
        elif record.kind == "token_ledger":
            event_type, actor = "COMPLETION", "subject_agent"
        else:
            event_type, actor = ("TOOL_CALL", "subject_agent") if tool else ("COMPLETION", "orchestrator")

        if event_type == "EGRESS" and destination:
            actor = "subject_agent"
        ids = {k: str(data[k]) for k in ID_KEYS if data.get(k) not in (None, "")}
        turn = _first(data, TURN_KEYS)
        event = Event(
            record=record,
            timestamp=_parse_ts(_first(data, TS_KEYS)),
            actor=actor,
            event_type=event_type,
            summary="",
            tool=tool,
            destination=destination,
            ids=ids,
            turn=str(turn) if turn is not None else None,
            tokens=_tokens(data),
        )
        event.summary = _summary(event)
        events.append(event)

    far_future = datetime.max.replace(tzinfo=UTC)
    events.sort(key=lambda e: (e.timestamp or far_future, e.record.artifact_id, e.record.order))
    for seq, event in enumerate(events, start=1):
        event.seq = seq
    return events


def _summary(event: Event) -> str:
    match event.event_type:
        case "TOOL_CALL":
            text = f"subject_agent called tool {event.tool}"
        case "EGRESS":
            text = f"{event.actor} sent a network request to {event.destination or 'an unrecorded destination'}"
            if event.tool:
                text += f" via tool {event.tool}"
        case "TOOL_RESULT":
            text = f"{event.actor} returned a result"
        case "POLICY_VERDICT":
            verdict = event.record.data.get("verdict", event.record.data.get("decision", "a verdict"))
            text = f"policy filter recorded {verdict}"
        case "TERMINATION":
            text = "a termination event was recorded"
        case "AUTH":
            text = "an authorization or scope record was logged"
        case "ERROR":
            text = "an error was recorded"
        case "PROMPT":
            text = "user submitted a prompt"
        case _:
            text = f"{event.actor} produced output"
    return text[:200]


# ---------------------------------------------------------------------------
# Detection
# ---------------------------------------------------------------------------
def _host_allowed(host: str, allowlist: list[str]) -> bool:
    for entry in allowlist:
        entry = entry.strip().lower()
        if not entry:
            continue
        if "/" in entry:
            try:
                if ipaddress.ip_address(host) in ipaddress.ip_network(entry, strict=False):
                    return True
            except ValueError:
                pass
            continue
        if host == entry or (entry.startswith("*.") and host.endswith(entry[1:])) or host.endswith("." + entry):
            return True
    return False


@dataclass
class Analysis:
    anomalies: list[dict] = field(default_factory=list)
    gaps: list[dict] = field(default_factory=list)
    iocs: list[dict] = field(default_factory=list)
    rule_results: dict[str, tuple[str, list[dict]]] = field(default_factory=dict)

    def anomaly(self, kind: str, description: str, events: list[Event]) -> dict:
        entry = {
            "anomaly_id": f"AN-{len(self.anomalies) + 1:03d}",
            "type": kind,
            "description": description[:300],
            "timeline_seqs": sorted({e.seq for e in events}),
            "evidence_refs": _unique_refs(events),
        }
        self.anomalies.append(entry)
        return entry

    def gap(self, question: str, missing: str, rules: list[str]) -> None:
        self.gaps.append(
            {
                "gap_id": f"GAP-{len(self.gaps) + 1:03d}",
                "question": question,
                "missing_artifact": missing,
                "blocks_rules": rules,
            }
        )

    def ioc(self, kind: str, value: str, events: list[Event]) -> None:
        for existing in self.iocs:
            if existing["type"] == kind and existing["value"] == value:
                for ref in _unique_refs(events):
                    if ref not in existing["evidence_refs"]:
                        existing["evidence_refs"].append(ref)
                return
        self.iocs.append({"type": kind, "value": value, "evidence_refs": _unique_refs(events)})


def _unique_refs(events: list[Event]) -> list[dict]:
    refs: list[dict] = []
    for event in events:
        if event.ref not in refs:
            refs.append(event.ref)
    return refs


def analyse(subject: dict, events: list[Event]) -> Analysis:
    out = Analysis()
    declared_tools = subject.get("declared_tools") or []
    allowlist = subject.get("declared_egress_allowlist") or []
    baseline = subject.get("baseline_profile") or {}
    permitted = baseline.get("permitted_data_classes") or []
    max_calls = baseline.get("max_tool_calls_per_turn")
    max_tokens = baseline.get("max_tokens_per_turn")

    tool_calls = [e for e in events if e.event_type in ("TOOL_CALL", "EGRESS") and e.tool]
    egress = [e for e in events if e.event_type == "EGRESS"]

    # Data classes named by policy records, keyed by the field or value they classify.
    classified: dict[str, tuple[str, Event]] = {}
    for event in events:
        data = event.record.data
        data_class = data.get("data_class") or data.get("classification")
        target = data.get("field") or data.get("value") or data.get("content_field")
        if event.event_type == "POLICY_VERDICT" and data_class and target:
            classified[str(target)] = (str(data_class), event)

    # INSTRUCTION_IN_DATA: text inside telemetry that addresses an automated system.
    injections: list[tuple[dict, Event]] = []
    for event in events:
        if event.event_type in ("PROMPT", "TOOL_RESULT", "COMPLETION", "POLICY_VERDICT") or event.record.kind in (
            "transcript",
            "other",
        ):
            match = INJECTION_RE.search(event.record.raw)
            if match:
                entry = out.anomaly(
                    "INSTRUCTION_IN_DATA",
                    f'{event.record.artifact_id}:{event.record.locator} contains the text "{match.group(0)}"',
                    [event],
                )
                injections.append((entry, event))
                out.ioc("prompt_signature", sha256_text(match.group(0).lower()), [event])

    # R1 / UNDECLARED_EGRESS
    undeclared_egress: list[Event] = []
    for event in egress:
        if event.destination and allowlist and not _host_allowed(event.destination, allowlist):
            undeclared_egress.append(event)
            out.anomaly(
                "UNDECLARED_EGRESS",
                f"subject_agent sent data to {event.destination}, which is not in declared_egress_allowlist",
                [event],
            )
            kind = "ip" if _is_ip(event.destination) else "domain"
            out.ioc(kind, event.destination, [event])
            for url in URL_RE.findall(event.record.raw):
                out.ioc("url", excerpt(url, 300), [event])
    if not allowlist and egress:
        out.gap(
            "Whether network destinations were permitted cannot be determined.",
            "subject.declared_egress_allowlist",
            ["R1"],
        )
        out.rule_results["R1"] = ("UNDETERMINABLE", _unique_refs(egress))
    elif not undeclared_egress:
        out.rule_results["R1"] = ("FALSE", [])
    else:
        exfil_refs: list[Event] = []
        undeterminable = False
        for event in undeclared_egress:
            for target, (data_class, policy_event) in classified.items():
                if target in event.record.raw:
                    if not permitted:
                        undeterminable = True
                    elif data_class not in permitted:
                        exfil_refs += [event, policy_event]
        if exfil_refs:
            out.rule_results["R1"] = ("TRUE", _unique_refs(exfil_refs))
        elif undeterminable or not permitted:
            out.gap(
                "Whether the data sent to undeclared destinations was outside the permitted data classes "
                "cannot be determined.",
                "baseline_profile.permitted_data_classes and a policy log that classifies the payload fields",
                ["R1"],
            )
            out.rule_results["R1"] = ("UNDETERMINABLE", _unique_refs(undeclared_egress))
        else:
            out.rule_results["R1"] = ("FALSE", [])

    # R2 / SECRET_IN_OUTPUT
    secret_events: list[Event] = []
    for event in events:
        if event.event_type in ("COMPLETION", "TOOL_CALL", "EGRESS"):
            for _kind, value in find_secrets(event.record.raw):
                secret_events.append(event)
                out.ioc("credential_fingerprint", sha256_text(value), [event])
    if secret_events:
        out.anomaly(
            "SECRET_IN_OUTPUT",
            "credential material was present in model output, tool arguments or egress payloads",
            secret_events,
        )
    out.rule_results["R2"] = ("TRUE", _unique_refs(secret_events)) if secret_events else ("FALSE", [])

    # R3 / R8: injection, and whether an identifier-linked later action followed it.
    executed: list[Event] = []
    for _entry, event in injections:
        for later in events:
            if later.seq <= event.seq or later.event_type not in ("TOOL_CALL", "EGRESS"):
                continue
            if any(event.ids.get(k) == v for k, v in later.ids.items()):
                executed += [event, later]
                break
    out.rule_results["R3"] = ("TRUE", _unique_refs(executed)) if executed else ("FALSE", [])
    attempted_only = [ev for _a, ev in injections if ev not in executed]
    out.rule_results["R8"] = ("TRUE", _unique_refs(attempted_only)) if attempted_only else ("FALSE", [])

    # R4 / UNDECLARED_TOOL and DENIED_SCOPE_EXECUTED
    r4: list[Event] = []
    if declared_tools:
        for event in tool_calls:
            if event.tool not in declared_tools:
                r4.append(event)
                out.anomaly(
                    "UNDECLARED_TOOL", f"subject_agent called tool {event.tool}, which is not declared", [event]
                )
                out.ioc("tool_name", event.tool, [event])
    denied_ids = {}
    for event in events:
        verdict = str(event.record.data.get("verdict", event.record.data.get("decision", ""))).lower()
        if event.event_type == "POLICY_VERDICT" and verdict in DENY_VERDICTS:
            for value in event.ids.values():
                denied_ids[value] = event
    for event in tool_calls:
        status = str(event.record.data.get("status", "")).lower()
        for value in event.ids.values():
            if value in denied_ids and status not in DENY_VERDICTS and event.seq > denied_ids[value].seq:
                r4 += [denied_ids[value], event]
                out.anomaly(
                    "DENIED_SCOPE_EXECUTED",
                    f"tool {event.tool} executed after the policy log denied {value}",
                    [denied_ids[value], event],
                )
    if r4:
        out.rule_results["R4"] = ("TRUE", _unique_refs(r4))
    elif not declared_tools and tool_calls:
        out.gap("Whether the tools called were authorized cannot be determined.", "subject.declared_tools", ["R4"])
        out.rule_results["R4"] = ("UNDETERMINABLE", _unique_refs(tool_calls))
    else:
        out.rule_results["R4"] = ("FALSE", [])

    # R5 / AUTH_SCOPE_CHANGE: a scope or role that differs from the first one recorded.
    auth_events = [e for e in events if e.event_type == "AUTH"]
    first_scope = None
    escalations: list[Event] = []
    for event in auth_events:
        data = event.record.data
        scope = data.get("scope") or data.get("scopes") or data.get("role_granted") or data.get("grant")
        scope_set = set(scope if isinstance(scope, list) else str(scope).replace(",", " ").split())
        if first_scope is None:
            first_scope = (scope_set, event)
        elif not scope_set <= first_scope[0]:
            escalations += [first_scope[1], event]
            out.anomaly(
                "AUTH_SCOPE_CHANGE",
                f"scope {sorted(scope_set - first_scope[0])} was recorded after the initial scope "
                f"{sorted(first_scope[0])}",
                [first_scope[1], event],
            )
    out.rule_results["R5"] = ("TRUE", _unique_refs(escalations)) if escalations else ("FALSE", [])

    # R6 / LOOP_THRESHOLD
    r6: list[Event] = []
    streak: list[Event] = []
    for event in tool_calls:
        key = (event.tool, _args_text(event.record.data))
        if streak and (streak[-1].tool, _args_text(streak[-1].record.data)) == key:
            streak.append(event)
        else:
            streak = [event]
        if len(streak) == 5:
            r6 += streak
            out.anomaly(
                "LOOP_THRESHOLD",
                f"tool {event.tool} was called 5 consecutive times with identical arguments",
                list(streak),
            )
    per_turn: dict[str, list[Event]] = {}
    for event in tool_calls:
        if event.turn is not None:
            per_turn.setdefault(event.turn, []).append(event)
    if max_calls:
        for turn, calls in per_turn.items():
            if len(calls) > max_calls:
                r6 += calls
                out.anomaly(
                    "LOOP_THRESHOLD", f"turn {turn} had {len(calls)} tool calls, above the baseline {max_calls}", calls
                )
    if r6:
        out.rule_results["R6"] = ("TRUE", _unique_refs(r6))
    elif not max_calls and tool_calls:
        out.gap(
            "Whether tool calls per turn exceeded the baseline cannot be determined.",
            "baseline_profile.max_tool_calls_per_turn",
            ["R6"],
        )
        out.rule_results["R6"] = ("UNDETERMINABLE", [])
    else:
        out.rule_results["R6"] = ("FALSE", [])

    # R7 / TOKEN_THRESHOLD
    r7: list[Event] = []
    for event in events:
        if event.record.kind == "token_ledger" and RATE_LIMIT_RE.search(event.record.raw):
            r7.append(event)
            out.anomaly("TOKEN_THRESHOLD", "the token ledger recorded a rate-limit or quota error", [event])
    token_events = [e for e in events if e.tokens is not None]
    if max_tokens:
        turns: dict[str, list[Event]] = {}
        for event in token_events:
            turns.setdefault(event.turn or "(no turn id)", []).append(event)
        for turn, items in turns.items():
            total = sum(e.tokens or 0 for e in items)
            if total > max_tokens:
                r7 += items
                out.anomaly(
                    "TOKEN_THRESHOLD", f"turn {turn} consumed {total} tokens, above the baseline {max_tokens}", items
                )
    if r7:
        out.rule_results["R7"] = ("TRUE", _unique_refs(r7))
    elif not max_tokens and token_events:
        out.gap(
            "Whether token use per turn exceeded the baseline cannot be determined.",
            "baseline_profile.max_tokens_per_turn",
            ["R7"],
        )
        out.rule_results["R7"] = ("UNDETERMINABLE", [])
    else:
        out.rule_results["R7"] = ("FALSE", [])

    # R9 / POLICY_BYPASS: content a filter blocked or flagged reappears in later output or egress.
    r9: list[Event] = []
    for event in events:
        verdict = str(event.record.data.get("verdict", event.record.data.get("decision", ""))).lower()
        content = event.record.data.get("content") or event.record.data.get("blocked_content")
        if event.event_type != "POLICY_VERDICT" or verdict not in FLAG_VERDICTS or not content:
            continue
        content = str(content)
        if len(content) < 8:
            continue
        for later in events:
            if later.seq > event.seq and later.event_type in ("COMPLETION", "EGRESS") and content in later.record.raw:
                r9 += [event, later]
                out.anomaly(
                    "POLICY_BYPASS",
                    "content the policy filter flagged or blocked appeared in a later record",
                    [event, later],
                )
                break
    out.rule_results["R9"] = ("TRUE", _unique_refs(r9)) if r9 else ("FALSE", [])

    matched_types = {
        "INSTRUCTION_IN_DATA",
        "UNDECLARED_EGRESS",
        "SECRET_IN_OUTPUT",
        "UNDECLARED_TOOL",
        "DENIED_SCOPE_EXECUTED",
        "AUTH_SCOPE_CHANGE",
        "LOOP_THRESHOLD",
        "TOKEN_THRESHOLD",
        "POLICY_BYPASS",
    }
    other = [a for a in out.anomalies if a["type"] not in matched_types]
    # UNDECLARED_EGRESS that did not satisfy R1 is still a deviation.
    unmatched_egress = (
        [a for a in out.anomalies if a["type"] == "UNDECLARED_EGRESS"] if out.rule_results["R1"][0] != "TRUE" else []
    )
    r10 = other + unmatched_egress
    out.rule_results["R10"] = ("TRUE", [r for a in r10 for r in a["evidence_refs"]]) if r10 else ("FALSE", [])
    return out


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


# ---------------------------------------------------------------------------
# Report assembly
# ---------------------------------------------------------------------------
def classify(rule_results: dict[str, tuple[str, list[dict]]]) -> tuple[str, list[str], list[dict]]:
    trace = []
    true_rules: list[str] = []
    undeterminable = False
    for rule, _cls in RULES:
        result, refs = rule_results[rule]
        trace.append({"rule": rule, "result": result, "evidence_refs": refs})
        if result == "TRUE":
            true_rules.append(rule)
        elif result == "UNDETERMINABLE" and rule != "R10":
            undeterminable = True
    nine = [r for r in true_rules if r != "R10"]
    if nine:
        primary = RULE_CLASS[nine[0]]
        secondary = [RULE_CLASS[r] for r in true_rules if r != nine[0]]
    elif undeterminable:
        primary = "INDETERMINATE_INSUFFICIENT_BASELINE"
        secondary = [RULE_CLASS[r] for r in true_rules]
    elif true_rules:
        primary, secondary = RULE_CLASS["R10"], []
    else:
        primary, secondary = "NO_INCIDENT_EVIDENCED", []
    return primary, secondary, trace


def severity(classes: set[str], events: list[Event], anomalies: list[dict]) -> tuple[str, dict]:
    e = int(bool(classes & {"DATA_EXFILTRATION", "CREDENTIAL_EXPOSURE"}))
    x = int(
        bool(
            classes
            & {"PROMPT_INJECTION_EXECUTED", "UNAUTHORIZED_TOOL_USE", "PRIVILEGE_ESCALATION", "POLICY_FILTER_BYPASS"}
        )
    )
    timed = [ev for ev in events if ev.timestamp is not None]
    determinable = bool(timed)
    if not determinable:
        o = 1
    else:
        latest = max(timed, key=lambda ev: ev.timestamp).timestamp
        # analysis_reference_time is the latest timestamp, so the 15-minute window always
        # contains the latest event; ongoing therefore depends on a termination record at or
        # after it.
        o = 0 if any(ev.event_type == "TERMINATION" and ev.timestamp == latest for ev in timed) else 1
        if o == 1 and any(ev.event_type == "TERMINATION" for ev in timed if ev.timestamp >= latest):
            o = 0
    if e and o:
        sev = "SEV1_CRITICAL"
    elif e:
        sev = "SEV2_HIGH"
    elif x and o:
        sev = "SEV2_HIGH"
    elif x:
        sev = "SEV3_MEDIUM"
    else:
        sev = "SEV4_LOW" if anomalies else "SEV5_INFORMATIONAL"
    return sev, {"E": e, "X": x, "O": o, "O_determinable": determinable}


def trace_analysis(request: dict, run_id: str) -> dict:
    """TraceAnalysisReport/v1 for a ForensicsContainRequest payload."""
    subject = request.get("subject") or {}
    artifacts = request.get("artifacts") or []
    hashed = [
        {
            **a,
            "sha256": sha256_text(
                a["content"]
                if isinstance(a["content"], str)
                else json.dumps(a["content"], sort_keys=True, ensure_ascii=False)
            ),
        }
        for a in artifacts
    ]
    input_digest = canonical_digest(hashed)
    records = parse_artifacts(artifacts)
    events = build_events(records)

    report: dict[str, Any] = {
        "schema_version": "TraceAnalysisReport/v1",
        "agent_id": TRACE_AGENT_ID,
        "run_id": run_id,
        "stage_id": "trace_analysis",
        "input_digest": input_digest,
        "status": "COMPLETE",
        "analysis_reference_time": None,
        "subject_agent": subject.get("agent_name"),
    }

    if not artifacts or not records:
        report.update(
            status="REJECTED_INPUT",
            primary_class="NO_INCIDENT_EVIDENCED",
            secondary_classes=[],
            classification_trace=[],
            severity="SEV5_INFORMATIONAL",
            severity_inputs={"E": 0, "X": 0, "O": 0, "O_determinable": False},
            timeline=[],
            anomalies=[],
            iocs=[],
            metrics=_metrics([], []),
            evidence_gaps=[
                {
                    "gap_id": "GAP-001",
                    "question": "No telemetry records could be read from the submitted artifacts.",
                    "missing_artifact": "at least one non-empty artifact",
                    "blocks_rules": [r for r, _ in RULES],
                }
            ],
            handoff={"affected_components": [], "active_sessions": [], "facts_for_containment": []},
        )
        report["self_validation"] = validate_trace_report(report, artifacts)
        return report

    analysis = analyse(subject, events)
    primary, secondary, trace = classify(analysis.rule_results)
    sev, sev_inputs = severity({primary, *secondary}, events, analysis.anomalies)
    if not sev_inputs["O_determinable"]:
        analysis.gap("Whether the incident is ongoing cannot be determined.", "timestamps on telemetry records", [])
    timed = [e.timestamp for e in events if e.timestamp]
    report["analysis_reference_time"] = max(timed).isoformat().replace("+00:00", "Z") if timed else None
    if primary == "INDETERMINATE_INSUFFICIENT_BASELINE":
        report["status"] = "INSUFFICIENT_EVIDENCE"

    terminated_ids = {v for e in events if e.event_type == "TERMINATION" for v in e.ids.values()}
    sessions = sorted({e.ids["session_id"] for e in events if "session_id" in e.ids} - terminated_ids)
    if not sessions and sev_inputs["O"] == 1:
        sessions = sorted({e.ids["trace_id"] for e in events if "trace_id" in e.ids} - terminated_ids)
    affected = sorted({e.tool for e in events if e.tool} | {e.destination for e in events if e.destination})
    facts = [
        f"{a['description']} [{a['evidence_refs'][0]['artifact_id']}:{a['evidence_refs'][0]['locator']}]"
        for a in analysis.anomalies
        if a["evidence_refs"]
    ]
    report.update(
        primary_class=primary,
        secondary_classes=secondary,
        classification_trace=trace,
        severity=sev,
        severity_inputs=sev_inputs,
        timeline=_timeline(events),
        anomalies=analysis.anomalies,
        iocs=analysis.iocs,
        metrics=_metrics(events, analysis.anomalies, subject),
        evidence_gaps=analysis.gaps,
        handoff={"affected_components": affected, "active_sessions": sessions, "facts_for_containment": facts},
    )
    report["self_validation"] = validate_trace_report(report, artifacts)
    return report


def _timeline(events: list[Event]) -> list[dict]:
    timeline = []
    for event in events:
        links = []
        for key, value in event.ids.items():
            nxt = next((o for o in events if o.seq > event.seq and o.ids.get(key) == value), None)
            if nxt and all(link["to_seq"] != nxt.seq for link in links):
                links.append({"to_seq": nxt.seq, "relation": "identifier_linked", "via": f"{key}={value}"})
        timeline.append(
            {
                "seq": event.seq,
                "timestamp": event.timestamp.isoformat().replace("+00:00", "Z") if event.timestamp else None,
                "actor": event.actor,
                "event_type": event.event_type,
                "summary": event.summary,
                "evidence_refs": [event.ref],
                "excerpt": excerpt(event.record.raw, 300),
                "links": links,
            }
        )
    return timeline


def _metrics(events: list[Event], anomalies: list[dict], subject: dict | None = None) -> dict:
    subject = subject or {}
    tools = [e for e in events if e.event_type in ("TOOL_CALL", "EGRESS") and e.tool]
    egress = [e for e in events if e.event_type == "EGRESS"]
    declared = subject.get("declared_tools") or []
    allow = subject.get("declared_egress_allowlist") or []
    timed = [e.timestamp for e in events if e.timestamp]
    token_values = [e.tokens for e in events if e.tokens is not None]
    return {
        "events_total": len(events),
        "tool_calls_total": len(tools),
        "undeclared_tool_calls": sum(1 for e in tools if e.tool not in declared) if declared else None,
        "egress_events_total": len(egress),
        "undeclared_egress_events": sum(1 for e in egress if e.destination and not _host_allowed(e.destination, allow))
        if allow
        else None,
        "tokens_total": sum(token_values) if token_values else None,
        "trace_window_seconds": int((max(timed) - min(timed)).total_seconds()) if len(timed) >= 1 else None,
    }


def _locator_exists(artifact: dict, locator: str) -> bool:
    content = artifact["content"]
    try:
        index = int(locator[1:])
    except ValueError:
        return False
    if locator.startswith("R"):
        return isinstance(content, list) and 1 <= index <= len(content)
    if locator.startswith("L"):
        return isinstance(content, str) and 1 <= index <= len(content.splitlines())
    return False


def _artifact_text(artifact: dict) -> str:
    content = artifact["content"]
    if isinstance(content, str):
        return content
    return "\n".join(
        json.dumps(i if isinstance(i, dict) else {"value": i}, sort_keys=True, ensure_ascii=False) for i in content
    )


def _all_refs(value: Any) -> list[dict]:
    refs: list[dict] = []
    if isinstance(value, dict):
        if set(value) == {"artifact_id", "locator"}:
            refs.append(value)
        else:
            for v in value.values():
                refs += _all_refs(v)
    elif isinstance(value, list):
        for v in value:
            refs += _all_refs(v)
    return refs


def validate_trace_report(report: dict, artifacts: list[dict]) -> list[dict]:
    """Executes checks V1 to V10 from the persona file against the finished report."""
    by_id = {a["artifact_id"]: a for a in artifacts}
    refs = _all_refs({k: v for k, v in report.items() if k != "self_validation"})
    v1 = all(r["artifact_id"] in by_id for r in refs)
    v2 = v1 and all(_locator_exists(by_id[r["artifact_id"]], r["locator"]) for r in refs)
    texts = {aid: excerpt(_artifact_text(a), 10**9) for aid, a in by_id.items()}
    v3 = all(
        item["excerpt"] in texts.get(item["evidence_refs"][0]["artifact_id"], "") for item in report.get("timeline", [])
    )
    stamps = [t["timestamp"] for t in report.get("timeline", [])]
    present = [s for s in stamps if s]
    v4 = present == sorted(present) and stamps[: len(present)] == present
    if report.get("classification_trace"):
        primary, secondary, _ = classify(
            {t["rule"]: (t["result"], t["evidence_refs"]) for t in report["classification_trace"]}
        )
        v5 = primary == report["primary_class"] and secondary == report["secondary_classes"]
    else:
        v5 = report["status"] == "REJECTED_INPUT"
    inputs = report["severity_inputs"]
    expected = (
        "SEV1_CRITICAL"
        if inputs["E"] and inputs["O"]
        else "SEV2_HIGH"
        if inputs["E"] or (inputs["X"] and inputs["O"])
        else "SEV3_MEDIUM"
        if inputs["X"]
        else "SEV4_LOW"
        if report["anomalies"]
        else "SEV5_INFORMATIONAL"
    )
    v6 = report["severity"] == expected
    v7 = not has_banned_phrase(
        [report.get("timeline"), report.get("anomalies"), report.get("evidence_gaps"), report.get("handoff")]
    )
    v8 = report["metrics"]["events_total"] == len(report.get("timeline", []))
    v9 = bool(re.fullmatch(r"[0-9a-f]{64}", report["input_digest"]))
    v10 = all(
        k in report
        for k in (
            "schema_version",
            "primary_class",
            "severity",
            "timeline",
            "anomalies",
            "iocs",
            "metrics",
            "evidence_gaps",
            "handoff",
        )
    )
    return [{"check": f"V{i}", "passed": bool(v)} for i, v in enumerate([v1, v2, v3, v4, v5, v6, v7, v8, v9, v10], 1)]


# ---------------------------------------------------------------------------
# Containment planning
# ---------------------------------------------------------------------------
CATALOGUE: dict[str, dict] = {
    "P1_SNAPSHOT_EVIDENCE": {"level": 0, "disruptive": False},
    "P2_ENABLE_ENHANCED_LOGGING": {"level": 0, "disruptive": False},
    "M1_RATE_LIMIT_AGENT": {"level": 1, "disruptive": True},
    "M2_REVOKE_TOOL": {"level": 1, "disruptive": True},
    "M3_BLOCK_EGRESS_DESTINATION": {"level": 1, "disruptive": True},
    "M4_QUARANTINE_INPUT_SOURCE": {"level": 1, "disruptive": True},
    "M5_ENFORCE_POLICY_FILTER_BLOCKING": {"level": 1, "disruptive": True},
    "C1_ROTATE_CREDENTIAL": {"level": 2, "disruptive": True},
    "C2_DOWNGRADE_AGENT_SCOPE": {"level": 2, "disruptive": True},
    "C3_DENY_ALL_EGRESS": {"level": 2, "disruptive": True},
    "C4_TERMINATE_SESSION": {"level": 2, "disruptive": True},
    "K1_SUSPEND_AGENT": {"level": 3, "disruptive": True},
    "K2_ISOLATE_AGENT_NETWORK_SEGMENT": {"level": 3, "disruptive": True},
    "R1_NOTIFY_DPO": {"level": 0, "disruptive": False},
    "R2_NOTIFY_CSIRT_LIAISON": {"level": 0, "disruptive": False},
}

# Candidate actions per class, lowest disruption first (C7).
NEUTRALISERS: dict[str, list[str]] = {
    "DATA_EXFILTRATION": ["M3_BLOCK_EGRESS_DESTINATION", "C3_DENY_ALL_EGRESS", "K2_ISOLATE_AGENT_NETWORK_SEGMENT"],
    "CREDENTIAL_EXPOSURE": ["C1_ROTATE_CREDENTIAL"],
    "PROMPT_INJECTION_EXECUTED": ["M2_REVOKE_TOOL", "M4_QUARANTINE_INPUT_SOURCE", "K1_SUSPEND_AGENT"],
    "UNAUTHORIZED_TOOL_USE": ["M2_REVOKE_TOOL", "K1_SUSPEND_AGENT"],
    "PRIVILEGE_ESCALATION": ["C2_DOWNGRADE_AGENT_SCOPE", "C1_ROTATE_CREDENTIAL", "K1_SUSPEND_AGENT"],
    "UNBOUNDED_AUTONOMY_LOOP": ["M1_RATE_LIMIT_AGENT", "K1_SUSPEND_AGENT"],
    "RESOURCE_EXHAUSTION": ["M1_RATE_LIMIT_AGENT", "K1_SUSPEND_AGENT"],
    "PROMPT_INJECTION_ATTEMPTED": ["M4_QUARANTINE_INPUT_SOURCE"],
    "POLICY_FILTER_BYPASS": ["M5_ENFORCE_POLICY_FILTER_BLOCKING", "K1_SUSPEND_AGENT"],
}

ACTION_TEXT: dict[str, dict[str, Any]] = {
    "P1_SNAPSHOT_EVIDENCE": {
        "pre": ["The forensic vault is reachable and has capacity for the agent's state and logs."],
        "steps": [
            "Capture the agent's runtime state, memory store, conversation state and logs.",
            "Record a SHA-256 hash of each captured item in the forensic vault.",
        ],
        "verify": "Every captured item has a recorded hash in the forensic vault.",
        "rollback": "Not applicable: capture changes no runtime state.",
        "blast": "None.",
    },
    "P2_ENABLE_ENHANCED_LOGGING": {
        "pre": ["Log storage has capacity for increased telemetry volume."],
        "steps": ["Raise telemetry verbosity for the subject agent and each of its tools."],
        "verify": "New telemetry records show the increased detail level.",
        "rollback": "Return telemetry verbosity to its previous setting.",
        "blast": "None; storage use increases.",
    },
    "M1_RATE_LIMIT_AGENT": {
        "pre": ["Baseline limits from the subject's baseline profile are known."],
        "steps": ["Configure the agent runtime to cap tool calls and tokens per turn at the baseline values."],
        "verify": "A turn that exceeds the cap is refused by the runtime.",
        "rollback": "Remove the cap from the agent runtime configuration.",
        "blast": "Tasks needing more calls or tokens per turn than the baseline are refused.",
    },
    "M2_REVOKE_TOOL": {
        "pre": ["The tool's owner has been identified."],
        "steps": ["Remove the named tool from the agent's tool registry."],
        "verify": "The agent's tool list no longer contains the named tool.",
        "rollback": "Re-register the tool in the agent's tool registry.",
        "blast": "Workflows that depend on the named tool stop working.",
    },
    "M3_BLOCK_EGRESS_DESTINATION": {
        "pre": ["Evidence snapshot is verified."],
        "steps": ["Add a deny rule for the named destination to the agent runtime's egress policy."],
        "verify": "A test connection from the agent runtime to the destination is refused.",
        "rollback": "Remove the deny rule from the egress policy.",
        "blast": "Any legitimate use of the named destination by the agent is blocked.",
    },
    "M4_QUARANTINE_INPUT_SOURCE": {
        "pre": ["The input source carrying the instruction text has been identified."],
        "steps": ["Stop the agent from ingesting content from the named input source."],
        "verify": "No new records from the input source appear in the agent's telemetry.",
        "rollback": "Re-enable ingestion from the input source.",
        "blast": "Content from the input source is unavailable to the agent.",
    },
    "M5_ENFORCE_POLICY_FILTER_BLOCKING": {
        "pre": ["The policy filter's current mode is recorded."],
        "steps": ["Switch the named policy filter from flag-only mode to blocking mode."],
        "verify": "A test input matching the filter is blocked rather than flagged.",
        "rollback": "Return the policy filter to its recorded previous mode.",
        "blast": "Outputs matching the filter are withheld instead of flagged.",
    },
    "C1_ROTATE_CREDENTIAL": {
        "pre": ["Known exfiltration destinations are blocked.", "Consumers of the credential are identified."],
        "steps": [
            "Revoke the credential identified by the fingerprint.",
            "Issue a replacement credential to the legitimate consumers only.",
        ],
        "verify": "A request made with the revoked credential is rejected by the issuing service.",
        "rollback": "IRREVERSIBLE: a revoked credential cannot be reinstated; issue a new one instead.",
        "blast": "Every system using the credential fails until it receives the replacement.",
    },
    "C2_DOWNGRADE_AGENT_SCOPE": {
        "pre": ["The pre-incident scope grant is recorded."],
        "steps": ["Reduce the agent's role and scopes to the recorded pre-incident grant."],
        "verify": "The identity provider shows only the pre-incident scopes for the agent.",
        "rollback": "Re-grant the removed scopes after review.",
        "blast": "Actions requiring the removed scopes fail.",
    },
    "C3_DENY_ALL_EGRESS": {
        "pre": ["Evidence snapshot is verified.", "The forensic vault destination is excluded from the deny rule."],
        "steps": ["Apply a deny-all egress policy to the agent runtime, excepting the forensic vault."],
        "verify": "A test connection to any destination other than the vault is refused.",
        "rollback": "Remove the deny-all egress policy.",
        "blast": "Every network-dependent capability of the agent stops.",
    },
    "C4_TERMINATE_SESSION": {
        "pre": ["Evidence snapshot is verified."],
        "steps": ["End the named session in the agent runtime."],
        "verify": "The session no longer appears in the runtime's active session list.",
        "rollback": "IRREVERSIBLE: a terminated session cannot be resumed; the user starts a new one.",
        "blast": "The user of the session loses in-progress work.",
    },
    "K1_SUSPEND_AGENT": {
        "pre": ["Evidence snapshot is verified."],
        "steps": ["Stop the agent process while retaining its state on disk."],
        "verify": "No new telemetry records are produced by the agent.",
        "rollback": "Start the agent process from the retained state after review.",
        "blast": "The agent is unavailable to all users.",
    },
    "K2_ISOLATE_AGENT_NETWORK_SEGMENT": {
        "pre": ["Evidence snapshot is verified.", "An isolated network segment is available."],
        "steps": ["Move the agent runtime to the isolated network segment with no route to production."],
        "verify": "A route check from the runtime to production networks fails.",
        "rollback": "Move the runtime back to its original segment after review.",
        "blast": "The agent cannot reach any production system.",
    },
    "R1_NOTIFY_DPO": {
        "pre": [],
        "steps": ["Send the Data Protection Officer this plan and the trace report for a GDPR Art. 33 assessment."],
        "verify": "The DPO has acknowledged receipt.",
        "rollback": "Not applicable.",
        "blast": "None.",
    },
    "R2_NOTIFY_CSIRT_LIAISON": {
        "pre": [],
        "steps": ["Send the NIS2 incident liaison this plan and the trace report for an Art. 23 assessment."],
        "verify": "The liaison has acknowledged receipt.",
        "rollback": "Not applicable.",
        "blast": "None.",
    },
}

ORDER_GROUP = {
    "P1_SNAPSHOT_EVIDENCE": 0,
    "P2_ENABLE_ENHANCED_LOGGING": 1,
    "C4_TERMINATE_SESSION": 2,
    "K1_SUSPEND_AGENT": 2,
    "M3_BLOCK_EGRESS_DESTINATION": 3,
    "C3_DENY_ALL_EGRESS": 3,
    "K2_ISOLATE_AGENT_NETWORK_SEGMENT": 3,
    "C1_ROTATE_CREDENTIAL": 4,
    "M2_REVOKE_TOOL": 5,
    "C2_DOWNGRADE_AGENT_SCOPE": 5,
    "M4_QUARANTINE_INPUT_SOURCE": 5,
    "M5_ENFORCE_POLICY_FILTER_BLOCKING": 5,
    "M1_RATE_LIMIT_AGENT": 5,
    "R1_NOTIFY_DPO": 6,
    "R2_NOTIFY_CSIRT_LIAISON": 6,
}

TIERS = {
    "SEV1_CRITICAL": "T1_KILL",
    "SEV2_HIGH": "T2_ISOLATE",
    "SEV3_MEDIUM": "T3_RESTRICT",
    "SEV4_LOW": "T4_MONITOR",
    "SEV5_INFORMATIONAL": "T5_NO_ACTION",
}
PERSONAL_DATA_RE = re.compile(r"personal|pii|gdpr|special.?categor", re.IGNORECASE)


def containment_plan(trace_report: dict, environment: dict, run_id: str) -> dict:
    """ContainmentPlan/v1 built only from the trace report and the client's declared controls."""
    available = set(environment.get("available_controls") or [])
    critical = set(environment.get("business_critical_components") or [])
    upstream_digest = canonical_digest(trace_report)
    plan: dict[str, Any] = {
        "schema_version": "ContainmentPlan/v1",
        "agent_id": CONTAINMENT_AGENT_ID,
        "run_id": run_id,
        "stage_id": "containment_planning",
        "input_digest": canonical_digest({"upstream_report": trace_report, "environment": environment}),
        "upstream_report_digest": upstream_digest,
        "status": "PLAN_READY",
        "incident_class": trace_report.get("primary_class"),
        "upstream_severity": trace_report.get("severity"),
    }
    actions: list[dict] = []
    control_gaps: list[dict] = []
    risks: list[dict] = []
    issues: list[dict] = []

    def add(code: str, target: str | None, refs: list[dict], why: str, mandated_by: str | None = None) -> None:
        if any(a["code"] == code and a["target"] == target for a in actions):
            return
        if code not in available and code not in ("R1_NOTIFY_DPO", "R2_NOTIFY_CSIRT_LIAISON"):
            control_gaps.append(
                {
                    "missing_control": code,
                    "mandated_by": mandated_by or "class",
                    "target": target,
                    "substitute_action_order": None,
                }
            )
            return
        meta, text = CATALOGUE[code], ACTION_TEXT[code]
        actions.append(
            {
                "order": 0,
                "code": code,
                "target": target,
                "disruption_level": meta["level"],
                "disruptive": meta["disruptive"],
                "parallelisable": code.startswith("R"),
                "requires_human_approval": True,
                "requires_escalation": bool(target and target in critical),
                "finding_refs": refs,
                "justification": why[:250],
                "preconditions": text["pre"],
                "operator_steps": text["steps"],
                "verification": text["verify"],
                "rollback": text["rollback"],
                "blast_radius": text["blast"],
            }
        )

    if trace_report.get("status") == "REJECTED_INPUT" or "severity" not in trace_report:
        plan.update(status="REJECTED_INPUT", tier="T4_MONITOR")
        add(
            "P2_ENABLE_ENHANCED_LOGGING",
            None,
            [{"field": "status", "id": None}],
            "No validated analysis exists.",
            "failure mode",
        )
        risks.append(
            {
                "risk": "No validated trace analysis exists, so the incident scope is unknown.",
                "upstream_gap_id": None,
                "recommended_evidence": "resubmit readable telemetry",
            }
        )
        return _finish_plan(plan, actions, control_gaps, risks, issues, trace_report, critical)

    sev = trace_report["severity"]
    tier = TIERS[sev]
    plan["tier"] = tier
    classes = [trace_report["primary_class"], *trace_report.get("secondary_classes", [])]
    sessions = trace_report.get("handoff", {}).get("active_sessions", [])
    primary_ref = [{"field": "primary_class", "id": trace_report["primary_class"]}]
    sev_ref = [{"field": "severity", "id": sev}]

    # Upstream consistency (C4): recompute the class from its own trace.
    if trace_report.get("classification_trace"):
        expected, _, _ = classify(
            {t["rule"]: (t["result"], t["evidence_refs"]) for t in trace_report["classification_trace"]}
        )
        if expected != trace_report["primary_class"]:
            plan["status"] = "UPSTREAM_INCONSISTENT"
            issues.append(
                {
                    "field": "primary_class",
                    "issue": f"classification_trace yields {expected}, report states {trace_report['primary_class']}",
                }
            )

    # Mandatory actions by tier.
    if tier == "T1_KILL":
        add("P1_SNAPSHOT_EVIDENCE", None, sev_ref, f"Tier {tier} requires evidence capture first.", tier)
        add("K1_SUSPEND_AGENT", None, sev_ref, f"Severity {sev} mandates suspending the agent.", tier)
        if "DATA_EXFILTRATION" in classes:
            add(
                "K2_ISOLATE_AGENT_NETWORK_SEGMENT",
                None,
                primary_ref,
                "DATA_EXFILTRATION at tier T1_KILL mandates network isolation.",
                tier,
            )
        add("R2_NOTIFY_CSIRT_LIAISON", None, sev_ref, f"Severity {sev} routes to the NIS2 liaison.", tier)
    elif tier == "T2_ISOLATE":
        add("P1_SNAPSHOT_EVIDENCE", None, sev_ref, f"Tier {tier} requires evidence capture first.", tier)
        for session in sessions:
            add(
                "C4_TERMINATE_SESSION",
                session,
                [{"field": "handoff.active_sessions", "id": session}],
                f"Session {session} has no termination record.",
                tier,
            )
        add("R2_NOTIFY_CSIRT_LIAISON", None, sev_ref, f"Severity {sev} routes to the NIS2 liaison.", tier)
    elif tier == "T3_RESTRICT":
        add("P1_SNAPSHOT_EVIDENCE", None, sev_ref, f"Tier {tier} requires evidence capture first.", tier)
    elif tier == "T4_MONITOR":
        add("P2_ENABLE_ENHANCED_LOGGING", None, sev_ref, f"Tier {tier} requires enhanced logging.", tier)

    # One neutraliser per class, lowest available disruption (C7).
    anomalies = trace_report.get("anomalies", [])
    iocs = trace_report.get("iocs", [])
    for cls in classes:
        candidates = NEUTRALISERS.get(cls)
        if not candidates:
            continue
        cls_ref = [{"field": "primary_class" if cls == classes[0] else "secondary_classes", "id": cls}]
        targets = _targets_for(cls, anomalies, iocs)
        chosen = next((c for c in candidates if c in available), None)
        if chosen is None:
            control_gaps.append(
                {"missing_control": candidates[0], "mandated_by": cls, "target": None, "substitute_action_order": None}
            )
            risks.append(
                {
                    "risk": f"{cls} has no available neutralising control.",
                    "upstream_gap_id": None,
                    "recommended_evidence": f"confirm availability of {', '.join(candidates)}",
                }
            )
            continue
        if chosen in ("M2_REVOKE_TOOL", "M3_BLOCK_EGRESS_DESTINATION", "C1_ROTATE_CREDENTIAL") and targets:
            for target, refs in targets:
                add(chosen, target, refs, f"Neutralises {cls} for {target}.", cls)
        else:
            add(chosen, None, cls_ref, f"Neutralises {cls}.", cls)

    if any(PERSONAL_DATA_RE.search(json.dumps(x)) for x in (anomalies, iocs, trace_report.get("timeline", []))) and (
        {"DATA_EXFILTRATION", "CREDENTIAL_EXPOSURE"} & set(classes)
    ):
        add("R1_NOTIFY_DPO", None, primary_ref, "Personal data is referenced in the cited findings.", "class")

    if trace_report.get("status") == "INSUFFICIENT_EVIDENCE":
        add(
            "P2_ENABLE_ENHANCED_LOGGING",
            None,
            [{"field": "status", "id": "INSUFFICIENT_EVIDENCE"}],
            "Upstream evidence is insufficient.",
            "failure mode",
        )
    for gap in trace_report.get("evidence_gaps", []):
        risks.append(
            {"risk": gap["question"], "upstream_gap_id": gap["gap_id"], "recommended_evidence": gap["missing_artifact"]}
        )

    # Disruptive actions require P1 first even when the tier did not mandate it (C6).
    if any(a["disruptive"] for a in actions) and not any(a["code"] == "P1_SNAPSHOT_EVIDENCE" for a in actions):
        add("P1_SNAPSHOT_EVIDENCE", None, sev_ref, "Disruptive actions require evidence capture first.", "C6")
    return _finish_plan(plan, actions, control_gaps, risks, issues, trace_report, critical)


def _targets_for(cls: str, anomalies: list[dict], iocs: list[dict]) -> list[tuple[str, list[dict]]]:
    out: list[tuple[str, list[dict]]] = []
    for index, ioc in enumerate(iocs):
        ref = [{"field": "iocs", "id": str(index)}]
        if cls == "DATA_EXFILTRATION" and ioc["type"] in ("domain", "ip"):
            out.append((ioc["value"], ref))
        elif cls in ("UNAUTHORIZED_TOOL_USE", "PROMPT_INJECTION_EXECUTED") and ioc["type"] == "tool_name":
            out.append((ioc["value"], ref))
        elif cls == "CREDENTIAL_EXPOSURE" and ioc["type"] == "credential_fingerprint":
            out.append((ioc["value"], ref))
    return out


def _finish_plan(plan, actions, control_gaps, risks, issues, trace_report, critical) -> dict:
    actions.sort(key=lambda a: (ORDER_GROUP[a["code"]], a["code"], a["target"] or ""))
    for order, action in enumerate(actions, start=1):
        action["order"] = order
    for gap in control_gaps:
        gap.pop("target", None)
    escalations = [
        {"action_order": a["order"], "component": a["target"], "reason": "listed in business_critical_components"}
        for a in actions
        if a["requires_escalation"]
    ]
    do_not_do = [
        {
            "prohibition": "Do not delete, restart or redeploy the subject agent before the evidence snapshot is "
            "verified.",
            "reason": "It destroys volatile state.",
            "finding_refs": [],
        },
        {
            "prohibition": "Do not re-run the subject agent against the same inputs on production infrastructure.",
            "reason": "It can repeat the incident and overwrite evidence.",
            "finding_refs": [],
        },
    ]
    destinations = [(i, x) for i, x in enumerate(trace_report.get("iocs", [])) if x["type"] in ("domain", "ip", "url")]
    if destinations:
        do_not_do.append(
            {
                "prohibition": "Do not notify or contact any external party named in the IOCs.",
                "reason": "Contact can alert the recipient and alter remote evidence.",
                "finding_refs": [{"field": "iocs", "id": str(i)} for i, _ in destinations],
            }
        )
    if any(a["code"] == "C1_ROTATE_CREDENTIAL" for a in actions):
        do_not_do.append(
            {
                "prohibition": "Do not rotate a credential while its known exfiltration destination is "
                "still reachable.",
                "reason": "A new credential can be exfiltrated the same way.",
                "finding_refs": [],
            }
        )
    codes = {a["code"] for a in actions}
    plan.setdefault("tier", "T4_MONITOR")
    plan.update(
        actions=actions,
        do_not_do=do_not_do,
        escalations=escalations,
        control_gaps=control_gaps,
        uncontained_risks=risks,
        upstream_issues=issues,
        regulatory_routing={
            "dpo_notification_recommended": "R1_NOTIFY_DPO" in codes,
            "csirt_notification_recommended": "R2_NOTIFY_CSIRT_LIAISON" in codes,
            "basis_refs": [ref for a in actions if a["code"].startswith("R") for ref in a["finding_refs"]],
        },
    )
    plan["self_validation"] = validate_plan(plan, trace_report, critical)
    return plan


COMMAND_SYNTAX_RE = re.compile(r"(\$\(|`|\bsudo\b|\bkubectl\b|\bcurl\b|\brm -|\|\s*sh\b|&&)")


def validate_plan(plan: dict, trace_report: dict, critical: set[str]) -> list[dict]:
    actions = plan["actions"]
    codes = [a["code"] for a in actions]
    v1 = bool(re.fullmatch(r"[0-9a-f]{64}", plan["input_digest"]))
    v2 = plan["status"] == "REJECTED_INPUT" or plan["tier"] == TIERS.get(trace_report.get("severity"), "")
    mandated = {
        "T1_KILL": ["P1_SNAPSHOT_EVIDENCE", "K1_SUSPEND_AGENT", "R2_NOTIFY_CSIRT_LIAISON"],
        "T2_ISOLATE": ["P1_SNAPSHOT_EVIDENCE", "R2_NOTIFY_CSIRT_LIAISON"],
        "T3_RESTRICT": ["P1_SNAPSHOT_EVIDENCE"],
        "T4_MONITOR": ["P2_ENABLE_ENHANCED_LOGGING"],
        "T5_NO_ACTION": [],
    }[plan["tier"]]
    gaps = {g["missing_control"] for g in plan["control_gaps"]}
    v3 = all(code in codes or code in gaps for code in mandated)
    v4 = all(code in CATALOGUE for code in codes)
    v5 = all(a["finding_refs"] for a in actions)
    v6 = not any(a["disruptive"] for a in actions) or codes[0] == "P1_SNAPSHOT_EVIDENCE"
    groups = [ORDER_GROUP[c] for c in codes]
    v7 = groups == sorted(groups)
    classes = [trace_report.get("primary_class"), *trace_report.get("secondary_classes", [])]
    neutralised = {cls for cls in classes if any(c in codes for c in NEUTRALISERS.get(cls, []))}
    risky = " ".join(r["risk"] for r in plan["uncontained_risks"])
    v8 = all(cls in neutralised or cls in risky or cls not in NEUTRALISERS for cls in classes)
    v9 = all(a["requires_escalation"] for a in actions if a["target"] in critical)
    v10 = not has_banned_phrase(plan["actions"]) and not any(
        COMMAND_SYNTAX_RE.search(step) for a in actions for step in a["operator_steps"]
    )
    v11 = all(a["requires_human_approval"] is True for a in actions)
    return [
        {"check": f"V{i}", "passed": bool(v)} for i, v in enumerate([v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11], 1)
    ]
