"""A read-only view of one run folder, for the dashboard and its API.

Nothing in this module writes a file. It reads the run folder (events,
incidents, verdicts, approvals, the audit log) and the policy, and turns them
into plain data for display:

  * Decisions are never taken from decisions.jsonl. Every incident is decided
    again from its events and the current policy, the way ``act`` does (D30),
    so the dashboard shows what ``act`` would do now.
  * The model's verdict is kept in its own part of the data and marked as
    AI-written, next to a decision it does not influence (D1).
  * When any of those files changes, everything is read again.
"""

from __future__ import annotations

import hashlib
import json
import re
import threading
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from aegis import audit
from aegis.approvals import FOLDER as APPROVALS_FOLDER
from aegis.approvals import Approval, load_approval
from aegis.cli import AUDIT_NAME, EVENTS_NAME, INCIDENTS_NAME, LATE, VERDICTS_NAME
from aegis.compare import variant_name
from aegis.contracts.decision import BANDS, ActionDecision, ActionOutcome, Decision
from aegis.contracts.event import ContractError, Event, format_ts, parse_ts
from aegis.contracts.incident import _INCIDENT_ID_RE, Incident, LinkReason
from aegis.contracts.verdict import Verdict
from aegis.decide import decide, latest_verdict
from aegis.evidence import target_key
from aegis.feed import SUPERSEDED_NAME, read_status, read_superseded
from aegis.policy import DEFAULT_POLICY_FILE, Policy, load_policy
from aegis.store import read_events, read_incidents, read_verdicts

LINK_TEXT = {
    LinkReason.SAME_PROCESS: "same process",
    LinkReason.PARENT_PROCESS: "parent or child process",
    LinkReason.SAME_PARENT: "started by the same process",
    LinkReason.SAME_SOURCE_IP: "same source address",
    LinkReason.SAME_ACCOUNT: "same account",
    LinkReason.SAME_RULE: "same rule firing again",
}
ACTION_KINDS = ("approval", "action_refused", "action_started", "action_result")
FEED_SILENT = 90  # seconds without contact before a running feed counts as silent


@dataclass
class Snapshot:
    """Everything the dashboard shows, read at one moment."""

    run_dir: Path
    policy_path: Path
    version: str  # fingerprint of the files this was read from
    events: dict = field(default_factory=dict)  # event id -> Event
    incidents: list = field(default_factory=list)
    verdicts: list = field(default_factory=list)
    policy: Policy | None = None
    audit_state: audit.Verification = audit.Verification(True, 0, audit.GENESIS)
    audit_entries: list = field(default_factory=list)  # (entry dict, verified?)
    approvals: dict = field(default_factory=dict)  # incident id -> Approval
    decisions: dict = field(default_factory=dict)  # incident id -> Decision, decided now
    problems: list = field(default_factory=list)  # what could not be read, in words
    incident_problems: dict = field(default_factory=dict)  # incident id -> why it cannot be decided
    incidents_of: dict = field(default_factory=dict)  # event id -> incident ids holding it
    trail: dict = field(default_factory=dict)  # incident id -> its verified audit entries
    superseded: dict = field(default_factory=dict)  # old incident id -> the incident it grew into
    earlier: dict = field(default_factory=dict)  # current incident id -> the old ids it grew from

    def find(self, wanted: str) -> Incident | None:
        """The incident with this id, or the only one whose id starts with it."""
        wanted = wanted.strip().lower()
        prefix = wanted if wanted.startswith("inc-") else "inc-" + wanted
        if not re.fullmatch(r"inc-[0-9a-f]{4,16}", prefix):
            return None
        matches = [i for i in self.incidents if i.incident_id.startswith(prefix)]
        return matches[0] if len(matches) == 1 else None

    def successor(self, old_id: str) -> str | None:
        """The current incident an old, grown incident id became, if the live feed recorded it."""
        current = {i.incident_id for i in self.incidents}
        seen = set()
        while old_id in self.superseded and old_id not in seen:
            seen.add(old_id)
            old_id = self.superseded[old_id]
        return old_id if seen and old_id in current else None


class RunView:
    """Hands out the current Snapshot, reading the files again only when they change."""

    def __init__(self, run_dir: Path | str, policy_path: Path | str | None = None):
        self.run_dir = Path(run_dir)
        self.policy_path = Path(policy_path) if policy_path else DEFAULT_POLICY_FILE
        self._lock = threading.Lock()
        self._snapshot: Snapshot | None = None

    def current(self) -> Snapshot:
        version = fingerprint(self.run_dir, self.policy_path)
        with self._lock:
            if self._snapshot is None or self._snapshot.version != version:
                for _ in range(3):
                    snap = load_snapshot(self.run_dir, self.policy_path, version)
                    after = fingerprint(self.run_dir, self.policy_path)
                    if after == version:
                        break
                    version = after  # a file changed while it was being read (the live feed): read again
                self._snapshot = snap
            return self._snapshot


def watched_files(run_dir: Path, policy_path: Path) -> list[Path]:
    files = [run_dir / name for name in (EVENTS_NAME, INCIDENTS_NAME, VERDICTS_NAME, AUDIT_NAME, SUPERSEDED_NAME)]
    files.append(policy_path)
    folder = run_dir / APPROVALS_FOLDER
    if folder.is_dir():
        files += sorted(folder.glob("*.json"))
    return files


def fingerprint(run_dir: Path, policy_path: Path) -> str:
    """Changes whenever one of the files the dashboard reads changes."""
    parts = []
    for path in watched_files(run_dir, policy_path):
        try:
            stat = path.stat()
            parts.append(f"{path}|{stat.st_mtime_ns}|{stat.st_size}")
        except OSError:
            parts.append(f"{path}|missing")
    return hashlib.sha256("\n".join(parts).encode("utf-8", "replace")).hexdigest()[:12]


def load_snapshot(run_dir: Path, policy_path: Path, version: str | None = None) -> Snapshot:
    run_dir, policy_path = Path(run_dir), Path(policy_path)
    snap = Snapshot(run_dir, policy_path, version or fingerprint(run_dir, policy_path))
    hint = f"--dir {run_dir}"
    events = _read(snap, read_events, run_dir / EVENTS_NAME, f"run 'python -m aegis ingest <alerts file> {hint}'")
    incidents = _read(snap, read_incidents, run_dir / INCIDENTS_NAME, f"run 'python -m aegis correlate {hint}'")
    verdicts = _read(snap, read_verdicts, run_dir / VERDICTS_NAME, "")
    snap.policy = _read(snap, load_policy, policy_path, "check the --policy path")
    snap.events = {event.event_id: event for event in events or []}
    snap.incidents = incidents or []
    snap.verdicts = verdicts or []
    for incident in snap.incidents:
        for event_id in incident.event_ids:
            snap.incidents_of.setdefault(event_id, []).append(incident.incident_id)
    snap.superseded = read_superseded(run_dir)
    for old_id in snap.superseded:
        now_id = snap.successor(old_id)
        if now_id:
            snap.earlier.setdefault(now_id, []).append(old_id)
    _read_approvals(snap)
    _read_audit(snap)
    _decide_all(snap)
    return snap


def _read(snap: Snapshot, reader, path: Path, hint: str):
    try:
        return reader(path)
    except FileNotFoundError:
        snap.problems.append(f"{path} does not exist yet" + (f" ({hint})" if hint else ""))
    except (OSError, UnicodeError, ContractError) as exc:
        snap.problems.append(f"cannot read {path}: {exc}")
    return None


def _read_approvals(snap: Snapshot) -> None:
    folder = snap.run_dir / APPROVALS_FOLDER
    if not folder.is_dir():
        return
    for path in sorted(folder.glob("*.json")):
        if not _INCIDENT_ID_RE.match(path.stem):
            snap.problems.append(f"{path} is not named after an incident, so it is not read as an approval")
            continue
        try:
            approval = load_approval(snap.run_dir, path.stem)
        except (OSError, UnicodeError, ContractError) as exc:
            snap.problems.append(f"cannot read {path}: {exc}")
            continue
        if approval is not None:
            snap.approvals[approval.incident_id] = approval


def _read_audit(snap: Snapshot) -> None:
    path = snap.run_dir / AUDIT_NAME
    try:
        snap.audit_state = audit.verify(path)
        lines = path.read_text(encoding="utf-8").splitlines() if path.exists() else []
    except (OSError, UnicodeError) as exc:
        snap.audit_state = audit.Verification(False, 0, audit.GENESIS, f"cannot read the log: {exc}")
        snap.problems.append(f"cannot read {path}: {exc}")
        return
    position = 0
    for number, line in enumerate(lines, 1):
        if not line.strip():
            continue
        try:
            entry = json.loads(line)
        except json.JSONDecodeError:
            entry = None
        if not isinstance(entry, dict):
            entry = {"seq": None, "kind": "unreadable", "incident_id": "", "time": "",
                     "data": {"line": number}}
        verified = position < snap.audit_state.entries  # the entries before a break
        snap.audit_entries.append((entry, verified))
        if verified and isinstance(entry.get("incident_id"), str):
            snap.trail.setdefault(entry["incident_id"], []).append(entry)
        position += 1


def _decide_all(snap: Snapshot) -> None:
    if snap.policy is None:
        return
    for incident in snap.incidents:
        missing = [event_id for event_id in incident.event_ids if event_id not in snap.events]
        if missing:
            snap.incident_problems[incident.incident_id] = (
                f"{len(missing)} of this incident's events are not in {EVENTS_NAME} (first: {missing[0]}); "
                "the files come from different runs. Run ingest and correlate again.")
            continue
        events = [snap.events[event_id] for event_id in incident.event_ids]
        try:
            snap.decisions[incident.incident_id] = decide(
                incident, events, snap.policy, latest_verdict(snap.verdicts, incident.incident_id))
        except (ContractError, KeyError, ValueError) as exc:
            snap.incident_problems[incident.incident_id] = f"cannot decide this incident: {exc}"


# --------------------------------------------------------------------------
# Plain data for the pages and the JSON API
# --------------------------------------------------------------------------

def header(snap: Snapshot, now: datetime | None = None) -> dict:
    state = snap.audit_state
    feed = feed_view(snap.run_dir, now)
    problems = list(snap.problems)
    if feed:
        problems += [f"Live feed gap ({gap.get('time', '')[:19]} UTC): {gap.get('reason')}" for gap in feed["gaps"]]
        if feed["issue_count"]:
            latest = feed["issues"][-1]["text"] if feed["issues"] else ""
            problems.append(f"Live feed: {feed['issue_count']} alert(s) or lines could not be read; latest: {latest}")
    return {
        "version": snap.version,
        "run_dir": str(snap.run_dir),
        "policy": {"id": snap.policy.id if snap.policy else None, "file": str(snap.policy_path)},
        "audit": {"ok": state.ok, "entries": state.entries, "last_hash": state.last_hash,
                  "problem": state.problem, "lines": len(snap.audit_entries)},
        "feed": feed,
        "problems": problems,
    }


def feed_view(run_dir: Path, now: datetime | None = None) -> dict | None:
    """The live feed's state, read fresh on every request (it changes every few seconds)."""
    state = read_status(run_dir)
    if state is None:
        return None
    now = now or datetime.now(timezone.utc)
    try:
        age = int((now - parse_ts(state["last_contact"])).total_seconds())
    except (KeyError, TypeError, ContractError):
        age = None
    status = state.get("status")
    if status == "connected":
        shown = "connected" if age is not None and age <= FEED_SILENT else "silent"
    elif status in ("connecting", "disconnected"):
        shown = "reconnecting"
    elif status == "stopped":
        shown = "stopped"
    else:
        shown = "unknown"
    gaps = state.get("gaps") if isinstance(state.get("gaps"), list) else []
    issues = state.get("issues") if isinstance(state.get("issues"), list) else []
    return {
        "state": shown, "status": status, "manager": state.get("manager"), "message": state.get("message") or "",
        "last_contact": state.get("last_contact"), "age_seconds": age,
        "alerts": state.get("alerts", 0), "events_added": state.get("events_added", 0),
        "gaps": [g for g in gaps if isinstance(g, dict)],
        "issues": [i for i in issues if isinstance(i, dict)],
        "issue_count": int(state.get("issue_count") or 0),
    }


def overview(snap: Snapshot, min_band: str | None = None, host: str | None = None) -> dict:
    rows = []
    hosts: Counter = Counter()
    for incident in snap.incidents:
        mode = _host_mode(snap, incident)
        hosts[(incident.host.agent_id, incident.host.name, mode)] += 1
        decision = snap.decisions.get(incident.incident_id)
        if host and incident.host.agent_id != host:
            continue
        if min_band and (decision is None or BANDS.index(decision.risk.band) < BANDS.index(min_band)):
            continue
        verdict = latest_verdict(snap.verdicts, incident.incident_id)
        rows.append({
            "incident_id": incident.incident_id,
            "host": {"agent_id": incident.host.agent_id, "name": incident.host.name},
            "host_mode": mode,
            "max_level": incident.max_level,
            "event_count": len(incident.event_ids),
            "first_seen": format_ts(incident.first_seen),
            "last_seen": format_ts(incident.last_seen),
            "duration_seconds": int(incident.duration.total_seconds()),
            "title": incident.title,
            "risk": {"score": decision.risk.score, "band": decision.risk.band} if decision else None,
            "actions": [_action_brief(snap, incident.incident_id, action) for action in decision.actions]
            if decision else [],
            "problem": snap.incident_problems.get(incident.incident_id),
            "ai": {"ai_written": True, "label": verdict.label.value if verdict else None},
        })
    rows.sort(key=lambda row: row["first_seen"], reverse=True)  # newest first among equals
    rows.sort(key=lambda row: (-(row["risk"]["score"] if row["risk"] else -1), -row["max_level"]))
    bands = Counter(d.risk.band for d in snap.decisions.values())
    statuses = Counter(_status(snap, incident_id, action)
                       for incident_id, decision in snap.decisions.items() for action in decision.actions)
    return {
        "header": header(snap),
        "filters": {"min_band": min_band, "host": host},
        "hosts": [{"agent_id": a, "name": n, "mode": m, "incidents": c} for (a, n, m), c in sorted(hosts.items())],
        "counts": {
            "incidents": len(snap.incidents),
            "shown": len(rows),
            "events": len(snap.events),
            "verdicts": len(snap.verdicts),
            "bands": {band: bands[band] for band in reversed(BANDS)},
            "waiting_for_approval": statuses["waiting"],
            "approved": statuses["approved"],
            "done": statuses["done"],
            "failed": statuses["failed"],
        },
        "incidents": rows,
    }


def incident_view(snap: Snapshot, incident: Incident) -> dict:
    incident_id = incident.incident_id
    label_of = {event_id: f"E{n}" for n, event_id in enumerate(incident.event_ids, 1)}
    links_of: dict[str, list] = defaultdict(list)
    for link in incident.links:
        links_of[link.event_id].append({
            "reason": link.reason.value, "text": LINK_TEXT[link.reason], "value": link.value,
            "linked_to": link.linked_to, "linked_label": label_of.get(link.linked_to, ""),
        })
    events = [snap.events[e] for e in incident.event_ids if e in snap.events]
    delayed = [e.delay for e in events if e.delay is not None and e.delay >= LATE]
    reasons: dict[str, Counter] = defaultdict(Counter)
    for link in incident.links:
        reasons[link.reason.value][link.value] += 1

    verdicts = sorted((v for v in snap.verdicts if v.incident_id == incident_id),
                      key=lambda v: (v.created_at, v.run.attempt))
    latest = latest_verdict(verdicts, incident_id)
    decision = snap.decisions.get(incident_id)
    trail = snap.trail.get(incident_id, [])
    decided = [e for e in trail if e.get("kind") == "decision"]

    summary = incident.to_dict()
    summary.pop("links")
    summary["duration_seconds"] = int(incident.duration.total_seconds())
    summary["host_mode"] = _host_mode(snap, incident)
    return {
        "header": header(snap),
        "incident": summary,
        "problem": snap.incident_problems.get(incident_id),
        "ingest": {
            "event_count": len(incident.event_ids),
            "events_found": len(events),
            "rules": summary["rules"],
            "delayed": {"count": len(delayed),
                        "longest_seconds": int(max(delayed).total_seconds()) if delayed else 0,
                        "threshold_minutes": int(LATE.total_seconds() // 60)},
        },
        "correlate": {
            "links": len(incident.links),
            "reasons": [{"reason": reason.value, "text": LINK_TEXT[reason],
                         "count": sum(reasons[reason.value].values()),
                         "values": [[value, count] for value, count in reasons[reason.value].most_common(6)],
                         "more_values": max(0, len(reasons[reason.value]) - 6)}
                        for reason in LinkReason if reason.value in reasons],
        },
        "investigate": {
            "ai_written": True,
            "verdict": _verdict_data(snap, latest, label_of) if latest else None,
            "answers": [{"model": variant_name(v.run), "attempt": v.run.attempt, "label": v.label.value,
                         "confidence": v.confidence.value, "created_at": format_ts(v.created_at)}
                        for v in verdicts],
        },
        "decide": _decision_data(snap, incident, decision, label_of) if decision else None,
        "act": {
            "approval": _approval_data(snap, incident_id),
            "trail": [audit_entry(e, True) for e in history(snap, incident_id) if e.get("kind") in ACTION_KINDS],
            "decisions_recorded": len(decided),
            "last_decided": decided[-1].get("time") if decided else None,
            "earlier_versions": len(snap.earlier.get(incident_id, [])),
            "earlier_approvals": [dict(_approval_data(snap, old_id), incident_id=old_id)
                                  for old_id in snap.earlier.get(incident_id, []) if old_id in snap.approvals],
        },
        "events": [_event_data(event, label_of, links_of) for event in events],
    }


def event_view(snap: Snapshot, event: Event) -> dict:
    data = event.to_dict()
    data["delay_seconds"] = int(event.delay.total_seconds()) if event.delay is not None else None
    return {"header": header(snap), "event": data, "incidents": snap.incidents_of.get(event.event_id, [])}


def audit_view(snap: Snapshot, last: int | None = None) -> dict:
    known = {incident.incident_id for incident in snap.incidents}
    entries = [dict(audit_entry(entry, verified), incident_known=entry.get("incident_id") in known)
               for entry, verified in snap.audit_entries]
    entries.reverse()  # newest first
    shown = entries if last is None else entries[:last]
    return {"header": header(snap), "total": len(entries), "entries": shown}


def audit_entry(entry: dict, verified: bool) -> dict:
    data = entry.get("data") if isinstance(entry.get("data"), dict) else {}
    kind = entry.get("kind")
    if kind == "decision":
        summary = f"risk {data.get('risk')} {data.get('band')}, {len(data.get('actions') or [])} candidate actions"
    elif kind == "approval":
        summary = f"{data.get('action')} {data.get('target')} approved by {data.get('approved_by')}"
    elif kind == "action_result":
        summary = (f"{data.get('action')} {data.get('target')}: {'done' if data.get('ok') else 'FAILED'}"
                   f" - {data.get('message')}")
    elif kind == "unreadable":
        summary = f"line {data.get('line')} is not a readable entry"
    else:
        summary = f"{data.get('action')} {data.get('target')}"
    return {"seq": entry.get("seq"), "time": entry.get("time", ""), "kind": kind,
            "incident_id": entry.get("incident_id", ""), "summary": summary, "data": data,
            "hash": entry.get("hash", ""), "verified": verified}


def _host_mode(snap: Snapshot, incident: Incident) -> str:
    decision = snap.decisions.get(incident.incident_id)
    if decision is not None:
        return decision.host_mode
    return snap.policy.host_mode(incident.host)[0] if snap.policy else "advice"


def _refs(snap: Snapshot, event_ids, label_of: dict) -> list[dict]:
    return [{"event_id": e, "label": label_of.get(e, ""), "known": e in snap.events} for e in event_ids]


def history(snap: Snapshot, incident_id: str) -> list[dict]:
    """Verified audit entries for this incident and for the earlier versions it grew from.

    What was done stays done when an incident grows; an approval does not carry
    over (it was for different evidence), and the pages say so.
    """
    entries = list(snap.trail.get(incident_id, []))
    for old_id in snap.earlier.get(incident_id, []):
        entries += snap.trail.get(old_id, [])
    return sorted(entries, key=lambda e: e.get("seq") or 0)


def _results(snap: Snapshot, incident_id: str, action: str, target: str) -> list[dict]:
    key = (action, target_key(action, target))
    return [e for e in history(snap, incident_id) if e.get("kind") == "action_result"
            and isinstance(e.get("data"), dict)
            and (e["data"].get("action"), target_key(action, str(e["data"].get("target", "")))) == key]


def _approved(snap: Snapshot, incident_id: str, action: str, target: str) -> dict | None:
    approval: Approval | None = snap.approvals.get(incident_id)
    if approval is None:
        return None
    for item in approval.actions:
        if (item.action, target_key(item.action, item.target)) == (action, target_key(action, target)):
            counts = snap.policy is not None and approval.covers(action, target, snap.policy.id)
            return {"by": item.approved_by, "at": item.approved_at, "policy_id": approval.policy_id,
                    "counts": counts}
    return None


def _status(snap: Snapshot, incident_id: str, action: ActionDecision) -> str:
    """What has happened to this action: done / failed / approved / waiting / denied / allowed."""
    results = _results(snap, incident_id, action.action, action.target)
    if results:
        return "done" if results[-1]["data"].get("ok") else "failed"
    if action.outcome is ActionOutcome.DENY:
        return "denied"
    if action.outcome is ActionOutcome.NEEDS_APPROVAL:
        approved = _approved(snap, incident_id, action.action, action.target)
        return "approved" if approved and approved["counts"] else "waiting"
    return "allowed"


def _action_brief(snap: Snapshot, incident_id: str, action: ActionDecision) -> dict:
    return {"action": action.action, "target": action.target, "outcome": action.outcome.value,
            "status": _status(snap, incident_id, action)}


def _decision_data(snap: Snapshot, incident: Incident, decision: Decision, label_of: dict) -> dict:
    risk = decision.risk
    return {
        "computed": "now, from the events and the current policy",
        "policy_id": decision.policy_id,
        "host_mode": decision.host_mode,
        "host_reason": snap.policy.host_mode(incident.host)[1] if snap.policy else "",
        "risk": {"score": risk.score, "band": risk.band,
                 "factors": [{"id": f.id, "points": f.points, "reason": f.reason,
                              "evidence": _refs(snap, f.evidence, label_of)} for f in risk.factors]},
        "actions": [{
            "action": a.action, "target": a.target, "outcome": a.outcome.value,
            "source": a.source, "reasons": list(a.reasons), "evidence": _refs(snap, a.evidence, label_of),
            "status": _status(snap, incident.incident_id, a),
            "approved": _approved(snap, incident.incident_id, a.action, a.target),
            "results": [audit_entry(e, True) for e in _results(snap, incident.incident_id, a.action, a.target)],
        } for a in decision.actions],
        "ai": {"ai_written": True, "model_label": decision.model_label, "model_run": decision.model_run},
    }


def _approval_data(snap: Snapshot, incident_id: str) -> dict | None:
    approval = snap.approvals.get(incident_id)
    if approval is None:
        return None
    current = snap.policy.id if snap.policy else None
    return {"policy_id": approval.policy_id, "current_policy": current,
            "counts": approval.policy_id == current,
            "actions": [{"action": a.action, "target": a.target, "by": a.approved_by, "at": a.approved_at}
                        for a in approval.actions]}


def _verdict_data(snap: Snapshot, verdict: Verdict, label_of: dict) -> dict:
    run = verdict.run
    return {
        "ai_written": True,
        "model": variant_name(run),
        "attempt": run.attempt,
        "created_at": format_ts(verdict.created_at),
        "replayed": run.replayed,
        "duration_ms": run.duration_ms,
        "knowledge": run.knowledge,
        "notes_shown": list(verdict.notes_shown),
        "label": verdict.label.value,
        "confidence": verdict.confidence.value,
        "summary": verdict.summary,
        "reasoning": {
            "what_happened": verdict.reasoning.what_happened,
            "started_by": verdict.reasoning.started_by,
            "innocent_explanation": verdict.reasoning.innocent_explanation,
            "attack_explanation": verdict.reasoning.attack_explanation,
            "against_innocent": verdict.reasoning.against_innocent,
        },
        "findings": [{"claim": f.claim, "evidence": _refs(snap, f.evidence, label_of)} for f in verdict.findings],
        "technique_ids": list(verdict.technique_ids),
        "proposed_actions": [{"action": a.action, "target": a.target, "reason": a.reason,
                              "evidence": _refs(snap, a.evidence, label_of)} for a in verdict.proposed_actions],
        "rejected": [{"kind": r.kind, "text": r.text, "reason": r.reason} for r in verdict.rejected],
    }


def _event_data(event: Event, label_of: dict, links_of: dict) -> dict[str, Any]:
    data = event.to_dict()
    data["label"] = label_of.get(event.event_id, "")
    data["links"] = links_of.get(event.event_id, [])
    data["delay_seconds"] = int(event.delay.total_seconds()) if event.delay is not None else None
    return data
