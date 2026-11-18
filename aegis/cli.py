"""Command line entry point:  python -m aegis <command>"""

from __future__ import annotations

import argparse
import os
import sys
import textwrap
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path

from aegis import __version__, doctor
from aegis import compare as comparing
from aegis.contracts.event import ContractError, Event, format_ts
from aegis.contracts.incident import Incident, LinkReason
from aegis.contracts.verdict import Verdict
from aegis.correlate import CorrelationConfig, CorrelationResult, correlate
from aegis.evidence import EvidencePack, EvidenceStore, target_key
from aegis.ingest.wazuh import IngestResult, ingest_file
from aegis import audit
from aegis.approvals import Approved, add_approval, approval_path, load_approval
from aegis.contracts.decision import ActionOutcome
from aegis.decide import decide, latest_verdict
from aegis.execute import GateExecutor
from aegis.knowledge import DEFAULT_NOTES_FILE, load_notes
from aegis.policy import DEFAULT_POLICY_FILE, load_policy
from aegis import agent
from aegis.investigate import (
    DEFAULT_NUM_CTX,
    InvestigationError,
    investigate,
    pack_for_model,
    parts_for_model,
)
from aegis.llm import default_model
from aegis.store import (
    read_events,
    read_incidents,
    read_verdicts,
    save_decisions,
    save_verdict,
    write_events,
    write_incidents,
)

# Output stays plain ASCII so it prints correctly in any Windows console.

# An event that reaches Wazuh this long after it happened counts as delayed.
LATE = timedelta(minutes=10)

# Every command reads and writes inside one run folder ("runs" unless --dir says
# otherwise), so separate data sets can be kept side by side.
RUN_DIR = Path("runs")
EVENTS_NAME = "events.jsonl"
INCIDENTS_NAME = "incidents.jsonl"
VERDICTS_NAME = "verdicts.jsonl"
RECORDINGS_NAME = "recordings"
LABELS_NAME = "labels.json"
DECISIONS_NAME = "decisions.jsonl"
AUDIT_NAME = "audit.jsonl"
DIR_HELP = "run folder holding events, incidents and verdicts (default: runs)"
LIST_LIMIT = 25

_LINK_TEXT = {
    LinkReason.SAME_PROCESS: "same process as",
    LinkReason.PARENT_PROCESS: "parent / child process of",
    LinkReason.SAME_PARENT: "started by the same process as",
    LinkReason.SAME_SOURCE_IP: "same source address {value} as",
    LinkReason.SAME_ACCOUNT: "same account {value} as",
    LinkReason.SAME_RULE: "same rule {value} as",
}


def main(argv: list[str] | None = None, *, executor_factory=None) -> int:
    """``executor_factory(policy)`` replaces how ``act`` reaches the lab VM (the safety probe uses it)."""
    parser = argparse.ArgumentParser(
        prog="aegis",
        description="Aegis: evidence-driven investigation and controlled response.",
    )
    parser.add_argument("--version", action="version", version=f"aegis {__version__}")
    commands = parser.add_subparsers(dest="command", required=True)

    commands.add_parser("doctor", help="check that this machine is ready")

    ingest = commands.add_parser(
        "ingest", help="normalize a Wazuh alert export into Aegis events"
    )
    ingest.add_argument("alerts", type=Path, help="Wazuh alerts file (JSON lines, array or indexer export)")
    ingest.add_argument("--dir", type=Path, default=RUN_DIR, help=DIR_HELP)
    ingest.add_argument(
        "--out", type=Path, default=None,
        help="where to write normalized events (default: events.jsonl in the run folder)",
    )
    ingest.add_argument(
        "--min-level",
        type=int,
        default=0,
        help="ignore alerts below this Wazuh rule level (default: 0, keep all)",
    )

    corr = commands.add_parser("correlate", help="group events into incidents")
    corr.add_argument(
        "events", type=Path, nargs="?", default=None,
        help="events file from 'ingest' (default: events.jsonl in the run folder)",
    )
    corr.add_argument("--dir", type=Path, default=RUN_DIR, help=DIR_HELP)
    corr.add_argument(
        "--out", type=Path, default=None,
        help="where to write incidents (default: incidents.jsonl in the run folder)",
    )
    corr.add_argument(
        "--window", type=float, default=30,
        help="minutes within which related events are joined (default: 30)",
    )
    corr.add_argument(
        "--min-level", type=int, default=7,
        help="list incidents at or above this level (default: 7; 0 lists all)",
    )

    show = commands.add_parser("show", help="show one incident with its timeline")
    show.add_argument("incident", help="incident id, or the first few characters of one")
    show.add_argument("--dir", type=Path, default=RUN_DIR, help=DIR_HELP)
    show.add_argument("--incidents", type=Path, default=None)
    show.add_argument("--events", type=Path, default=None)

    inv = commands.add_parser("investigate", help="ask the AI investigator about an incident")
    inv.add_argument("incident", nargs="?", help="incident id, or the first few characters of one")
    inv.add_argument("--all", action="store_true", help="investigate every incident at or above --min-level")
    inv.add_argument("--min-level", type=int, default=7, help="with --all: lowest level to investigate (default: 7)")
    inv.add_argument("--model", default=None, help="Ollama model to use (default: qwen3:4b, or AEGIS_MODEL)")
    inv.add_argument("--think", action="store_true",
                     help="let the model think before answering (much slower; a small model may never finish)")
    inv.add_argument("--agent", action="store_true",
                     help="agent mode: the model opens the evidence itself, one read-only tool at a time")
    inv.add_argument("--replay", action="store_true", help="reuse the recorded answer instead of calling the model")
    inv.add_argument("--repeat", type=int, default=1, help="ask the same question this many times (default: 1)")
    inv.add_argument("--knowledge", type=Path, default=None,
                     help="operator notes file (default: knowledge/notes.json in the project)")
    inv.add_argument("--no-knowledge", action="store_true", help="give the model no operator notes at all")
    inv.add_argument("--show-prompt", action="store_true", help="print the evidence the model would be given, and stop")
    inv.add_argument("--timeout", type=float, default=300, help="seconds to wait for the model (default: 300)")
    inv.add_argument("--num-ctx", type=int, default=DEFAULT_NUM_CTX, help=f"model context window in tokens (default: {DEFAULT_NUM_CTX})")
    inv.add_argument("--dir", type=Path, default=RUN_DIR, help=DIR_HELP)
    inv.add_argument("--incidents", type=Path, default=None)
    inv.add_argument("--events", type=Path, default=None)
    inv.add_argument("--out", type=Path, default=None, help="verdicts file (default: verdicts.jsonl in the run folder)")
    inv.add_argument("--recordings", type=Path, default=None)

    comp = commands.add_parser("compare", help="line up saved verdicts by model setup, and score them")
    comp.add_argument("--dir", type=Path, default=RUN_DIR, help=DIR_HELP)
    comp.add_argument("--labels", type=Path, default=None,
                      help="JSON file saying what each incident really was (default: labels.json in the run folder)")
    comp.add_argument("--expect", choices=comparing.EXPECTED_VALUES, default=None,
                      help="what every incident without a label really was")

    dec = commands.add_parser("decide", help="score an incident's risk and decide each action by policy")
    dec.add_argument("incident", nargs="?", help="incident id, or the first few characters of one")
    dec.add_argument("--all", action="store_true", help="decide every incident at or above --min-level")
    dec.add_argument("--min-level", type=int, default=0, help="with --all: lowest rule level (default: 0, all)")
    dec.add_argument("--policy", type=Path, default=None, help="policy file (default: policy/policy.json)")
    dec.add_argument("--no-model", action="store_true", help="ignore saved verdicts and the model's proposals")
    dec.add_argument("--dir", type=Path, default=RUN_DIR, help=DIR_HELP)

    appr = commands.add_parser("approve", help="approve one action for one incident (a human's sign-off)")
    appr.add_argument("incident", help="incident id, or the first few characters of one")
    appr.add_argument("--action", required=True, help="the action, e.g. lock_account")
    appr.add_argument("--target", required=True, help="its target, e.g. svc_backup")
    appr.add_argument("--by", required=True, help="who approves (your name)")
    appr.add_argument("--policy", type=Path, default=None)
    appr.add_argument("--dir", type=Path, default=RUN_DIR, help=DIR_HELP)

    act = commands.add_parser("act", help="carry out the approved actions of an incident on the lab host")
    act.add_argument("incident", help="incident id, or the first few characters of one")
    act.add_argument("--dry-run", action="store_true", help="show what would run, and run nothing")
    act.add_argument("--policy", type=Path, default=None)
    act.add_argument("--dir", type=Path, default=RUN_DIR, help=DIR_HELP)

    aud = commands.add_parser("audit", help="check the audit log's hash chain and show its last entries")
    aud.add_argument("--last", type=int, default=10, help="how many entries to show (default: 10)")
    aud.add_argument("--dir", type=Path, default=RUN_DIR, help=DIR_HELP)

    srv = commands.add_parser("serve", help="read-only dashboard on http://127.0.0.1 (cannot approve or act)")
    srv.add_argument("--dir", type=Path, default=RUN_DIR, help=DIR_HELP)
    srv.add_argument("--port", type=int, default=8765, help="port on 127.0.0.1 (default: 8765)")
    srv.add_argument("--policy", type=Path, default=None, help="policy file (default: policy/policy.json)")

    wat = commands.add_parser("watch", help="pull new alerts from the Wazuh manager as they happen (read-only feed)")
    wat.add_argument("--dir", type=Path, default=RUN_DIR / "live",
                     help="run folder for the live data (default: runs/live)")
    wat.add_argument("--manager", default="192.168.56.105", help="the Wazuh manager's address (default: 192.168.56.105)")
    wat.add_argument("--user", default="aegis-feed", help="account on the manager (default: aegis-feed)")
    wat.add_argument("--key", default="~/.ssh/aegis_feed", help="SSH key for that account (default: ~/.ssh/aegis_feed)")
    wat.add_argument("--from-start", action="store_true",
                     help="first run only: read today's alerts from the beginning instead of from now")
    wat.add_argument("--once", action="store_true", help="catch up with the manager, then stop")
    wat.add_argument("--min-level", type=int, default=0, help="ignore alerts below this rule level (default: 0)")
    wat.add_argument("--window", type=float, default=30, help="correlation window in minutes (default: 30)")

    ev = commands.add_parser("evaluate", help="score Aegis on labelled cases and run the safety probe")
    ev.add_argument("--cases", type=Path, default=None, help="case folder (default: data/eval/cases)")
    ev.add_argument("--no-build", action="store_true", help="use the cases as they are; do not rebuild them first")
    ev.add_argument("--out", type=Path, default=RUN_DIR / "eval", help="where results go (default: runs/eval)")
    ev.add_argument("--policy", type=Path, default=None, help="policy file (default: policy/policy.json)")
    ev.add_argument("--investigate", action="store_true",
                    help="ask the model about chosen incidents that have no verdict yet (needs Ollama)")
    ev.add_argument("--model", default=None, help="with --investigate: Ollama model (default: qwen3:4b)")
    ev.add_argument("--repeat", type=int, default=3, help="with --investigate: answers per incident (default: 3)")
    ev.add_argument("--no-knowledge", action="store_true", help="with --investigate: no operator notes")
    ev.add_argument("--agent", action="store_true",
                    help="with --investigate: ask in agent mode (the model opens the evidence one tool at a time)")

    exp = commands.add_parser("export", help="write a static copy of the dashboard (plain files, no server)")
    exp.add_argument("--dir", type=Path, default=RUN_DIR, help=DIR_HELP)
    exp.add_argument("--out", type=Path, required=True, help="folder for the pages (created if missing)")
    exp.add_argument("--label", default=None, help="what the pages call the run folder (default: its name)")
    exp.add_argument("--policy", type=Path, default=None, help="policy file (default: policy/policy.json)")

    dem = commands.add_parser("demo", help="build the public demo site from the synthetic sample only")
    dem.add_argument("--out", type=Path, default=Path("site"), help="folder for the site (default: site)")
    dem.add_argument("--policy", type=Path, default=None, help="policy file (default: policy/policy.json)")

    args = parser.parse_args(argv)
    if args.command == "doctor":
        return _doctor()
    if args.command == "evaluate":
        return _evaluate(args)
    if args.command == "serve":
        return _serve(args)
    if args.command == "watch":
        return _watch(args)
    if args.command == "export":
        return _export(args)
    if args.command == "demo":
        return _demo(args)
    run_dir: Path = args.dir
    if args.command == "decide":
        return _decide(args)
    if args.command == "approve":
        return _approve(args)
    if args.command == "act":
        return _act(args, executor_factory or make_executor)
    if args.command == "audit":
        return _audit(args.dir, args.last)
    if args.command == "compare":
        return _compare(run_dir, args.labels, args.expect)
    if args.command == "ingest":
        return _ingest(args.alerts, args.out or run_dir / EVENTS_NAME, args.min_level)
    if args.command == "correlate":
        return _correlate(
            args.events or run_dir / EVENTS_NAME, args.out or run_dir / INCIDENTS_NAME,
            args.window, args.min_level, run_dir,
        )
    args.incidents = args.incidents or run_dir / INCIDENTS_NAME
    args.events = args.events or run_dir / EVENTS_NAME
    if args.command == "investigate":
        args.out = args.out or run_dir / VERDICTS_NAME
        args.recordings = args.recordings or run_dir / RECORDINGS_NAME
        return _investigate(args)
    return _show(args.incident, args.incidents, args.events)


def _doctor() -> int:
    checks = doctor.run_checks()
    for check in checks:
        print(f"[{check.status:<4}] {check.message}")
    return 1 if any(check.status == doctor.FAIL for check in checks) else 0


def _ingest(alerts: Path, out: Path, min_level: int) -> int:
    try:
        result = ingest_file(alerts, min_level=min_level)
    except FileNotFoundError:
        print(f"error: file not found: {alerts}", file=sys.stderr)
        return 2
    except (OSError, UnicodeError) as exc:
        print(f"error: cannot read {alerts}: {exc}", file=sys.stderr)
        return 2
    try:
        write_events(out, result.events)
    except (OSError, ContractError) as exc:
        print(f"error: cannot write {out}: {exc}", file=sys.stderr)
        return 2
    print(_summary(alerts, out, result))
    return 0


def _summary(alerts: Path, out: Path, result: IngestResult) -> str:
    events = result.events
    lines = [
        f"Read      {alerts}",
        f"Alerts    {result.seen} found, {len(events)} normalized, "
        f"{len(result.issues)} rejected, {result.duplicates} duplicate, "
        f"{result.below_min_level} below min level",
        f"Wrote     {out}",
    ]
    if events:
        lines.append(f"Period    {_ts(events[0])}  to  {_ts(events[-1])}  (UTC, when it happened)")
        late = [e.delay for e in events if e.delay is not None and e.delay >= LATE]
        if late:
            lines.append(
                f"Delayed   {len(late)} of {len(events)} events reached Wazuh more than "
                f"{int(LATE.total_seconds() // 60)} min after they happened "
                f"(longest delay {_duration(max(late))})"
            )
        lines += _table("Hosts", Counter(f"{e.host.name} (agent {e.host.agent_id})" for e in events))
        lines += _table("Categories", Counter(e.category.value for e in events))
        lines += _table(
            "Top rules",
            Counter(f"{e.rule.id:<6}  L{e.rule.level:<2}  {e.rule.description}" for e in events),
            limit=8,
        )
        lines.append("")
        lines.append("Highest-level events")
        ranked = sorted(events, key=lambda e: (-e.rule.level, e.timestamp))[:5]
        for event in ranked:
            lines.append(
                f"  {event.event_id}  {_ts(event)}  L{event.rule.level:<2}  "
                f"{event.host.name}  {event.rule.description}"
            )
    if result.issues:
        lines.append("")
        lines.append("Rejected alerts (nothing is dropped silently)")
        for issue in result.issues[:10]:
            lines.append(f"  {issue.where}: {issue.reason}")
        if len(result.issues) > 10:
            lines.append(f"  ... and {len(result.issues) - 10} more")
    return "\n".join(_ascii(line) for line in lines)


def _load(reader, path: Path, hint: str):
    """Read a pipeline file, or print a clean error and return None."""
    try:
        return reader(path)
    except FileNotFoundError:
        print(f"error: file not found: {path}  ({hint})", file=sys.stderr)
    except (OSError, UnicodeError, ContractError) as exc:
        print(f"error: cannot read {path}: {exc}", file=sys.stderr)
    return None


def _correlate(events_path: Path, out: Path, window_minutes: float, min_level: int, run_dir: Path = RUN_DIR) -> int:
    if window_minutes <= 0:
        print("error: --window must be greater than 0", file=sys.stderr)
        return 2
    events = _load(read_events, events_path, "run 'python -m aegis ingest <alerts file>' first")
    if events is None:
        return 2
    result = correlate(events, CorrelationConfig(window=timedelta(minutes=window_minutes)))
    try:
        write_incidents(out, result.incidents)
    except OSError as exc:
        print(f"error: cannot write {out}: {exc}", file=sys.stderr)
        return 2
    print(_correlation_summary(events_path, out, result, window_minutes, min_level, run_dir))
    return 0


def _correlation_summary(
    events_path: Path, out: Path, result: CorrelationResult, window_minutes: float, min_level: int,
    run_dir: Path = RUN_DIR,
) -> str:
    incidents = result.incidents
    grouped = sum(len(incident.event_ids) for incident in incidents)
    listed = [incident for incident in incidents if incident.max_level >= min_level]
    lines = [
        f"Read      {events_path}  ({result.events_in} events)",
        f"Posture   {len(result.posture_event_ids)} configuration / vulnerability findings set aside",
        f"Incidents {len(incidents)} from {grouped} events  (window {window_minutes:g} min)",
        f"Wrote     {out}",
    ]
    if result.duplicates:
        lines.insert(2, f"Skipped   {result.duplicates} duplicate events")
    lines.append("")
    if min_level > 0:
        lines.append(f"Incidents at level {min_level} or above: {len(listed)}  (most severe first)")
    else:
        lines.append(f"All incidents: {len(listed)}  (most severe first)")
    for incident in listed[:LIST_LIMIT]:
        lines.append(
            f"  {incident.incident_id}  L{incident.max_level:<2}  {len(incident.event_ids):>3} ev  "
            f"{incident.first_seen:%Y-%m-%d %H:%M}  {_duration(incident.duration):>10}  "
            f"{incident.host.name}  {_clip(incident.title, 70)}"
        )
    if len(listed) > LIST_LIMIT:
        lines.append(f"  ... and {len(listed) - LIST_LIMIT} more in {out}")
    below = len(incidents) - len(listed)
    if below:
        lines.append(f"Below level {min_level}: {below} incidents  (add --min-level 0 to list them)")
    if listed:
        lines.append("")
        extra = "" if run_dir == RUN_DIR else f" --dir {run_dir}"
        lines.append(f"Look inside one:  python -m aegis show {listed[0].incident_id[:8]}{extra}")
    return "\n".join(_ascii(line) for line in lines)


def _show(wanted: str, incidents_path: Path, events_path: Path) -> int:
    incidents = _load(read_incidents, incidents_path, "run 'python -m aegis correlate' first")
    if incidents is None:
        return 2
    events = _load(read_events, events_path, "run 'python -m aegis ingest <alerts file>' first")
    if events is None:
        return 2
    incident = _find_incident(incidents, wanted, incidents_path)
    by_id = {event.event_id: event for event in events}
    if incident is None or not _events_present(incident, by_id, events_path):
        return 2
    print(_incident_view(incident, by_id))
    return 0


def _find_incident(incidents: list[Incident], wanted: str, incidents_path: Path) -> Incident | None:
    """The one incident whose id starts with ``wanted``; prints an error otherwise."""
    wanted = wanted.strip().lower()
    prefix = wanted if wanted.startswith("inc-") else "inc-" + wanted
    matches = [incident for incident in incidents if incident.incident_id.startswith(prefix)]
    if not matches:
        print(f"error: no incident id starts with {prefix!r} in {incidents_path}", file=sys.stderr)
        return None
    if len(matches) > 1:
        print(f"error: {len(matches)} incidents start with {prefix!r}; type more characters:", file=sys.stderr)
        for incident in matches[:10]:
            print(f"  {incident.incident_id}", file=sys.stderr)
        return None
    return matches[0]


def _events_present(incident: Incident, by_id: dict[str, Event], events_path: Path) -> bool:
    missing = [event_id for event_id in incident.event_ids if event_id not in by_id]
    if missing:
        print(
            f"error: {len(missing)} event(s) of incident {incident.incident_id} are not in {events_path} "
            f"(first: {missing[0]}). The two files are from different runs; "
            "run ingest and correlate again.",
            file=sys.stderr,
        )
    return not missing


def _investigate(args: argparse.Namespace) -> int:
    if bool(args.incident) == bool(args.all):
        print("error: give one incident id, or --all (not both, not neither)", file=sys.stderr)
        return 2
    if args.num_ctx < 2048:
        print("error: --num-ctx must be at least 2048", file=sys.stderr)
        return 2
    if not 1 <= args.repeat <= 20:
        print("error: --repeat must be between 1 and 20", file=sys.stderr)
        return 2
    if args.agent and args.think:
        print("error: agent mode runs with thinking off (thinking never finished on this hardware, D20)",
              file=sys.stderr)
        return 2
    incidents = _load(read_incidents, args.incidents, "run 'python -m aegis correlate' first")
    if incidents is None:
        return 2
    events = _load(read_events, args.events, "run 'python -m aegis ingest <alerts file>' first")
    if events is None:
        return 2
    by_id = {event.event_id: event for event in events}
    store = EvidenceStore(events)
    model = args.model or default_model()
    notes = None
    if not args.no_knowledge:
        notes_path = args.knowledge or DEFAULT_NOTES_FILE
        if args.knowledge is None and not notes_path.exists():
            notes = None  # no notes file in the project: run without
        else:
            notes = _load(load_notes, notes_path, "check the --knowledge path")
            if notes is None:
                return 2

    if args.all:
        chosen = [incident for incident in incidents if incident.max_level >= args.min_level]
        if not chosen:
            print(f"No incidents at level {args.min_level} or above.")
            return 0
    else:
        incident = _find_incident(incidents, args.incident, args.incidents)
        if incident is None:
            return 2
        chosen = [incident]
    for incident in chosen:
        if not _events_present(incident, by_id, args.events):
            return 2

    if args.show_prompt:
        for incident in chosen:
            if args.agent:  # what the model starts from; the rest it has to open itself
                print(_ascii(agent.Desk(parts_for_model(incident, store, args.num_ctx, notes or ()))
                             .outline(agent.MAX_TOOL_CALLS)))
            else:
                print(_ascii(pack_for_model(incident, store, args.num_ctx, notes or ()).text))
            print()
        return 0

    counts: Counter = Counter()
    for number, incident in enumerate(chosen, 1):
        if args.all:
            print(f"[{number}/{len(chosen)}] {incident.incident_id}  L{incident.max_level:<2}  "
                  f"{_ascii(_clip(incident.title, 60))}", flush=True)
        for attempt in range(1, args.repeat + 1):
            try:
                if args.agent:
                    result = agent.investigate_agent(
                        incident, store, model=model, num_ctx=args.num_ctx, recordings=args.recordings,
                        replay=args.replay, attempt=attempt, notes=notes, timeout=args.timeout,
                    )
                else:
                    result = investigate(
                        incident, store, model=model, think=args.think, num_ctx=args.num_ctx,
                        recordings=args.recordings, replay=args.replay, attempt=attempt, notes=notes,
                        timeout=args.timeout,
                    )
            except InvestigationError as exc:
                print(f"error: {exc}", file=sys.stderr)
                return 2
            try:
                save_verdict(args.out, result.verdict)
            except (OSError, ContractError) as exc:
                print(f"error: cannot save the verdict to {args.out}: {exc}", file=sys.stderr)
                return 2
            verdict = result.verdict
            counts[verdict.label.value] += 1
            one_line = (f"-> {verdict.label.value.upper()} ({verdict.confidence.value} confidence), "
                        f"{_count(len(verdict.findings), 'finding')}, {len(verdict.rejected)} removed by the checker"
                        + (f", {_count(len(verdict.run.steps), 'tool')}" if args.agent else "")
                        + _timing(verdict))
            if args.all:
                print(f"        {one_line}", flush=True)
            elif attempt == 1:
                print(_verdict_view(incident, verdict, result.pack))
                print(f"\nSaved     {args.out}" + (f"   (recording: {result.recording})" if result.recording else ""))
            else:
                print(f"Asked again ({attempt} of {args.repeat})  {one_line}", flush=True)
    extra = "" if args.dir == RUN_DIR else f" --dir {args.dir}"
    if args.all:
        print()
        print("Verdicts  " + ", ".join(f"{count} {label}" for label, count in sorted(counts.items())))
        print(f"Saved     {args.out}")
        print(f"Read one in full:  python -m aegis investigate {chosen[0].incident_id[:8]} --replay"
              f"{' --agent' if args.agent else ''}{extra}")
        print(f"Side by side:      python -m aegis compare{extra}")
    return 0


def _decide(args: argparse.Namespace) -> int:
    if bool(args.incident) == bool(args.all):
        print("error: give one incident id, or --all (not both, not neither)", file=sys.stderr)
        return 2
    run_dir: Path = args.dir
    incidents = _load(read_incidents, run_dir / INCIDENTS_NAME, "run 'python -m aegis correlate' first")
    if incidents is None:
        return 2
    events = _load(read_events, run_dir / EVENTS_NAME, "run 'python -m aegis ingest <alerts file>' first")
    if events is None:
        return 2
    policy = _load(load_policy, args.policy or DEFAULT_POLICY_FILE, "check the --policy path")
    if policy is None:
        return 2
    verdicts = [] if args.no_model else _load(read_verdicts, run_dir / VERDICTS_NAME, "")
    if verdicts is None:
        return 2
    by_id = {event.event_id: event for event in events}
    if args.all:
        chosen = [incident for incident in incidents if incident.max_level >= args.min_level]
    else:
        incident = _find_incident(incidents, args.incident, run_dir / INCIDENTS_NAME)
        if incident is None:
            return 2
        chosen = [incident]
    for incident in chosen:
        if not _events_present(incident, by_id, run_dir / EVENTS_NAME):
            return 2
    made = []
    for incident in chosen:
        incident_events = [by_id[event_id] for event_id in incident.event_ids]
        made.append((incident, decide(incident, incident_events, policy, latest_verdict(verdicts, incident.incident_id))))
    try:
        save_decisions(run_dir / DECISIONS_NAME, [decision for _, decision in made])
        for _, decision in made:
            audit.append(run_dir / AUDIT_NAME, "decision", decision.incident_id, _decision_record(decision))
    except (OSError, ContractError, ValueError) as exc:
        print(f"error: cannot save decisions to {run_dir / DECISIONS_NAME}: {exc}", file=sys.stderr)
        return 2
    if args.all:
        print(_decision_table(made, policy.id))
    else:
        print(_decision_view(*made[0]))
    print(f"\nSaved     {run_dir / DECISIONS_NAME}   (policy {policy.id})")
    waiting = [(i, a) for i, d in made for a in d.actions if a.outcome is ActionOutcome.NEEDS_APPROVAL]
    if waiting:
        extra = "" if run_dir == RUN_DIR else f" --dir {run_dir}"
        incident, action = waiting[0]
        print("Nothing has been executed. To approve an action:")
        print(_ascii(f"  python -m aegis approve {incident.incident_id[:8]} --action {action.action} "
                     f"--target {action.target} --by <your name>{extra}"))
    else:
        print("Nothing has been executed, and nothing is waiting for approval.")
    return 0


def _decision_record(decision) -> dict:
    return {
        "policy_id": decision.policy_id,
        "host": decision.host.name,
        "host_mode": decision.host_mode,
        "risk": decision.risk.score,
        "band": decision.risk.band,
        "model_label": decision.model_label,
        "actions": [[a.action, a.target, a.outcome.value] for a in decision.actions],
    }


def _evaluate(args: argparse.Namespace) -> int:
    from aegis import evalcases
    from aegis import evaluate as evaluating
    from aegis.investigate import InvestigationError

    if not 1 <= args.repeat <= 10:
        print("error: --repeat must be between 1 and 10", file=sys.stderr)
        return 2
    cases = args.cases or evalcases.DEFAULT_CASES
    try:
        if not args.no_build:
            built = evalcases.build_all(cases)
            kinds = Counter(spec["kind"] for spec in built)
            print(_ascii(f"Cases     {len(built)} built in {cases}  ({', '.join(f'{n} {k}' for k, n in kinds.items())})"))
    except (OSError, ContractError, evalcases.CaseError) as exc:
        print(_ascii(f"error: cannot build the cases: {exc}"), file=sys.stderr)
        return 2
    policy_path = args.policy or DEFAULT_POLICY_FILE
    policy = _load(load_policy, policy_path, "check the --policy path")
    if policy is None:
        return 2
    investigate = None
    if args.investigate:
        notes = None
        if not args.no_knowledge and DEFAULT_NOTES_FILE.exists():
            notes = _load(load_notes, DEFAULT_NOTES_FILE, "")
            if notes is None:
                return 2
        investigate = {"model": args.model or default_model(), "repeat": args.repeat, "notes": notes,
                       "mode": agent.MODE if args.agent else "single_call"}
    try:
        outcome = evaluating.run(cases, args.out, policy, policy_path, investigate=investigate,
                                 say=lambda text: print(_ascii(text), flush=True))
    except InvestigationError as exc:
        print(_ascii(f"error: {exc}"), file=sys.stderr)
        print("The answers received so far are saved; run the same command again to carry on.", file=sys.stderr)
        return 2
    except (OSError, ContractError, evalcases.CaseError) as exc:
        print(_ascii(f"error: {exc}"), file=sys.stderr)
        return 2
    results, probe = outcome["results"], outcome["probe"]
    print()
    print(f"{'case':<24} {'kind':<9} {'incidents':>9}  {'attacks med+/high+':>18}  {'benign med+/high+':>17}  "
          f"{'asked':>5}  {'model runs':>10}")
    for r in results:
        c = r.counts()
        attacks = f"{c['attacks_medium']}/{c['attacks_high']} of {c['attacks']}" if c["attacks"] else "-"
        benign = f"{c['benign_medium']}/{c['benign_high']} of {c['benign']}" if c["benign"] else "-"
        runs = sum(m.runs for m in r.models) or "-"
        print(_ascii(f"{r.name:<24} {r.kind:<9} {c['incidents']:>9}  {attacks:>18}  {benign:>17}  "
                     f"{c['benign_asked'] if c['benign'] else '-':>5}  {runs:>10}"))
    checks = [(r.name, c, ok, got) for r in results for c, ok, got in r.expectations]
    failed = [x for x in checks if not x[2]]
    violations = [v for r in results for v in r.violations]
    print()
    print(f"Expectations  {len(checks) - len(failed)}/{len(checks)} hold")
    for name, check, _, got in failed:
        print(_ascii(f"  FAILED  {name}: {check} (got {got})"))
    print("Invariants    " + ("none broken" if not violations else f"{len(violations)} BROKEN"))
    prompts, leaks = outcome["leaks"]
    print(f"Leaks         " + (f"none in {prompts} prompts" if not leaks else f"{len(leaks)} FOUND"))
    for leak in leaks[:10]:
        print(_ascii(f"  LEAK    {leak}"))
    for violation in violations:
        print(_ascii(f"  BROKEN  {violation}"))
    unsafe = []
    for r in results:
        unsafe += [e for e in r.executed if not e[4]]
    if any(r.executed for r in results):
        done = sum(len(r.executed) for r in results)
        print(f"Executed      {done} action(s) in the real runs, "
              + ("each approved by a human first" if not unsafe else f"{len(unsafe)} WITHOUT AN APPROVAL FIRST"))
    print(f"Probe         {sum(1 for row in probe.rows if row.hostile)} hostile proposals, "
          f"{probe.hostile_executed} carried out; the sober control was "
          f"{'carried out after approval' if probe.control_executed else 'NOT carried out'}")
    print(f"Agent probe   {len(probe.agent_rows)} hostile tool scripts: "
          + ("only read-only tools ran, every run ended in time, no file changed, nothing reached the gate"
             if probe.agent_ok else "SOMETHING GOT THROUGH (see the report)"))
    for row in outcome["modes"]:
        if row.mode != "single_call" and row.runs:
            print(_ascii(f"Agent mode    {row.data}: {row.variant}, {row.runs} runs on {row.incidents} incidents "
                         f"answered in both modes (side by side in the report)"))
    missing = [r.name for r in results if not r.models]
    if missing:
        print(_ascii(f"Model         no verdicts yet for {len(missing)} cases ({', '.join(missing)})"))
        print("              to ask it, on the laptop with Ollama running:  python -m aegis evaluate --investigate")
    print(_ascii(f"Report        {outcome['out'] / 'report.md'}"))
    print(_ascii(f"              open a case in the dashboard:  python -m aegis serve --dir {outcome['out']}{os.sep}<case>"))
    bad = (failed or violations or unsafe or leaks or probe.hostile_executed or not probe.control_executed
           or not probe.agent_ok)
    return 1 if bad else 0


def _watch(args: argparse.Namespace) -> int:
    from aegis.feed import Feed, FeedError, FeedSettings  # only this command needs the feed

    if args.window <= 0:
        print("error: --window must be greater than 0", file=sys.stderr)
        return 2
    try:
        settings = FeedSettings(args.manager, args.user, args.key, args.min_level, timedelta(minutes=args.window))
    except FeedError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    extra = f" --dir {args.dir}"
    print(_ascii(f"Live feed from {args.user}@{args.manager} into {args.dir}   (read-only; Ctrl+C stops)"))
    print(_ascii(f"Dashboard: python -m aegis serve{extra}   (in another window)"), flush=True)
    feed = Feed(args.dir, settings, say=lambda text: print(_ascii(text), flush=True))
    try:
        return feed.run(once=args.once, from_start=args.from_start)
    except FeedError as exc:
        print(_ascii(f"error: {exc}"), file=sys.stderr)
        return 2


def _serve(args: argparse.Namespace) -> int:
    from aegis import server  # only this command needs the web server

    if not args.dir.is_dir():
        print(f"error: no run folder {args.dir}", file=sys.stderr)
        return 2
    if not 0 <= args.port <= 65535:
        print("error: --port must be between 1 and 65535", file=sys.stderr)
        return 2
    try:
        httpd = server.make_server(args.dir, args.port, args.policy)
    except OSError as exc:
        print(f"error: cannot listen on 127.0.0.1:{args.port} ({exc}). Is a dashboard already running? "
              f"Try --port {args.port + 1}.", file=sys.stderr)
        return 2
    snap = httpd.view.current()
    state = snap.audit_state
    port = httpd.server_address[1]
    lines = [
        f"Dashboard http://127.0.0.1:{port}/   (read-only: GET only, from this computer only)",
        f"Run folder {args.dir}   {len(snap.incidents)} incidents, {len(snap.events)} events, "
        f"{len(snap.verdicts)} verdicts",
        f"Policy    {snap.policy.id if snap.policy else 'NOT READ'}   every decision is worked out again from it, "
        "as act does",
        f"Audit log {state.entries} entries, " + ("chain intact" if state.ok else f"BROKEN: {state.problem}"),
    ]
    lines += [f"Note      {problem}" for problem in snap.problems]
    lines.append("Approving and acting stay on the command line. Press Ctrl+C to stop.")
    print("\n".join(_ascii(line) for line in lines), flush=True)
    try:
        httpd.serve_forever(poll_interval=0.5)
    except KeyboardInterrupt:
        print("Stopped.")
    finally:
        httpd.server_close()
    return 0


def _fresh_decision(args: argparse.Namespace):
    """Load everything and decide the incident again, from scratch.

    Approving and acting never trust a saved decision: they recompute it from
    the events and the current policy, which by construction gives the same
    answer unless the evidence or the policy changed.
    """
    run_dir: Path = args.dir
    incidents = _load(read_incidents, run_dir / INCIDENTS_NAME, "run 'python -m aegis correlate' first")
    events = _load(read_events, run_dir / EVENTS_NAME, "run 'python -m aegis ingest <alerts file>' first") \
        if incidents is not None else None
    policy = _load(load_policy, args.policy or DEFAULT_POLICY_FILE, "check the --policy path") \
        if events is not None else None
    if policy is None:
        return None
    verdicts = _load(read_verdicts, run_dir / VERDICTS_NAME, "") or []
    incident = _find_incident(incidents, args.incident, run_dir / INCIDENTS_NAME)
    by_id = {event.event_id: event for event in events}
    if incident is None or not _events_present(incident, by_id, run_dir / EVENTS_NAME):
        return None
    incident_events = [by_id[event_id] for event_id in incident.event_ids]
    decision = decide(incident, incident_events, policy, latest_verdict(verdicts, incident.incident_id))
    return incident, decision, policy


def _approve(args: argparse.Namespace) -> int:
    loaded = _fresh_decision(args)
    if loaded is None:
        return 2
    incident, decision, policy = loaded
    match = [a for a in decision.actions if a.action == args.action and
             target_key(a.action, a.target) == target_key(args.action, args.target)]
    if not match:
        print(f"error: {args.action} {args.target} is not one of this incident's candidate actions", file=sys.stderr)
        for a in decision.actions:
            print(f"  {a.outcome.value:<15} {a.action} {a.target}", file=sys.stderr)
        return 2
    action = match[0]
    if action.outcome is not ActionOutcome.NEEDS_APPROVAL:
        why = "; ".join(action.reasons)
        print(f"error: {action.action} {action.target} cannot be approved: the policy says "
              f"{action.outcome.value} ({why})", file=sys.stderr)
        return 2
    by = " ".join(args.by.split())
    if not by:
        print("error: --by needs a name", file=sys.stderr)
        return 2
    when = format_ts(datetime.now(timezone.utc).replace(microsecond=0))
    try:
        add_approval(args.dir, incident.incident_id, policy.id, Approved(action.action, action.target, by, when))
        audit.append(args.dir / AUDIT_NAME, "approval", incident.incident_id, {
            "policy_id": policy.id, "action": action.action, "target": action.target, "approved_by": by,
            "risk": decision.risk.score, "band": decision.risk.band,
        })
    except (OSError, ContractError, ValueError) as exc:
        print(f"error: cannot record the approval: {exc}", file=sys.stderr)
        return 2
    print(_ascii(f"Approved  {action.action} {action.target}  for {incident.incident_id}  by {by}"))
    print(_ascii(f"          risk {decision.risk.score} ({decision.risk.band}), policy {policy.id}, "
                 f"host {decision.host.name}"))
    print(f"Saved     {approval_path(args.dir, incident.incident_id)}")
    extra = "" if args.dir == RUN_DIR else f" --dir {args.dir}"
    print(f"Carry it out:  python -m aegis act {incident.incident_id[:8]}{extra}")
    return 0


def _export(args: argparse.Namespace) -> int:
    from aegis.export import check_site, export_run

    if not (args.dir / INCIDENTS_NAME).exists():
        print(f"error: no {INCIDENTS_NAME} in {args.dir}; run 'python -m aegis correlate' first", file=sys.stderr)
        return 2
    try:
        written = export_run(args.dir, args.out, label=args.label or args.dir.name, policy_path=args.policy)
    except (OSError, ContractError, ValueError) as exc:
        print(_ascii(f"error: cannot export: {exc}"), file=sys.stderr)
        return 2
    problems = check_site(args.out)
    print(_ascii(f"Exported  {written} pages from {args.dir} into {args.out}"))
    print(_ascii(f"Open      {args.out / 'index.html'}"))
    print("Note      the copy holds every alert in the run folder, raw alerts included. Publish it only if "
          "that data may be public; the public demo is 'python -m aegis demo' (synthetic data only).")
    for problem in problems[:10]:
        print(_ascii(f"  PROBLEM  {problem}"), file=sys.stderr)
    return 1 if problems else 0


def _demo(args: argparse.Namespace) -> int:
    from aegis.demo import DemoError, build_demo
    from aegis.investigate import InvestigationError

    try:
        built = build_demo(args.out, policy_path=args.policy, say=lambda text: print(_ascii(text), flush=True))
    except (DemoError, InvestigationError, OSError, ContractError, ValueError) as exc:
        print(_ascii(f"error: the demo was not built: {exc}"), file=sys.stderr)
        return 2
    locked = built["locked"]
    print(_ascii(f"Built     {built['pages']} pages: the sample, {built['twins']} twins and the evaluation"))
    print(_ascii(f"Simulated lock_account svc_backup on {locked['host']} ({locked['incident']}), approved by "
                 f"'demo', sent to a stand-in gate: {', '.join(locked['requests'])}"))
    print(_ascii(f"Open      {built['out'] / 'index.html'}"))
    return 0


def make_executor(policy) -> GateExecutor:
    return GateExecutor(policy.executor.ssh_user, policy.executor.ssh_key)


def _act(args: argparse.Namespace, executor_factory=None) -> int:
    loaded = _fresh_decision(args)
    if loaded is None:
        return 2
    incident, decision, policy = loaded
    try:
        approval = load_approval(args.dir, incident.incident_id)
    except ContractError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    log = args.dir / AUDIT_NAME
    state = audit.verify(log)
    if not state.ok:
        print(f"error: the audit log is damaged ({state.problem}); nothing will run until it is fixed",
              file=sys.stderr)
        return 2
    entry = policy.hosts.get(decision.host.agent_id)
    lines = [
        f"Incident  {incident.incident_id}  ({decision.host.name}, risk {decision.risk.score} "
        f"{decision.risk.band}, policy {policy.id})",
    ]
    if approval is not None and approval.policy_id != policy.id:
        lines.append(f"Note      the approval file was made under policy {approval.policy_id}; the policy has "
                     "changed since, so it does not count. Approve again.")
    to_run = []
    for action in decision.actions:
        label = f"{action.action} {action.target}"
        if action.outcome is ActionOutcome.DENY:
            lines.append(f"  skip     {label}: denied by the policy ({'; '.join(action.reasons)})")
            continue
        if action.outcome is ActionOutcome.NEEDS_APPROVAL and not (
                approval and approval.covers(action.action, action.target, policy.id)):
            lines.append(f"  waiting  {label}: needs a human's approval (python -m aegis approve)")
            continue
        to_run.append(action)
    if not decision.actions:
        lines.append("  (no candidate actions)")
    if to_run and (entry is None or decision.host_mode != "lab" or not entry.address):
        print("error: the policy gives no lab address for this host", file=sys.stderr)
        return 2
    print(_ascii("\n".join(lines)))
    if not to_run:
        print("Nothing to run.")
        return 0
    if args.dry_run:
        for action in to_run:
            print(_ascii(f"  would run  {action.action} {action.target} on {entry.address}"))
        print("Dry run: nothing was run.")
        return 0

    executor = (executor_factory or make_executor)(policy)
    failed = 0
    for action in to_run:
        record = {"policy_id": policy.id, "action": action.action, "target": action.target,
                  "host": decision.host.name, "address": entry.address,
                  "approved_by": next((a.approved_by for a in approval.actions
                                       if a.action == action.action and
                                       target_key(a.action, a.target) == target_key(action.action, action.target)),
                                      "") if approval else ""}
        try:
            audit.append(log, "action_started", incident.incident_id, record)
        except (OSError, ValueError) as exc:
            print(f"error: cannot write the audit log, so not running anything: {exc}", file=sys.stderr)
            return 2
        result = executor.run(entry.address, action.action, action.target)
        audit.append(log, "action_result", incident.incident_id, dict(
            record, ok=result.ok, message=result.message, before=result.before, after=result.after))
        failed += not result.ok
        print(_ascii(f"  {'DONE' if result.ok else 'FAILED':<8} {action.action} {action.target}: {result.message}"))
        if result.before:
            print(_ascii(f"           before: {result.before}"))
        if result.after:
            print(_ascii(f"           after:  {result.after}"))
    print(f"Recorded  {log}")
    return 1 if failed else 0


def _audit(run_dir: Path, last: int) -> int:
    log = run_dir / AUDIT_NAME
    state = audit.verify(log)
    if state.entries == 0 and state.ok:
        print(f"No audit entries yet in {log}.")
        return 0
    if state.ok:
        print(f"OK        {state.entries} entries, hash chain intact   ({log})")
    else:
        print(f"BROKEN    {state.problem}   ({log}; {state.entries} entries before that are intact)")
    print(f"Last hash {state.last_hash}")
    print("          (write this down somewhere else: an attacker who deletes entries from the end")
    print("           leaves a valid chain, but not one ending in this hash)")
    entries = audit.read_entries(log) if state.ok else []
    if entries and last > 0:
        print()
        for entry in entries[-last:]:
            data = entry.get("data", {})
            if entry["kind"] == "decision":
                summary = f"risk {data.get('risk')} {data.get('band')}, {len(data.get('actions', []))} actions"
            elif entry["kind"] == "approval":
                summary = f"{data.get('action')} {data.get('target')} approved by {data.get('approved_by')}"
            elif entry["kind"] == "action_result":
                summary = f"{data.get('action')} {data.get('target')}: {'ok' if data.get('ok') else 'FAILED'} - {data.get('message')}"
            else:
                summary = f"{data.get('action')} {data.get('target')}"
            print(_ascii(f"  {entry['seq']:>4}  {entry['time'][:19]}  {entry['kind']:<15} "
                         f"{entry['incident_id'][:13]}  {summary}"))
    return 0 if state.ok else 1


_OUTCOME_TEXT = {"needs_approval": "NEEDS APPROVAL", "allow": "ALLOW", "deny": "DENY"}


def _decision_view(incident: Incident, decision) -> str:
    label_of = {event_id: f"E{n}" for n, event_id in enumerate(incident.event_ids, 1)}

    def cite(event_ids) -> str:
        labels = [label_of.get(e, "?") for e in event_ids]
        return ", ".join(labels) if len(labels) <= 8 else ", ".join(labels[:8]) + f" +{len(labels) - 8} more"

    risk = decision.risk
    lines = [
        f"Incident  {incident.incident_id}  (level {incident.max_level}, "
        f"{_count(len(incident.event_ids), 'event')}, {incident.host.name})",
        f"Title     {_clip(incident.title, 100)}",
        f"Host      {decision.host.name} (agent {decision.host.agent_id}): {decision.host_mode}  "
        f"(policy {decision.policy_id})",
        "",
        f"Risk      {risk.score} / 100   {risk.band.upper()}   (worked out from the evidence by fixed rules)",
    ]
    for factor in risk.factors:
        lines += textwrap.wrap(f"{factor.points:+4d}  {factor.id:<22} {factor.reason}", width=110,
                               initial_indent="  ", subsequent_indent=" " * 31)
        lines.append(" " * 31 + f"evidence: {cite(factor.evidence)}")
    model = f"{decision.model_label} ({decision.model_run})" if decision.model_label else "no saved verdict"
    lines += ["", f"Model     {model}   - shown for information; not part of the score", "", "Actions"]
    if not decision.actions:
        lines.append("  (none suggested by the risk rules or the model)")
    for action in decision.actions:
        lines.append(f"  {_OUTCOME_TEXT[action.outcome.value]:<15} {action.action} {action.target}   "
                     f"(suggested by: {action.source.replace('+', ' and ')})")
        for reason in action.reasons:
            lines += textwrap.wrap(reason, width=104, initial_indent="      - ", subsequent_indent="        ")
    return "\n".join(_ascii(line) for line in lines)


def _decision_table(made, policy_id: str) -> str:
    rows = sorted(made, key=lambda item: (-item[1].risk.score, -item[0].max_level, item[0].incident_id))
    lines = [f"{'incident':<13} {'lvl':>3} {'risk':>4}  {'band':<8}  {'mode':<6}  {'model said':<12}  "
             f"{'actions':<26}  title"]
    for incident, decision in rows:
        counts = Counter(a.outcome.value for a in decision.actions)
        actions = ", ".join(f"{counts[k]} {k.replace('needs_approval', 'to approve').replace('deny', 'denied')}"
                            for k in ("needs_approval", "allow", "deny") if counts[k]) or "-"
        lines.append(f"{incident.incident_id[:13]:<13} {incident.max_level:>3} {decision.risk.score:>4}  "
                     f"{decision.risk.band:<8}  {decision.host_mode:<6}  {decision.model_label or '-':<12}  "
                     f"{actions:<26}  {_clip(incident.title, 40)}")
    bands = Counter(decision.risk.band for _, decision in made)
    lines += ["", "Risk bands  " + ", ".join(f"{bands[b]} {b}" for b in ("critical", "high", "medium", "low") if bands[b])]
    waiting = sum(1 for _, d in made for a in d.actions if a.outcome.value == "needs_approval")
    lines.append(f"Actions waiting for a human: {waiting}")
    return "\n".join(_ascii(line) for line in lines)


def _compare(run_dir: Path, labels_path: Path | None, expect: str | None) -> int:
    incidents = _load(read_incidents, run_dir / INCIDENTS_NAME, "run 'python -m aegis correlate' first")
    if incidents is None:
        return 2
    verdicts = _load(read_verdicts, run_dir / VERDICTS_NAME, "run 'python -m aegis investigate --all' first")
    if verdicts is None:
        return 2
    labels: dict = {}
    if labels_path is None and (run_dir / LABELS_NAME).exists():
        labels_path = run_dir / LABELS_NAME
    if labels_path is not None:
        labels = _load(comparing.load_labels, labels_path, "check the --labels path")
        if labels is None:
            return 2
    print(f"Verdicts  {run_dir / VERDICTS_NAME}" + (f"   labels: {labels_path}" if labels_path else ""))
    print()
    print(_ascii(comparing.render(comparing.compare(incidents, verdicts, labels, expect))))
    return 0


def _timing(verdict: Verdict) -> str:
    run = verdict.run
    if run.duration_ms is None:
        return ""
    return f", {run.duration_ms / 1000:.1f} s"


def _verdict_view(incident: Incident, verdict: Verdict, pack: EvidencePack) -> str:
    label_of = {event_id: label for label, event_id in pack.labels.items()}

    def cite(event_ids: tuple) -> str:
        if len(event_ids) > 4:  # many events: labels only; the ids are in the verdicts file
            return ", ".join(label_of.get(event_id, "?") for event_id in event_ids)
        return ", ".join(f"{label_of.get(event_id, '?')} {event_id}" for event_id in event_ids)

    def wrapped(prefix: str, text: str, indent: str) -> list[str]:
        return textwrap.wrap(text, width=100, initial_indent=prefix, subsequent_indent=indent) or [prefix.rstrip()]

    run = verdict.run
    mode = "single call" if run.mode == "single_call" else f"agent mode ({run.mode})"
    how = f"{run.model}, {mode}, thinking {'on' if run.thinking else 'off'}"
    if run.duration_ms is not None:
        how += f"  ({run.duration_ms / 1000:.1f} s"
        if run.prompt_tokens is not None and run.output_tokens is not None:
            how += f", {run.prompt_tokens} prompt + {run.output_tokens} answer tokens"
        how += ")"
    if run.replayed:
        how += "  [replayed from a recording]"
    if not run.knowledge:
        notes_line = "none in use"
    elif verdict.notes_shown:
        notes_line = ", ".join(verdict.notes_shown) + f"  (operator notes that matched; notes file {run.knowledge_id})"
    else:
        notes_line = f"none matched this incident  (notes file {run.knowledge_id})"
    lines = [
        f"Incident  {incident.incident_id}  (level {incident.max_level}, {_count(len(incident.event_ids), 'event')}, "
        f"{incident.host.name})",
        f"Title     {_clip(incident.title, 100)}",
        f"Model     {how}",
        f"Notes     {notes_line}",
        "",
        f"Verdict   {verdict.label.value.upper()}   (confidence: {verdict.confidence.value})",
    ]
    lines += wrapped("Summary   ", verdict.summary or "(none)", " " * 10)
    if run.mode != "single_call":
        lines += [""] + wrapped("Opened    ", "; ".join(run.steps) or "nothing (it answered from the outline)",
                                " " * 10)
    reasoning = verdict.reasoning
    steps = [
        ("What happened", reasoning.what_happened),
        ("Started by", reasoning.started_by),
        ("Innocent reading", reasoning.innocent_explanation),
        ("Attack reading", reasoning.attack_explanation),
        ("Against innocent", reasoning.against_innocent),
    ]
    if any(text for _, text in steps):
        lines += ["", "Reasoning  (the model's working before it chose; not checked)"]
        for name, text in steps:
            lines += wrapped(f"  {name + ':':<18}", text or "(none)", " " * 20)
    lines += ["", "Findings  (each cites evidence that was checked to exist)"]
    if not verdict.findings:
        lines.append("  (none)")
    for number, finding in enumerate(verdict.findings, 1):
        lines += wrapped(f"  {number}. ", finding.claim, "     ")
        lines.append(f"     evidence: {cite(finding.evidence)}")
    if verdict.technique_ids:
        lines += ["", f"ATT&CK    {', '.join(verdict.technique_ids)}"]
    lines += ["", "Proposed actions  (proposals only - nothing is executed)"]
    if not verdict.proposed_actions:
        lines.append("  (none)")
    for action in verdict.proposed_actions:
        lines += wrapped(f"  - {action.action} {action.target}: ", action.reason or "(no reason given)", "    ")
        lines.append(f"    evidence: {cite(action.evidence)}")
    if verdict.rejected:
        lines += ["", "Removed or flagged by the checker"]
        for rejection in verdict.rejected:
            lines += wrapped(f"  - {rejection.kind}: ", f'"{rejection.text}" - {rejection.reason}', "    ")
    if pack.omitted:
        lines += ["", f"Note      {pack.omitted} events in the middle of this incident were not shown to the model."]
    lines += ["", "The verdict, summary, findings and proposals are AI-written. The checks are not."]
    return "\n".join(_ascii(line) for line in lines)


def _incident_view(incident: Incident, by_id: dict[str, Event]) -> str:
    lines = [
        f"Incident  {incident.incident_id}",
        f"Title     {incident.title}",
        f"Host      {incident.host.name} (agent {incident.host.agent_id})",
        f"When      {incident.first_seen:%Y-%m-%d %H:%M:%S}  to  {incident.last_seen:%Y-%m-%d %H:%M:%S} UTC"
        f"  ({_duration(incident.duration)})",
        f"Events    {len(incident.event_ids)}, highest level {incident.max_level}",
    ]
    if incident.technique_ids:
        lines.append(f"ATT&CK    {', '.join(incident.technique_ids)}  ({', '.join(incident.tactics)})")
    if incident.accounts:
        lines.append(f"Accounts  {', '.join(incident.accounts)}")
    if incident.source_ips:
        lines.append(f"Sources   {', '.join(incident.source_ips)}")
    lines += ["", "Rules"]
    for rule in incident.rules:
        lines.append(f"  {rule.count:>4} x  L{rule.level:<2}  {rule.rule_id:<6}  {_clip(rule.description, 90)}")

    links: dict[str, list] = {}
    for link in incident.links:
        links.setdefault(link.event_id, []).append(link)
    lines += ["", "Timeline (UTC)"]
    for event_id in incident.event_ids:
        event = by_id[event_id]
        lines.append(
            f"  {event.timestamp:%H:%M:%S}.{event.timestamp.microsecond // 1000:03d}  "
            f"L{event.rule.level:<2}  {event.rule.id:<6}  {_clip(event.rule.description, 80)}"
        )
        detail = _detail(event)
        lines.append(f"      {event.event_id}" + (f"  {detail}" if detail else ""))
        for link in links.get(event_id, []):
            reason = _LINK_TEXT[link.reason].format(value=link.value)
            lines.append(f"      linked: {reason} {link.linked_to}")
    return "\n".join(_ascii(line) for line in lines)


def _detail(event: Event) -> str:
    """The few fields that say what an event was about, on one line."""
    parts = []
    if event.user:
        parts.append(f"user={event.user}" + (f" -> {event.target_user}" if event.target_user else ""))
    network = event.network
    if network and network.src_ip:
        parts.append(f"from={network.src_ip}" + (f":{network.src_port}" if network.src_port else ""))
    if network and (network.dst_ip or network.dst_host):
        target = network.dst_host or network.dst_ip
        parts.append(f"to={target}" + (f":{network.dst_port}" if network.dst_port else ""))
    process = event.process
    if process and process.command_line:
        parts.append(f"cmd={_clip(process.command_line, 110)}")
    elif process and process.image:
        parts.append(f"process={process.image}")
    if event.file_path:
        parts.append(f"file={event.file_path}")
    if event.registry_key:
        parts.append(f"key={_clip(event.registry_key, 90)}")
    return "  ".join(parts)


def _count(number: int, noun: str) -> str:
    return f"{number} {noun}" if number == 1 else f"{number} {noun}s"


def _clip(text: str, width: int) -> str:
    text = " ".join(text.split())
    return text if len(text) <= width else text[: width - 3] + "..."


def _table(title: str, counts: Counter, limit: int | None = None) -> list[str]:
    lines = ["", title]
    for label, count in counts.most_common(limit):
        lines.append(f"  {count:>5}  {label}")
    return lines


def _ts(event: Event) -> str:
    return event.timestamp.strftime("%Y-%m-%d %H:%M:%S")


def _duration(value: timedelta) -> str:
    seconds = int(value.total_seconds())
    if seconds < 60:
        return f"{seconds} s"
    minutes = seconds // 60
    return f"{minutes // 60} h {minutes % 60:02d} min" if minutes >= 60 else f"{minutes} min"


def _ascii(text: str) -> str:
    return text.encode("ascii", "backslashreplace").decode("ascii")
