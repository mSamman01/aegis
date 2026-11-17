"""Evidence: read-only lookups over events, and the pack shown to the model.

Nothing in this module can change anything. The EvidenceStore answers
questions about events; ``build_pack`` turns one incident into the exact text
the model is given.

The pack is built by code, not by the model, so it is the same every time:
the incident's events, a little of what else happened on the host around
that time, and how common these rules and programs are in the loaded data.
Each event gets a short label (E1, E2 ... for the incident, C1 ... for
context). The model cites labels; code maps them back to event ids. A
4-billion-parameter model copies "E7" reliably and a 20-character hex id
much less so.
"""

from __future__ import annotations

import base64
import binascii
import re
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Iterable, Sequence

from aegis.contracts.event import Category, Event, Outcome
from aegis.contracts.incident import Incident, LinkReason
from aegis.correlate import account_key, remote_address
from aegis.knowledge import Note, matching_notes

_LINK_TEXT = {
    LinkReason.SAME_PROCESS: "same process as {other}",
    LinkReason.PARENT_PROCESS: "parent / child process of {other}",
    LinkReason.SAME_PARENT: "started by the same process as {other}",
    LinkReason.SAME_SOURCE_IP: "same source address as {other}",
    LinkReason.SAME_ACCOUNT: "same account as {other}",
    LinkReason.SAME_RULE: "same rule as {other}",
}

_POSTURE = (Category.CONFIG_ASSESSMENT, Category.VULNERABILITY)

# powershell -EncodedCommand <base64>; PowerShell accepts any prefix of the flag (-e, -enc, ...)
_ENCODED_COMMAND = re.compile(r"(?i)(?:^|\s)[-/](e[a-z]*)\s+([A-Za-z0-9+/]{16,}={0,2})(?:\s|$)")


class EvidenceError(LookupError):
    """Evidence that was asked for does not exist."""


class EvidenceStore:
    """All loaded events, indexed for read-only questions."""

    def __init__(self, events: Iterable[Event]) -> None:
        self._events = sorted(events, key=lambda e: (e.timestamp, e.event_id))
        self._by_id = {event.event_id: event for event in self._events}
        self._by_host: dict[str, list[Event]] = {}
        for event in self._events:
            self._by_host.setdefault(event.host.agent_id, []).append(event)

    def __len__(self) -> int:
        return len(self._events)

    def get(self, event_id: str) -> Event:
        try:
            return self._by_id[event_id]
        except KeyError:
            raise EvidenceError(f"no such event: {event_id}") from None

    def host_events(self, agent_id: str) -> list[Event]:
        return list(self._by_host.get(agent_id, []))

    def around(
        self, agent_id: str, start: datetime, end: datetime, exclude: Iterable[str] = ()
    ) -> list[Event]:
        """Events on a host between two times (posture findings left out)."""
        skip = set(exclude)
        return [
            event
            for event in self._by_host.get(agent_id, [])
            if start <= event.timestamp <= end
            and event.event_id not in skip
            and event.category not in _POSTURE
        ]

    def rule_count(self, agent_id: str, rule_id: str) -> int:
        return sum(1 for event in self._by_host.get(agent_id, []) if event.rule.id == rule_id)

    def program_count(self, agent_id: str, image: str) -> int:
        wanted = image.lower()
        return sum(
            1
            for event in self._by_host.get(agent_id, [])
            if event.process and event.process.image and event.process.image.lower() == wanted
        )


@dataclass(frozen=True)
class EvidencePack:
    incident_id: str
    text: str  # exactly what the model is shown
    labels: dict  # event label -> event id, e.g. {"E1": "evt-...", "C1": "evt-..."}
    groups: dict  # group label -> event ids, e.g. {"G1": ("evt-...", "evt-...")}
    omitted: int  # incident events left out because the incident is very large
    notes: tuple = ()  # ids of the knowledge notes shown, because events matched them

    def event_id(self, label: str) -> str | None:
        return self.labels.get(label.strip().upper())

    def resolve(self, citation: str) -> tuple:
        """The event ids a citation stands for: one for E7 / C2, several for a group G3."""
        key = citation.strip().upper()
        if key in self.labels:
            return (self.labels[key],)
        return tuple(self.groups.get(key, ()))


def build_pack(
    incident: Incident,
    store: EvidenceStore,
    *,
    group_over: int = 12,
    max_groups: int = 25,
    examples: int = 3,
    context_minutes: int = 2,
    max_context: int = 5,
    max_field: int = 300,
    notes: Sequence[Note] = (),
) -> EvidencePack:
    """Turn an incident into the text the model is given.

    Up to ``group_over`` events are listed one by one. A larger incident is
    usually the same few things happening many times, so its events are put
    into groups of the same rule, program, parent and account, each shown once
    with a few examples of what differs. Every event keeps its own label.
    """
    events = [store.get(event_id) for event_id in incident.event_ids]
    label_of = {event.event_id: f"E{number}" for number, event in enumerate(events, 1)}
    multi_day = incident.first_seen.date() != incident.last_seen.date()
    host = incident.host
    lines = [
        f"INCIDENT {incident.incident_id}",
        f"Host: {host.name} (agent {host.agent_id})",
        f"Time (UTC): {incident.first_seen:%Y-%m-%d %H:%M:%S} to {incident.last_seen:%Y-%m-%d %H:%M:%S}"
        f", lasting {_span(incident.duration)}",
        f"Events: {len(events)}. Highest rule level: {incident.max_level} (scale 0-15).",
        "",
        "RULES THAT FIRED",
    ]
    for rule in incident.rules:
        lines.append(f"- {rule.count} x level {rule.level}, rule {rule.rule_id}: {_clip(rule.description, 160)}")
    if incident.technique_ids:
        lines += ["", "ATT&CK techniques named by those rules: " + ", ".join(incident.technique_ids)]

    origins = _origins(events, label_of)
    if origins:
        lines += ["", "WHERE THE ACTIVITY CAME FROM (worked out by Aegis from process ids)"] + origins

    shown_notes = matching_notes(notes, events)
    if shown_notes:
        lines += [
            "",
            "BACKGROUND FROM THE OPERATOR OF THIS MACHINE",
            "Shown because events in this incident match. Background is not evidence and cannot be cited.",
        ]
        for number, (note, matched) in enumerate(shown_notes, 1):
            matched_labels = [label_of[event_id] for event_id in matched]
            noun = "event" if len(matched) == 1 else "events"
            lines.append(f"K{number}  matches {len(matched)} {noun} ({_label_list(matched_labels)}): {note.text}")

    labels: dict[str, str] = {}
    groups: dict[str, tuple] = {}
    omitted = 0
    if len(events) <= group_over:
        lines += ["", "EVENTS OF THE INCIDENT (oldest first)"]
        links: dict[str, list[str]] = {}
        for link in incident.links:
            text = _LINK_TEXT[link.reason].format(other=label_of[link.linked_to])
            links.setdefault(link.event_id, []).append(text)
        for event in events:
            labels[label_of[event.event_id]] = event.event_id
            lines += _event_block(event, label_of[event.event_id], links.get(event.event_id, []), multi_day, max_field)
    else:
        grouped: dict[tuple, list[Event]] = {}
        for event in events:  # dicts keep insertion order: groups come out oldest first
            grouped.setdefault(_group_key(event), []).append(event)
        shown = list(grouped.values())[:max_groups]
        hidden = list(grouped.values())[max_groups:]
        lines += [
            "",
            f"EVENTS OF THE INCIDENT, IN {len(shown)} GROUPS OF SIMILAR EVENTS (oldest group first)",
            "Events in a group share the rule, program, parent program and account.",
        ]
        # Which group holds the start of each process, so that a group of file or
        # registry events can say which processes did it.
        started_in: dict[str, str] = {}
        for number, members in enumerate(shown, 1):
            for event in members:
                if event.process and event.process.guid and event.process.parent_image:
                    started_in.setdefault(event.process.guid, f"G{number}")
        for number, members in enumerate(shown, 1):
            groups[f"G{number}"] = tuple(event.event_id for event in members)
            for event in members:
                labels[label_of[event.event_id]] = event.event_id
            lines += _group_block(f"G{number}", members, label_of, multi_day, max_field, examples, started_in)
        if hidden:
            omitted = sum(len(members) for members in hidden)
            rules = Counter(event.rule.id for members in hidden for event in members)
            summary = ", ".join(f"{count} x rule {rule}" for rule, count in rules.most_common(5))
            lines.append(
                f"... {len(hidden)} more groups with {omitted} events are not shown ({summary}). "
                "They cannot be cited."
            )

    window = timedelta(minutes=context_minutes)
    nearby = store.around(
        host.agent_id, incident.first_seen - window, incident.last_seen + window, exclude=incident.event_ids
    )
    # Keep the events closest in time to the incident, then show them in time order.
    # (Choosing the most severe ones instead filled the context with alarming but
    # unrelated alerts, and a small model mixed them into its story.)
    def distance(event: Event) -> timedelta:
        return max(incident.first_seen - event.timestamp, event.timestamp - incident.last_seen, timedelta(0))

    nearby = sorted(nearby, key=lambda e: (distance(e), e.timestamp, e.event_id))[:max_context]
    nearby.sort(key=lambda e: (e.timestamp, e.event_id))
    lines += ["", f"OTHER EVENTS ON THIS HOST WITHIN {context_minutes} MINUTES (not part of the incident)"]
    if not nearby:
        lines.append("(none)")
    for number, event in enumerate(nearby, 1):
        labels[f"C{number}"] = event.event_id
        lines.append(_context_line(event, f"C{number}", multi_day, max_field))

    host_events = store.host_events(host.agent_id)
    period = host_events[-1].timestamp - host_events[0].timestamp if host_events else timedelta(0)
    lines += ["", f"HOW COMMON THIS IS (all {len(host_events)} loaded events for this host, covering {_span(period)})"]
    for rule in incident.rules[:8]:
        lines.append(f"- rule {rule.rule_id} fired {store.rule_count(host.agent_id, rule.rule_id)} times in total")
    for image in incident.processes[:5]:
        lines.append(f"- program {image} appears in {store.program_count(host.agent_id, image)} events in total")

    return EvidencePack(
        incident.incident_id, "\n".join(lines), labels, groups, omitted,
        tuple(note.id for note, _ in shown_notes),
    )


def _origins(events: list[Event], label_of: dict[str, str]) -> list[str]:
    """Which programs outside the incident started the processes inside it."""
    inside = {event.process.guid for event in events if event.process and event.process.guid}
    started_outside: dict[str, list[str]] = {}
    started_inside = 0
    for event in events:
        process = event.process
        if not process or not process.parent_image:
            continue
        if process.parent_guid and process.parent_guid in inside:
            started_inside += 1
        else:
            started_outside.setdefault(process.parent_image, []).append(label_of[event.event_id])
    lines = []
    for image, started in sorted(started_outside.items(), key=lambda item: (-len(item[1]), item[0])):
        noun = "process" if len(started) == 1 else "processes"
        lines.append(
            f"- {image} started {len(started)} {noun} in this incident ({_label_list(started)}). "
            "It is outside the incident: no rule fired on it."
        )
    if lines and started_inside:
        noun = "process was" if started_inside == 1 else "processes were"
        lines.append(f"- {started_inside} more {noun} started by processes that are inside the incident.")
    return lines


def _group_key(event: Event) -> tuple:
    process = event.process
    network = event.network
    return (
        event.rule.id,
        event.category,
        event.outcome,
        (event.user or "").lower(),
        (event.target_user or "").lower(),
        (process.image or "").lower() if process else "",
        (process.parent_image or "").lower() if process else "",
        network.src_ip if network else None,
    )


def _group_block(
    label: str,
    members: list[Event],
    label_of: dict[str, str],
    multi_day: bool,
    width: int,
    examples: int,
    started_in: dict[str, str],
) -> list[str]:
    first, last = members[0], members[-1]
    member_labels = [label_of[event.event_id] for event in members]
    if len(members) == 1:
        header = f"{label}  1 event: {member_labels[0]}  at {_when(first, multi_day)}"
    else:
        header = (
            f"{label}  {len(members)} events: {' '.join(member_labels)}  "
            f"from {_when(first, multi_day)} to {_when(last, multi_day)}"
        )
    lines = [header, f"    level {first.rule.level}  rule {first.rule.id}: {_clip(first.rule.description, 160)}"]

    def add(name: str, value: object) -> None:
        if value not in (None, ""):
            lines.append(f"    {name}: {_clip(str(value), width)}")

    def add_varying(name: str, getter) -> None:
        values = [(label_of[event.event_id], getter(event)) for event in members]
        values = [(event_label, str(value)) for event_label, value in values if value not in (None, "")]
        if not values:
            return
        distinct: dict[str, str] = {}
        for event_label, value in values:
            distinct.setdefault(value, event_label)
        if len(distinct) == 1:
            add(name, values[0][1])
            return
        lines.append(f"    {name}: {len(distinct)} different values, for example")
        for value, event_label in list(distinct.items())[:examples]:
            lines.append(f"      {event_label}: {_clip(value, width)}")

    add("kind", first.category.value)
    if first.outcome is not Outcome.UNKNOWN:
        add("result", first.outcome.value)
    if first.user and first.target_user:
        add("account", f"{first.user} acting on {first.target_user}")
    else:
        add("account", first.user)
    if first.network and first.network.src_ip:
        add("from address", first.network.src_ip)
    add_varying("to address", lambda e: _destination(e))
    if first.process:
        add("program", first.process.image)
        add("started by", first.process.parent_image)
        if not first.process.parent_image:
            doers = sorted(
                {started_in[e.process.guid] for e in members if e.process and e.process.guid in started_in} - {label},
                key=lambda name: int(name[1:]),
            )
            if doers:
                add("done by the processes started in", ", ".join(doers))
    add_varying("command line", lambda e: e.process.command_line if e.process else None)
    add_varying("decoded command (decoded by Aegis)",
                lambda e: decode_powershell(e.process.command_line) if e.process else None)
    add_varying("started by command line", lambda e: e.process.parent_command_line if e.process else None)
    add_varying("file", lambda e: e.file_path)
    add_varying("registry key", lambda e: e.registry_key)
    add_varying("registry value written", lambda e: e.registry_value)
    add_varying("log line", lambda e: e.message.splitlines()[0] if "full_log" in e.raw and e.message else None)
    if first.mitre.technique_ids:
        add("rule's ATT&CK", ", ".join(first.mitre.technique_ids))
    return lines


def _destination(event: Event) -> str | None:
    network = event.network
    if not network or not (network.dst_ip or network.dst_host):
        return None
    target = " / ".join(part for part in (network.dst_host, network.dst_ip) if part)
    return target + (f" port {network.dst_port}" if network.dst_port else "")


def _label_list(labels: list[str], limit: int = 12) -> str:
    if len(labels) <= limit:
        return ", ".join(labels)
    return ", ".join(labels[:limit]) + f" and {len(labels) - limit} more"


def _event_block(event: Event, label: str, links: list[str], multi_day: bool, width: int) -> list[str]:
    lines = [
        f"{label}  {_when(event, multi_day)}  level {event.rule.level}  "
        f"rule {event.rule.id}: {_clip(event.rule.description, 160)}"
    ]

    def add(name: str, value: object) -> None:
        if value not in (None, ""):
            lines.append(f"    {name}: {_clip(str(value), width)}")

    add("kind", event.category.value)
    if event.outcome is not Outcome.UNKNOWN:
        add("result", event.outcome.value)
    if event.user and event.target_user:
        add("account", f"{event.user} acting on {event.target_user}")
    else:
        add("account", event.user)
    network = event.network
    if network:
        if network.src_ip:
            add("from address", network.src_ip + (f" port {network.src_port}" if network.src_port else ""))
        if network.dst_ip or network.dst_host:
            target = " / ".join(part for part in (network.dst_host, network.dst_ip) if part)
            add("to address", target + (f" port {network.dst_port}" if network.dst_port else ""))
    process = event.process
    if process:
        add("program", process.image)
        add("command line", process.command_line)
        add("decoded command (decoded by Aegis)", decode_powershell(process.command_line))
        add("started by", process.parent_image)
        add("started by command line", process.parent_command_line)
    add("file", event.file_path)
    add("registry key", event.registry_key)
    add("registry value written", event.registry_value)
    if "full_log" in event.raw and event.message:
        add("log line", event.message.splitlines()[0])
    if event.mitre.technique_ids:
        add("rule's ATT&CK", ", ".join(event.mitre.technique_ids))
    if links:
        add("grouped because", "; ".join(links))
    return lines


def _context_line(event: Event, label: str, multi_day: bool, width: int) -> str:
    parts = [
        f"{label}  {_when(event, multi_day)}  level {event.rule.level}  "
        f"rule {event.rule.id}: {_clip(event.rule.description, 120)}"
    ]
    if event.user:
        parts.append(f"account: {event.user}")
    if event.process and event.process.image:
        parts.append(f"program: {event.process.image}")
    if event.process and event.process.command_line:
        parts.append(f"command line: {_clip(event.process.command_line, 140)}")
    if event.file_path:
        parts.append(f"file: {event.file_path}")
    if event.registry_value:
        parts.append(f"registry value written: {event.registry_value}")
    return _clip("  |  ".join(parts), width + 200)


def decode_powershell(command_line: str | None) -> str | None:
    """The script hidden in a PowerShell ``-EncodedCommand`` argument, if any.

    Decoding base64 is arithmetic, so code does it; a small model asked to
    read base64 would guess.
    """
    if not command_line or "powershell" not in command_line.lower():
        return None
    for match in _ENCODED_COMMAND.finditer(command_line):
        if not "encodedcommand".startswith(match.group(1).lower()):
            continue
        try:
            decoded = base64.b64decode(match.group(2), validate=True).decode("utf-16-le")
        except (binascii.Error, ValueError, UnicodeDecodeError):
            continue
        if decoded and all(char.isprintable() or char in "\r\n\t" for char in decoded):
            return decoded
    return None


def _when(event: Event, multi_day: bool) -> str:
    stamp = event.timestamp
    clock = f"{stamp:%H:%M:%S}.{stamp.microsecond // 1000:03d}"
    return f"{stamp:%m-%d} {clock}" if multi_day else clock


def _span(value: timedelta) -> str:
    seconds = int(value.total_seconds())
    if seconds < 60:
        return f"{seconds} s"
    minutes = seconds // 60
    return f"{minutes // 60} h {minutes % 60:02d} min" if minutes >= 60 else f"{minutes} min"


def _clip(text: str, width: int) -> str:
    text = " ".join(text.split())
    return text if len(text) <= width else text[: width - 3] + "..."


def incident_targets(incident: Incident, events: list[Event]) -> dict[str, dict[str, str]]:
    """For each action, the targets that really appear in the incident's events.

    Keys are normalized with ``target_key``; values are the target as written.
    """
    addresses: dict[str, str] = {}
    files: dict[str, str] = {}
    programs: dict[str, str] = {}
    for event in events:
        if event.network:
            for value in (event.network.src_ip, event.network.dst_ip):
                address = remote_address(value)
                if address:
                    addresses[address] = address
        if event.file_path:
            files[event.file_path.lower()] = event.file_path
        if event.process and event.process.image:
            programs[event.process.image.lower()] = event.process.image
    return {
        "lock_account": {account: account for account in incident.accounts},
        "block_ip": addresses,
        "kill_process": programs,
        "quarantine_file": files,
        "isolate_host": {incident.host.name.lower(): incident.host.name},
    }


def target_key(action: str, target: str) -> str:
    if action == "lock_account":
        return account_key(target) or ""
    if action == "block_ip":
        return remote_address(target) or ""
    return target.lower()
