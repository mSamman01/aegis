"""Correlation: Events -> Incidents.

Two events on the same host go into the same incident when they share
something specific and happen within a time window of each other:

  1. the same process, a parent and its child, or two children of one parent
     (Sysmon's process ids make this exact)
  2. the same remote source address
  3. the same user account - only for events that carry no process identity,
     so that on a one-user PC "the same user" does not glue everything together
  4. the same rule firing again

Links chain: if A links to B and B links to C, all three are one incident.
Everything here is deterministic - the same events always give the same
incidents, with the same ids - and every link is recorded with its reason.

Posture findings (failed CIS checks, vulnerable packages) describe the state
of a machine, not something that happened, so they are set aside and never
become incidents.
"""

from __future__ import annotations

import ipaddress
import re
from collections import Counter
from dataclasses import dataclass, field
from datetime import timedelta
from typing import Iterable

from aegis.contracts.event import Category, Event
from aegis.contracts.incident import Incident, Link, LinkReason, RuleCount, incident_id_for

# Windows processes that start nearly everything. "Started by services.exe"
# says nothing about two programs being related, so these never link their
# children to each other. (Their own actions are still linked normally.)
HUB_PROCESSES = frozenset(
    {
        "services.exe",
        "svchost.exe",
        "explorer.exe",
        "wininit.exe",
        "winlogon.exe",
        "userinit.exe",
        "smss.exe",
        "csrss.exe",
        "lsass.exe",
        "sihost.exe",
        "taskhostw.exe",
        "runtimebroker.exe",
    }
)

# Accounts shared by the operating system itself. They are not "a user".
_SYSTEM_ACCOUNT = re.compile(
    r"^(system|local service|network service|anonymous logon|"
    r"dwm-\d+|umfd-\d+|"  # Windows desktop / font driver accounts
    r".*\$|"  # computer accounts end in $
    r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})$"  # virtual accounts
)

# Strongest first: when two events share several things, the strongest is kept.
_STRENGTH = [
    LinkReason.SAME_PROCESS,
    LinkReason.PARENT_PROCESS,
    LinkReason.SAME_PARENT,
    LinkReason.SAME_SOURCE_IP,
    LinkReason.SAME_ACCOUNT,
    LinkReason.SAME_RULE,
]

_SELF, _CHILD = "self", "child"


@dataclass(frozen=True)
class CorrelationConfig:
    window: timedelta = timedelta(minutes=30)
    hub_processes: frozenset = HUB_PROCESSES
    posture_categories: frozenset = frozenset(
        {Category.CONFIG_ASSESSMENT, Category.VULNERABILITY}
    )

    def __post_init__(self) -> None:
        if self.window <= timedelta(0):
            raise ValueError("the correlation window must be positive")


@dataclass
class CorrelationResult:
    incidents: list[Incident] = field(default_factory=list)  # most severe first
    posture_event_ids: list[str] = field(default_factory=list)
    events_in: int = 0
    duplicates: int = 0


def account_key(name: str | None) -> str | None:
    """Normalize an account name for matching; None for system accounts.

    ``WIN-LAPTOP\\labuser`` and ``labuser`` are the same account.
    """
    if not name:
        return None
    short = name.replace("/", "\\").split("\\")[-1].strip().lower()
    if not short or _SYSTEM_ACCOUNT.match(short):
        return None
    return short


def remote_address(value: str | None) -> str | None:
    """A source address worth linking on; None for loopback / empty ones."""
    if not value:
        return None
    try:
        address = ipaddress.ip_address(value.strip())
    except ValueError:
        return None
    if address.is_loopback or address.is_unspecified:
        return None
    return str(address)


def correlate(events: Iterable[Event], config: CorrelationConfig | None = None) -> CorrelationResult:
    config = config or CorrelationConfig()
    result = CorrelationResult()

    # Oldest first, with the event id as a tie-break so the order is fixed.
    ordered: list[Event] = []
    seen: set[str] = set()
    for event in sorted(events, key=lambda e: (e.timestamp, e.event_id)):
        result.events_in += 1
        if event.event_id in seen:
            result.duplicates += 1
        elif event.category in config.posture_categories:
            seen.add(event.event_id)
            result.posture_event_ids.append(event.event_id)
        else:
            seen.add(event.event_id)
            ordered.append(event)

    # Union-find: every event starts as its own group; a link merges two groups.
    group = list(range(len(ordered)))

    def find(index: int) -> int:
        while group[index] != index:
            group[index] = group[group[index]]
            index = group[index]
        return index

    last_seen: dict[tuple, tuple[int, str | None]] = {}
    links: dict[int, dict[int, tuple[LinkReason, str]]] = {}

    for index, event in enumerate(ordered):
        for kind, value, role in _keys(event, config):
            key = (event.host.agent_id, kind, value)
            earlier = last_seen.get(key)
            if earlier is not None:
                other, other_role = earlier
                if event.timestamp - ordered[other].timestamp <= config.window:
                    reason = _reason(kind, role, other_role)
                    kept = links.setdefault(index, {}).get(other)
                    if kept is None or _STRENGTH.index(reason) < _STRENGTH.index(kept[0]):
                        links[index][other] = (reason, value)
                    group[find(index)] = find(other)
            last_seen[key] = (index, role)

    members: dict[int, list[int]] = {}
    for index in range(len(ordered)):
        members.setdefault(find(index), []).append(index)

    for indexes in members.values():
        result.incidents.append(_incident([ordered[i] for i in indexes], indexes, ordered, links))
    result.incidents.sort(
        key=lambda inc: (-inc.max_level, -len(inc.event_ids), inc.first_seen, inc.incident_id)
    )
    return result


def _keys(event: Event, config: CorrelationConfig) -> list[tuple[str, str, str | None]]:
    """The things an event can be linked on: ``(kind, value, role)``."""
    keys: list[tuple[str, str, str | None]] = []
    process = event.process
    has_process_identity = bool(process and process.guid)
    if process and process.guid:
        keys.append(("process", process.guid, _SELF))
    if process and process.parent_guid:
        parent_name = _basename(process.parent_image)
        if parent_name not in config.hub_processes:
            keys.append(("process", process.parent_guid, _CHILD))
    address = remote_address(event.network.src_ip if event.network else None)
    if address:
        keys.append(("address", address, None))
    if not has_process_identity:
        for account in sorted({account_key(event.user), account_key(event.target_user)} - {None}):
            keys.append(("account", account, None))
    keys.append(("rule", event.rule.id, None))
    return keys


def _reason(kind: str, role: str | None, other_role: str | None) -> LinkReason:
    if kind == "process":
        if role == _SELF and other_role == _SELF:
            return LinkReason.SAME_PROCESS
        if role == _CHILD and other_role == _CHILD:
            return LinkReason.SAME_PARENT
        return LinkReason.PARENT_PROCESS
    if kind == "address":
        return LinkReason.SAME_SOURCE_IP
    if kind == "account":
        return LinkReason.SAME_ACCOUNT
    return LinkReason.SAME_RULE


def _incident(
    events: list[Event],
    indexes: list[int],
    ordered: list[Event],
    links: dict[int, dict[int, tuple[LinkReason, str]]],
) -> Incident:
    counts = Counter(event.rule.id for event in events)
    by_rule = {event.rule.id: event.rule for event in events}
    rules = tuple(
        sorted(
            (
                RuleCount(rule_id, by_rule[rule_id].level, by_rule[rule_id].description, count)
                for rule_id, count in counts.items()
            ),
            key=lambda rule: (-rule.level, -rule.count, rule.rule_id),
        )
    )
    incident_links = tuple(
        Link(ordered[index].event_id, ordered[other].event_id, reason, value)
        for index in indexes
        for other, (reason, value) in sorted(links.get(index, {}).items())
    )
    event_ids = tuple(event.event_id for event in events)
    return Incident(
        incident_id=incident_id_for(event_ids),
        host=events[0].host,
        first_seen=events[0].timestamp,
        last_seen=events[-1].timestamp,
        event_ids=event_ids,
        max_level=rules[0].level,
        title=_title(rules, len(events)),
        rules=rules,
        categories=_distinct(event.category.value for event in events),
        technique_ids=_distinct(t for event in events for t in event.mitre.technique_ids),
        tactics=_distinct(t for event in events for t in event.mitre.tactics),
        accounts=_distinct(
            account
            for event in events
            for account in (account_key(event.user), account_key(event.target_user))
            if account
        ),
        source_ips=_distinct(
            address
            for event in events
            for address in [remote_address(event.network.src_ip if event.network else None)]
            if address
        ),
        processes=_distinct(
            event.process.image for event in events if event.process and event.process.image
        ),
        links=incident_links,
    )


def _title(rules: tuple[RuleCount, ...], event_count: int) -> str:
    top = rules[0]
    if event_count == 1:
        return top.description
    if len(rules) == 1:
        return f"{top.description} (x{event_count})"
    others = event_count - top.count
    noun = "event" if others == 1 else "events"
    return f"{top.description} (+{others} related {noun}, {len(rules)} rules)"


def _distinct(values: Iterable[str]) -> tuple[str, ...]:
    return tuple(sorted(set(values)))


def _basename(path: str | None) -> str:
    return (path or "").replace("/", "\\").split("\\")[-1].lower()
