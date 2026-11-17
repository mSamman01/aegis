"""The Incident contract.

An Incident is a group of Events on one host that belong to the same story,
plus the reason each event is in the group. It holds event ids, not copies of
events: the Events remain the evidence, the Incident says which ones go
together and why.

Rules of this contract:
  * ``incident_id`` is a hash of the member event ids. A different set of
    evidence is a different incident, so a verdict or an approval made for one
    incident can never silently apply to another set of events.
  * Every Link names two member events and the thing they share. "Why is this
    event here?" always has an answer that can be checked.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, fields
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Iterable, Mapping

from aegis.contracts.event import (
    _EVENT_ID_RE,
    ContractError,
    Host,
    _build,
    _plain,
    parse_ts,
)

INCIDENT_SCHEMA_VERSION = 1

_INCIDENT_ID_RE = re.compile(r"^inc-[0-9a-f]{16}$")


class LinkReason(str, Enum):
    """Why two events are in the same incident, strongest first."""

    SAME_PROCESS = "same_process"  # both come from one process
    PARENT_PROCESS = "parent_process"  # one process started the other
    SAME_PARENT = "same_parent_process"  # both started by one process
    SAME_SOURCE_IP = "same_source_ip"  # same remote address
    SAME_ACCOUNT = "same_account"  # same user account
    SAME_RULE = "same_rule"  # the same detection firing again


@dataclass(frozen=True)
class Link:
    event_id: str  # the later event
    linked_to: str  # an earlier event in the same incident
    reason: LinkReason
    value: str  # what they share: a process id, an address, an account, a rule id


@dataclass(frozen=True)
class RuleCount:
    rule_id: str
    level: int
    description: str
    count: int


@dataclass(frozen=True)
class Incident:
    incident_id: str  # "inc-" + 16 hex chars, from the member event ids
    host: Host
    first_seen: datetime  # event time of the earliest event, UTC
    last_seen: datetime  # event time of the latest event, UTC
    event_ids: tuple[str, ...]  # oldest first
    max_level: int
    title: str
    rules: tuple[RuleCount, ...] = ()  # most severe first
    categories: tuple[str, ...] = ()
    technique_ids: tuple[str, ...] = ()
    tactics: tuple[str, ...] = ()
    accounts: tuple[str, ...] = ()
    source_ips: tuple[str, ...] = ()
    processes: tuple[str, ...] = ()  # distinct program paths involved
    links: tuple[Link, ...] = ()
    schema_version: int = INCIDENT_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if not isinstance(self.incident_id, str) or not _INCIDENT_ID_RE.match(self.incident_id):
            raise ContractError(f"bad incident_id: {self.incident_id!r}")
        if not isinstance(self.host, Host) or not self.host.agent_id:
            raise ContractError("host with an agent_id is required")
        if not self.event_ids:
            raise ContractError("an incident needs at least one event")
        for event_id in self.event_ids:
            if not isinstance(event_id, str) or not _EVENT_ID_RE.match(event_id):
                raise ContractError(f"bad event id in incident: {event_id!r}")
        if len(set(self.event_ids)) != len(self.event_ids):
            raise ContractError("an event appears twice in the incident")
        if self.incident_id != incident_id_for(self.event_ids):
            raise ContractError("incident_id does not match the member events")
        for name in ("first_seen", "last_seen"):
            value = getattr(self, name)
            if not isinstance(value, datetime) or value.utcoffset() != timedelta(0):
                raise ContractError(f"{name} must be an aware UTC datetime")
        if self.first_seen > self.last_seen:
            raise ContractError("first_seen is after last_seen")
        level = self.max_level
        if isinstance(level, bool) or not isinstance(level, int) or not 0 <= level <= 16:
            raise ContractError(f"max_level must be an integer 0-16, got {level!r}")
        if self.rules:
            if sum(rule.count for rule in self.rules) != len(self.event_ids):
                raise ContractError("rule counts do not add up to the number of events")
            if max(rule.level for rule in self.rules) != level:
                raise ContractError("max_level does not match the rules")
        members = set(self.event_ids)
        for link in self.links:
            if not isinstance(link, Link) or not isinstance(link.reason, LinkReason):
                raise ContractError("links must be Link objects with a LinkReason")
            if link.event_id not in members or link.linked_to not in members:
                raise ContractError("a link points at an event outside the incident")
            if link.event_id == link.linked_to:
                raise ContractError("a link cannot join an event to itself")
        if self.schema_version != INCIDENT_SCHEMA_VERSION:
            raise ContractError(
                f"unsupported incident schema_version {self.schema_version!r} "
                f"(this build understands {INCIDENT_SCHEMA_VERSION})"
            )

    @property
    def duration(self) -> timedelta:
        return self.last_seen - self.first_seen

    def to_dict(self) -> dict[str, Any]:
        return _plain(self)

    @classmethod
    def from_dict(cls, data: Any) -> "Incident":
        if not isinstance(data, Mapping):
            raise ContractError("incident must be a JSON object")
        allowed = {f.name for f in fields(cls)}
        unknown = sorted(set(data) - allowed)
        if unknown:
            raise ContractError(f"unknown incident field(s): {', '.join(unknown)}")
        for key in ("incident_id", "host", "first_seen", "last_seen", "event_ids", "max_level", "title"):
            if key not in data:
                raise ContractError(f"missing required incident field: {key}")
        try:
            return cls(
                incident_id=data["incident_id"],
                host=_build(Host, data["host"]),
                first_seen=parse_ts(data["first_seen"]),
                last_seen=parse_ts(data["last_seen"]),
                event_ids=_strings(data["event_ids"], "event_ids"),
                max_level=data["max_level"],
                title=str(data["title"]),
                rules=tuple(_build(RuleCount, item) for item in _list(data.get("rules"), "rules")),
                categories=_strings(data.get("categories"), "categories"),
                technique_ids=_strings(data.get("technique_ids"), "technique_ids"),
                tactics=_strings(data.get("tactics"), "tactics"),
                accounts=_strings(data.get("accounts"), "accounts"),
                source_ips=_strings(data.get("source_ips"), "source_ips"),
                processes=_strings(data.get("processes"), "processes"),
                links=tuple(_link(item) for item in _list(data.get("links"), "links")),
                schema_version=data.get("schema_version", INCIDENT_SCHEMA_VERSION),
            )
        except ContractError:
            raise
        except (TypeError, ValueError) as exc:
            raise ContractError(f"invalid incident: {exc}") from exc


def incident_id_for(event_ids: Iterable[str]) -> str:
    """The id of the incident made of exactly these events (order-independent)."""
    basis = "\x1f".join(sorted(event_ids))
    return "inc-" + hashlib.sha256(basis.encode("utf-8")).hexdigest()[:16]


def _list(value: Any, name: str) -> list:
    if value is None:
        return []
    if not isinstance(value, (list, tuple)):
        raise ContractError(f"{name} must be a list")
    return list(value)


def _strings(value: Any, name: str) -> tuple[str, ...]:
    items = _list(value, name)
    if not all(isinstance(item, str) for item in items):
        raise ContractError(f"{name} must be a list of strings")
    return tuple(items)


def _link(data: Any) -> Link:
    if not isinstance(data, Mapping):
        raise ContractError("link must be a JSON object")
    link = _build(Link, data)
    try:
        return Link(link.event_id, link.linked_to, LinkReason(link.reason), str(link.value))
    except ValueError as exc:
        raise ContractError(f"invalid link: {exc}") from exc
