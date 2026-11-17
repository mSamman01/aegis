"""The normalized Event contract.

An Event is one security-relevant observation (one Wazuh alert, today) in a
fixed shape. Every later stage - correlation, the AI investigator, the policy
engine, the audit log - works with Events and refers to them by ``event_id``.
Nothing downstream reads raw Wazuh JSON, so a change in Wazuh's format only
ever touches the ingest stage.

Rules of this contract:
  * ``event_id`` is deterministic: the same alert always gets the same id, so
    an id written in a verdict or an audit log can be checked later.
  * Timestamps are timezone-aware and stored in UTC. ``timestamp`` is when
    the activity happened on the machine; ``observed_at`` is when the source
    system (the Wazuh manager) processed it. They can be hours apart: an
    agent that was offline delivers its backlog when it reconnects.
  * ``raw`` keeps the original alert untouched. Normalized fields are a
    convenience; ``raw`` is the evidence.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field, fields, is_dataclass
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any, Mapping

SCHEMA_VERSION = 1

_EVENT_ID_RE = re.compile(r"^evt-[0-9a-f]{16}$")
_TS_RE = re.compile(
    r"^(\d{4}-\d{2}-\d{2})[T ](\d{2}:\d{2}:\d{2})(?:\.(\d+))?(Z|[+-]\d{2}:?\d{2})?$"
)


class ContractError(ValueError):
    """Raised when data does not satisfy the Event contract."""


class Category(str, Enum):
    """What kind of activity the event describes."""

    AUTHENTICATION = "authentication"  # logons, logoffs, sudo/su, credential use
    PROCESS = "process"  # process start, injection, image load
    NETWORK = "network"  # connections, DNS lookups
    FILE = "file"  # file created / changed / deleted
    REGISTRY = "registry"  # Windows registry changes
    ACCOUNT = "account"  # users / groups created, changed, deleted
    CONFIG_ASSESSMENT = "config_assessment"  # SCA / CIS benchmark results
    VULNERABILITY = "vulnerability"  # a vulnerable package was found
    OTHER = "other"


class Outcome(str, Enum):
    """Result of the activity. Only meaningful for authentication events."""

    SUCCESS = "success"
    FAILURE = "failure"
    UNKNOWN = "unknown"


# --------------------------------------------------------------------------
# Timestamps
# --------------------------------------------------------------------------

def parse_ts(value: str) -> datetime:
    """Parse an ISO-8601 timestamp into an aware UTC datetime.

    Accepts the forms Wazuh produces: ``2026-11-14T21:14:02.123+0300`` (alert
    files), ``2026-11-14T18:14:02.123Z`` (indexer) and ``+03:00`` offsets.
    A timestamp with no offset is rejected: evidence must not have an
    ambiguous time.
    """
    if not isinstance(value, str):
        raise ContractError(f"timestamp must be a string, got {type(value).__name__}")
    match = _TS_RE.match(value.strip())
    if not match:
        raise ContractError(f"unrecognized timestamp: {value!r}")
    date_part, time_part, fraction, offset = match.groups()
    if offset is None:
        raise ContractError(f"timestamp has no timezone offset: {value!r}")
    try:
        naive = datetime.strptime(f"{date_part} {time_part}", "%Y-%m-%d %H:%M:%S")
    except ValueError as exc:
        raise ContractError(f"invalid timestamp: {value!r}") from exc
    micro = int((fraction or "0")[:6].ljust(6, "0"))
    if offset == "Z":
        tz = timezone.utc
    else:
        sign = -1 if offset[0] == "-" else 1
        digits = offset[1:].replace(":", "")
        tz = timezone(sign * timedelta(hours=int(digits[:2]), minutes=int(digits[2:])))
    return naive.replace(microsecond=micro, tzinfo=tz).astimezone(timezone.utc)


def format_ts(value: datetime) -> str:
    """Format an aware datetime as UTC ISO-8601, exact to the microsecond.

    Full precision matters: Windows logs many events within one millisecond,
    and their order is evidence.
    """
    if value.tzinfo is None:
        raise ContractError("cannot format a timestamp without a timezone")
    text = value.astimezone(timezone.utc).isoformat(timespec="microseconds")
    return text.replace("+00:00", "Z")


# --------------------------------------------------------------------------
# Parts of an event
# --------------------------------------------------------------------------

@dataclass(frozen=True)
class Host:
    """The monitored machine the event came from (a Wazuh agent)."""

    agent_id: str
    name: str
    ip: str | None = None


@dataclass(frozen=True)
class Rule:
    """The detection rule that fired."""

    id: str
    level: int  # Wazuh severity, 0 (noise) to 15 (critical)
    description: str
    groups: tuple[str, ...] = ()


@dataclass(frozen=True)
class Mitre:
    """MITRE ATT&CK mapping supplied by the rule, if any."""

    technique_ids: tuple[str, ...] = ()
    tactics: tuple[str, ...] = ()
    techniques: tuple[str, ...] = ()


@dataclass(frozen=True)
class Process:
    image: str | None = None
    command_line: str | None = None
    parent_image: str | None = None
    parent_command_line: str | None = None
    pid: int | None = None
    sha256: str | None = None
    # Sysmon gives every process a unique id. Unlike a pid it is never
    # reused, so it links a process to its children and to what it touched.
    guid: str | None = None
    parent_guid: str | None = None


@dataclass(frozen=True)
class Network:
    src_ip: str | None = None
    src_port: int | None = None
    dst_ip: str | None = None
    dst_port: int | None = None
    dst_host: str | None = None
    protocol: str | None = None


# --------------------------------------------------------------------------
# The event
# --------------------------------------------------------------------------

@dataclass(frozen=True)
class Event:
    event_id: str  # "evt-" + 16 hex chars, deterministic
    timestamp: datetime  # when it happened; aware, UTC
    source: str  # which system produced it, e.g. "wazuh"
    source_ref: str  # the id of the record in that system
    host: Host
    rule: Rule
    category: Category
    outcome: Outcome = Outcome.UNKNOWN
    mitre: Mitre = field(default_factory=Mitre)
    user: str | None = None  # the account acting / logging on
    target_user: str | None = None  # e.g. "root" for a sudo to root
    process: Process | None = None
    network: Network | None = None
    file_path: str | None = None
    registry_key: str | None = None
    registry_value: str | None = None  # what was written to the key
    observed_at: datetime | None = None  # when the source system processed it
    message: str = ""  # the original log line, when there is one
    raw: Mapping[str, Any] = field(default_factory=dict)
    schema_version: int = SCHEMA_VERSION

    def __post_init__(self) -> None:
        if not isinstance(self.event_id, str) or not _EVENT_ID_RE.match(self.event_id):
            raise ContractError(f"bad event_id: {self.event_id!r}")
        if not isinstance(self.timestamp, datetime) or self.timestamp.tzinfo is None:
            raise ContractError("timestamp must be a timezone-aware datetime")
        if self.timestamp.utcoffset() != timedelta(0):
            raise ContractError("timestamp must be in UTC")
        if self.observed_at is not None and (
            not isinstance(self.observed_at, datetime)
            or self.observed_at.utcoffset() != timedelta(0)
        ):
            raise ContractError("observed_at must be an aware UTC datetime")
        if not isinstance(self.source, str) or not self.source:
            raise ContractError("source must be a non-empty string")
        if not isinstance(self.host, Host) or not self.host.agent_id:
            raise ContractError("host with an agent_id is required")
        if not isinstance(self.rule, Rule) or not self.rule.id:
            raise ContractError("rule with an id is required")
        level = self.rule.level
        if isinstance(level, bool) or not isinstance(level, int) or not 0 <= level <= 16:
            raise ContractError(f"rule level must be an integer 0-16, got {level!r}")
        if not isinstance(self.category, Category):
            raise ContractError("category must be a Category")
        if not isinstance(self.outcome, Outcome):
            raise ContractError("outcome must be an Outcome")
        if self.schema_version != SCHEMA_VERSION:
            raise ContractError(
                f"unsupported schema_version {self.schema_version!r} "
                f"(this build understands {SCHEMA_VERSION})"
            )

    @property
    def delay(self) -> timedelta | None:
        """How long after it happened the source system processed the event."""
        if self.observed_at is None:
            return None
        return self.observed_at - self.timestamp

    def to_dict(self) -> dict[str, Any]:
        """Plain JSON-ready dict. ``Event.from_dict(e.to_dict()) == e``."""
        return _plain(self)

    @classmethod
    def from_dict(cls, data: Any) -> "Event":
        """Build an Event from a dict, rejecting anything off-contract."""
        if not isinstance(data, Mapping):
            raise ContractError("event must be a JSON object")
        allowed = {f.name for f in fields(cls)}
        unknown = sorted(set(data) - allowed)
        if unknown:
            raise ContractError(f"unknown event field(s): {', '.join(unknown)}")
        for key in ("event_id", "timestamp", "source", "host", "rule", "category"):
            if key not in data:
                raise ContractError(f"missing required event field: {key}")
        try:
            return cls(
                event_id=data["event_id"],
                timestamp=parse_ts(data["timestamp"]),
                source=data["source"],
                source_ref=str(data.get("source_ref", "")),
                host=_build(Host, data["host"]),
                rule=_build(Rule, data["rule"]),
                category=Category(data["category"]),
                outcome=Outcome(data.get("outcome", Outcome.UNKNOWN.value)),
                mitre=_build(Mitre, data.get("mitre") or {}),
                user=data.get("user"),
                target_user=data.get("target_user"),
                process=_build(Process, data["process"]) if data.get("process") else None,
                network=_build(Network, data["network"]) if data.get("network") else None,
                file_path=data.get("file_path"),
                registry_key=data.get("registry_key"),
                registry_value=data.get("registry_value"),
                observed_at=parse_ts(data["observed_at"]) if data.get("observed_at") else None,
                message=data.get("message", ""),
                raw=data.get("raw") or {},
                schema_version=data.get("schema_version", SCHEMA_VERSION),
            )
        except ContractError:
            raise
        except (TypeError, ValueError) as exc:
            raise ContractError(f"invalid event: {exc}") from exc


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------

def _build(cls: type, data: Any) -> Any:
    """Build one of the small part-dataclasses from a dict, strictly."""
    if not isinstance(data, Mapping):
        raise ContractError(f"{cls.__name__.lower()} must be a JSON object")
    allowed = {f.name: f for f in fields(cls)}
    unknown = sorted(set(data) - set(allowed))
    if unknown:
        raise ContractError(
            f"unknown {cls.__name__.lower()} field(s): {', '.join(unknown)}"
        )
    kwargs = {}
    for name, value in data.items():
        # JSON has no tuples; list-valued fields come back as lists.
        kwargs[name] = tuple(value) if isinstance(value, list) else value
    try:
        return cls(**kwargs)
    except TypeError as exc:
        raise ContractError(f"invalid {cls.__name__.lower()}: {exc}") from exc


def _plain(value: Any) -> Any:
    """Recursively convert dataclasses / enums / datetimes to JSON types."""
    if is_dataclass(value) and not isinstance(value, type):
        return {f.name: _plain(getattr(value, f.name)) for f in fields(value)}
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, datetime):
        return format_ts(value)
    if isinstance(value, Mapping):
        return {str(k): _plain(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_plain(v) for v in value]
    return value
