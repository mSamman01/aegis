"""Wazuh ingest: raw Wazuh alert JSON -> normalized Event.

Accepted input, auto-detected:
  * the manager's alert file (``/var/ossec/logs/alerts/alerts.json``):
    one JSON object per line
  * a JSON array of alerts
  * a Wazuh indexer / OpenSearch search response (``hits.hits[]._source``)

One rule above all: nothing is dropped silently. An alert that cannot be
normalized is reported as an IngestIssue with its position and the reason.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterator

from aegis.contracts.event import (
    Category,
    ContractError,
    Event,
    Host,
    Mitre,
    Network,
    Outcome,
    Process,
    Rule,
    format_ts,
    parse_ts,
)

SOURCE = "wazuh"

_SYSMON_PROVIDER = "Microsoft-Windows-Sysmon"

# Sysmon event id -> category
_SYSMON_CATEGORY = {
    1: Category.PROCESS,  # process creation
    5: Category.PROCESS,  # process terminated
    6: Category.PROCESS,  # driver loaded
    7: Category.PROCESS,  # image loaded
    8: Category.PROCESS,  # CreateRemoteThread
    10: Category.PROCESS,  # process access
    25: Category.PROCESS,  # process tampering
    3: Category.NETWORK,  # network connection
    22: Category.NETWORK,  # DNS query
    2: Category.FILE,  # file creation time changed
    11: Category.FILE,  # file created
    15: Category.FILE,  # file stream created
    23: Category.FILE,  # file delete (archived)
    26: Category.FILE,  # file delete (logged)
    12: Category.REGISTRY,
    13: Category.REGISTRY,
    14: Category.REGISTRY,
}

# Windows Security event ids that are about authentication
_WIN_AUTH_EVENT_IDS = {4624, 4625, 4634, 4647, 4648, 4672, 4740, 4768, 4769, 4771, 4776}
# ...the subset where targetUserName is the account logging on or off
_WIN_LOGON_EVENT_IDS = {4624, 4625, 4634, 4647, 4648, 4768, 4769, 4771, 4776}
# Windows Security event ids for user / group management
_WIN_ACCOUNT_EVENT_IDS = {
    4720, 4722, 4723, 4724, 4725, 4726, 4738, 4781,  # user accounts
    4727, 4728, 4729, 4730, 4731, 4732, 4733, 4734, 4735, 4737,  # groups
    4754, 4755, 4756, 4757, 4758,
}
_ACCOUNT_GROUPS = {"account_changed", "adduser", "addgroup", "group_changed", "win_group_changed"}

_AUTH_FAILURE_GROUPS = {
    "authentication_failed",
    "authentication_failures",
    "invalid_login",
    "win_authentication_failed",
}
_AUTH_SUCCESS_GROUPS = {"authentication_success"}
_AUTH_OTHER_GROUPS = {"sudo", "su", "pam"}

_SHA256_IN_HASHES = re.compile(r"SHA256=([0-9A-Fa-f]{64})")


class AlertError(ValueError):
    """A raw alert cannot be turned into an Event."""


@dataclass(frozen=True)
class IngestIssue:
    where: str  # "line 12", "item 3", ...
    reason: str


@dataclass
class IngestResult:
    events: list[Event] = field(default_factory=list)
    issues: list[IngestIssue] = field(default_factory=list)
    seen: int = 0  # alerts found in the input
    duplicates: int = 0  # same alert appearing more than once
    below_min_level: int = 0  # dropped by the --min-level filter


# --------------------------------------------------------------------------
# Reading the input
# --------------------------------------------------------------------------

def read_text(path: Path) -> str:
    """Read an export as text.

    PowerShell's ``>`` writes UTF-16, so both UTF-16 and UTF-8 (with or
    without a byte-order mark) are handled. Undecodable bytes raise instead
    of being replaced: evidence is never quietly altered.
    """
    data = Path(path).read_bytes()
    if data.startswith((b"\xff\xfe", b"\xfe\xff")):
        return data.decode("utf-16")
    return data.decode("utf-8-sig")


def iter_raw_alerts(text: str) -> Iterator[tuple[str, Any, str | None]]:
    """Yield ``(where, alert, error)`` for every alert found in ``text``.

    Exactly one of ``alert`` / ``error`` is set.
    """
    if not text.strip():
        return
    lines = [(n, ln) for n, ln in enumerate(text.splitlines(), 1) if ln.strip()]

    whole_first = text.lstrip().startswith("[") or _parse(lines[0][1]) is _INVALID
    if whole_first:
        document = _parse(text)
        if document is not _INVALID:
            yield from _unwrap(document, "")
            return

    for number, line in lines:
        obj = _parse(line)
        if obj is _INVALID:
            yield f"line {number}", None, "not valid JSON"
        else:
            yield from _unwrap(obj, f"line {number}")


_INVALID = object()


def _parse(text: str) -> Any:
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return _INVALID


def _unwrap(obj: Any, where: str) -> Iterator[tuple[str, Any, str | None]]:
    """Peel list / indexer-response / ``_source`` wrappers off an alert."""
    if isinstance(obj, list):
        for index, item in enumerate(obj, 1):
            yield from _unwrap(item, f"{where} item {index}".strip())
        return
    label = where or "item 1"
    if isinstance(obj, dict):
        hits = obj.get("hits")
        if isinstance(hits, dict) and isinstance(hits.get("hits"), list):
            yield from _unwrap(hits["hits"], where)
            return
        if isinstance(obj.get("_source"), dict):
            yield label, obj["_source"], None
            return
        yield label, obj, None
        return
    yield label, None, f"expected a JSON object, got {type(obj).__name__}"


# --------------------------------------------------------------------------
# Normalizing one alert
# --------------------------------------------------------------------------

def normalize_alert(raw: Any) -> Event:
    """Turn one raw Wazuh alert into an Event. Raises AlertError if it can't."""
    if not isinstance(raw, dict):
        raise AlertError("alert is not a JSON object")

    ts_raw = raw.get("timestamp") or raw.get("@timestamp")
    if not isinstance(ts_raw, str):
        raise AlertError("missing timestamp")
    try:
        observed_at = parse_ts(ts_raw)  # when the Wazuh manager processed it
    except ContractError as exc:
        raise AlertError(str(exc)) from exc

    rule_raw = raw.get("rule")
    if not isinstance(rule_raw, dict) or rule_raw.get("id") in (None, ""):
        raise AlertError("missing rule.id")
    level = rule_raw.get("level")
    if isinstance(level, bool) or not isinstance(level, int):
        raise AlertError(f"rule.level is not an integer: {level!r}")

    agent = raw.get("agent")
    if not isinstance(agent, dict) or agent.get("id") in (None, ""):
        raise AlertError("missing agent.id")

    data = _dict(raw.get("data"))
    win = _dict(data.get("win"))
    system = _dict(win.get("system"))
    eventdata = {k: _unescape_win(v) for k, v in _dict(win.get("eventdata")).items()}
    syscheck = _dict(raw.get("syscheck"))

    groups = _str_tuple(rule_raw.get("groups"))
    mitre_raw = _dict(rule_raw.get("mitre"))
    win_event_id = _to_int(system.get("eventID"))
    is_sysmon = system.get("providerName") == _SYSMON_PROVIDER

    is_security = not is_sysmon and win_event_id is not None and str(
        system.get("providerName") or ""
    ).endswith("Security-Auditing")
    user, target_user = _users(data, eventdata, win_event_id if is_security else None)
    source_ref = str(raw.get("id") or "")
    agent_id = str(agent["id"])

    try:
        return Event(
            event_id=_event_id(agent_id, source_ref, observed_at, raw),
            timestamp=_event_time(system, observed_at),
            observed_at=observed_at,
            source=SOURCE,
            source_ref=source_ref,
            host=Host(
                agent_id=agent_id,
                name=str(agent.get("name") or agent_id),
                ip=_text(agent.get("ip")),
            ),
            rule=Rule(
                id=str(rule_raw["id"]),
                level=level,
                description=_unescape_win(str(rule_raw.get("description") or "")),
                groups=groups,
            ),
            category=_category(groups, data, syscheck, win_event_id, is_sysmon),
            outcome=_outcome(groups, win_event_id, is_sysmon),
            mitre=Mitre(
                technique_ids=_str_tuple(mitre_raw.get("id")),
                tactics=_str_tuple(mitre_raw.get("tactic")),
                techniques=_str_tuple(mitre_raw.get("technique")),
            ),
            user=user,
            target_user=target_user,
            process=_process(data, eventdata),
            network=_network(data, eventdata),
            file_path=_text(syscheck.get("path")) or _text(eventdata.get("targetFilename")),
            registry_key=_text(eventdata.get("targetObject")) if is_sysmon else None,
            registry_value=_text(eventdata.get("details")) if is_sysmon else None,
            message=_text(raw.get("full_log")) or _text(system.get("message")) or "",
            raw=raw,
        )
    except ContractError as exc:
        raise AlertError(str(exc)) from exc


def _event_time(system: dict, observed_at: Any) -> Any:
    """When the activity happened on the machine.

    Windows events carry their own time (``systemTime``). The alert's
    ``timestamp`` is only when the manager processed it, which can be hours
    later if the agent was delivering a backlog. Without a usable event time
    (syslog lines have no year or timezone) the manager's time is used.
    """
    system_time = system.get("systemTime")
    if isinstance(system_time, str):
        try:
            return parse_ts(system_time)
        except ContractError:
            pass
    return observed_at


def _event_id(agent_id: str, source_ref: str, observed_at: Any, raw: dict) -> str:
    """Deterministic id: the same alert always hashes to the same event_id."""
    if source_ref:
        basis = "\x1f".join((SOURCE, agent_id, source_ref, format_ts(observed_at)))
    else:  # no alert id: fall back to the alert's full content
        basis = json.dumps(raw, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return "evt-" + hashlib.sha256(basis.encode("utf-8")).hexdigest()[:16]


def _category(
    groups: tuple[str, ...],
    data: dict,
    syscheck: dict,
    win_event_id: int | None,
    is_sysmon: bool,
) -> Category:
    gs = set(groups)
    if "sca" in gs or isinstance(data.get("sca"), dict):
        return Category.CONFIG_ASSESSMENT
    if "vulnerability-detector" in gs or isinstance(data.get("vulnerability"), dict):
        return Category.VULNERABILITY
    if "syscheck" in gs or syscheck:
        path = str(syscheck.get("path") or "")
        if "syscheck_registry" in gs or path.upper().startswith("HKEY_"):
            return Category.REGISTRY
        return Category.FILE
    if is_sysmon and win_event_id in _SYSMON_CATEGORY:
        return _SYSMON_CATEGORY[win_event_id]
    if gs & _ACCOUNT_GROUPS or (not is_sysmon and win_event_id in _WIN_ACCOUNT_EVENT_IDS):
        return Category.ACCOUNT
    if (
        gs & (_AUTH_FAILURE_GROUPS | _AUTH_SUCCESS_GROUPS | _AUTH_OTHER_GROUPS)
        or any(g.startswith("authentication_") for g in gs)
        or (not is_sysmon and win_event_id in _WIN_AUTH_EVENT_IDS)
    ):
        return Category.AUTHENTICATION
    return Category.OTHER


def _outcome(groups: tuple[str, ...], win_event_id: int | None, is_sysmon: bool) -> Outcome:
    gs = set(groups)
    if gs & _AUTH_FAILURE_GROUPS:
        return Outcome.FAILURE
    if gs & _AUTH_SUCCESS_GROUPS:
        return Outcome.SUCCESS
    if not is_sysmon and win_event_id == 4625:
        return Outcome.FAILURE
    if not is_sysmon and win_event_id == 4624:
        return Outcome.SUCCESS
    return Outcome.UNKNOWN


def _users(
    data: dict, eventdata: dict, security_event_id: int | None = None
) -> tuple[str | None, str | None]:
    """Return ``(user, target_user)``.

    ``user`` is the account acting or logging on; ``target_user`` is a second
    account being acted on (``root`` for a sudo to root, the changed account
    for "user account changed").

    Windows Security events name a *subject* (who did it) and a *target*.
    For logon and logoff events the target is the account logging on, and the
    subject is usually just the computer's own account, so it is ignored.
    """
    src = _text(data.get("srcuser"))
    dst = _text(data.get("dstuser"))
    if src and dst:
        return src, dst
    if src or dst:
        return src or dst, None

    subject = _text(eventdata.get("subjectUserName"))
    target = _text(eventdata.get("targetUserName"))
    if security_event_id in _WIN_LOGON_EVENT_IDS:
        return target, None
    if security_event_id is not None:
        if subject and target:
            return subject, target
        return subject or target, None
    return _text(eventdata.get("user")) or target or subject, None


def _process(data: dict, eventdata: dict) -> Process | None:
    hashes = _text(eventdata.get("hashes")) or ""
    sha = _SHA256_IN_HASHES.search(hashes)
    process = Process(
        image=_text(eventdata.get("image")),
        command_line=_text(eventdata.get("commandLine")) or _text(data.get("command")),
        parent_image=_text(eventdata.get("parentImage")),
        parent_command_line=_text(eventdata.get("parentCommandLine")),
        pid=_to_int(eventdata.get("processId")),
        sha256=sha.group(1).lower() if sha else None,
        guid=_guid(eventdata.get("processGuid")),
        parent_guid=_guid(eventdata.get("parentProcessGuid")),
    )
    return process if process != Process() else None


def _network(data: dict, eventdata: dict) -> Network | None:
    network = Network(
        src_ip=_text(data.get("srcip"))
        or _text(eventdata.get("ipAddress"))
        or _text(eventdata.get("sourceIp")),
        src_port=_first_int(data.get("srcport"), eventdata.get("ipPort"), eventdata.get("sourcePort")),
        dst_ip=_text(data.get("dstip")) or _text(eventdata.get("destinationIp")),
        dst_port=_first_int(data.get("dstport"), eventdata.get("destinationPort")),
        dst_host=_text(eventdata.get("destinationHostname")),
        protocol=_text(data.get("protocol")) or _text(eventdata.get("protocol")),
    )
    return network if network != Network() else None


# --------------------------------------------------------------------------
# Small value helpers
# --------------------------------------------------------------------------

def _guid(value: Any) -> str | None:
    """A Sysmon process id, or None.

    Sysmon writes an all-zero id when it does not know the process (for
    example a parent that had already exited). That is "unknown", not an id
    shared by every such event.
    """
    text = _text(value)
    if not text:
        return None
    guid = text.strip("{}").lower()
    return guid if guid.strip("0-") else None


def _dict(value: Any) -> dict:
    return value if isinstance(value, dict) else {}


def _text(value: Any) -> str | None:
    """A usable string, or None. Wazuh uses "-" and "" for 'no value'."""
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        value = str(value)
    if not isinstance(value, str):
        return None
    value = value.strip()
    return None if value in ("", "-") else value


def _to_int(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        try:
            return int(value.strip(), 10)
        except ValueError:
            return None
    return None


def _first_int(*values: Any) -> int | None:
    for value in values:
        number = _to_int(value)
        if number is not None:
            return number
    return None


def _str_tuple(value: Any) -> tuple[str, ...]:
    if isinstance(value, str):
        return (value,)
    if isinstance(value, list):
        return tuple(str(v) for v in value if isinstance(v, (str, int)) and not isinstance(v, bool))
    return ()


def _unescape_win(value: Any) -> Any:
    """Undo the extra escaping Wazuh leaves in Windows event fields.

    Wazuh writes a backslash as two backslashes and a double quote as
    backslash-quote, so ``C:\\\\Windows\\\\cmd.exe`` is really ``C:\\Windows\\cmd.exe``.
    If the value contains a backslash that is not part of such a pair, it was
    never escaped and is returned unchanged. The untouched original always
    stays in ``Event.raw``.
    """
    if not isinstance(value, str) or "\\" not in value:
        return value
    out = []
    index, length = 0, len(value)
    while index < length:
        char = value[index]
        if char != "\\":
            out.append(char)
            index += 1
            continue
        following = value[index + 1] if index + 1 < length else ""
        if following not in ("\\", '"'):
            return value  # a lone backslash: this value was never escaped
        out.append(following)
        index += 2
    return "".join(out)


# --------------------------------------------------------------------------
# Ingesting a whole export
# --------------------------------------------------------------------------

def ingest_text(text: str, min_level: int = 0) -> IngestResult:
    """Normalize every alert in ``text``. Events come back oldest first."""
    result = IngestResult()
    seen_ids: set[str] = set()
    for where, raw, error in iter_raw_alerts(text):
        result.seen += 1
        if error is not None:
            result.issues.append(IngestIssue(where, error))
            continue
        try:
            event = normalize_alert(raw)
        except AlertError as exc:
            result.issues.append(IngestIssue(where, str(exc)))
            continue
        if event.event_id in seen_ids:
            result.duplicates += 1
            continue
        seen_ids.add(event.event_id)
        if event.rule.level < min_level:
            result.below_min_level += 1
            continue
        result.events.append(event)
    result.events.sort(key=lambda e: (e.timestamp, e.event_id))
    return result


def ingest_file(path: Path | str, min_level: int = 0) -> IngestResult:
    return ingest_text(read_text(Path(path)), min_level=min_level)
