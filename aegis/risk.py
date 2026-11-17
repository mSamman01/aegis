"""Risk score: how dangerous an incident is, worked out from evidence alone.

Fixed rules, each looking for something that happened - not for how alarming
a rule's name sounds. Every rule that fires adds points with a reason and the
events behind it, so a score can always be checked by reading those events.

The score never uses the model's verdict, and never uses operator notes: a
note says a pattern is usually harmless, and an attacker can imitate a
pattern (D21). A rule's level counts, but only up to 15 of 100 points (D11).

    score   0-24 low   25-49 medium   50-74 high   75-100 critical

Some rules also suggest an action (lock the account that was guessed, block
the address that guessed it). Suggestions are only candidates: the policy
decides what happens to them.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from datetime import timedelta
from typing import Callable, Iterable

from aegis.contracts.decision import RiskFactor, RiskScore, band_for
from aegis.contracts.event import Category, Event, Outcome
from aegis.contracts.incident import Incident
from aegis.correlate import account_key, remote_address
from aegis.evidence import decode_powershell

BRUTE_FORCE_FAILURES = 3  # failures before a success that make it a guessed password
MANY_FAILURES = 5
GUESS_WINDOW = timedelta(minutes=30)  # failures older than this before a success do not count

_CREDENTIAL_ACCESS = re.compile(
    r"/etc/(g?shadow|security/opasswd)\b"
    r"|\\config\\(SAM|SECURITY)\b"
    r"|\b(mimikatz|sekurlsa|lsadump)\b"
    r"|\blsass(\.exe|\.dmp)?\b.*\b(dump|minidump|-ma)\b"
    r"|\b(procdump|comsvcs)\b.*\blsass\b",
    re.IGNORECASE,
)
_CRITICAL_FILES = re.compile(
    r"^(/etc/(passwd|shadow|gshadow|group|sudoers)|/etc/sudoers\.d/.+|/etc/ssh/sshd_config"
    r"|/root/\.ssh/authorized_keys|/home/[^/]+/\.ssh/authorized_keys)$"
)
_SERVICE_IMAGE_PATH = re.compile(r"\\Services\\[^\\]+\\ImagePath$", re.IGNORECASE)
_RUN_KEY = re.compile(r"\\CurrentVersion\\(Run|RunOnce)\\", re.IGNORECASE)
_USER_WRITABLE = re.compile(r"\\Users\\|\\AppData\\|\\Temp\\|\\ProgramData\\|^/tmp/|^/dev/shm/|^/var/tmp/", re.IGNORECASE)
_SCRIPT_HOSTS = frozenset({
    "powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe",
    "mshta.exe", "rundll32.exe", "regsvr32.exe", "certutil.exe", "bitsadmin.exe",
})
_INTERNAL_NETWORKS = tuple(ipaddress.ip_network(n) for n in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "169.254.0.0/16",
    "::1/128", "fc00::/7", "fe80::/10",
))
_ACCOUNT_CREATED_IDS = {"4720"}
# Aegis's own way of acting on the lab VM (lab/aegis-gate). Running it through
# sudo is Aegis doing its job, recorded in the audit log - not someone
# becoming root. Only the exact command counts: anything else run with sudo,
# by any account, still does.
AEGIS_GATE = "/usr/local/sbin/aegis-gate"
_ACCOUNT_CREATED_GROUPS = {"adduser"}


@dataclass(frozen=True)
class Suggestion:
    action: str
    target: str
    reason: str
    evidence: tuple[str, ...]


@dataclass(frozen=True)
class Assessment:
    risk: RiskScore
    suggestions: tuple[Suggestion, ...]


def assess(incident: Incident, events: Iterable[Event]) -> Assessment:
    """Score one incident. ``events`` are the incident's own events."""
    events = sorted(events, key=lambda e: (e.timestamp, e.event_id))
    wanted = set(incident.event_ids)
    if {e.event_id for e in events} != wanted:
        raise ValueError("assess() needs exactly the incident's events")
    factors: list[RiskFactor] = []
    suggestions: list[Suggestion] = []
    for rule in RULES:
        for factor, suggested in rule(events):
            factors.append(factor)
            suggestions.extend(suggested)
    score = max(0, min(100, sum(f.points for f in factors)))
    return Assessment(RiskScore(score, band_for(score), tuple(factors)), tuple(_unique(suggestions)))


# --------------------------------------------------------------------------
# The rules. Each returns [(factor, [suggestions])].
# --------------------------------------------------------------------------

def rule_severity(events: list[Event]):
    top = max(events, key=lambda e: (e.rule.level, -e.timestamp.timestamp()))
    level = min(top.rule.level, 15)
    if level == 0:
        return []
    return [(RiskFactor("rule_level", level,
                        f"highest Wazuh rule level is {top.rule.level} (rule {top.rule.id}); "
                        "the level counts for at most 15 points", (top.event_id,)), [])]


def rule_password_guessing(events: list[Event]):
    """Failed logins from one remote address, and whether one then succeeded.

    A success counts as a guessed password only if it is a login to an account
    that was being guessed from that address, after at least three failures
    from it in the 30 minutes before. Someone else logging in from the same
    address - in the lab, the administrator on the same laptop - is not it.
    """
    found = []
    by_address: dict[str, list[Event]] = {}
    for event in events:
        if event.category is Category.AUTHENTICATION and event.network:
            address = remote_address(event.network.src_ip)
            if address:
                by_address.setdefault(address, []).append(event)
    for address, attempts in sorted(by_address.items()):
        all_failures = [e for e in attempts if e.outcome is Outcome.FAILURE]
        failures: list[Event] = []
        success = None
        for event in attempts:
            if event.outcome is not Outcome.SUCCESS:
                continue
            recent = [f for f in all_failures if event.timestamp - GUESS_WINDOW <= f.timestamp <= event.timestamp]
            guessed = {account_key(f.user) for f in recent} - {None}
            if len(recent) >= BRUTE_FORCE_FAILURES and account_key(event.user) in guessed:
                success, failures = event, recent
                break
        if success is None:
            failures = all_failures
        if success is not None:
            accounts = sorted({account_key(e.user) for e in failures if account_key(e.user)})
            who = account_key(success.user)
            evidence = tuple(e.event_id for e in failures) + (success.event_id,)
            suggested = [Suggestion("block_ip", address, f"{address} guessed passwords", evidence)]
            if who:
                suggested.insert(0, Suggestion("lock_account", who,
                                               f"the password of {who} was guessed from {address}",
                                               (success.event_id,)))
            found.append((RiskFactor(
                "password_guessed", 35,
                f"{len(failures)} failed logins from {address} (accounts: {', '.join(accounts) or 'unknown'}), "
                f"then a successful login as {success.user or 'an unknown account'}", evidence), suggested))
        elif len(failures) >= MANY_FAILURES:
            evidence = tuple(e.event_id for e in failures)
            found.append((RiskFactor(
                "password_guessing", 10, f"{len(failures)} failed logins from {address}, none succeeded",
                evidence), [Suggestion("block_ip", address, f"{address} is guessing passwords", evidence)]))
    return found


def rule_privilege(events: list[Event]):
    hits = [e for e in events
            if e.category is Category.AUTHENTICATION
            and (e.target_user or "").lower() in ("root", "administrator")
            and account_key(e.user)
            and {"sudo", "su"} & set(e.rule.groups)
            and not (e.process and (e.process.command_line or "").strip() == AEGIS_GATE)]
    if not hits:
        return []
    who = sorted({account_key(e.user) for e in hits})
    return [(RiskFactor("became_admin", 15, f"{', '.join(who)} switched to an administrator account",
                        tuple(e.event_id for e in hits)), [])]


def rule_credential_access(events: list[Event]):
    hits = [e for e in events if _CREDENTIAL_ACCESS.search(_text_of(e))]
    if not hits:
        return []
    return [(RiskFactor("credential_access", 25,
                        "password hashes or credential stores were read (for example /etc/shadow, SAM, LSASS)",
                        tuple(e.event_id for e in hits)), [])]


def rule_encoded_powershell(events: list[Event]):
    hits = [e for e in events if e.process and decode_powershell(e.process.command_line)]
    if not hits:
        return []
    return [(RiskFactor("hidden_command", 20, "PowerShell ran a base64-encoded command, which hides what it does",
                        tuple(e.event_id for e in hits)), [])]


def rule_outbound_script_host(events: list[Event]):
    hits = []
    for e in events:
        if not (e.network and e.network.dst_ip and e.process and e.process.image):
            continue
        if _basename(e.process.image) in _SCRIPT_HOSTS and _external(e.network.dst_ip):
            hits.append(e)
    if not hits:
        return []
    destinations = sorted({e.network.dst_host or e.network.dst_ip for e in hits})
    suggested = [Suggestion("block_ip", e.network.dst_ip, f"a script host connected to {e.network.dst_ip}",
                            (e.event_id,)) for e in hits]
    return [(RiskFactor("script_host_online", 15,
                        f"a command interpreter connected to the internet ({', '.join(destinations)})",
                        tuple(e.event_id for e in hits)), suggested)]


def rule_persistence(events: list[Event]):
    found = []
    services = [e for e in events if e.registry_key and _SERVICE_IMAGE_PATH.search(e.registry_key)
                and _USER_WRITABLE.search(e.registry_value or "")]
    run_keys = [e for e in events if e.registry_key and _RUN_KEY.search(e.registry_key)
                and _USER_WRITABLE.search(e.registry_value or "")]
    if services:
        found.append((RiskFactor("persistence", 25,
                                 "a Windows service was set to run a program from a folder any user can write to",
                                 tuple(e.event_id for e in services)), []))
    if run_keys:
        found.append((RiskFactor("persistence_run_key", 20,
                                 "a program in a user-writable folder was set to start at every logon",
                                 tuple(e.event_id for e in run_keys)), []))
    created = [e for e in events if e.category is Category.ACCOUNT and (
        _win_event_id(e) in _ACCOUNT_CREATED_IDS or _ACCOUNT_CREATED_GROUPS & set(e.rule.groups))]
    if created:
        found.append((RiskFactor("account_created", 15, "a new user account was created",
                                 tuple(e.event_id for e in created)), []))
    return found


def rule_critical_file(events: list[Event]):
    hits = [e for e in events if e.category is Category.FILE and e.file_path and _CRITICAL_FILES.match(e.file_path)]
    if not hits:
        return []
    files = sorted({e.file_path for e in hits})
    return [(RiskFactor("critical_file_changed", 20, f"a file that controls who can log in changed: {', '.join(files)}",
                        tuple(e.event_id for e in hits)), [])]


RULES: tuple[Callable, ...] = (
    rule_severity,
    rule_password_guessing,
    rule_privilege,
    rule_credential_access,
    rule_encoded_powershell,
    rule_outbound_script_host,
    rule_persistence,
    rule_critical_file,
)


# --------------------------------------------------------------------------

def _text_of(event: Event) -> str:
    parts = [event.file_path or ""]
    if event.process:
        parts += [event.process.command_line or "", event.process.image or ""]
    return "\n".join(parts)


def _basename(path: str) -> str:
    return path.replace("/", "\\").split("\\")[-1].lower()


def _external(address: str) -> bool:
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        return False
    return not ip.is_unspecified and not any(ip in network for network in _INTERNAL_NETWORKS)


def _win_event_id(event: Event) -> str:
    system = (event.raw.get("data") or {}).get("win", {}).get("system", {}) if isinstance(event.raw, dict) else {}
    return str(system.get("eventID", "")) if isinstance(system, dict) else ""


def _unique(suggestions: list[Suggestion]) -> list[Suggestion]:
    seen, out = set(), []
    for s in suggestions:
        key = (s.action, s.target.lower())
        if key not in seen:
            seen.add(key)
            out.append(s)
    return out
