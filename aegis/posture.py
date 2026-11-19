"""Posture advice for one PC: its weak spots, ranked, with fix steps - all worked out by code.

Input: the file lab/aegis-posture writes on the Wazuh manager (the agent's CIS
checks and the vulnerability alerts with their bounds). Output: advice. Aegis
never applies a fix: on the laptop the policy denies every action (D7), and
nothing in this module can change anything on any machine.

No model is used (D47). Everything a model would write here, code can work
out exactly from Wazuh's own data:

  * programs: the version that fixes every CVE of a program is arithmetic over
    Wazuh's bounds ("Package less than 3.13.14", "... less than or equal to 3.14.4")
  * CIS checks: the registry value a check tests is in its rule; code turns it
    into one `reg add` command, only where the value's type is known, and
    checks that the value it writes satisfies the check's own rule
  * ranking: fixed points, each with its reason, like the risk score (D27)

Wazuh's data comes over the network and is treated as untrusted text (D16):
names that are not safe in a command get no command, every step goes through
the checker (which drops anything that would weaken the PC), links are kept
only to known sites, and a shareable copy is refused while a name it should
hide survives.
"""

from __future__ import annotations

import hashlib
import json
import re
import threading
from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Sequence

EXPORT_FORMAT = 1
TOP = 10
POSTURE_DIR = Path(__file__).resolve().parent.parent / "data" / "posture"  # real exports (git-ignored, D8)
STALE_DAYS = 7  # the dashboard flags an export older than this

# --------------------------------------------------------------------------
# Data, as read from the export
# --------------------------------------------------------------------------


class PostureError(ValueError):
    """The export cannot be used."""


@dataclass(frozen=True)
class Cve:
    id: str
    severity: str
    score: float | None
    condition: str  # Wazuh's bound, e.g. "Package less than 3.13.14"
    network: bool = False  # attack vector NETWORK
    no_privileges: bool = False  # privileges required NONE
    no_interaction: bool = False  # user interaction NONE
    vector_known: bool = False  # the CVSS vector was in Wazuh's data (the alerts have it, the inventory not)
    under_evaluation: bool = False  # NVD has not scored it yet


@dataclass(frozen=True)
class Bound:
    """The version that fixes every CVE of a program, worked out from Wazuh's conditions."""

    version: str | None  # None: no condition could be read
    newer_than: bool = False  # True: this version is itself affected; a newer one is needed
    unread: tuple = ()  # CVEs whose condition could not be read
    dated: tuple = ()  # CVEs whose bound is a build date, which does not compare with the installed version

    def text(self) -> str:
        if self.version is None:
            if self.dated:
                return ("its latest version (Wazuh gives the bounds as build dates, which cannot be compared with "
                        "the version Windows lists)")
            return "no fixed version is known (Wazuh gave no bound Aegis can read)"
        text = f"a version newer than {self.version}" if self.newer_than else f"version {self.version} or newer"
        if self.dated:
            text += (f"; for {len(self.dated)} more CVE{'s' if len(self.dated) != 1 else ''} Wazuh gives a build "
                     "date, which cannot be compared with the version Windows lists, so make sure it is fully up "
                     "to date")
        return text


@dataclass(frozen=True)
class Program:
    name: str
    version: str
    cves: tuple
    bound: Bound
    type: str = ""  # Wazuh's package type: win, pypi, npm ...


@dataclass(frozen=True)
class Target:
    """The one registry value a CIS check tests, and what it must hold."""

    key: str  # as Wazuh writes it, e.g. HKEY_LOCAL_MACHINE\SOFTWARE\Policies\...
    value: str
    kind: str  # "literal", "compare" or "choice"
    literal: str | None = None
    op: str | None = None
    number: int | None = None
    choices: tuple = ()

    def wanted(self) -> str:
        if self.kind == "literal":
            return self.literal or ""
        if self.kind == "compare":
            return f"{self.op} {self.number}"
        return " or ".join(self.choices)

    def satisfied_by(self, data: str) -> bool:
        """Does ``data`` pass the check's rule? The same test Wazuh's SCA applies."""
        if self.kind == "literal":
            return data == self.literal
        if self.kind == "choice":
            return data in self.choices
        match = re.match(r"^(\d+)", data)
        if not match:
            return False
        number = int(match.group(1))
        return {"<": number < self.number, "<=": number <= self.number, ">": number > self.number,
                ">=": number >= self.number, "==": number == self.number, "!=": number != self.number}[self.op]


@dataclass(frozen=True)
class Check:
    policy: str
    id: int
    cis: str  # the CIS section, e.g. 18.10.43.5.1
    title: str
    rationale: str
    remediation: str
    references: tuple
    targets: tuple  # the registry values the check tests; () if its rules are not that simple
    why_no_target: str = ""


@dataclass(frozen=True)
class Posture:
    agent_id: str
    agent_name: str
    os_name: str
    made_at: str
    policy: dict  # name, score, pass, fail, invalid, total
    checks: tuple  # the failed checks
    programs: tuple
    passed: int
    solved: int  # CVEs the alerts say were solved since
    problems: tuple  # from the export, and from reading it


def load(path: Path | str) -> Posture:
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8-sig"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise PostureError(f"{path}: cannot be read as JSON ({exc})") from exc
    if not isinstance(data, dict) or data.get("aegis_posture_export") != EXPORT_FORMAT:
        raise PostureError(f"{path}: not a file written by lab/aegis-posture (format {EXPORT_FORMAT})")
    return read_export(data)


def read_export(data: dict) -> Posture:
    problems = [str(p) for p in data.get("problems") or []]
    agent = data.get("agent") if isinstance(data.get("agent"), dict) else {}
    os_info = agent.get("os") if isinstance(agent.get("os"), dict) else {}
    policies = [p for p in data.get("sca_policies") or [] if isinstance(p, dict)]
    policy = {}
    if policies:
        first = policies[0]
        policy = {key: first.get(key) for key in ("policy_id", "name", "score", "pass", "fail", "invalid",
                                                  "total_checks", "end_scan")}
        if len(policies) > 1:
            problems.append(f"{len(policies)} SCA policies; the advice covers every failed check of all of them")
    checks, passed = [], 0
    for policy_id, items in (data.get("sca_checks") or {}).items():
        for item in items if isinstance(items, list) else []:
            if not isinstance(item, dict):
                continue
            result = str(item.get("result") or "").lower()
            if result == "passed":
                passed += 1
            elif result == "failed":
                try:
                    checks.append(read_check(str(policy_id), item))
                except (TypeError, ValueError) as exc:
                    problems.append(f"SCA check {item.get('id')!r} could not be read: {exc}")
    programs, solved, more = read_programs(data.get("vulnerability_alerts") or [], data.get("vulnerabilities") or [])
    problems += more
    return Posture(
        agent_id=str(data.get("agent_id") or agent.get("id") or ""),
        agent_name=str(agent.get("name") or ""),
        os_name=str(os_info.get("name") or ""),
        made_at=str(data.get("made_at") or ""),
        policy=policy,
        checks=tuple(sorted(checks, key=lambda c: c.id)),
        programs=tuple(programs),
        passed=passed,
        solved=solved,
        problems=tuple(problems),
    )


# --------------------------------------------------------------------------
# Programs: CVEs and the version that fixes all of them
# --------------------------------------------------------------------------

_CONDITION = re.compile(r"^package\s+(less than or equal to|less than|equal to)\s+([0-9][0-9A-Za-z.+-]*)$", re.I)
_DATE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
_RANGE = re.compile(r"^package\s+greater than(?: or equal to)?\s+\S+\s+and\s+(less than or equal to|less than)\s+"
                    r"([0-9][0-9A-Za-z.+-]*)$", re.I)


def version_key(version: str) -> tuple:
    """Compare versions part by part, numbers as numbers: 3.13.14 > 3.13.9; 26.2 == 26.2.0."""
    parts = []
    for piece in re.split(r"[.+-]", version.strip()):
        match = re.match(r"^(\d+)(.*)$", piece)
        parts.append((int(match.group(1)), match.group(2)) if match else (-1, piece))
    while parts and parts[-1] == (0, ""):
        parts.pop()
    return tuple(parts)


def read_condition(text: str) -> tuple[str, bool] | None:
    """Wazuh's bound as (version, version itself affected). None if it is not one Aegis can read.

    "less than X": X is fixed. "less than or equal to X" and "equal to X": X is affected, a newer one is not.
    """
    text = " ".join(str(text or "").split())
    match = _CONDITION.match(text) or _RANGE.match(text)
    if not match:
        return None
    return match.group(2), match.group(1).lower().endswith("equal to")


def comparable(condition: str, installed: str) -> bool:
    """False when the bound is a build date and the installed version is not (or the other way round)."""
    read = read_condition(condition)
    return read is not None and bool(_DATE.match(read[0])) == bool(_DATE.match(installed.strip()))


def fixing_bound(conditions: Iterable[tuple[str, str]], installed: str = "") -> Bound:
    """The lowest version that is outside every condition. ``conditions``: (cve, condition text)."""
    best: tuple | None = None  # (version key, newer_than, version)
    unread, dated = [], []
    for cve, text in conditions:
        read = read_condition(text)
        if read is None:
            unread.append(cve)
            continue
        if installed and not comparable(text, installed):
            dated.append(cve)
            continue
        version, inclusive = read
        candidate = (version_key(version), inclusive, version)
        if best is None or candidate[:2] > best[:2]:
            best = candidate
    if best is None:
        return Bound(None, unread=tuple(unread), dated=tuple(dated))
    return Bound(best[2], best[1], tuple(unread), tuple(dated))


def fixes(bound: Bound, condition: str) -> bool:
    """True if every version the bound allows is outside ``condition`` (the evaluation checks this)."""
    read = read_condition(condition)
    if bound.version is None or read is None:
        return False
    version, inclusive = read
    have, limit = version_key(bound.version), version_key(version)
    if inclusive:  # affected up to and including `version`
        return have > limit or (have == limit and bound.newer_than)
    return have >= limit  # affected below `version`


def read_programs(alerts: Sequence, inventory: Sequence) -> tuple[list, int, list]:
    """Programs with active CVEs.

    The inventory, when Wazuh has one, is the current state; the alerts then only add the CVSS vector
    the inventory lacks. Without an inventory the alerts are all there is (newest record per CVE).
    """
    problems = []
    latest: dict[tuple, dict] = {}
    for record in alerts:
        vulnerability = record.get("vulnerability") if isinstance(record, dict) else None
        if not isinstance(vulnerability, dict):
            continue
        package = vulnerability.get("package") if isinstance(vulnerability.get("package"), dict) else {}
        key = (str(vulnerability.get("cve") or ""), str(package.get("name") or ""), str(package.get("version") or ""))
        if not all(key):
            problems.append("a vulnerability alert without a CVE, program or version was left out")
            continue
        if key not in latest or str(record.get("timestamp")) >= str(latest[key].get("timestamp")):
            latest[key] = record
    solved = sum(1 for record in latest.values()
                 if str(record["vulnerability"].get("status") or "Active").lower() != "active")
    found: dict[tuple, list] = {}
    if inventory:
        for record in inventory:
            vulnerability = record.get("vulnerability") if isinstance(record, dict) else None
            package = record.get("package") if isinstance(record, dict) else None
            if not isinstance(vulnerability, dict) or not isinstance(package, dict):
                problems.append("an inventory record without a vulnerability or a package was left out")
                continue
            key = (str(vulnerability.get("id") or ""), str(package.get("name") or ""), str(package.get("version") or ""))
            if not all(key):
                problems.append("an inventory record without a CVE, program or version was left out")
                continue
            alert = (latest.get(key) or {}).get("vulnerability") or {}
            condition = ((vulnerability.get("scanner") or {}).get("condition")
                         or (alert.get("package") or {}).get("condition") or "")
            found.setdefault((key[1], key[2], str(package.get("type") or "")), []).append(
                _cve(key[0], vulnerability, alert, condition))
    else:
        for (cve, name, version), record in sorted(latest.items()):
            vulnerability = record["vulnerability"]
            if str(vulnerability.get("status") or "Active").lower() != "active":
                continue
            found.setdefault((name, version, ""), []).append(
                _cve(cve, vulnerability, vulnerability, (vulnerability.get("package") or {}).get("condition") or ""))
    programs = []
    for (name, version, kind), cves in sorted(found.items()):
        cves = sorted({c.id: c for c in cves}.values(), key=lambda c: c.id)
        bound = fixing_bound(((c.id, c.condition) for c in cves), version)
        programs.append(Program(name, version, tuple(cves), bound, kind))
        if bound.unread:
            problems.append(f"{name}: no bound could be read for {', '.join(bound.unread)}")
    return programs, solved, problems


def _cve(cve: str, record: dict, alert: dict, condition: Any) -> Cve:
    """One CVE: score and severity from ``record``, the CVSS vector from ``alert`` when there is one."""
    vector = ((alert.get("cvss") or {}).get("cvss3") or {}).get("vector") or {}
    score = (record.get("score") or {}).get("base")
    if score in (None, ""):
        score = ((record.get("cvss") or {}).get("cvss3") or {}).get("base_score")
    try:
        score = round(float(score), 1) if score not in (None, "") else None
    except (TypeError, ValueError):
        score = None
    if score is not None and score < 0:  # -1: NVD has not scored it yet
        score = None
    return Cve(
        id=cve, severity=str(record.get("severity") or ""), score=score,
        condition=" ".join(str(condition or "").split()),
        network=str(vector.get("attack_vector") or "").upper() == "NETWORK",
        no_privileges=str(vector.get("privileges_required") or "").upper() == "NONE",
        no_interaction=str(vector.get("user_interaction") or "").upper() == "NONE",
        vector_known=bool(vector), under_evaluation=bool(record.get("under_evaluation")),
    )


# --------------------------------------------------------------------------
# CIS checks: the registry value each one tests
# --------------------------------------------------------------------------

_COMPARE = re.compile(r"^n:\^?\(\\d\+\)\s+compare\s+(<=|>=|==|!=|<|>)\s+(\d+)$")
_CHOICE = re.compile(r"^r:(\^[A-Za-z0-9]{1,20}\$)(\|\^[A-Za-z0-9]{1,20}\$)*$")


def read_check(policy: str, item: dict) -> Check:
    compliance = {str(c.get("key")): str(c.get("value")) for c in item.get("compliance") or [] if isinstance(c, dict)}
    references = tuple(r.strip() for r in str(item.get("references") or "").split(",") if r.strip())
    targets, why = read_targets(item)
    return Check(policy, int(item.get("id")), compliance.get("cis", ""), _text(item.get("title")),
                 _text(item.get("rationale")), _text(item.get("remediation")), references, targets, why)


def read_targets(item: dict) -> tuple[tuple, str]:
    """The registry values a check tests, if its rules only say what each of a few values must hold."""
    rules = [str(r.get("rule") or "") for r in item.get("rules") or [] if isinstance(r, dict)]
    if str(item.get("condition") or "").lower() != "all":
        return (), f"the check passes when {item.get('condition')!r} of its rules hold"
    if not rules or not all(rule.startswith("r:") for rule in rules):
        names = {"c": "a command's output", "f": "a file", "d": "a folder", "p": "a running process",
                 "not": "that something is absent", "r": "a registry value"}
        kinds = sorted({names.get(rule.split(":", 1)[0] if ":" in rule[:5] else rule.split(" ", 1)[0], "other things")
                        for rule in rules if not rule.startswith("r:")})
        return (), f"the check also tests {' and '.join(kinds)}, which Aegis does not turn into a setting"
    parts = [[piece.strip() for piece in rule[2:].split(" -> ")] for rule in rules]
    full = [p for p in parts if len(p) == 3]
    if not full or len(full) > 3:
        return (), "the check does not name one to three registry values with what each must hold"
    if len({(p[0].lower(), p[1].lower()) for p in full}) != len(full):
        return (), "the check tests one registry value more than once"
    prefixes = {(p[0],) for p in full} | {(p[0], p[1]) for p in full}
    for other in parts:
        if len(other) != 3 and tuple(other) not in prefixes:
            return (), "the check's rules name more registry keys or values than it sets"
    targets = []
    for key, value, content in full:
        compare, choice = _COMPARE.match(content), _CHOICE.match(content)
        if compare:
            targets.append(Target(key, value, "compare", op=compare.group(1), number=int(compare.group(2))))
        elif choice:
            targets.append(Target(key, value, "choice", choices=tuple(re.findall(r"\^([A-Za-z0-9]+)\$", content))))
        elif re.match(r"^[nr]:", content):
            return (), "a value is tested with a pattern Aegis does not turn into a setting"
        else:
            targets.append(Target(key, value, "literal", literal=content))
    return tuple(targets), ""


def _text(value: Any) -> str:
    return " ".join(str(value or "").split())


# --------------------------------------------------------------------------
# Fix steps, and the checker every step goes through
# --------------------------------------------------------------------------

@dataclass(frozen=True)
class Step:
    kind: str  # "run" (a command to type), "check" (a command that only reads), "do" (an instruction)
    text: str
    source: str  # "Aegis" (made by code from the data) or "CIS, via Wazuh" (text as Wazuh gave it)


_HIVES = {"HKEY_LOCAL_MACHINE": "HKLM", "HKEY_CURRENT_USER": "HKCU", "HKEY_USERS": "HKU",
          "HKLM": "HKLM", "HKCU": "HKCU", "HKU": "HKU"}
_SAFE_TEXT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 _.-]{0,63}$")  # text data Aegis will put in a command

# Where Windows stores a number as REG_DWORD - well-known locations, written out so they can be checked.
DWORD_KEYS = (
    r"\\software\\policies\\",
    r"\\software\\microsoft\\windows\\currentversion\\policies\\(system|explorer)(\\|$)",
    r"\\system\\currentcontrolset\\control\\lsa(\\|$)",
    r"\\system\\currentcontrolset\\services\\(lanmanserver|lanmanworkstation|netbt|tcpip|tcpip6)\\parameters$",
    r"\\system\\currentcontrolset\\control\\session manager(\\kernel)?$",
    r"\\software\\(wow6432node\\)?microsoft\\cryptography\\wintrust\\config$",
)
# ... and the exceptions: numbers stored as text.
STRING_KEYS = (r"\\windows defender exploit guard\\asr\\rules$",)
_SAFE_NAME = re.compile(r"^[A-Za-z0-9 _.{}()\\-]{1,255}$")


def registry_steps(check: Check) -> tuple[list, str]:
    """The `reg add` commands that make the check pass, and the `reg query` that shows they did - or why none.

    All of a check's values get a command, or none of them does.
    """
    if not check.targets:
        return [], check.why_no_target
    run, look = [], []
    for target in check.targets:
        hive, _, rest = target.key.partition("\\")
        short = _HIVES.get(hive.upper())
        if short is None or not rest:
            return [], f"the key {target.key[:60]!r} is not under a hive Aegis writes commands for"
        if not _SAFE_NAME.match(rest) or not _SAFE_NAME.match(target.value) or "\\\\" in rest:
            return [], "a key or value name holds characters that are not safe in a command"
        data = chosen_data(target)
        if data is None:
            return [], "no single value is known to satisfy the check"
        if not target.satisfied_by(data):  # cannot happen; checked again so a mistake cannot ship
            return [], f"Aegis's value {data!r} would not satisfy the check"
        kind = value_type(target, data)
        if kind is None:
            return [], (f"the registry type of {target.value} is not known for this key, so no command is given; "
                        f"set it to {data} with the type it already has")
        path = f"{short}\\{rest}"
        shown = data if kind == "REG_DWORD" else f'"{data}"'
        run.append(Step("run", f'reg add "{path}" /v "{target.value}" /t {kind} /d {shown} /f', "Aegis"))
        look.append(Step("check", f'reg query "{path}" /v "{target.value}"', "Aegis"))
    return run + look, ""


def chosen_data(target: Target) -> str | None:
    """The value Aegis would write: the check's own literal, its first allowed choice, or its boundary."""
    if target.kind == "literal":
        return target.literal
    if target.kind == "choice":
        return target.choices[0] if target.choices else None
    n = target.number
    value = {"<=": n, ">=": n, "==": n, "<": n - 1, ">": n + 1}.get(target.op)  # "!=" names no single value
    return str(value) if value is not None and value >= 0 else None


def value_type(target: Target, data: str) -> str | None:
    """REG_DWORD or REG_SZ where the type is certain; None where it is not (then there is no command)."""
    key = target.key.lower()
    number = re.fullmatch(r"\d{1,10}", data) is not None and int(data) <= 0xFFFFFFFF
    if any(re.search(pattern, key) for pattern in STRING_KEYS):
        return "REG_SZ" if _SAFE_TEXT.match(data) else None
    if number and (any(re.search(pattern, key) for pattern in DWORD_KEYS) or (
            re.search(r"\\system\\currentcontrolset\\services\\[^\\]+$", key) and target.value.lower() == "start")):
        return "REG_DWORD"
    if not number and "\\software\\policies\\" in key and _SAFE_TEXT.match(data):
        return "REG_SZ"
    return None


# Settings that weaken the PC, whoever proposes them: (key pattern, value pattern, test of the data, why).
WEAKENING = (
    (r"\\windows defender(\\real-time protection)?$",
     r"^(disableantispyware|disableantivirus|disablerealtimemonitoring|disablebehaviormonitoring|"
     r"disableioavprotection|disableonaccessprotection|disablescanonrealtimeenable)$",
     lambda d: d != "0", "turns parts of Microsoft Defender off"),
    (r"\\windowsfirewall\\(domain|private|public|standard)profile$", r"^enablefirewall$",
     lambda d: d == "0", "turns the firewall off"),
    (r"\\policies\\system$", r"^enablelua$", lambda d: d == "0", "turns User Account Control off"),
    (r"\\policies\\system$", r"^consentpromptbehavioradmin$", lambda d: d == "0",
     "lets programs gain administrator rights without asking"),
    (r"\\services\\lanmanserver\\parameters$", r"^smb1$", lambda d: d != "0", "turns SMBv1 back on"),
    (r"\\services\\mrxsmb10$", r"^start$", lambda d: d != "4", "turns the SMBv1 client back on"),
    (r"\\windowsupdate\\au$", r"^noautoupdate$", lambda d: d != "0", "turns automatic updates off"),
    (r"\\control\\lsa$", r"^lmcompatibilitylevel$", lambda d: d.isdigit() and int(d) < 3,
     "allows LM or NTLMv1 authentication"),
    (r"\\control\\lsa$", r"^nolmhash$", lambda d: d == "0", "lets Windows store LM password hashes"),
    (r"\\control\\lsa$", r"^runasppl$", lambda d: d == "0", "turns LSA protection off"),
    (r"\\wdigest$", r"^uselogoncredential$", lambda d: d != "0", "keeps passwords in memory in clear text"),
    (r"\\lanmanworkstation$", r"^allowinsecureguestauth$", lambda d: d != "0", "allows unauthenticated guest access to shares"),
    (r"\\terminal server$", r"^fdenytsconnections$", lambda d: d == "0", "opens Remote Desktop to the network"),
)

# Commands in free text that weaken the PC. They are command syntax, not words, so CIS's own
# wording ("set 'Turn off Microsoft Defender Antivirus' to Disabled") never matches.
WEAKENING_COMMANDS = (
    (r"set-mppreference\b[^\n;|]*-disable\w*\s+(\$true|1)\b", "turns parts of Microsoft Defender off"),
    (r"add-mppreference\b[^\n;|]*-exclusion", "adds a Microsoft Defender exclusion"),
    (r"netsh\s+(advfirewall\s+set\s+\w+\s+state\s+off|firewall\s+set\s+opmode\s+(mode=)?disable)", "turns the firewall off"),
    (r"set-netfirewallprofile\b[^\n;|]*-enabled\s+(\$?false|0)\b", "turns the firewall off"),
    (r"(set-executionpolicy|-executionpolicy)\s+(-executionpolicy\s+)?(bypass|unrestricted)\b",
     "lets every PowerShell script run unchecked"),
    (r"\b(sc(\.exe)?\s+(config|stop|delete)|stop-service|set-service)\b[^\n;|]*\b(windefend|mpssvc|wuauserv|wscsvc|"
     r"securityhealthservice|sense|wdnissvc|bfe)\b", "stops or changes a security service"),
    (r"\bbcdedit\b[^\n;|]*\b(nointegritychecks|testsigning|disableelamdrivers)\b", "weakens the boot's integrity checks"),
    (r"enable-windowsoptionalfeature\b[^\n;|]*smb1protocol", "turns SMBv1 back on"),
    (r"\bwevtutil\s+(cl|clear-log)\b|clear-eventlog\b", "erases event logs"),
    (r"\bvssadmin\b[^\n;|]*\bdelete\s+shadows\b", "deletes the system's restore points"),
    (r"\breg(\.exe)?\s+(add|delete|import)\b|\bset-itemproperty\b|\bnew-itemproperty\b",
     "changes the registry (only Aegis's own checked command may do that)"),
)

ALLOWED_SITES = ("cisecurity.org", "microsoft.com", "nvd.nist.gov", "cve.org", "cve.mitre.org", "wazuh.com",
                 "python.org", "pypa.io", "github.com")


def check_step(step: Step) -> str | None:
    """Why a step must not be shown (it would weaken the PC), or None."""
    text = step.text
    lowered = text.lower()
    reg = re.match(r'^reg add "(?P<path>[^"]+)" /v "(?P<value>[^"]+)" /t (?P<type>REG_DWORD|REG_SZ) '
                   r'/d (?P<data>"[^"]*"|\S+) /f$', text)
    if reg:
        data = reg["data"].strip('"')
        for key_pattern, value_pattern, test, why in WEAKENING:
            if re.search(key_pattern, reg["path"].lower()) and re.search(value_pattern, reg["value"].lower()) \
                    and test(data):
                return why
        return None
    if step.source == "Aegis" and step.kind == "check" and re.match(r'^reg query "[^"]+" /v "[^"]+"$', text):
        return None
    for pattern, why in WEAKENING_COMMANDS:
        if re.search(pattern, lowered):
            return why
    return None


def allowed_link(url: str) -> bool:
    match = re.match(r"^https://([A-Za-z0-9.-]+)(/[^\s\"'<>]*)?$", url)
    if not match:
        return False
    host = match.group(1).lower()
    return any(host == site or host.endswith("." + site) for site in ALLOWED_SITES)


# --------------------------------------------------------------------------
# Ranking: fixed points, every point with its reason
# --------------------------------------------------------------------------

# What a CIS setting is worth on a single Windows 11 Home PC: (pattern over the check's title in
# lower case, points, area). The first match counts, so the more specific patterns come first.
IMPORTANCE = (
    # reachable from the network
    (r"enable insecure guest logons", 50, "File sharing (SMB)"),
    (r"lan manager authentication level", 50, "Credentials and NTLM"),
    (r"anonymous enumeration of sam accounts and shares", 45, "Credentials and NTLM"),
    (r"turn off multicast name resolution", 45, "Name resolution"),
    (r"netbt nodetype", 40, "Name resolution"),
    (r"allow print spooler to accept client connections", 45, "Printing"),
    (r"limits print driver installation to administrators", 40, "Printing"),
    (r"point and print restrictions", 35, "Printing"),
    (r"print spooler \(spooler\)", 30, "Printing"),
    (r"queue-specific files|print drivers over http|printing over http", 20, "Printing"),
    (r"digitally sign communications \(always\)", 40, "File sharing (SMB)"),
    (r"digitally sign communications \(if client agrees\)|server spn target name validation", 25, "File sharing (SMB)"),
    (r"\(lanmanserver\)", 35, "File sharing (SMB)"),
    (r"hardened unc paths", 35, "File sharing (SMB)"),
    (r"solicited remote assistance", 40, "Remote access"),
    (r"\(winrm\)|allow remote shell access|disallow digest authentication|disallow winrm from storing", 30,
     "Remote access"),
    (r"rpc endpoint mapper client authentication", 25, "Remote access"),
    (r"rpc connection settings|rpc listener settings|rpc over tcp port", 15, "Remote access"),
    (r"ssdp discovery|upnp device host", 25, "Services"),
    (r"suggested open hotspots", 30, "Wi-Fi and networks"),
    (r"ip source routing|icmp redirects|irdp|keepalivetime|tcpmaxdataretransmissions", 15, "Network stack"),
    (r"dns over https", 20, "Name resolution"),
    # credentials and sign-in
    (r"lsass to run as a protected process", 45, "Credentials and NTLM"),
    (r"custom ssps and aps", 40, "Credentials and NTLM"),
    (r"encryption oracle remediation", 40, "Credentials and NTLM"),
    (r"minimum session security for ntlm", 35, "Credentials and NTLM"),
    (r"storage of passwords and credentials for network authentication", 30, "Credentials and NTLM"),
    (r"delegation of non- ?exportable credentials", 20, "Credentials and NTLM"),
    (r"restrict ntlm|computer identity for ntlm", 15, "Credentials and NTLM"),
    (r"elevation prompt for administrators", 45, "User Account Control"),
    (r"elevation prompt for standard users", 20, "User Account Control"),
    (r"account lockout threshold", 30, "Accounts and passwords"),
    (r"minimum password length'", 30, "Accounts and passwords"),
    # malware and exploits
    (r"attack surface reduction", 45, "Microsoft Defender"),
    (r"accessing dangerous websites", 45, "Microsoft Defender"),
    (r"potentially unwanted applications", 40, "Microsoft Defender"),
    (r"scan removable drives", 30, "Microsoft Defender"),
    (r"application guard", 5, "Microsoft Defender"),
    (r"e-mail scanning|file hash computation|watson events", 10, "Microsoft Defender"),
    (r"smartscreen", 40, "SmartScreen"),
    (r"autoplay|autorun", 35, "AutoRun and AutoPlay"),
    (r"structured exception handling overwrite protection", 35, "Exploit protection"),
    (r"msdt interactive communication", 30, "Exploit protection"),
    (r"redirection guard", 30, "Exploit protection"),
    (r"virtualization based security", 25, "Exploit protection"),
    (r"certificate padding", 25, "Exploit protection"),
    (r"boot-start driver initialization", 20, "Exploit protection"),
    # seeing what happened
    (r"process creation", 20, "Event logs and auditing"),
    (r"powershell transcription", 15, "PowerShell"),
    (r"^ensure 'audit |'audit:", 15, "Event logs and auditing"),
    (r"maximum log file size", 10, "Event logs and auditing"),
    # settings that matter little on a home PC
    (r"windows firewall: domain:", 5, "Firewall"),
    (r"windows firewall: \w+: logging:|windows firewall: \w+: settings: display a notification", 10, "Firewall"),
    (r"windows firewall: \w+: settings: apply local", 10, "Firewall"),
    (r"bitlocker|dma devices|kernel dma protection", 10, "Disk encryption (BitLocker)"),
    (r"remote desktop|redirection|disconnected sessions|prompt for password upon connection|"
     r"secure rpc communication|security layer for remote", 10, "Remote Desktop host"),
    (r"remove access to \"pause updates\"|preview builds and feature updates", 15, "Windows Update"),
)
# Fallback, for a check no title pattern matches: (area, points, pattern over "key\value", pattern over the title).
AREAS = (
    ("Firewall", 30, r"\\windowsfirewall\\", r"windows (defender )?firewall"),
    ("Microsoft Defender", 30, r"\\windows defender\\", r"defender antivirus|microsoft defender"),
    ("Windows Update", 25, r"\\windowsupdate\\", r"windows update|automatic updates"),
    ("Credentials and NTLM", 25, r"\\control\\lsa(\\|$)|\\wdigest\\|\\credssp\\", r"lan manager|ntlm|credential"),
    ("File sharing (SMB)", 25, r"\\lanmanserver\\|\\lanmanworkstation\\|\\mrxsmb", r"\bsmb\b"),
    ("Remote access", 20, r"terminal services|\\winrm\\", r"remote (desktop|assistance)|winrm"),
    ("Event logs and auditing", 10, r"\\eventlog\\", r"event log"),
    ("Accounts and passwords", 10, r"\\control\\sam\\", r"password|account lockout|accounts:"),
    ("Services", 10, r"\\system\\currentcontrolset\\services\\[^\\]+\\start$", r"\(\w+\)' is set to 'disabled"),
)
# Settings Windows 11 Home does not have, over "key\value" or the title: still listed, with a note.
NOT_ON_HOME = (
    (r"\\fve\\|bitlocker", "BitLocker management"),
    (r"\\deviceguard\\lsacfgflags$|credential guard", "Credential Guard"),
    (r"\\apphvsi\\|application guard", "Microsoft Defender Application Guard"),
    (r"\\srpv2\\", "AppLocker"),
    (r"windows firewall: domain:|domain controller|domain-joined|on your dns domain network|domain authenticated "
     r"network|group policy objects", "a domain to join"),
    (r"terminal services\\(f(deny|disable|single)\w*|maxidletime|maxdisconnectiontime|fpromptforpassword|"
     r"fencryptrpctraffic|securitylayer|minencryptionlevel|userauthentication)$", "a Remote Desktop host"),
)
# Settings Aegis gives no command for: on a home PC they can lock you out or break everyday use.
# The advice still says what CIS recommends; the command is held back, with the reason.
DISRUPTIVE = (
    (r"\\policies\\system\\noconnecteduser$", "it can lock you out of this PC if you sign in with a Microsoft account"),
    (r"\\microsoftaccount\\disableuserauth$", "it stops Microsoft-account sign-in in apps (Store, Xbox, Office)"),
    (r"\\windowsfirewall\\\w+profile\\allowlocal(ipsec)?policymerge$",
     "Windows would ignore the firewall rules your programs created; it is meant for PCs a company manages"),
    (r"\\tcpip6\\parameters\\disabledcomponents$", "it turns IPv6 off, which Microsoft advises against"),
    (r"\\windowsstore\\(removewindowsstore|requireprivatestoreonly|disablestoreapps)$",
     "it turns the Microsoft Store off"),
    (r"\\appinstaller\\enableappinstaller$", "it turns App Installer off, and winget with it"),
    (r"\\onedrive\\disablefilesyncngsc$", "it turns OneDrive off"),
    (r"\\camera\\allowcamera$", "it turns the camera off"),
    (r"\\services\\(bthserv|btagservice)\\start$", "it turns Bluetooth off"),
    (r"\\services\\(xboxgipsvc|xblauthmanager|xblgamesave|xboxnetapisvc)\\start$",
     "it breaks Xbox and Game Pass sign-in, which many PC games use"),
    (r"\\services\\spooler\\start$", "it turns printing off"),
    (r"\\services\\(lfsvc|mapsbroker)\\start$", "apps that use your location or maps stop working"),
    (r"\\deviceinstall\\restrictions\\", "it can stop new devices from installing"),
    (r"\\kernel dma protection\\deviceenumerationpolicy$", "it blocks some Thunderbolt and USB4 devices"),
    (r"\\gamedvr\\allowgamedvr$", "it turns game recording and broadcasting off"),
    (r"\\power\\powersettings\\abfc2519-3608-4c2a-94ea-171b0ed546ab\\", "it changes how the laptop sleeps"),
)
# Settings Aegis gives a command for, with a warning first: they are hard to undo, or something
# ordinary may stop working.
WARNINGS = (
    (r"\\control\\lsa\\runasppl$", "With UEFI lock, turning it off later needs Microsoft's opt-out tool; some old "
                                    "security or VPN software stops working with it."),
    (r"\\deviceguard\\", "With UEFI lock it is hard to undo; some old drivers stop loading."),
    (r"\\netbt\\parameters\\nodetype$|\\dnsclient\\enablemulticast$",
     "Other PCs on your home network may no longer be found by name; use their address, or names your router "
     "gives them."),
    (r"\\control\\lsa\\lmcompatibilitylevel$|\\parameters\\requiresecuritysignature$",
     "Very old network storage or printers that cannot do this may stop working with this PC."),
)


@dataclass(frozen=True)
class Advice:
    item: str  # "program: pip 25.0.1" or "check 26004"
    kind: str  # "program" or "check"
    title: str
    area: str
    score: int
    reasons: tuple  # (points, why)
    steps: tuple  # Step, after the checker
    removed: tuple = ()  # (step text, why the checker dropped it: it would weaken the PC)
    held: tuple = ()  # (command, why Aegis holds it back: it can lock you out or break everyday use)
    links: tuple = ()
    detail: str = ""  # what is wrong, in one line
    notes: tuple = ()


def program_advice(program: Program) -> Advice:
    reasons = []
    top = max((c.score for c in program.cves if c.score is not None), default=None)
    if top is not None:
        reasons.append((round(top * 5), f"highest CVSS score {top}"))
    if any(c.network and c.no_privileges for c in program.cves):
        reasons.append((15, "a CVE can be reached over the network without signing in"))
        if any(c.network and c.no_privileges and c.no_interaction for c in program.cves):
            reasons.append((5, "... and without anyone clicking anything"))
    if not any(c.vector_known for c in program.cves):
        reasons.append((0, "whether it can be reached over the network is unknown: Wazuh's inventory gives no "
                           "CVSS vector"))
    reasons.append((min(10, len(program.cves)), f"{len(program.cves)} CVE{'s' if len(program.cves) != 1 else ''} "
                                                "fixed by one update"))
    notes = []
    waiting = sum(c.under_evaluation for c in program.cves)
    if waiting:
        notes.append(f"{waiting} of these CVEs {'is' if waiting == 1 else 'are'} still under evaluation at NVD "
                     "(no score yet).")
    if program.bound.dated:
        notes.append("Some of Wazuh's bounds are build dates. Programs that update themselves (Steam, for one) "
                     "can keep an old version number in Windows' list of programs, so these CVEs may be false "
                     "alarms; check the version in the program itself.")
    steps = [Step("do", f"Update {program.name} (installed: {program.version}) to {program.bound.text()}.", "Aegis")]
    pypi = program.type == "pypi" or program.name.lower() == "pip"
    if pypi and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,99}", program.name):
        wanted = (f'"{program.name}>={program.bound.version}"'
                  if program.bound.version and not program.bound.newer_than else program.name)
        steps.append(Step("run", f"python -m pip install --upgrade {wanted}", "Aegis"))
        steps.append(Step("check", f"python -m pip show {program.name}", "Aegis"))
    elif program.name.lower().startswith("python "):
        steps.append(Step("do", "Install it from python.org, or with winget; then remove the old version under "
                                "Settings > Apps if it is no longer needed.", "Aegis"))
    else:
        steps.append(Step("do", "Use the program's own updater or the vendor's installer; `winget upgrade` lists "
                                "what winget can update.", "Aegis"))
    worst = sorted(program.cves, key=lambda c: (-(c.score or 0), c.id))
    detail = (f"{len(program.cves)} active CVE{'s' if len(program.cves) != 1 else ''}, worst {worst[0].id} "
              f"({worst[0].severity}, {worst[0].score if worst[0].score is not None else 'no score yet'})")
    links = tuple(f"https://cti.wazuh.com/vulnerabilities/cves/{c.id}" for c in worst[:3]
                  if re.fullmatch(r"CVE-\d{4}-\d{4,}", c.id))
    return _finish(Advice(f"program: {program.name} {program.version}", "program", program.name,
                          "Vulnerable program", 0, tuple(reasons), tuple(steps), links=links, detail=detail,
                          notes=tuple(notes)))


def check_advice(check: Check) -> Advice:
    where = "\n".join(f"{t.key}\\{t.value}" for t in check.targets).lower()
    title = check.title.lower()
    area, points = next(((area, points) for pattern, points, area in IMPORTANCE if re.search(pattern, title)),
                        (None, None))
    if area is None:
        area, points = next(((name, value) for name, value, key_pattern, title_pattern in AREAS
                             if (where and re.search(key_pattern, where)) or re.search(title_pattern, title)),
                            ("Other settings", 10))
    reasons = [(points, f"{area}")]
    notes = []
    for pattern, feature in NOT_ON_HOME:
        if (where and re.search(pattern, where, re.M)) or re.search(pattern, title):
            reasons.append((-(points // 2), f"Windows 11 Home has no {feature}"))
            notes.append(f"Windows 11 Home has no {feature}: this setting may do nothing there.")
            break
    steps, why = registry_steps(check)
    held = []
    for pattern, reason in DISRUPTIVE:
        if where and re.search(pattern, where, re.M):
            held = [(step.text, reason) for step in steps if step.kind == "run"]
            steps = []
            notes.append(f"No command on purpose: {reason}. Change it only if that is fine for you; CIS's text "
                         "below says how.")
            break
    else:
        if why:
            notes.append(f"No command: {why}.")
    for pattern, warning in WARNINGS:
        if steps and where and re.search(pattern, where, re.M):
            notes.insert(0, warning)
            break
    steps.append(Step("do", check.remediation, "CIS, via Wazuh") if check.remediation else
                 Step("do", "Wazuh gave no remediation text for this check.", "Aegis"))
    detail = "; ".join(f"Wazuh checks {t.key}\\{t.value} = {t.wanted()}" for t in check.targets)
    return _finish(Advice(f"check {check.id}", "check", check.title, area, 0, tuple(reasons), tuple(steps),
                          held=tuple(held), links=tuple(check.references), detail=detail, notes=tuple(notes)))


def _finish(advice: Advice) -> Advice:
    kept, removed = [], []
    for step in advice.steps:
        why = check_step(step)
        if why:
            removed.append((step.text, why))
        else:
            kept.append(step)
    links = tuple(link for link in advice.links if allowed_link(link))
    score = max(0, min(100, sum(points for points, _ in advice.reasons)))
    return replace(advice, steps=tuple(kept), removed=tuple(removed), links=links, score=score)


def rank(posture: Posture) -> list[Advice]:
    return [advice for advice, _ in ranked(posture)]


def ranked(posture: Posture) -> list[tuple[Advice, Program | Check]]:
    """The advice, most important first, each with the program or check it is about."""
    pairs = [(program_advice(p), p) for p in posture.programs] + [(check_advice(c), c) for c in posture.checks]
    return sorted(pairs, key=lambda pair: (-pair[0].score, pair[0].kind != "program", pair[0].item))


# --------------------------------------------------------------------------
# Sharing: names and addresses out
# --------------------------------------------------------------------------

class SanitizeError(ValueError):
    """A shareable copy would still hold a name it must hide."""


_IP = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_SID = re.compile(r"\bS-1-5-21(?:-\d+){3,4}\b", re.I)
_PROFILE = re.compile(r"(?i)\b([a-z]:\\users\\)(?!<user>)([^\\/\s\"'<>|]+)")


def sanitize(text: str, names: Sequence[str]) -> str:
    """Replace the given names (the PC's name, user names), SIDs, IP addresses and profile paths."""
    text = _PROFILE.sub(lambda m: m.group(1) + "<user>", text)
    text = _SID.sub("<sid>", text)
    text = _IP.sub("<address>", text)
    for name in sorted({n for n in names if n and len(n) >= 3}, key=len, reverse=True):
        text = re.sub(re.escape(name), "<name>", text, flags=re.I)
    return text


def check_shareable(text: str, names: Sequence[str]) -> None:
    left = [name for name in names if name and len(name) >= 3 and name.lower() in text.lower()]
    if left or _SID.search(text) or _PROFILE.search(text):
        raise SanitizeError("the shareable copy still holds " + (", ".join(repr(n) for n in left) or
                                                                 "a SID or a profile path"))


# --------------------------------------------------------------------------
# The report
# --------------------------------------------------------------------------

_STEP_LABEL = {"run": "Run, in a terminal opened as administrator", "check": "Then check", "do": "Do"}


def _md(text: str) -> str:
    """Wazuh's text in a Markdown line: one line, no table breaks, no stray code marks."""
    return " ".join(str(text).split()).replace("|", "/").replace("`", "'")


def render(posture: Posture, advice: Sequence[Advice], top: int = TOP) -> str:
    """The advice as Markdown: the top fixes in full, then everything else in counts."""
    policy = posture.policy
    checks = [a for a in advice if a.kind == "check"]
    programs = [a for a in advice if a.kind == "program"]
    cves = sum(len(p.cves) for p in posture.programs)
    lines = [
        f"# Posture advice for {posture.agent_name or 'agent ' + posture.agent_id}",
        "",
        f"{posture.os_name or 'Unknown system'}. Exported from Wazuh at {posture.made_at}. "
        f"{policy.get('name', 'No CIS policy')}: score {policy.get('score', '?')}% - {posture.passed} checks passed, "
        f"{len(posture.checks)} failed, {policy.get('invalid', 0)} not applicable. Vulnerable programs: "
        f"{len(programs)}, with {cves} active CVEs.",
        "",
        "This is advice only. Aegis never changes this PC: the policy denies every action on it (D7). Every "
        "ranking point, version and command below was worked out by code from Wazuh's data; no AI model wrote "
        "any of it (D47).",
        "",
        f"## The top {min(top, len(advice))} fixes",
    ]
    for number, item in enumerate(advice[:top], 1):
        lines += ["", f"### {number}. {_md(item.title)} ({item.score} points)", ""]
        lines.append("* Why it is here: " + "; ".join(f"{'+' if p >= 0 else ''}{p} {_md(w)}" for p, w in item.reasons))
        if item.detail:
            lines.append(f"* What is wrong: {_md(item.detail)}")
        lines += [f"* Note: {_md(note)}" for note in item.notes]
        for step in item.steps:
            text = f"`{step.text}`" if step.kind in ("run", "check") else _md(step.text)
            source = "" if step.source == "Aegis" else f" ({step.source})"
            lines.append(f"* {_STEP_LABEL[step.kind]}{source}: {text}")
        lines += [f"* Command held back: {_md(why)}" for _, why in item.held]
        lines += [f"* Removed by the checker: {_md(why)}" for _, why in item.removed]
        if item.links:
            lines.append("* More: " + ", ".join(item.links))
    rest = list(advice[top:])
    if rest:
        areas: dict[str, list] = {}
        for item in rest:
            areas.setdefault(item.area, []).append(item)
        lines += ["", "## Everything else, by area", "",
                  "| area | items | with a command | command held back | highest score |",
                  "|---|---|---|---|---|"]
        for area, items in sorted(areas.items(), key=lambda kv: (-max(a.score for a in kv[1]), kv[0])):
            lines.append(f"| {_md(area)} | {len(items)} | {sum(any(s.kind == 'run' for s in a.steps) for a in items)} "
                         f"| {sum(bool(a.held) for a in items)} | {max(a.score for a in items)} |")
        lines += ["", "Every one of them, with its command where there is one, is in advice.json beside this "
                      "report."]
    held = [(item, why) for item in advice for _, why in item.held]
    if held:
        lines += ["", "## Commands held back", "",
                  "CIS recommends these, but on a home PC they can lock you out or break everyday use, so Aegis "
                  "gives no command for them. Change one only if that is fine for you.", ""]
        lines += [f"* {_md(item.title)}: {_md(why)}" for item, why in held]
    removed = [(item, why) for item in advice for _, why in item.removed]
    lines += ["", "## Removed by the checker", ""]
    lines += [f"* {_md(item.title)}: {_md(why)}" for item, why in removed] or [
        "Nothing: no step would have weakened the PC."]
    if posture.problems:
        lines += ["", "## What Aegis could not read", ""] + [f"* {_md(p)}" for p in posture.problems]
    return "\n".join(lines) + "\n"


def advice_record(posture: Posture, advice: Sequence[Advice]) -> dict:
    return {
        "agent": {"id": posture.agent_id, "name": posture.agent_name, "os": posture.os_name},
        "made_at": posture.made_at, "policy": posture.policy, "passed": posture.passed,
        "failed": len(posture.checks), "solved_cves": posture.solved, "problems": list(posture.problems),
        "programs": [{"name": p.name, "version": p.version, "fix": p.bound.text(),
                      "cves": [c.__dict__ for c in p.cves]} for p in posture.programs],
        "advice": [{"item": a.item, "kind": a.kind, "title": a.title, "area": a.area, "score": a.score,
                    "reasons": [list(r) for r in a.reasons], "detail": a.detail, "notes": list(a.notes),
                    "steps": [s.__dict__ for s in a.steps], "held": [list(h) for h in a.held],
                    "removed": [list(r) for r in a.removed], "links": list(a.links)} for a in advice],
    }


def write_report(out: Path | str, posture: Posture, advice: Sequence[Advice], top: int = TOP,
                 hide: Sequence[str] | None = None, notice: str | None = None, home: str = "index.html") -> dict:
    """Write advice.json, report.md and index.html into ``out``; with ``hide``, a shareable copy too.

    The shareable copy (shareable.md, shareable.html) has the PC's name, the given names, SIDs,
    addresses and profile paths replaced, and is not written at all if any of them survives.
    """
    from aegis.export import WEB_DIR
    from aegis.web import pages
    import shutil

    out = Path(out)
    out.mkdir(parents=True, exist_ok=True)
    report = render(posture, advice, top)
    record = advice_record(posture, advice)
    (out / "advice.json").write_text(json.dumps(record, indent=1, ensure_ascii=False), encoding="utf-8",
                                     newline="\n")
    (out / "report.md").write_text(report, encoding="utf-8", newline="\n")
    notice = notice or ("Advice only: Aegis never changes this PC. Worked out by code from Wazuh's data; no AI "
                        "model wrote it.")
    links = pages.FileLinks()
    written = {"report": out / "report.md", "page": out / "index.html", "advice": out / "advice.json"}
    with pages.link_style(links):
        (out / "index.html").write_bytes(pages.simple_document("Aegis posture advice", pages.markdown(report),
                                                               notice, home))
        if hide is not None:
            names = [posture.agent_name, *hide]
            shared = sanitize(report, names)
            check_shareable(shared, names)
            (out / "shareable.md").write_text(shared, encoding="utf-8", newline="\n")
            (out / "shareable.html").write_bytes(pages.simple_document("Aegis posture advice (shareable)",
                                                                       pages.markdown(shared), notice,
                                                                       "shareable.html"))
            written["shareable"] = out / "shareable.md"
    shutil.copyfile(WEB_DIR / "style.css", out / links.stylesheet())
    return written


# --------------------------------------------------------------------------
# Verification (run by `evaluate`)
# --------------------------------------------------------------------------

_REG_ADD = re.compile(r'^reg add "[^"]+" /v "(?P<value>[^"]+)" /t REG_\w+ /d "?(?P<data>[^"]*?)"? /f$')


def verify(posture: Posture, advice: Sequence[Advice]) -> dict:
    """What must hold for every export: counts, and the failures that must stay at zero."""
    checks = {f"check {c.id}": c for c in posture.checks}
    result = {"programs": len(posture.programs), "cves": sum(len(p.cves) for p in posture.programs),
              "bounds_ok": 0, "bounds_unknown": 0, "checks": len(posture.checks), "with_command": 0, "commands": 0,
              "commands_failing": 0, "shown_rejected": 0, "held": sum(bool(a.held) for a in advice),
              "removed": sum(len(a.removed) for a in advice), "shareable_clean": True}
    for program in posture.programs:
        if program.bound.version is None:
            result["bounds_unknown"] += 1
        elif all(fixes(program.bound, cve.condition) for cve in program.cves
                 if comparable(cve.condition, program.version)):
            result["bounds_ok"] += 1
    for item in advice:
        result["with_command"] += item.kind == "check" and any(step.kind == "run" for step in item.steps)
        for step in item.steps:
            result["shown_rejected"] += check_step(step) is not None
            match = _REG_ADD.match(step.text)
            if match:
                result["commands"] += 1
                target = next((t for t in checks[item.item].targets if t.value == match["value"]), None)
                result["commands_failing"] += target is None or not target.satisfied_by(match["data"])
    try:
        check_shareable(sanitize(render(posture, advice), [posture.agent_name]), [posture.agent_name])
    except SanitizeError:
        result["shareable_clean"] = False
    result["ok"] = (result["bounds_ok"] + result["bounds_unknown"] == result["programs"]
                    and not result["commands_failing"] and not result["shown_rejected"]
                    and result["shareable_clean"])
    return result


# --------------------------------------------------------------------------
# For the dashboard (aegis serve): the newest export, ranked again when it changes
# --------------------------------------------------------------------------

def newest_export(folder: Path | str | None) -> Path | None:
    """The newest export in ``folder`` by modification time; None without a folder or an export."""
    if folder is None:
        return None
    found = []
    try:
        for path in Path(folder).glob("*.json"):
            try:
                if path.is_file():
                    found.append((path.stat().st_mtime_ns, path.name, path))
            except OSError:
                continue
    except OSError:
        return None
    return max(found)[2] if found else None


_SLUG = re.compile(r"^(check-\d{1,12}|program-[0-9a-f]{12})(-\d{1,4})?$")


def advice_slugs(advice: Sequence[Advice]) -> list[str]:
    """A short id per item for links: check-<id>, or program-<12 hex digits of its name and version>.

    A program's name comes from the PC and can hold anything, so it never goes into a link itself.
    Repeats (two policies with the same check id) get -2, -3 ...
    """
    seen: dict[str, int] = {}
    out = []
    for item in advice:
        if item.kind == "check" and re.fullmatch(r"check \d{1,12}", item.item):
            base = "check-" + item.item.split()[1]
        else:
            base = "program-" + hashlib.sha256(item.item.encode("utf-8")).hexdigest()[:12]
        seen[base] = seen.get(base, 0) + 1
        out.append(base if seen[base] == 1 else f"{base}-{seen[base]}")
    return out


def valid_slug(text: str) -> bool:
    return bool(_SLUG.match(text))


def area_slug(area: str) -> str:
    """Areas are names fixed in this module, never taken from the data."""
    return re.sub(r"[^a-z0-9]+", "-", area.lower()).strip("-") or "other"


@dataclass(frozen=True)
class Loaded:
    """What the dashboard shows. ``posture`` is None when there is no usable export."""

    folder: Path
    path: Path | None = None
    posture: Posture | None = None
    pairs: tuple = ()  # (Advice, Program | Check), most important first
    slugs: tuple = ()
    error: str = ""


class PostureView:
    """The newest export in a folder, ranked, and ranked again only when the newest file changes.

    It reads and never writes: the dashboard stays read-only (D35).
    """

    def __init__(self, folder: Path | str):
        self.folder = Path(folder)
        self._lock = threading.Lock()
        self._key: tuple | None = None
        self._loaded = Loaded(self.folder)

    def current(self) -> Loaded:
        path = newest_export(self.folder)
        key = None
        if path is not None:
            try:
                stat = path.stat()
                key = (str(path), stat.st_mtime_ns, stat.st_size)
            except OSError:
                path = None
        with self._lock:
            if key != self._key:
                self._loaded = self._read(path)
                self._key = key
            return self._loaded

    def _read(self, path: Path | None) -> Loaded:
        return read_loaded(path, self.folder) if path is not None else Loaded(self.folder)


def read_loaded(path: Path | str, folder: Path | str | None = None) -> Loaded:
    """One export, ranked, for the dashboard or a static copy. A damaged file gives an error, not an exception."""
    path = Path(path)
    folder = Path(folder) if folder is not None else path.parent
    try:
        posture = load(path)
        pairs = tuple(ranked(posture))
    except PostureError as exc:
        return Loaded(folder, path, error=str(exc))
    except (OSError, ValueError, TypeError, AttributeError, KeyError) as exc:  # a damaged export
        return Loaded(folder, path, error=f"{path.name}: could not be read ({type(exc).__name__}: {exc})")
    return Loaded(folder, path, posture, pairs, tuple(advice_slugs([advice for advice, _ in pairs])))


def export_age_days(made_at: str, now: datetime | None = None) -> float | None:
    try:
        when = datetime.fromisoformat(str(made_at).strip().replace("Z", "+00:00"))
    except ValueError:
        return None
    if when.tzinfo is None:
        when = when.replace(tzinfo=timezone.utc)
    return max(0.0, ((now or datetime.now(timezone.utc)) - when).total_seconds() / 86400)


# Filters on the dashboard's posture page: name -> label
SHOW = {"programs": "vulnerable programs", "commands": "with a command", "held": "command held back",
        "text": "CIS text only", "home": "not on Windows 11 Home"}


def _action(advice: Advice) -> str:
    if advice.kind == "program":
        return "update"
    if any(step.kind == "run" for step in advice.steps):
        return "command"
    return "held back" if advice.held else "CIS text only"


def _not_on_home(advice: Advice) -> bool:
    return any(note.startswith("Windows 11 Home has no") for note in advice.notes)


def _shows(row: dict, show: str | None) -> bool:
    return {None: True, "programs": row["kind"] == "program", "commands": row["action"] == "command",
            "held": row["action"] == "held back", "text": row["action"] == "CIS text only",
            "home": row["not_on_home"]}[show]


def overview_data(loaded: Loaded, area: str | None = None, show: str | None = None,
                  now: datetime | None = None) -> dict:
    """The posture page's data (also /api/posture): every item ranked, filtered by area or kind."""
    data = {"folder": str(loaded.folder), "file": loaded.path.name if loaded.path else None,
            "error": loaded.error, "ready": loaded.posture is not None}
    posture = loaded.posture
    if posture is None:
        return data
    rows = []
    for number, ((advice, _), slug) in enumerate(zip(loaded.pairs, loaded.slugs), 1):
        rows.append({"rank": number, "slug": slug, "kind": advice.kind, "title": advice.title, "area": advice.area,
                     "area_slug": area_slug(advice.area), "score": advice.score, "action": _action(advice),
                     "not_on_home": _not_on_home(advice), "detail": advice.detail})
    areas: dict[str, dict] = {}
    for row in rows:
        entry = areas.setdefault(row["area_slug"], {"area": row["area"], "slug": row["area_slug"], "items": 0,
                                                     "highest": 0})
        entry["items"] += 1
        entry["highest"] = max(entry["highest"], row["score"])
    area = area if area in areas else None
    show = show if show in SHOW else None
    shown = [row for row in rows if (area is None or row["area_slug"] == area) and _shows(row, show)]
    advice = [advice for advice, _ in loaded.pairs]
    age = export_age_days(posture.made_at, now)
    return dict(data, agent={"id": posture.agent_id, "name": posture.agent_name}, os=posture.os_name,
                made_at=posture.made_at, age_days=round(age, 1) if age is not None else None,
                stale=age is None or age > STALE_DAYS, stale_days=STALE_DAYS, policy=dict(posture.policy),
                counts={"failed": len(posture.checks), "passed": posture.passed,
                        "not_applicable": posture.policy.get("invalid") or 0,
                        "with_command": sum(row["action"] == "command" for row in rows),
                        "held": sum(bool(a.held) for a in advice), "removed": sum(len(a.removed) for a in advice),
                        "programs": len(posture.programs), "cves": sum(len(p.cves) for p in posture.programs),
                        "not_on_home": sum(row["not_on_home"] for row in rows), "items": len(rows),
                        "shown": len(shown)},
                problems=list(posture.problems),
                areas=sorted(areas.values(), key=lambda a: (-a["highest"], a["area"])),
                filters={"area": area, "show": show}, items=shown)


def _cve_status(program: Program, cve: Cve) -> str:
    if read_condition(cve.condition) is None:
        return "bound not readable"
    if not comparable(cve.condition, program.version):
        return "build date: check the version in the program itself"
    return "fixed by the advised version" if fixes(program.bound, cve.condition) else "NOT fixed by the advised version"


def item_data(loaded: Loaded, slug: str) -> dict | None:
    """One item in full (also /api/posture/<id>), with the check or program it is about."""
    if loaded.posture is None or slug not in loaded.slugs:
        return None
    index = loaded.slugs.index(slug)
    advice, about = loaded.pairs[index]
    posture = loaded.posture
    data = {"rank": index + 1, "of": len(loaded.pairs), "slug": slug, "file": loaded.path.name,
            "agent": {"id": posture.agent_id, "name": posture.agent_name}, "made_at": posture.made_at,
            "item": advice.item, "kind": advice.kind, "title": advice.title, "area": advice.area,
            "area_slug": area_slug(advice.area), "score": advice.score, "action": _action(advice),
            "reasons": [{"points": points, "why": why} for points, why in advice.reasons],
            "detail": advice.detail, "notes": list(advice.notes),
            "steps": [{"kind": s.kind, "text": s.text, "source": s.source} for s in advice.steps],
            "held": [{"why": why} for _, why in advice.held],  # held back means no command, here too
            "removed": [{"text": text, "why": why} for text, why in advice.removed],
            "links": list(advice.links), "check": None, "program": None}
    if isinstance(about, Check):
        data["check"] = {"policy": about.policy, "id": about.id, "cis": about.cis, "rationale": about.rationale,
                         "targets": [{"key": t.key, "value": t.value, "wanted": t.wanted()} for t in about.targets],
                         "why_no_target": about.why_no_target}
    else:
        data["program"] = {"name": about.name, "version": about.version, "type": about.type,
                           "fix": about.bound.text(),
                           "cves": [dict(c.__dict__, status=_cve_status(about, c)) for c in about.cves]}
    return data
