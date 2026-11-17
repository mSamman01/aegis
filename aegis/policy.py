"""The policy engine: for each candidate action, allow / needs approval / deny.

The policy is a file a human writes (``policy/policy.json``). The engine reads
it strictly - a broken or incomplete policy is an error, never a default -
and applies the same checks to every action, collecting every reason that
applies:

  1. the host's mode: an "advice" host (and any host not listed) denies all
  2. the host's identity: agent id and name must both match the policy
  3. the action must be enabled
  4. the target must appear in the incident's own events
  5. the target must not be protected (accounts, addresses, system paths)
  6. the risk band must reach the action's minimum
  7. otherwise: needs approval, or allow if the policy says no approval

Two rules are built into the code and cannot be switched off in the file:
locking an account and isolating a host always need a human.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path

from aegis.contracts.decision import BANDS, HOST_MODES, ActionOutcome
from aegis.contracts.event import ContractError, Event, Host
from aegis.contracts.incident import Incident
from aegis.contracts.verdict import ACTION_CATALOG
from aegis.correlate import account_key, remote_address
from aegis.evidence import incident_targets, target_key

DEFAULT_POLICY_FILE = Path(__file__).resolve().parent.parent / "policy" / "policy.json"
ALWAYS_NEEDS_APPROVAL = frozenset({"lock_account", "isolate_host"})


@dataclass(frozen=True)
class ActionRule:
    enabled: bool
    min_band: str
    approval: bool


@dataclass(frozen=True)
class HostEntry:
    name: str
    mode: str
    address: str = ""  # where the executor reaches a lab host


@dataclass(frozen=True)
class ExecutorSettings:
    ssh_user: str
    ssh_key: str


@dataclass(frozen=True)
class Policy:
    id: str  # fingerprint of the file's content
    default_mode: str
    hosts: dict
    protected_accounts: frozenset
    protected_addresses: frozenset
    protected_paths: tuple
    actions: dict
    executor: ExecutorSettings = ExecutorSettings("aegis-exec", "~/.ssh/aegis_lab")

    def host_mode(self, host: Host) -> tuple[str, str]:
        """``(mode, explanation)`` for a host."""
        entry = self.hosts.get(host.agent_id)
        if entry is None:
            return self.default_mode, f"agent {host.agent_id} is not listed in the policy (default: {self.default_mode})"
        if entry.name.lower() != host.name.lower():
            return "advice", (f"agent {host.agent_id} is named {host.name!r} but the policy expects "
                              f"{entry.name!r}; treated as advice-only")
        return entry.mode, f"agent {host.agent_id} ({entry.name}) is a {entry.mode} host"

    def evaluate(self, action: str, target: str, incident: Incident, events: list[Event],
                 band: str) -> tuple[ActionOutcome, tuple[str, ...], str]:
        """Decide one action. Returns ``(outcome, reasons, target as written in the evidence)``."""
        deny: list[str] = []
        if action not in ACTION_CATALOG:
            return ActionOutcome.DENY, (f"{action!r} is not in the action catalog",), target
        mode, why = self.host_mode(incident.host)
        if mode != "lab":
            deny.append(f"advice-only host: {why}")
        rule = self.actions[action]
        if not rule.enabled:
            deny.append(f"{action} is switched off in the policy")
        known = incident_targets(incident, events)[action].get(target_key(action, target))
        if known is None:
            deny.append(f"{target!r} does not appear in this incident's events")
        else:
            target = known
        protected = self._protected(action, target)
        if protected:
            deny.append(protected)
        if BANDS.index(band) < BANDS.index(rule.min_band):
            deny.append(f"risk is {band}; {action} needs at least {rule.min_band}")
        if deny:
            return ActionOutcome.DENY, tuple(deny), target
        if rule.approval or action in ALWAYS_NEEDS_APPROVAL:
            return ActionOutcome.NEEDS_APPROVAL, ("allowed by the policy once a human approves it",), target
        return ActionOutcome.ALLOW, ("allowed by the policy without approval",), target

    def _protected(self, action: str, target: str) -> str | None:
        if action == "lock_account" and account_key(target) in self.protected_accounts:
            return f"{target} is a protected account"
        if action == "block_ip" and remote_address(target) in self.protected_addresses:
            return f"{target} is a protected address"
        if action in ("kill_process", "quarantine_file"):
            lowered = target.lower()
            for prefix in self.protected_paths:
                if lowered.startswith(prefix.lower()):
                    return f"{target} is under the protected path {prefix}"
        return None


def load_policy(path: Path | str = DEFAULT_POLICY_FILE) -> Policy:
    path = Path(path)
    raw = path.read_text(encoding="utf-8-sig")
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ContractError(f"{path}: not valid JSON ({exc.msg}, line {exc.lineno})") from exc
    if not isinstance(data, dict):
        raise ContractError(f"{path}: expected a JSON object")
    data = _strip_comments(data)
    expected = {"default_mode", "hosts", "executor", "protected_accounts", "protected_addresses",
                "protected_paths", "actions"}
    missing, unknown = sorted(expected - set(data)), sorted(set(data) - expected)
    if missing:
        raise ContractError(f"{path}: missing key(s): {', '.join(missing)}")
    if unknown:
        raise ContractError(f"{path}: unknown key(s): {', '.join(unknown)}")

    def fail(message: str):
        raise ContractError(f"{path}: {message}")

    if data["default_mode"] != "advice":
        fail("default_mode must be 'advice': a host nobody listed must never be acted on")
    hosts = {}
    if not isinstance(data["hosts"], dict):
        fail("hosts must be an object of agent id -> {name, mode}")
    for agent_id, entry in data["hosts"].items():  # "_why" notes were already stripped
        if not isinstance(entry, dict) or not {"name", "mode"} <= set(entry) <= {"name", "mode", "address"}:
            fail(f"host {agent_id}: needs 'name' and 'mode', and 'address' for a lab host")
        if not isinstance(entry["name"], str) or not entry["name"]:
            fail(f"host {agent_id}: name must be text")
        if entry["mode"] not in HOST_MODES:
            fail(f"host {agent_id}: mode must be one of {', '.join(HOST_MODES)}")
        address = entry.get("address", "")
        if entry["mode"] == "lab" and not remote_address(address):
            fail(f"host {agent_id}: a lab host needs its IP address in 'address'")
        hosts[str(agent_id)] = HostEntry(entry["name"], entry["mode"], address)

    executor = data["executor"]
    if not isinstance(executor, dict) or set(executor) != {"ssh_user", "ssh_key"} or not all(
            isinstance(v, str) and v for v in executor.values()):
        fail("executor needs 'ssh_user' and 'ssh_key' as text")

    def strings(key: str) -> list[str]:
        value = data[key]
        if not isinstance(value, list) or not all(isinstance(v, str) and v for v in value):
            fail(f"{key} must be a list of text")
        return value

    accounts = frozenset(account_key(a) or a.lower() for a in strings("protected_accounts"))
    addresses = set()
    for value in strings("protected_addresses"):
        address = remote_address(value) or (value if value in ("127.0.0.1", "::1") else None)
        if address is None:
            fail(f"protected_addresses: {value!r} is not an IP address")
        addresses.add(address)
    paths = tuple(strings("protected_paths"))

    if not isinstance(data["actions"], dict) or set(data["actions"]) != set(ACTION_CATALOG):
        fail(f"actions must list exactly: {', '.join(ACTION_CATALOG)}")
    actions = {}
    for name, rule in data["actions"].items():
        if not isinstance(rule, dict) or set(rule) != {"enabled", "min_band", "approval"}:
            fail(f"action {name}: needs exactly 'enabled', 'min_band' and 'approval'")
        if not isinstance(rule["enabled"], bool) or not isinstance(rule["approval"], bool):
            fail(f"action {name}: 'enabled' and 'approval' must be true or false")
        if rule["min_band"] not in BANDS:
            fail(f"action {name}: min_band must be one of {', '.join(BANDS)}")
        if name in ALWAYS_NEEDS_APPROVAL and not rule["approval"]:
            fail(f"action {name}: always needs a human; 'approval' cannot be false")
        actions[name] = ActionRule(rule["enabled"], rule["min_band"], rule["approval"])

    canonical = json.dumps(data, sort_keys=True, separators=(",", ":"))
    fingerprint = hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:6]
    return Policy(fingerprint, data["default_mode"], hosts, accounts, frozenset(addresses), paths, actions,
                  ExecutorSettings(executor["ssh_user"], executor["ssh_key"]))


def _strip_comments(value):
    """Keys starting with "_" are notes for humans and are ignored."""
    if isinstance(value, dict):
        return {k: _strip_comments(v) for k, v in value.items() if not str(k).startswith("_")}
    if isinstance(value, list):
        return [_strip_comments(v) for v in value]
    return value
