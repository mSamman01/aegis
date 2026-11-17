"""Approvals: a human's sign-off, one file per incident.

``<run folder>/approvals/<incident id>.json`` lists the exact actions a person
approved for that incident:

    {"incident_id": "inc-...", "policy_id": "7e58fd",
     "actions": [{"action": "lock_account", "target": "svc_backup",
                  "approved_by": "Mohammed", "approved_at": "..."}]}

An approval is bound three ways. The incident id is a hash of the exact
events (D12), so new evidence makes a new incident that nobody approved. The
policy id is a hash of the policy file, so an approval given under one policy
does not carry over to an edited one. And it names one action and one target.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from aegis.contracts.event import ContractError
from aegis.evidence import target_key

FOLDER = "approvals"


@dataclass(frozen=True)
class Approved:
    action: str
    target: str
    approved_by: str
    approved_at: str


@dataclass(frozen=True)
class Approval:
    incident_id: str
    policy_id: str
    actions: tuple

    def covers(self, action: str, target: str, policy_id: str) -> bool:
        if policy_id != self.policy_id:
            return False
        wanted = (action, target_key(action, target))
        return any((a.action, target_key(a.action, a.target)) == wanted for a in self.actions)


def approval_path(run_dir: Path, incident_id: str) -> Path:
    return Path(run_dir) / FOLDER / f"{incident_id}.json"


def load_approval(run_dir: Path, incident_id: str) -> Approval | None:
    path = approval_path(run_dir, incident_id)
    if not path.exists():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8-sig"))
        if data["incident_id"] != incident_id:
            raise ContractError(f"{path} is for incident {data['incident_id']}, not {incident_id}")
        actions = tuple(Approved(a["action"], a["target"], a["approved_by"], a["approved_at"])
                        for a in data["actions"])
        return Approval(incident_id, str(data["policy_id"]), actions)
    except ContractError:
        raise
    except (json.JSONDecodeError, KeyError, TypeError) as exc:
        raise ContractError(f"{path} is not a valid approval file: {exc}") from exc


def add_approval(run_dir: Path, incident_id: str, policy_id: str, approved: Approved) -> Approval:
    """Record one approved action. An approval under an older policy is replaced."""
    current = load_approval(run_dir, incident_id)
    actions = list(current.actions) if current and current.policy_id == policy_id else []
    actions = [a for a in actions if (a.action, target_key(a.action, a.target))
               != (approved.action, target_key(approved.action, approved.target))]
    actions.append(approved)
    approval = Approval(incident_id, policy_id, tuple(actions))
    path = approval_path(run_dir, incident_id)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({
        "incident_id": incident_id,
        "policy_id": policy_id,
        "actions": [a.__dict__ for a in actions],
    }, indent=2) + "\n", encoding="utf-8", newline="\n")
    return approval
