"""Execution: carry out one approved action on the lab host, with proof.

The only executor is ``GateExecutor``: it calls ``aegis-gate`` on the lab VM
over SSH (lab/aegis-gate, D29, D49). It supports two actions:

  * ``lock_account`` - lock a Linux account (``status`` -> ``lock`` -> ``status``)
  * ``block_ip``     - drop an attacker's address at the firewall
                       (``block-status`` -> ``block`` -> ``block-status``)

For each it records the target's state before and after, so the result is
shown, not assumed. Everything else is refused here, before any connection.

The target is checked again before it is sent, and the gate checks it a
third time on the VM. Only the lab VM's address is ever a target (the policy
decides that, D7); protected accounts and addresses are refused here, at the
gate, and by the policy.
"""

from __future__ import annotations

import os
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

_USER_NAME = re.compile(r"^[a-z_][a-z0-9_-]{0,31}$")
_IPV4 = re.compile(r"^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$")


def _valid_user(target: str) -> tuple[bool, str]:
    return bool(_USER_NAME.match(target)), f"{target!r} is not a plain Linux user name"


def _valid_ip(target: str) -> tuple[bool, str]:
    match = _IPV4.match(target)
    ok = bool(match) and all(0 <= int(part) <= 255 for part in match.groups())
    return ok, f"{target!r} is not an IPv4 address"


def _is_locked(after: str) -> bool:
    return " password=L " in f" {after} " and "account_expires=never" not in after


def _is_blocked(after: str) -> bool:
    return " blocked=yes " in f" {after} "


@dataclass(frozen=True)
class ActionResult:
    action: str
    target: str
    ok: bool
    message: str
    before: str = ""
    after: str = ""


@dataclass(frozen=True)
class _Plan:
    """One action on the gate: a read, a change, the same read again, and what proves it took."""

    status: str                               # the gate request that reports the target's state
    verb: str                                 # the gate request that changes it
    valid: Callable[[str], tuple[bool, str]]  # is the target the right shape?
    confirms: Callable[[str], bool]           # does the after-state show the change took?
    done: str                                 # message when it took
    not_done: str                             # message when it did not


_PLANS = {
    "lock_account": _Plan("status", "lock", _valid_user, _is_locked,
                          "account locked and expired", "the account does not show as locked afterwards"),
    "block_ip": _Plan("block-status", "block", _valid_ip, _is_blocked,
                      "address blocked at the firewall", "the address does not show as blocked afterwards"),
}


class GateExecutor:
    SUPPORTED = tuple(_PLANS)

    def __init__(self, ssh_user: str, ssh_key: str, *, timeout: float = 20.0,
                 runner: Callable[..., subprocess.CompletedProcess] = subprocess.run) -> None:
        self.ssh_user = ssh_user
        self.ssh_key = str(Path(os.path.expanduser(ssh_key)))
        self.timeout = timeout
        self.runner = runner

    def command(self, address: str, request: str) -> list[str]:
        return [
            "ssh", "-i", self.ssh_key,
            "-o", "BatchMode=yes",          # never wait for a password or a question
            "-o", "ConnectTimeout=10",
            "-o", "IdentitiesOnly=yes",     # use this key, and only this key
            f"{self.ssh_user}@{address}", request,
        ]

    def _call(self, address: str, request: str) -> tuple[bool, str]:
        try:
            done = self.runner(self.command(address, request), capture_output=True, text=True,
                               timeout=self.timeout)
        except FileNotFoundError:
            return False, "the ssh program was not found on this computer"
        except subprocess.TimeoutExpired:
            return False, f"no answer from {address} within {self.timeout:g} s"
        output = (done.stdout or "").strip()
        if done.returncode != 0 or not output:
            detail = output or (done.stderr or "").strip() or f"exit code {done.returncode}"
            return False, detail.splitlines()[-1][:300]
        return True, output.splitlines()[-1][:300]

    def run(self, address: str, action: str, target: str) -> ActionResult:
        plan = _PLANS.get(action)
        if plan is None:
            return ActionResult(action, target, False, f"{action} is not available on the lab host yet")
        valid, why = plan.valid(target)
        if not valid:
            return ActionResult(action, target, False, why)
        ok, before = self._call(address, f"{plan.status} {target}")
        if not ok:
            return ActionResult(action, target, False, f"status check failed: {before}")
        ok, output = self._call(address, f"{plan.verb} {target}")
        if not ok:
            return ActionResult(action, target, False, f"{plan.verb} failed: {output}", before=before)
        ok, after = self._call(address, f"{plan.status} {target}")
        if not ok:
            return ActionResult(action, target, False,
                                f"{plan.verb} sent, but the check afterwards failed: {after}", before=before)
        took = plan.confirms(after)
        return ActionResult(action, target, took, plan.done if took else plan.not_done,
                            before=before, after=after)
