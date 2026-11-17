"""Execution: carry out one action on the lab host, with proof.

The only executor is ``GateExecutor``: it calls ``aegis-gate`` on the lab VM
over SSH (lab/aegis-gate, D29). It supports one action, ``lock_account``,
and for it records the account's status before and after, so the result is
shown, not assumed. Everything else is refused here, before any connection.

The target is checked again before it is sent, and the gate checks it a
third time on the VM.
"""

from __future__ import annotations

import os
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

_USER_NAME = re.compile(r"^[a-z_][a-z0-9_-]{0,31}$")


@dataclass(frozen=True)
class ActionResult:
    action: str
    target: str
    ok: bool
    message: str
    before: str = ""
    after: str = ""


class GateExecutor:
    SUPPORTED = ("lock_account",)

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
        if action not in self.SUPPORTED:
            return ActionResult(action, target, False, f"{action} is not available on the lab host yet")
        if not _USER_NAME.match(target):
            return ActionResult(action, target, False, f"{target!r} is not a plain Linux user name")
        ok, before = self._call(address, f"status {target}")
        if not ok:
            return ActionResult(action, target, False, f"status check failed: {before}")
        ok, output = self._call(address, f"lock {target}")
        if not ok:
            return ActionResult(action, target, False, f"lock failed: {output}", before=before)
        ok, after = self._call(address, f"status {target}")
        if not ok:
            return ActionResult(action, target, False, f"lock sent, but the check afterwards failed: {after}",
                                before=before)
        locked = " password=L " in f" {after} " and "account_expires=never" not in after
        message = "account locked and expired" if locked else "the account does not show as locked afterwards"
        return ActionResult(action, target, locked, message, before=before, after=after)
