"""Milestone 5 (laptop side): audit log, approvals, and carrying out actions."""

import contextlib
import io
import json
import subprocess
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock

from aegis import audit
from aegis.approvals import Approved, add_approval, load_approval
from aegis.cli import main
from aegis.contracts import ContractError
from aegis.execute import GateExecutor

ROOT = Path(__file__).resolve().parent.parent
SAMPLE = ROOT / "data" / "samples" / "wazuh_alerts_sample.jsonl"
SSH_INCIDENT = "inc-dd29f3ede71f6a05"


def clock(start=datetime(2026, 11, 17, 18, 0, tzinfo=timezone.utc)):
    ticks = iter(range(10_000))
    return lambda: start + timedelta(seconds=next(ticks))


class AuditLogTests(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.addCleanup(self.folder.cleanup)
        self.log = Path(self.folder.name) / "audit.jsonl"
        now = clock()
        for n in range(1, 5):
            audit.append(self.log, "decision", f"inc-{n:016x}", {"risk": n * 10}, now=now)

    def lines(self):
        return self.log.read_text(encoding="utf-8").splitlines()

    def write(self, lines):
        self.log.write_text("\n".join(lines) + "\n", encoding="utf-8")

    def test_chain_is_intact_and_linked(self):
        state = audit.verify(self.log)
        self.assertEqual((state.ok, state.entries), (True, 4))
        entries = audit.read_entries(self.log)
        self.assertEqual(entries[0]["prev"], audit.GENESIS)
        for before, after in zip(entries, entries[1:]):
            self.assertEqual(after["prev"], before["hash"])
        self.assertEqual(state.last_hash, entries[-1]["hash"])
        self.assertEqual([e["seq"] for e in entries], [1, 2, 3, 4])
        self.assertEqual(audit.verify(Path(self.folder.name) / "none.jsonl"),
                         audit.Verification(True, 0, audit.GENESIS))

    def test_changing_an_entry_is_detected(self):
        lines = self.lines()
        lines[1] = lines[1].replace('"risk": 20', '"risk": 99')
        self.write(lines)
        state = audit.verify(self.log)
        self.assertFalse(state.ok)
        self.assertEqual(state.entries, 1)
        self.assertIn("entry 2 was changed after it was written", state.problem)

    def test_recomputing_the_hash_of_a_changed_entry_is_still_detected(self):
        entries = audit.read_entries(self.log)
        entries[1]["data"]["risk"] = 99
        entries[1]["hash"] = audit.entry_hash(entries[1])  # a careful forger
        self.write([json.dumps(e, sort_keys=True) for e in entries])
        state = audit.verify(self.log)
        self.assertFalse(state.ok)
        self.assertIn("entry 3 does not follow entry 2", state.problem)

    def test_removing_inserting_and_reordering_are_detected(self):
        original = self.lines()
        for changed, expected in (
            (original[:1] + original[2:], "expected entry 2, found 3"),
            (original[:2] + [original[1]] + original[2:], "expected entry 3, found 2"),
            ([original[1], original[0]] + original[2:], "expected entry 1, found 2"),
            (original[:2] + ["{not json"] + original[2:], "line 3 is not valid JSON"),
        ):
            with self.subTest(expected=expected):
                self.write(changed)
                state = audit.verify(self.log)
                self.assertFalse(state.ok)
                self.assertIn(expected, state.problem)

    def test_a_damaged_log_is_not_extended(self):
        lines = self.lines()
        lines[0] = lines[0].replace('"risk": 10', '"risk": 11')
        self.write(lines)
        with self.assertRaises(ValueError):
            audit.append(self.log, "decision", "inc-" + "0" * 16, {})
        self.assertEqual(len(self.lines()), 4)

    def test_unknown_kind_is_refused(self):
        with self.assertRaises(ValueError):
            audit.append(self.log, "gossip", "inc-" + "0" * 16, {})


class ApprovalFileTests(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.addCleanup(self.folder.cleanup)
        self.dir = Path(self.folder.name)

    def test_approval_is_bound_to_policy_action_and_target(self):
        self.assertIsNone(load_approval(self.dir, SSH_INCIDENT))
        add_approval(self.dir, SSH_INCIDENT, "aaaaaa", Approved("lock_account", "svc_backup", "M", "t"))
        approval = load_approval(self.dir, SSH_INCIDENT)
        self.assertTrue(approval.covers("lock_account", "SVC_BACKUP", "aaaaaa"))
        self.assertTrue(approval.covers("lock_account", "LAB\\svc_backup", "aaaaaa"))
        self.assertFalse(approval.covers("lock_account", "svc_backup", "bbbbbb"))
        self.assertFalse(approval.covers("lock_account", "admin", "aaaaaa"))
        self.assertFalse(approval.covers("block_ip", "svc_backup", "aaaaaa"))

    def test_a_new_policy_replaces_older_approvals(self):
        add_approval(self.dir, SSH_INCIDENT, "aaaaaa", Approved("lock_account", "svc_backup", "M", "t"))
        add_approval(self.dir, SSH_INCIDENT, "aaaaaa", Approved("block_ip", "10.0.0.9", "M", "t"))
        self.assertEqual(len(load_approval(self.dir, SSH_INCIDENT).actions), 2)
        add_approval(self.dir, SSH_INCIDENT, "bbbbbb", Approved("block_ip", "10.0.0.9", "M", "t"))
        approval = load_approval(self.dir, SSH_INCIDENT)
        self.assertEqual((approval.policy_id, len(approval.actions)), ("bbbbbb", 1))

    def test_a_file_for_another_incident_or_broken_file_is_an_error(self):
        path = self.dir / "approvals" / f"{SSH_INCIDENT}.json"
        path.parent.mkdir()
        path.write_text(json.dumps({"incident_id": "inc-" + "1" * 16, "policy_id": "x", "actions": []}))
        with self.assertRaises(ContractError):
            load_approval(self.dir, SSH_INCIDENT)
        path.write_text("{oops")
        with self.assertRaises(ContractError):
            load_approval(self.dir, SSH_INCIDENT)


class FakeGate:
    """Stands in for ssh + aegis-gate on the lab VM."""

    def __init__(self, locks=True, blocks=True, fail_on=None, error=None):
        self.calls = []
        self.locked = False
        self.blocked = False
        self.locks = locks
        self.blocks = blocks
        self.fail_on = fail_on
        self.error = error

    def __call__(self, command, **kwargs):
        self.calls.append(command)
        if self.error:
            raise self.error
        verb, target = command[-1].split()
        if verb == self.fail_on:
            return subprocess.CompletedProcess(command, 255, "", "ssh: connect to host x port 22: timed out\n")
        if verb == "lock" and self.locks:
            self.locked = True
        if verb == "block" and self.blocks:
            self.blocked = True
        if verb in ("status", "lock", "unlock"):
            state = "password=L account_expires=Jan_02,_1970" if self.locked else "password=P account_expires=never"
            return subprocess.CompletedProcess(command, 0, f"user={target} {state} processes=0\n", "")
        blocked = "yes" if self.blocked else "no"
        return subprocess.CompletedProcess(command, 0, f"ip={target} blocked={blocked} connections=0\n", "")


class GateExecutorTests(unittest.TestCase):
    def test_lock_with_before_and_after(self):
        gate = FakeGate()
        result = GateExecutor("aegis-exec", "~/.ssh/aegis_lab", runner=gate).run("192.168.56.107", "lock_account", "svc_backup")
        self.assertTrue(result.ok)
        self.assertEqual(result.message, "account locked and expired")
        self.assertIn("password=P", result.before)
        self.assertIn("password=L", result.after)
        self.assertEqual([c[-1] for c in gate.calls], ["status svc_backup", "lock svc_backup", "status svc_backup"])
        command = gate.calls[0]
        self.assertEqual(command[0], "ssh")
        self.assertIn("BatchMode=yes", command)
        self.assertIn("IdentitiesOnly=yes", command)
        self.assertEqual(command[-2], "aegis-exec@192.168.56.107")
        self.assertTrue(command[2].endswith("aegis_lab") and "~" not in command[2])

    def test_block_with_before_and_after(self):
        gate = FakeGate()
        result = GateExecutor("aegis-exec", "~/.ssh/aegis_lab", runner=gate).run(
            "192.168.56.107", "block_ip", "192.168.56.108")
        self.assertTrue(result.ok)
        self.assertEqual(result.message, "address blocked at the firewall")
        self.assertIn("blocked=no", result.before)
        self.assertIn("blocked=yes", result.after)
        self.assertEqual([c[-1] for c in gate.calls],
                         ["block-status 192.168.56.108", "block 192.168.56.108", "block-status 192.168.56.108"])

    def test_a_block_that_does_not_show_is_a_failure(self):
        result = GateExecutor("u", "k", runner=FakeGate(blocks=False)).run("10.0.0.1", "block_ip", "192.168.56.108")
        self.assertFalse(result.ok)
        self.assertEqual(result.message, "the address does not show as blocked afterwards")

    def test_block_refuses_a_bad_address_before_connecting(self):
        for target in ("not-an-ip", "192.168.56.999", "10.0.0.1; reboot", "192.168.56.0/24", "svc_backup"):
            with self.subTest(target=target):
                gate = FakeGate()
                result = GateExecutor("u", "k", runner=gate).run("10.0.0.1", "block_ip", target)
                self.assertFalse(result.ok)
                self.assertIn("not an IPv4 address", result.message)
                self.assertEqual(gate.calls, [])

    def test_a_lock_that_does_not_show_is_a_failure(self):
        result = GateExecutor("u", "k", runner=FakeGate(locks=False)).run("10.0.0.1", "lock_account", "bob")
        self.assertFalse(result.ok)
        self.assertEqual(result.message, "the account does not show as locked afterwards")

    def test_failures_are_reported(self):
        cases = [
            (FakeGate(fail_on="status"), "status check failed: ssh: connect to host x port 22: timed out"),
            (FakeGate(fail_on="lock"), "lock failed: ssh: connect"),
            (FakeGate(error=FileNotFoundError()), "the ssh program was not found"),
            (FakeGate(error=subprocess.TimeoutExpired("ssh", 20)), "no answer from 10.0.0.1 within 20 s"),
        ]
        for gate, expected in cases:
            with self.subTest(expected=expected):
                result = GateExecutor("u", "k", runner=gate).run("10.0.0.1", "lock_account", "bob")
                self.assertFalse(result.ok)
                self.assertIn(expected, result.message)

    def test_refused_before_connecting(self):
        for action, target, expected in (
            ("isolate_host", "aegis-victim", "not available on the lab host"),
            ("lock_account", "bob; rm -rf /", "not a plain Linux user name"),
            ("lock_account", "LAB\\bob", "not a plain Linux user name"),
            ("block_ip", "10.0.0.1; reboot", "not an IPv4 address"),
        ):
            with self.subTest(action=action, target=target):
                gate = FakeGate()
                result = GateExecutor("u", "k", runner=gate).run("10.0.0.1", action, target)
                self.assertFalse(result.ok)
                self.assertIn(expected, result.message)
                self.assertEqual(gate.calls, [])


def run_cli(*args):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = main([str(a) for a in args])
    return code, out.getvalue(), err.getvalue()


class CommandTests(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.addCleanup(self.folder.cleanup)
        self.dir = Path(self.folder.name) / "run"
        self.assertEqual(run_cli("ingest", SAMPLE, "--dir", self.dir)[0], 0)
        self.assertEqual(run_cli("correlate", "--dir", self.dir)[0], 0)
        self.gate = FakeGate()
        patcher = mock.patch("aegis.cli.make_executor",
                             side_effect=lambda policy: GateExecutor("aegis-exec", "k", runner=self.gate))
        patcher.start()
        self.addCleanup(patcher.stop)

    def approve(self, *args):
        return run_cli("approve", "inc-dd29", "--by", "Mohammed", "--dir", self.dir, *args)

    def test_full_flow(self):
        code, out, _ = run_cli("act", "inc-dd29", "--dir", self.dir)
        self.assertEqual(code, 0)
        self.assertIn("waiting  lock_account svc_backup: needs a human's approval", out)
        self.assertIn("skip     block_ip 192.168.56.1: denied by the policy", out)
        self.assertEqual(self.gate.calls, [])

        code, out, err = self.approve("--action", "lock_account", "--target", "svc_backup")
        self.assertEqual(code, 0, err)
        self.assertIn("Approved  lock_account svc_backup  for inc-dd29f3ede71f6a05  by Mohammed", out)

        code, out, _ = run_cli("act", "inc-dd29", "--dir", self.dir, "--dry-run")
        self.assertEqual(code, 0)
        self.assertIn("would run  lock_account svc_backup on 192.168.56.107", out)
        self.assertEqual(self.gate.calls, [])

        code, out, err = run_cli("act", "inc-dd29", "--dir", self.dir)
        self.assertEqual(code, 0, err)
        self.assertIn("DONE     lock_account svc_backup: account locked and expired", out)
        self.assertIn("before: user=svc_backup password=P", out)
        self.assertIn("after:  user=svc_backup password=L", out)
        self.assertEqual(len(self.gate.calls), 3)

        code, out, _ = run_cli("audit", "--dir", self.dir)
        self.assertEqual(code, 0)
        self.assertIn("OK        3 entries, hash chain intact", out)
        kinds = [e["kind"] for e in audit.read_entries(self.dir / "audit.jsonl")]
        self.assertEqual(kinds, ["approval", "action_started", "action_result"])
        result = audit.read_entries(self.dir / "audit.jsonl")[-1]["data"]
        self.assertEqual((result["ok"], result["approved_by"], result["address"]), (True, "Mohammed", "192.168.56.107"))

    def test_denied_and_unknown_actions_cannot_be_approved(self):
        code, _, err = self.approve("--action", "block_ip", "--target", "192.168.56.1")
        self.assertEqual(code, 2)
        self.assertIn("cannot be approved: the policy says deny (192.168.56.1 is a protected address)", err)
        code, _, err = self.approve("--action", "lock_account", "--target", "root")
        self.assertEqual(code, 2)
        self.assertIn("not one of this incident's candidate actions", err)
        self.assertFalse((self.dir / "approvals").exists())

    def test_advice_host_actions_cannot_be_approved(self):
        code, _, err = run_cli("approve", "inc-e387", "--action", "block_ip", "--target", "203.0.113.50",
                               "--by", "M", "--dir", self.dir)
        self.assertEqual(code, 2)
        self.assertIn("advice-only host", err)

    def test_approval_under_another_policy_does_not_count(self):
        add_approval(self.dir, SSH_INCIDENT, "000000", Approved("lock_account", "svc_backup", "M", "t"))
        code, out, _ = run_cli("act", "inc-dd29", "--dir", self.dir)
        self.assertEqual(code, 0)
        self.assertIn("the approval file was made under policy 000000", out)
        self.assertIn("waiting  lock_account svc_backup", out)
        self.assertEqual(self.gate.calls, [])

    def test_nothing_runs_on_a_damaged_audit_log(self):
        self.approve("--action", "lock_account", "--target", "svc_backup")
        log = self.dir / "audit.jsonl"
        log.write_text(log.read_text().replace("Mohammed", "Mallory"))
        code, out, _ = run_cli("audit", "--dir", self.dir)
        self.assertEqual(code, 1)
        self.assertIn("BROKEN    entry 1 was changed after it was written", out)
        code, _, err = run_cli("act", "inc-dd29", "--dir", self.dir)
        self.assertEqual(code, 2)
        self.assertIn("the audit log is damaged", err)
        self.assertEqual(self.gate.calls, [])

    def test_a_failed_action_is_recorded_and_exits_non_zero(self):
        self.gate.fail_on = "status"
        self.approve("--action", "lock_account", "--target", "svc_backup")
        code, out, _ = run_cli("act", "inc-dd29", "--dir", self.dir)
        self.assertEqual(code, 1)
        self.assertIn("FAILED   lock_account svc_backup: status check failed", out)
        last = audit.read_entries(self.dir / "audit.jsonl")[-1]
        self.assertEqual((last["kind"], last["data"]["ok"]), ("action_result", False))

    def test_decide_writes_to_the_audit_log(self):
        run_cli("decide", "--all", "--dir", self.dir)
        entries = audit.read_entries(self.dir / "audit.jsonl")
        self.assertEqual(len(entries), 7)
        ssh = next(e for e in entries if e["incident_id"] == SSH_INCIDENT)
        self.assertEqual((ssh["data"]["risk"], ssh["data"]["band"], ssh["data"]["host_mode"]), (85, "critical", "lab"))


if __name__ == "__main__":
    unittest.main()
