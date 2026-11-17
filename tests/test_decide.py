"""Milestone 4: the risk score, the policy, and the decisions they make."""

import contextlib
import copy
import io
import json
import random
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from aegis.cli import main
from aegis.contracts import (
    Category, Confidence, ContractError, Event, Finding, Host, ModelRun, Network, Outcome, Process,
    ProposedAction, Rule, Verdict, VerdictLabel,
)
from aegis.contracts.decision import ActionOutcome, Decision, RiskFactor, RiskScore, band_for
from aegis.correlate import correlate
from aegis.decide import decide, latest_verdict
from aegis.evidence import EvidenceStore
from aegis.ingest import ingest_file
from aegis.policy import DEFAULT_POLICY_FILE, load_policy
from aegis.risk import assess
from aegis.store import read_decisions, save_decisions

ROOT = Path(__file__).resolve().parent.parent
SAMPLE = ROOT / "data" / "samples" / "wazuh_alerts_sample.jsonl"
T0 = datetime(2026, 11, 14, 12, 0, 0, tzinfo=timezone.utc)
LAB = Host(agent_id="002", name="aegis-victim")


def ev(n, *, seconds=None, host=LAB, rule="1", level=5, category=Category.OTHER, outcome=Outcome.UNKNOWN,
       user=None, target=None, groups=(), src=None, dst=None, image=None, command=None, file=None,
       key=None, value=None):
    process = Process(image=image, command_line=command) if (image or command) else None
    network = Network(src_ip=src, dst_ip=dst) if (src or dst) else None
    return Event(
        event_id=f"evt-{n:016x}", timestamp=T0 + timedelta(seconds=n if seconds is None else seconds),
        source="test", source_ref=str(n), host=host,
        rule=Rule(id=rule, level=level, description=f"rule {rule}", groups=tuple(groups)),
        category=category, outcome=outcome, user=user, target_user=target, process=process,
        network=network, file_path=file, registry_key=key, registry_value=value,
    )


def one_incident(events):
    """Correlate and insist the events form one incident."""
    incidents = correlate(events).incidents
    assert len(incidents) == 1, [len(i.event_ids) for i in incidents]
    return incidents[0]


def factors(events):
    incident = one_incident(events)
    result = assess(incident, events)
    return {f.id: f.points for f in result.risk.factors}, result


def failures(count, start=1, src="10.0.0.9", user="bob"):
    return [ev(start + i, rule="5760", category=Category.AUTHENTICATION, outcome=Outcome.FAILURE,
               user=user, src=src) for i in range(count)]


def success(n, src="10.0.0.9", user="bob"):
    return ev(n, rule="5715", level=3, category=Category.AUTHENTICATION, outcome=Outcome.SUCCESS, user=user, src=src)


class RiskRuleTests(unittest.TestCase):
    def test_rule_level_counts_at_most_15(self):
        got, _ = factors([ev(1, level=16)])
        self.assertEqual(got, {"rule_level": 15})
        got, _ = factors([ev(1, level=0)])
        self.assertEqual(got, {})

    def test_password_guessed_needs_three_failures_before_the_success(self):
        got, result = factors(failures(3) + [success(4)])
        self.assertEqual(got, {"rule_level": 5, "password_guessed": 35})
        self.assertEqual([(s.action, s.target) for s in result.suggestions],
                         [("lock_account", "bob"), ("block_ip", "10.0.0.9")])
        self.assertEqual(len(result.risk.factors[1].evidence), 4)
        got, _ = factors(failures(2) + [success(3)])
        self.assertNotIn("password_guessed", got)
        got, _ = factors([success(1)] + failures(3, start=2))
        self.assertNotIn("password_guessed", got)  # the success came first

    def test_a_success_counts_only_for_an_account_being_guessed(self):
        # The administrator logging in from the same address is not the guessed account.
        got, result = factors(failures(5, user="bob") + [success(6, user="labadmin")])
        self.assertNotIn("password_guessed", got)
        self.assertEqual(got.get("password_guessing"), 10)
        # ...but the guessed account succeeding later still is.
        got, result = factors(failures(5, user="bob") + [success(6, user="labadmin"), success(7, user="bob")])
        self.assertEqual(got.get("password_guessed"), 35)
        self.assertEqual([(s.action, s.target) for s in result.suggestions][0], ("lock_account", "bob"))
        self.assertIn("then a successful login as bob", result.risk.factors[1].reason)

    def test_old_failures_do_not_make_a_later_login_a_guess(self):
        old = failures(5, user="bob")
        later = success(5 + 31 * 60, user="bob")  # 31 minutes after the last failure
        events = old + [ev(4 + 20 * 60, src="10.0.0.9"), later]  # keep it one incident
        got, _ = factors(events)
        self.assertNotIn("password_guessed", got)
        recent = failures(3, start=5 + 31 * 60 - 60, user="bob")
        got, result = factors(old + [ev(4 + 20 * 60, src="10.0.0.9")] + recent + [success(5 + 31 * 60, user="bob")])
        self.assertEqual(got.get("password_guessed"), 35)
        self.assertEqual(len(result.risk.factors[1].evidence), 4)  # only the recent failures, and the success

    def test_many_failures_without_success(self):
        got, result = factors(failures(5))
        self.assertEqual(got["password_guessing"], 10)
        self.assertEqual([(s.action, s.target) for s in result.suggestions], [("block_ip", "10.0.0.9")])
        got, _ = factors(failures(4))
        self.assertNotIn("password_guessing", got)

    def test_local_logins_are_not_password_guessing(self):
        got, _ = factors(failures(6, src="127.0.0.1") + [success(7, src="127.0.0.1")])
        self.assertEqual(set(got), {"rule_level"})

    def test_switching_to_root(self):
        sudo = dict(category=Category.AUTHENTICATION, groups=("syslog", "sudo"), target="root")
        self.assertEqual(factors([ev(1, user="alice", **sudo)])[0].get("became_admin"), 15)
        self.assertNotIn("became_admin", factors([ev(1, user="alice", **dict(sudo, target="bob"))])[0])
        self.assertNotIn("became_admin", factors([ev(1, user="alice", **dict(sudo, groups=("pam",)))])[0])
        self.assertNotIn("became_admin", factors([ev(1, user="NT AUTHORITY\\SYSTEM", **sudo)])[0])

    def test_aegis_running_its_own_gate_is_not_someone_becoming_root(self):
        sudo = dict(category=Category.AUTHENTICATION, groups=("syslog", "sudo"), target="root", image="x")
        self.assertNotIn("became_admin", factors([ev(1, user="aegis-exec", command="/usr/local/sbin/aegis-gate", **sudo)])[0])
        for command in ("/usr/local/sbin/aegis-gate; id", "/bin/bash", "/usr/local/sbin/aegis-gate2"):
            with self.subTest(command=command):
                self.assertEqual(factors([ev(1, user="aegis-exec", command=command, **sudo)])[0].get("became_admin"), 15)

    def test_credential_access(self):
        for command in ("/usr/bin/cat /etc/shadow", "procdump.exe -ma lsass.exe out.dmp",
                        "rundll32 comsvcs.dll MiniDump 624 lsass.dmp full", "mimikatz sekurlsa::logonpasswords",
                        "reg save HKLM\\SAM C:\\x\\config\\SAM"):
            with self.subTest(command=command):
                self.assertEqual(factors([ev(1, image="x", command=command)])[0].get("credential_access"), 25)
        for command in ("C:\\Windows\\System32\\lsass.exe", "cat /etc/passwd", "shadowcopy list"):
            with self.subTest(command=command):
                self.assertNotIn("credential_access", factors([ev(1, image="x", command=command)])[0])

    def test_hidden_powershell_command(self):
        encoded = "VwByAGkAdABlAC0ASABvAHMAdAAgACIAYQBlAGcAaQBzACAAdABlAHMAdAAiAA=="
        got, _ = factors([ev(1, image="powershell.exe", command=f"powershell -enc {encoded}")])
        self.assertEqual(got.get("hidden_command"), 20)
        self.assertNotIn("hidden_command", factors([ev(1, image="powershell.exe", command="powershell -File a.ps1")])[0])

    def test_command_interpreter_going_online(self):
        ps = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
        got, result = factors([ev(1, image=ps, dst="203.0.113.50")])
        self.assertEqual(got.get("script_host_online"), 15)
        self.assertEqual([(s.action, s.target) for s in result.suggestions], [("block_ip", "203.0.113.50")])
        for image, dst in ((ps, "192.168.1.20"), (ps, "10.1.2.3"), ("C:\\x\\chrome.exe", "203.0.113.50")):
            with self.subTest(image=image, dst=dst):
                self.assertNotIn("script_host_online", factors([ev(1, image=image, dst=dst)])[0])

    def test_persistence(self):
        key = "HKLM\\System\\CurrentControlSet\\Services\\Updater\\ImagePath"
        run = "HKU\\S-1\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Updater"
        self.assertEqual(factors([ev(1, key=key, value="C:\\Users\\x\\AppData\\Local\\Temp\\u.exe")])[0]
                         .get("persistence"), 25)
        self.assertNotIn("persistence", factors([ev(1, key=key, value="C:\\WINDOWS\\system32\\svchost.exe -k x")])[0])
        self.assertEqual(factors([ev(1, key=run, value="C:\\Users\\x\\AppData\\u.exe")])[0]
                         .get("persistence_run_key"), 20)
        self.assertEqual(factors([ev(1, category=Category.ACCOUNT, groups=("adduser",))])[0]
                         .get("account_created"), 15)

    def test_critical_files(self):
        for path in ("/etc/passwd", "/etc/sudoers.d/99-x", "/root/.ssh/authorized_keys"):
            with self.subTest(path=path):
                self.assertEqual(factors([ev(1, category=Category.FILE, file=path)])[0]
                                 .get("critical_file_changed"), 20)
        for path in ("/etc/passwd.bak", "/home/x/notes.txt"):
            with self.subTest(path=path):
                self.assertNotIn("critical_file_changed", factors([ev(1, category=Category.FILE, file=path)])[0])

    def test_score_is_capped_and_banded(self):
        events = failures(5) + [success(6), ev(7, level=15, user="bob", category=Category.AUTHENTICATION,
                                              groups=("sudo",), target="root", image="x",
                                              command="cat /etc/shadow; mimikatz")]
        _, result = factors(events)
        self.assertEqual(sum(f.points for f in result.risk.factors), 90)
        self.assertEqual((result.risk.score, result.risk.band), (90, "critical"))
        self.assertEqual([band_for(s) for s in (0, 24, 25, 49, 50, 74, 75, 100)],
                         ["low", "low", "medium", "medium", "high", "high", "critical", "critical"])

    def test_wrong_events_are_refused(self):
        events = [ev(1), ev(2)]  # the same rule: one incident of two events
        incident = one_incident(events)
        with self.assertRaises(ValueError):
            assess(incident, events[:1])


class SampleDecisionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.events = ingest_file(SAMPLE).events
        cls.store = EvidenceStore(cls.events)
        cls.incidents = correlate(cls.events).incidents
        cls.policy = load_policy()
        cls.ssh = next(i for i in cls.incidents if i.max_level == 10)

    def events_of(self, incident):
        return [self.store.get(e) for e in incident.event_ids]

    def verdict(self, incident, label="malicious", actions=()):
        return Verdict(
            incident_id=incident.incident_id, label=VerdictLabel(label), confidence=Confidence.HIGH, summary="",
            run=ModelRun(model="fake:1b", mode="single_call", thinking=False, prompt_sha256="0" * 64),
            created_at=T0, findings=(Finding("x", (incident.event_ids[0],)),),
            proposed_actions=tuple(ProposedAction(a, t, "r", (incident.event_ids[0],)) for a, t in actions),
        )

    def test_scores_of_the_sample(self):
        scores = {}
        for incident in self.incidents:
            decision = decide(incident, self.events_of(incident), self.policy)
            rule = incident.rules[0].rule_id
            scores[rule] = (decision.risk.score, [f.id for f in decision.risk.factors])
        self.assertEqual(scores, {
            "5763": (85, ["rule_level", "password_guessed", "became_admin", "credential_access"]),
            "92057": (47, ["rule_level", "hidden_command", "script_host_online"]),
            "92307": (28, ["rule_level", "persistence"]),
            "550": (27, ["rule_level", "critical_file_changed"]),
            "60110": (8, ["rule_level"]),
            "554": (5, ["rule_level"]),
            "502": (3, ["rule_level"]),
        })

    def test_ssh_brute_force_on_the_lab_host(self):
        decision = decide(self.ssh, self.events_of(self.ssh), self.policy)
        self.assertEqual((decision.host_mode, decision.risk.band, decision.policy_id), ("lab", "critical", self.policy.id))
        got = {(a.action, a.target): (a.outcome, a.source) for a in decision.actions}
        self.assertEqual(got, {
            ("lock_account", "svc_backup"): (ActionOutcome.NEEDS_APPROVAL, "rules"),
            ("block_ip", "192.168.56.1"): (ActionOutcome.DENY, "rules"),
        })
        block = next(a for a in decision.actions if a.action == "block_ip")
        self.assertEqual(block.reasons, ("192.168.56.1 is a protected address",))

    def test_the_model_verdict_never_changes_the_score(self):
        events = self.events_of(self.ssh)
        verdicts = (None, self.verdict(self.ssh, "benign"), self.verdict(self.ssh, "malicious"),
                    self.verdict(self.ssh, "suspicious"))
        risks = {decide(self.ssh, events, self.policy, verdict).risk for verdict in verdicts}
        self.assertEqual(len(risks), 1)
        with_model = decide(self.ssh, events, self.policy, self.verdict(self.ssh, "benign"))
        self.assertEqual((with_model.model_label, with_model.model_run), ("benign", "fake:1b v0"))

    def test_model_proposals_get_the_same_checks(self):
        verdict = self.verdict(self.ssh, actions=[
            ("lock_account", "AEGIS-VICTIM\\SVC_BACKUP"),  # same as the rules' suggestion
            ("lock_account", "root"),  # protected
            ("kill_process", "/usr/bin/cat"),  # not in the incident (no process image) and protected path
            ("isolate_host", "aegis-victim"),  # switched off
        ])
        decision = decide(self.ssh, self.events_of(self.ssh), self.policy, verdict)
        got = {(a.action, a.target): (a.outcome.value, a.source, a.reasons) for a in decision.actions}
        self.assertEqual(got[("lock_account", "svc_backup")][:2], ("needs_approval", "rules+model"))
        self.assertEqual(got[("lock_account", "root")], ("deny", "model", ("root is a protected account",)))
        self.assertEqual(got[("kill_process", "/usr/bin/cat")][0], "deny")
        self.assertIn("'/usr/bin/cat' does not appear in this incident's events", got[("kill_process", "/usr/bin/cat")][2])
        self.assertIn("/usr/bin/cat is under the protected path /usr/", got[("kill_process", "/usr/bin/cat")][2])
        self.assertEqual(got[("isolate_host", "aegis-victim")], ("deny", "model", ("isolate_host is switched off in the policy",)))

    def test_advice_hosts_deny_everything(self):
        powershell = next(i for i in self.incidents if i.max_level == 12)  # host win-laptop, agent 001
        decision = decide(powershell, self.events_of(powershell), self.policy)
        self.assertEqual(decision.host_mode, "advice")
        self.assertTrue(decision.actions)
        for action in decision.actions:
            self.assertEqual(action.outcome, ActionOutcome.DENY)
            self.assertIn("advice-only host: agent 001 is named 'win-laptop' but the policy expects 'LenovoMSamman'",
                          action.reasons[0])

    def test_unknown_host_and_wrong_name(self):
        for agent_id, name, expected in (("009", "aegis-victim", "agent 009 is not listed in the policy"),
                                         ("002", "impostor", "agent 002 is named 'impostor'")):
            with self.subTest(agent=agent_id, name=name):
                events = [Event.from_dict(dict(e.to_dict(), host={"agent_id": agent_id, "name": name, "ip": None}))
                          for e in self.events_of(self.ssh)]
                incident = one_incident(events)
                decision = decide(incident, events, self.policy)
                self.assertEqual(decision.host_mode, "advice")
                self.assertTrue(all(a.outcome is ActionOutcome.DENY for a in decision.actions))
                self.assertIn(expected, decision.actions[0].reasons[0])

    def test_risk_too_low_for_the_action(self):
        events = failures(3, src="10.0.0.9", user="bob") + [success(4)]
        incident = one_incident(events)
        decision = decide(incident, events, self.policy)  # 5 + 35 = 40: medium
        got = {a.action: a for a in decision.actions}
        self.assertEqual(got["lock_account"].outcome, ActionOutcome.DENY)
        self.assertEqual(got["lock_account"].reasons, ("risk is medium; lock_account needs at least high",))
        self.assertEqual(got["block_ip"].outcome, ActionOutcome.NEEDS_APPROVAL)

    def test_same_input_always_gives_the_same_decision(self):
        events = self.events_of(self.ssh)
        first = decide(self.ssh, events, self.policy).to_dict()
        shuffled = list(events)
        random.Random(3).shuffle(shuffled)
        self.assertEqual(decide(self.ssh, shuffled, self.policy).to_dict(), first)
        self.assertEqual(json.dumps(decide(self.ssh, events, load_policy()).to_dict(), sort_keys=True),
                         json.dumps(first, sort_keys=True))

    def test_latest_verdict(self):
        old = self.verdict(self.ssh, "benign")
        new = Verdict.from_dict(dict(self.verdict(self.ssh, "malicious").to_dict(), created_at="2026-11-15T00:00:00Z"))
        self.assertIs(latest_verdict([new, old], self.ssh.incident_id), new)
        self.assertIsNone(latest_verdict([new], "inc-" + "0" * 16))


class PolicyFileTests(unittest.TestCase):
    def setUp(self):
        self.data = json.loads(DEFAULT_POLICY_FILE.read_text(encoding="utf-8"))
        self.folder = tempfile.TemporaryDirectory()
        self.addCleanup(self.folder.cleanup)

    def load(self, data):
        path = Path(self.folder.name) / "policy.json"
        path.write_text(data if isinstance(data, str) else json.dumps(data), encoding="utf-8")
        return load_policy(path)

    def test_project_policy(self):
        policy = load_policy()
        self.assertEqual(policy.hosts["001"].mode, "advice")
        self.assertEqual(policy.hosts["002"].mode, "lab")
        self.assertIn("root", policy.protected_accounts)
        self.assertIn("192.168.56.1", policy.protected_addresses)
        self.assertFalse(policy.actions["isolate_host"].enabled)
        self.assertTrue(all(rule.approval for rule in policy.actions.values()))
        self.assertRegex(policy.id, r"^[0-9a-f]{6}$")

    def test_comments_do_not_change_the_fingerprint_but_rules_do(self):
        same = copy.deepcopy(self.data)
        same["_about"] = "a different comment"
        self.assertEqual(self.load(same).id, load_policy().id)
        changed = copy.deepcopy(self.data)
        changed["protected_accounts"].append("bob")
        self.assertNotEqual(self.load(changed).id, load_policy().id)

    def test_approval_can_be_waived_but_not_for_locking_accounts(self):
        data = copy.deepcopy(self.data)
        data["actions"]["block_ip"]["approval"] = False
        policy = self.load(data)
        events = failures(5) + [success(6), ev(7, level=15, src="10.0.0.9")]  # 15 + 35 = 50: high
        decision = decide(one_incident(events), events, policy)
        outcomes = {a.action: a.outcome for a in decision.actions}
        self.assertEqual(outcomes, {"block_ip": ActionOutcome.ALLOW, "lock_account": ActionOutcome.NEEDS_APPROVAL})
        for action in ("lock_account", "isolate_host"):
            data = copy.deepcopy(self.data)
            data["actions"][action]["approval"] = False
            with self.assertRaises(ContractError) as caught:
                self.load(data)
            self.assertIn("always needs a human", str(caught.exception))

    def test_locking_needs_a_human_even_if_a_policy_says_otherwise(self):
        # The file loader refuses this; the engine refuses it again, in case a
        # policy is ever built some other way.
        import dataclasses
        from aegis.policy import ActionRule
        policy = load_policy()
        actions = dict(policy.actions, lock_account=ActionRule(True, "high", approval=False))
        policy = dataclasses.replace(policy, actions=actions)
        events = failures(5) + [success(6), ev(7, level=15, src="10.0.0.9")]
        decision = decide(one_incident(events), events, policy)
        lock = next(a for a in decision.actions if a.action == "lock_account")
        self.assertEqual(lock.outcome, ActionOutcome.NEEDS_APPROVAL)

    def test_broken_policies_are_errors(self):
        def changed(**edits):
            data = copy.deepcopy(self.data)
            for path, value in edits.items():
                target = data
                *parents, last = path.split("__")
                for part in parents:
                    target = target[part]
                if value is KeyError:
                    del target[last]
                else:
                    target[last] = value
            return data

        cases = [
            ("{oops", "not valid JSON"),
            ("[]", "expected a JSON object"),
            (changed(default_mode="lab"), "default_mode must be 'advice'"),
            (changed(hosts__002__mode="act"), "mode must be one of"),
            (changed(hosts__002__name=""), "name must be text"),
            (changed(hosts__003={"name": "x"}), "needs 'name' and 'mode'"),
            (changed(hosts__002__address=KeyError), "a lab host needs its IP address"),
            (changed(hosts__002__port=22), "needs 'name' and 'mode'"),
            (changed(executor={"ssh_user": "x"}), "executor needs"),
            (changed(protected_accounts="root"), "protected_accounts must be a list"),
            (changed(protected_addresses=["not-an-ip"]), "is not an IP address"),
            (changed(actions__kill_process=KeyError), "actions must list exactly"),
            (changed(actions__block_ip__min_band="severe"), "min_band must be one of"),
            (changed(actions__block_ip__enabled="yes"), "must be true or false"),
            (changed(extra=1), "unknown key(s): extra"),
            (changed(actions=KeyError), "missing key(s): actions"),
        ]
        for data, expected in cases:
            with self.subTest(expected=expected):
                with self.assertRaises(ContractError) as caught:
                    self.load(data)
                self.assertIn(expected, str(caught.exception))


class DecisionContractTests(unittest.TestCase):
    def setUp(self):
        events = ingest_file(SAMPLE).events
        store = EvidenceStore(events)
        self.incidents = correlate(events).incidents
        self.decisions = [decide(i, [store.get(e) for e in i.event_ids], load_policy()) for i in self.incidents]

    def test_round_trip_and_store(self):
        for decision in self.decisions:
            self.assertEqual(Decision.from_dict(json.loads(json.dumps(decision.to_dict()))), decision)
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "decisions.jsonl"
            self.assertEqual(read_decisions(path), [])
            save_decisions(path, self.decisions)
            save_decisions(path, self.decisions[:2])
            self.assertEqual(len(read_decisions(path)), 7)

    def test_invalid_decisions_are_rejected(self):
        ssh = next(d for d in self.decisions if d.risk.band == "critical")
        good = ssh.to_dict()
        bad = {
            "score not the sum": dict(risk=dict(good["risk"], score=99)),
            "band wrong": dict(risk=dict(good["risk"], band="low")),
            "advice host acting": dict(host_mode="advice"),
            "unknown mode": dict(host_mode="yolo"),
            "no policy": dict(policy_id=""),
            "unknown field": dict(executed=True),
            "action outside catalog": dict(actions=[dict(good["actions"][0], action="wipe")]),
            "action without reason": dict(actions=[dict(good["actions"][0], reasons=[])]),
            "unknown outcome": dict(actions=[dict(good["actions"][0], outcome="maybe")]),
            "unknown source": dict(actions=[dict(good["actions"][0], source="vibes")]),
        }
        for name, changes in bad.items():
            with self.subTest(name=name):
                with self.assertRaises(ContractError):
                    Decision.from_dict(dict(copy.deepcopy(good), **changes))
        with self.assertRaises(ContractError):
            RiskScore(10, "low", (RiskFactor("x", 5, "r", ()),))


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

    def test_decide_one(self):
        code, out, err = run_cli("decide", "inc-dd29", "--dir", self.dir)
        self.assertEqual(code, 0, err)
        for expected in (
            "Host      aegis-victim (agent 002): lab  (policy ",
            "Risk      85 / 100   CRITICAL",
            "+35  password_guessed",
            "evidence: E1, E2, E3, E4, E5, E6",
            "Model     no saved verdict",
            "NEEDS APPROVAL  lock_account svc_backup   (suggested by: rules)",
            "DENY            block_ip 192.168.56.1",
            "- 192.168.56.1 is a protected address",
            "Nothing has been executed.",
        ):
            self.assertIn(expected, out)
        self.assertTrue(out.isascii())
        self.assertEqual(len(read_decisions(self.dir / "decisions.jsonl")), 1)

    def test_decide_all(self):
        code, out, err = run_cli("decide", "--all", "--dir", self.dir)
        self.assertEqual(code, 0, err)
        lines = out.splitlines()
        self.assertTrue(lines[1].startswith("inc-dd29f3ede  10   85  critical  lab"))
        self.assertIn("1 to approve, 1 denied", lines[1])
        self.assertIn("Risk bands  1 critical, 3 medium, 3 low", out)
        self.assertIn("Actions waiting for a human: 1", out)
        self.assertEqual(len(read_decisions(self.dir / "decisions.jsonl")), 7)

    def test_errors(self):
        for args, expected in (((), "give one incident id, or --all"), (("zzz",), "no incident id starts with"),
                               (("inc-dd29", "--policy", self.dir / "missing.json"), "file not found")):
            with self.subTest(args=args):
                code, _, err = run_cli("decide", *args, "--dir", self.dir)
                self.assertEqual(code, 2)
                self.assertIn(expected, err)


if __name__ == "__main__":
    unittest.main()
