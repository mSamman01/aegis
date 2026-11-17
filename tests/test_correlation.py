"""Correlation: which events become one incident, and why."""

import contextlib
import io
import json
import random
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from aegis.cli import main
from aegis.contracts import (
    Category,
    ContractError,
    Event,
    Host,
    Incident,
    Link,
    LinkReason,
    Network,
    Process,
    Rule,
    RuleCount,
    incident_id_for,
)
from aegis.correlate import CorrelationConfig, account_key, correlate, remote_address
from aegis.ingest import ingest_file, normalize_alert
from aegis.store import read_incidents, write_incidents

SAMPLE = Path(__file__).resolve().parent.parent / "data" / "samples" / "wazuh_alerts_sample.jsonl"
T0 = datetime(2026, 11, 14, 12, 0, 0, tzinfo=timezone.utc)
GUID_A = "aaaaaaaa-0000-0000-0000-000000000001"
GUID_B = "bbbbbbbb-0000-0000-0000-000000000002"
GUID_C = "cccccccc-0000-0000-0000-000000000003"


def ev(n, minutes=0.0, *, host="001", rule=None, level=5, category=Category.OTHER,
       user=None, target=None, src_ip=None, guid=None, parent_guid=None, parent_image=None):
    """A small synthetic event. Each gets its own rule id unless one is given."""
    process = None
    if guid or parent_guid:
        process = Process(image="C:\\\\x\\\\app.exe", guid=guid, parent_guid=parent_guid, parent_image=parent_image)
    return Event(
        event_id=f"evt-{n:016x}",
        timestamp=T0 + timedelta(minutes=minutes),
        source="test",
        source_ref=str(n),
        host=Host(agent_id=host, name=f"host-{host}"),
        rule=Rule(id=rule or str(1000 + n), level=level, description=f"rule {rule or 1000 + n}"),
        category=category,
        user=user,
        target_user=target,
        process=process,
        network=Network(src_ip=src_ip) if src_ip else None,
    )


def groups(result):
    """Incidents as sorted lists of event numbers, e.g. [[1, 2], [3]]."""
    return sorted(sorted(int(e[4:], 16) for e in inc.event_ids) for inc in result.incidents)


def link_reasons(result):
    return {(int(l.event_id[4:], 16), int(l.linked_to[4:], 16)): l.reason
            for inc in result.incidents for l in inc.links}


class SampleStoryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.events = ingest_file(SAMPLE).events
        cls.by_id = {e.event_id: e for e in cls.events}
        cls.result = correlate(cls.events)

    def incident_with_rule(self, rule_id):
        found = [i for i in self.result.incidents if any(r.rule_id == rule_id for r in i.rules)]
        self.assertEqual(len(found), 1, f"rule {rule_id} should be in exactly one incident")
        return found[0]

    def test_overall_shape(self):
        self.assertEqual(self.result.events_in, 18)
        self.assertEqual(len(self.result.posture_event_ids), 2)
        self.assertEqual(len(self.result.incidents), 7)
        self.assertEqual(sum(len(i.event_ids) for i in self.result.incidents), 16)
        levels = [i.max_level for i in self.result.incidents]
        self.assertEqual(levels, sorted(levels, reverse=True))

    def test_ssh_brute_force_login_and_sudo_are_one_incident(self):
        incident = self.incident_with_rule("5763")
        self.assertEqual(incident.host.name, "aegis-victim")
        self.assertEqual(
            {r.rule_id: r.count for r in incident.rules},
            {"5710": 2, "5760": 2, "5763": 1, "5715": 1, "5402": 1},
        )
        self.assertEqual(incident.max_level, 10)
        self.assertEqual(incident.source_ips, ("192.168.56.1",))
        self.assertEqual(incident.accounts, ("admin", "root", "svc_backup", "test"))
        self.assertIn("T1110", incident.technique_ids)
        self.assertEqual(incident.first_seen, datetime(2026, 11, 14, 18, 14, 2, 118000, tzinfo=timezone.utc))
        self.assertEqual(incident.rules[0].rule_id, "5763")  # most severe first
        # the sudo has no source address: it joins through the account that logged in
        sudo = next(l for l in incident.links if self.by_id[l.event_id].rule.id == "5402")
        self.assertEqual((sudo.reason, sudo.value), (LinkReason.SAME_ACCOUNT, "svc_backup"))
        self.assertEqual(self.by_id[sudo.linked_to].rule.id, "5715")
        others = [l.reason for l in incident.links if l is not sudo]
        self.assertEqual(others, [LinkReason.SAME_SOURCE_IP] * 5)

    def test_powershell_and_its_network_connection_are_one_incident(self):
        incident = self.incident_with_rule("92057")
        self.assertEqual(incident.host.name, "win-laptop")
        self.assertEqual(len(incident.event_ids), 2)
        self.assertEqual([l.reason for l in incident.links], [LinkReason.SAME_PROCESS])
        self.assertEqual(incident.max_level, 12)

    def test_morning_logon_events_are_grouped_by_account(self):
        incident = self.incident_with_rule("60122")
        self.assertEqual({r.rule_id for r in incident.rules}, {"60122", "60106", "60110"})
        self.assertEqual({l.reason for l in incident.links}, {LinkReason.SAME_ACCOUNT})

    def test_posture_findings_are_set_aside(self):
        posture_rules = {self.by_id[e].rule.id for e in self.result.posture_event_ids}
        self.assertEqual(posture_rules, {"19007", "23505"})
        in_incidents = {e for i in self.result.incidents for e in i.event_ids}
        self.assertFalse(in_incidents & set(self.result.posture_event_ids))

    def test_unrelated_events_stay_separate(self):
        for rule_id in ("550", "554", "502", "92307"):
            self.assertEqual(len(self.incident_with_rule(rule_id).event_ids), 1)

    def test_same_input_in_any_order_gives_identical_incidents(self):
        shuffled = list(self.events)
        random.Random(7).shuffle(shuffled)
        again = correlate(shuffled)
        self.assertEqual(again.incidents, self.result.incidents)


class LinkingRuleTests(unittest.TestCase):
    def test_window_edge(self):
        inside = correlate([ev(1, 0, src_ip="10.0.0.9"), ev(2, 30, src_ip="10.0.0.9")])
        self.assertEqual(groups(inside), [[1, 2]])
        outside = correlate([ev(1, 0, src_ip="10.0.0.9"), ev(2, 30.02, src_ip="10.0.0.9")])
        self.assertEqual(groups(outside), [[1], [2]])

    def test_links_chain_beyond_one_window(self):
        events = [ev(n, 20 * n, src_ip="10.0.0.9") for n in range(1, 5)]
        self.assertEqual(groups(correlate(events)), [[1, 2, 3, 4]])

    def test_custom_window(self):
        events = [ev(1, 0, src_ip="10.0.0.9"), ev(2, 10, src_ip="10.0.0.9")]
        config = CorrelationConfig(window=timedelta(minutes=5))
        self.assertEqual(groups(correlate(events, config)), [[1], [2]])
        with self.assertRaises(ValueError):
            CorrelationConfig(window=timedelta(0))

    def test_hosts_are_never_mixed(self):
        events = [ev(1, 0, host="001", src_ip="10.0.0.9", user="alice", rule="77"),
                  ev(2, 1, host="002", src_ip="10.0.0.9", user="alice", rule="77")]
        self.assertEqual(groups(correlate(events)), [[1], [2]])

    def test_different_links_join_into_one_incident(self):
        events = [ev(1, 0, src_ip="10.0.0.9"),
                  ev(2, 1, src_ip="10.0.0.9", user="alice"),
                  ev(3, 2, user="alice"),
                  ev(4, 3, user="bob")]
        result = correlate(events)
        self.assertEqual(groups(result), [[1, 2, 3], [4]])
        self.assertEqual(link_reasons(result), {(2, 1): LinkReason.SAME_SOURCE_IP, (3, 2): LinkReason.SAME_ACCOUNT})

    def test_account_names_are_normalized(self):
        events = [ev(1, 0, user="WIN-LAPTOP\\\\Alice"), ev(2, 1, user="alice"), ev(3, 2, target="ALICE")]
        self.assertEqual(groups(correlate(events)), [[1, 2, 3]])

    def test_system_accounts_do_not_link(self):
        for name in ("NT AUTHORITY\\\\SYSTEM", "LOCAL SERVICE", "WIN-LAPTOP$", "DWM-2", "UMFD-1",
                     "548100E0-324C-5580-9B4B-6ECD12A6B9DB"):
            with self.subTest(name=name):
                self.assertIsNone(account_key(name))
                self.assertEqual(groups(correlate([ev(1, 0, user=name), ev(2, 1, user=name)])), [[1], [2]])
        self.assertEqual(account_key("root"), "root")
        self.assertIsNone(account_key(None))
        self.assertIsNone(account_key(""))

    def test_loopback_and_junk_addresses_do_not_link(self):
        for address in ("127.0.0.1", "::1", "0.0.0.0", "not-an-ip"):
            with self.subTest(address=address):
                self.assertIsNone(remote_address(address))
                events = [ev(1, 0, src_ip=address), ev(2, 1, src_ip=address)]
                self.assertEqual(groups(correlate(events)), [[1], [2]])
        self.assertEqual(remote_address(" 192.168.56.1 "), "192.168.56.1")

    def test_same_process(self):
        result = correlate([ev(1, 0, guid=GUID_A), ev(2, 1, guid=GUID_A)])
        self.assertEqual(groups(result), [[1, 2]])
        self.assertEqual(link_reasons(result), {(2, 1): LinkReason.SAME_PROCESS})

    def test_parent_and_child(self):
        result = correlate([ev(1, 0, guid=GUID_A), ev(2, 1, guid=GUID_B, parent_guid=GUID_A)])
        self.assertEqual(link_reasons(result), {(2, 1): LinkReason.PARENT_PROCESS})
        # the parent acting after its child started is the same relationship
        result = correlate([ev(1, 0, guid=GUID_B, parent_guid=GUID_A), ev(2, 1, guid=GUID_A)])
        self.assertEqual(link_reasons(result), {(2, 1): LinkReason.PARENT_PROCESS})

    def test_children_of_one_parent(self):
        result = correlate([ev(1, 0, guid=GUID_B, parent_guid=GUID_A, parent_image="C:\\\\agent\\\\agent.exe"),
                            ev(2, 1, guid=GUID_C, parent_guid=GUID_A, parent_image="C:\\\\agent\\\\agent.exe")])
        self.assertEqual(link_reasons(result), {(2, 1): LinkReason.SAME_PARENT})

    def test_children_of_a_hub_process_are_not_linked(self):
        for hub in ("C:\\\\Windows\\\\System32\\\\svchost.exe", "C:\\\\WINDOWS\\\\Explorer.EXE", "services.exe"):
            with self.subTest(hub=hub):
                events = [ev(1, 0, guid=GUID_B, parent_guid=GUID_A, parent_image=hub),
                          ev(2, 1, guid=GUID_C, parent_guid=GUID_A, parent_image=hub)]
                self.assertEqual(groups(correlate(events)), [[1], [2]])

    def test_a_hub_process_own_actions_are_still_linked(self):
        events = [ev(1, 0, guid=GUID_A), ev(2, 1, guid=GUID_A)]
        self.assertEqual(groups(correlate(events)), [[1, 2]])

    def test_account_is_ignored_when_the_process_is_known(self):
        # Two different programs run by the same person are not one story.
        events = [ev(1, 0, guid=GUID_A, user="alice"), ev(2, 1, guid=GUID_B, user="alice")]
        self.assertEqual(groups(correlate(events)), [[1], [2]])
        # ...but an event without a process identity still links by account.
        events = [ev(1, 0, user="alice"), ev(2, 1, user="alice")]
        self.assertEqual(groups(correlate(events)), [[1, 2]])

    def test_same_rule_firing_again(self):
        result = correlate([ev(1, 0, rule="61634"), ev(2, 5, rule="61634"), ev(3, 6, rule="999")])
        self.assertEqual(groups(result), [[1, 2], [3]])
        self.assertEqual(link_reasons(result), {(2, 1): LinkReason.SAME_RULE})
        self.assertEqual(result.incidents[0].title, "rule 61634 (x2)")

    def test_titles(self):
        one = correlate([ev(1, 0, rule="7", level=9)]).incidents[0]
        self.assertEqual(one.title, "rule 7")
        two = correlate([ev(1, 0, user="alice", rule="7", level=9), ev(2, 1, user="alice", rule="8")]).incidents[0]
        self.assertEqual(two.title, "rule 7 (+1 related event, 2 rules)")
        three = correlate([ev(1, 0, user="alice", rule="7", level=9), ev(2, 1, user="alice", rule="8"),
                           ev(3, 2, user="alice", rule="8")]).incidents[0]
        self.assertEqual(three.title, "rule 7 (+2 related events, 2 rules)")

    def test_strongest_reason_is_kept(self):
        result = correlate([ev(1, 0, guid=GUID_A, src_ip="10.0.0.9", rule="5"),
                            ev(2, 1, guid=GUID_A, src_ip="10.0.0.9", rule="5")])
        self.assertEqual(link_reasons(result), {(2, 1): LinkReason.SAME_PROCESS})

    def test_duplicate_events_are_counted_and_skipped(self):
        result = correlate([ev(1, 0), ev(1, 0), ev(2, 1)])
        self.assertEqual((result.events_in, result.duplicates), (3, 1))
        self.assertEqual(groups(result), [[1], [2]])

    def test_empty_input(self):
        result = correlate([])
        self.assertEqual((result.incidents, result.posture_event_ids, result.events_in), ([], [], 0))

    def test_unknown_parent_id_from_sysmon_is_not_an_identity(self):
        # Sysmon writes an all-zero id for a parent it could not identify.
        alerts = [json.loads(line) for line in SAMPLE.read_text(encoding="utf-8").splitlines()]
        alert = next(a for a in alerts if a["rule"]["id"] == "92057")
        alert["data"]["win"]["eventdata"]["parentProcessGuid"] = "{00000000-0000-0000-0000-000000000000}"
        event = normalize_alert(alert)
        self.assertIsNone(event.process.parent_guid)
        self.assertEqual(event.process.guid, "5a1b9c3e-7412-6917-a301-000000001f00")


class IncidentContractTests(unittest.TestCase):
    def setUp(self):
        self.incident = correlate([ev(1, 0, src_ip="10.0.0.9", level=9), ev(2, 1, src_ip="10.0.0.9")]).incidents[0]

    def rebuilt(self, **changes):
        data = self.incident.to_dict()
        data.update(changes)
        return Incident.from_dict(json.loads(json.dumps(data)))

    def test_round_trip_through_json(self):
        self.assertEqual(self.rebuilt(), self.incident)
        self.assertEqual(self.incident.to_dict()["links"][0]["reason"], "same_source_ip")
        self.assertEqual(self.incident.duration, timedelta(minutes=1))

    def test_id_is_bound_to_the_exact_set_of_events(self):
        a, b, c = "evt-%016x" % 1, "evt-%016x" % 2, "evt-%016x" % 3
        self.assertEqual(self.incident.incident_id, incident_id_for([a, b]))
        self.assertEqual(incident_id_for([a, b]), incident_id_for([b, a]))
        self.assertNotEqual(incident_id_for([a, b]), incident_id_for([a, b, c]))
        with self.assertRaises(ContractError):  # same id, different evidence
            self.rebuilt(event_ids=[a, c])

    def test_invalid_incidents_are_rejected(self):
        a, b = self.incident.event_ids
        bad_changes = {
            "bad id": dict(incident_id="inc-123"),
            "no events": dict(event_ids=[]),
            "repeated event": dict(event_ids=[a, a]),
            "not an event id": dict(event_ids=[a, "nope"]),
            "times reversed": dict(first_seen="2026-11-14T13:00:00Z"),
            "level out of range": dict(max_level=99),
            "level disagrees with rules": dict(max_level=5),
            "unknown field": dict(verdict="malicious"),
            "unknown link reason": dict(links=[{"event_id": b, "linked_to": a, "reason": "vibes", "value": "x"}]),
            "link outside incident": dict(links=[{"event_id": b, "linked_to": "evt-%016x" % 99, "reason": "same_rule", "value": "x"}]),
            "self link": dict(links=[{"event_id": a, "linked_to": a, "reason": "same_rule", "value": "x"}]),
            "rule counts wrong": dict(rules=[{"rule_id": "1", "level": 9, "description": "", "count": 5}]),
            "future schema": dict(schema_version=99),
        }
        for name, changes in bad_changes.items():
            with self.subTest(name=name):
                with self.assertRaises(ContractError):
                    self.rebuilt(**changes)
        for bad in (None, [], "incident"):
            with self.assertRaises(ContractError):
                Incident.from_dict(bad)

    def test_store_round_trip(self):
        result = correlate(ingest_file(SAMPLE).events)
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "runs" / "incidents.jsonl"
            self.assertEqual(write_incidents(path, result.incidents), 7)
            self.assertEqual(read_incidents(path), result.incidents)


def run_cli(*args):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = main([str(a) for a in args])
    return code, out.getvalue(), err.getvalue()


class CommandTests(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.addCleanup(self.folder.cleanup)
        self.events = Path(self.folder.name) / "events.jsonl"
        self.incidents = Path(self.folder.name) / "incidents.jsonl"
        code, _, err = run_cli("ingest", SAMPLE, "--out", self.events)
        self.assertEqual(code, 0, err)

    def correlate_cli(self, *extra):
        return run_cli("correlate", self.events, "--out", self.incidents, *extra)

    def test_correlate_writes_incidents_and_lists_the_serious_ones(self):
        code, out, err = self.correlate_cli()
        self.assertEqual(code, 0, err)
        self.assertEqual(len(read_incidents(self.incidents)), 7)
        self.assertIn("(18 events)", out)
        self.assertIn("2 configuration / vulnerability findings set aside", out)
        self.assertIn("Incidents 7 from 16 events  (window 30 min)", out)
        self.assertIn("Incidents at level 7 or above: 4", out)
        self.assertIn("Below level 7: 3 incidents", out)
        self.assertTrue(out.isascii())

    def test_min_level_zero_lists_everything(self):
        code, out, _ = self.correlate_cli("--min-level", "0")
        self.assertEqual(code, 0)
        self.assertIn("All incidents: 7", out)
        self.assertNotIn("Below level", out)

    def test_window_option(self):
        code, out, _ = self.correlate_cli("--window", "0.01")
        self.assertEqual(code, 0)
        # 0.6 s: only the logon and the account change 0.2 s after it stay joined
        self.assertIn("Incidents 15 from 16 events  (window 0.01 min)", out)
        code, _, err = self.correlate_cli("--window", "0")
        self.assertEqual(code, 2)
        self.assertIn("--window must be greater than 0", err)

    def test_show_prints_the_timeline_with_link_reasons(self):
        self.correlate_cli()
        ssh = next(i for i in read_incidents(self.incidents) if i.max_level == 10)
        for wanted in (ssh.incident_id, ssh.incident_id[:9], ssh.incident_id[4:12].upper()):
            with self.subTest(wanted=wanted):
                code, out, err = run_cli("show", wanted, "--incidents", self.incidents, "--events", self.events)
                self.assertEqual(code, 0, err)
                self.assertIn(f"Incident  {ssh.incident_id}", out)
                self.assertIn("aegis-victim (agent 002)", out)
                self.assertIn("Sources   192.168.56.1", out)
                self.assertIn("user=svc_backup -> root  cmd=/usr/bin/cat /etc/shadow", out)
                self.assertIn("linked: same account svc_backup as evt-", out)
                self.assertEqual(out.count("linked: same source address 192.168.56.1 as evt-"), 5)
                self.assertTrue(out.isascii())

    def test_show_errors(self):
        self.correlate_cli()
        show = lambda wanted: run_cli("show", wanted, "--incidents", self.incidents, "--events", self.events)
        code, _, err = show("zzzz")
        self.assertEqual(code, 2)
        self.assertIn("no incident id starts with", err)
        code, _, err = show("inc-")
        self.assertEqual(code, 2)
        self.assertIn("7 incidents start with", err)

    def test_missing_files_are_clean_errors(self):
        code, _, err = run_cli("correlate", Path(self.folder.name) / "nope.jsonl", "--out", self.incidents)
        self.assertEqual(code, 2)
        self.assertIn("file not found", err)
        self.assertIn("ingest", err)
        code, _, err = run_cli("show", "abc", "--incidents", self.incidents, "--events", self.events)
        self.assertEqual(code, 2)
        self.assertIn("correlate", err)

    def test_show_refuses_incidents_and_events_from_different_runs(self):
        self.correlate_cli()
        other_events = Path(self.folder.name) / "other.jsonl"
        run_cli("ingest", SAMPLE, "--out", other_events, "--min-level", "12")
        ssh = next(i for i in read_incidents(self.incidents) if i.max_level == 10)
        code, _, err = run_cli("show", ssh.incident_id, "--incidents", self.incidents, "--events", other_events)
        self.assertEqual(code, 2)
        self.assertIn("different runs", err)

    def test_corrupt_incident_file_is_a_clean_error(self):
        self.incidents.write_text('{"incident_id": "inc-0000000000000000"}\n', encoding="utf-8")
        code, _, err = run_cli("show", "inc-0", "--incidents", self.incidents, "--events", self.events)
        self.assertEqual(code, 2)
        self.assertIn("cannot read", err)


if __name__ == "__main__":
    unittest.main()
