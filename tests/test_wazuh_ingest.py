"""Wazuh ingest: real-shaped alerts in, contract-valid events out."""

import copy
import json
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from aegis.contracts import Category, Event, Outcome
from aegis.ingest import AlertError, ingest_file, ingest_text, normalize_alert
from aegis.ingest.wazuh import read_text
from aegis.store import read_events, write_events

SAMPLE = Path(__file__).resolve().parent.parent / "data" / "samples" / "wazuh_alerts_sample.jsonl"
UTC = timezone.utc


def sample_alerts():
    return [json.loads(line) for line in SAMPLE.read_text(encoding="utf-8").splitlines() if line.strip()]


def alert_with_rule(alerts, rule_id):
    """A fresh copy of the first raw sample alert fired by ``rule_id``."""
    return copy.deepcopy(next(a for a in alerts if a["rule"]["id"] == rule_id))


def by_rule(events, rule_id):
    found = [e for e in events if e.rule.id == rule_id]
    assert found, f"no event with rule {rule_id}"
    return found


class SampleFileTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.result = ingest_file(SAMPLE)
        cls.events = cls.result.events

    def test_every_alert_is_normalized(self):
        self.assertEqual(self.result.seen, 18)
        self.assertEqual(len(self.events), 18)
        self.assertEqual(self.result.issues, [])
        self.assertEqual(self.result.duplicates, 0)

    def test_events_are_sorted_oldest_first_and_ids_are_unique(self):
        stamps = [e.timestamp for e in self.events]
        self.assertEqual(stamps, sorted(stamps))
        self.assertEqual(len({e.event_id for e in self.events}), len(self.events))

    def test_local_time_is_converted_to_utc(self):
        first_ssh = by_rule(self.events, "5710")[0]
        self.assertEqual(first_ssh.timestamp, datetime(2026, 11, 14, 18, 14, 2, 118000, tzinfo=UTC))

    def test_event_time_is_when_it_happened_not_when_wazuh_saw_it(self):
        # This logon reached the manager 12 hours after it happened.
        failure = by_rule(self.events, "60122")[0]
        self.assertEqual(failure.timestamp, datetime(2026, 11, 14, 5, 2, 11, 330123, tzinfo=UTC))
        self.assertEqual(failure.observed_at, datetime(2026, 11, 14, 17, 2, 11, 640000, tzinfo=UTC))
        self.assertAlmostEqual(failure.delay.total_seconds(), 12 * 3600, delta=1)
        # ...so it sorts first, although it is the third line of the file.
        self.assertEqual(self.events[0].event_id, failure.event_id)

    def test_events_without_their_own_time_use_the_manager_time(self):
        ssh = by_rule(self.events, "5710")[0]
        self.assertEqual(ssh.timestamp, ssh.observed_at)
        self.assertEqual(ssh.delay.total_seconds(), 0)

    def test_account_change_has_actor_and_target(self):
        event = by_rule(self.events, "60110")[0]
        self.assertEqual(event.category, Category.ACCOUNT)
        self.assertEqual(event.user, "WIN-LAPTOP$")
        self.assertEqual(event.target_user, "labuser")

    def test_registry_event(self):
        event = by_rule(self.events, "92307")[0]
        self.assertEqual(event.category, Category.REGISTRY)
        self.assertEqual(
            event.registry_key,
            "HKLM\\System\\CurrentControlSet\\Services\\AegisUpdater\\ImagePath",
        )
        self.assertEqual(event.user, "NT AUTHORITY\\SYSTEM")
        # doubled backslashes are collapsed in the rule description too
        self.assertIn("HKLM\\System\\CurrentControlSet", event.rule.description)
        self.assertNotIn("\\\\", event.rule.description)

    def test_ssh_invalid_user(self):
        event = by_rule(self.events, "5710")[0]
        self.assertEqual(event.category, Category.AUTHENTICATION)
        self.assertEqual(event.outcome, Outcome.FAILURE)
        self.assertEqual(event.host.name, "aegis-victim")
        self.assertEqual(event.host.agent_id, "002")
        self.assertEqual(event.user, "admin")
        self.assertIsNone(event.target_user)
        self.assertEqual(event.network.src_ip, "192.168.56.1")
        self.assertEqual(event.network.src_port, 51820)
        self.assertEqual(event.mitre.technique_ids, ("T1110.001", "T1021.004"))
        self.assertIn("Invalid user admin", event.message)
        self.assertEqual(event.source, "wazuh")
        self.assertEqual(event.source_ref, "1794680042.14001")

    def test_ssh_brute_force_and_success(self):
        brute = by_rule(self.events, "5763")[0]
        self.assertEqual(brute.rule.level, 10)
        self.assertEqual(brute.outcome, Outcome.FAILURE)
        self.assertEqual(brute.user, "svc_backup")
        success = by_rule(self.events, "5715")[0]
        self.assertEqual(success.outcome, Outcome.SUCCESS)
        self.assertEqual(success.user, "svc_backup")

    def test_sudo_has_actor_target_and_command(self):
        event = by_rule(self.events, "5402")[0]
        self.assertEqual(event.category, Category.AUTHENTICATION)
        self.assertEqual(event.user, "svc_backup")
        self.assertEqual(event.target_user, "root")
        self.assertEqual(event.process.command_line, "/usr/bin/cat /etc/shadow")
        self.assertEqual(event.outcome, Outcome.UNKNOWN)

    def test_windows_logon_failure_and_success(self):
        failure = by_rule(self.events, "60122")[0]
        self.assertEqual(failure.category, Category.AUTHENTICATION)
        self.assertEqual(failure.outcome, Outcome.FAILURE)
        self.assertEqual(failure.user, "labuser")
        self.assertEqual(failure.network.src_ip, "127.0.0.1")
        self.assertEqual(failure.network.src_port, 0)
        success = by_rule(self.events, "60106")[0]
        self.assertEqual(success.outcome, Outcome.SUCCESS)

    def test_sysmon_process_creation(self):
        event = by_rule(self.events, "92057")[0]
        self.assertEqual(event.category, Category.PROCESS)
        self.assertEqual(event.rule.level, 12)
        # doubled backslashes from Wazuh are collapsed in normalized fields...
        self.assertEqual(
            event.process.image,
            "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        )
        self.assertEqual(event.user, "WIN-LAPTOP\\labuser")
        self.assertIn("-EncodedCommand", event.process.command_line)
        self.assertEqual(event.process.pid, 7412)
        self.assertEqual(event.process.sha256, "ab12" * 16)
        self.assertEqual(event.mitre.technique_ids, ("T1059.001",))
        # ...while the raw evidence is kept exactly as received.
        self.assertIn("C:\\\\Windows", event.raw["data"]["win"]["eventdata"]["image"])

    def test_sysmon_network_connection(self):
        event = by_rule(self.events, "100103")[0]
        self.assertEqual(event.category, Category.NETWORK)
        self.assertEqual(event.network.dst_ip, "203.0.113.50")
        self.assertEqual(event.network.dst_port, 443)
        self.assertEqual(event.network.dst_host, "updates.example.net")
        self.assertEqual(event.network.protocol, "tcp")
        self.assertEqual(event.outcome, Outcome.UNKNOWN)

    def test_file_integrity_events(self):
        added = by_rule(self.events, "554")[0]
        self.assertEqual(added.category, Category.FILE)
        self.assertTrue(added.file_path.endswith("update.ps1"))
        changed = by_rule(self.events, "550")[0]
        self.assertEqual(changed.file_path, "/etc/passwd")

    def test_posture_findings_get_their_own_categories(self):
        self.assertEqual(by_rule(self.events, "19007")[0].category, Category.CONFIG_ASSESSMENT)
        self.assertEqual(by_rule(self.events, "23505")[0].category, Category.VULNERABILITY)

    def test_manager_event_is_other(self):
        event = by_rule(self.events, "502")[0]
        self.assertEqual(event.category, Category.OTHER)
        self.assertEqual(event.host.agent_id, "000")
        self.assertIsNone(event.host.ip)
        self.assertIsNone(event.process)
        self.assertIsNone(event.network)

    def test_event_ids_are_deterministic(self):
        again = ingest_file(SAMPLE).events
        self.assertEqual([e.event_id for e in again], [e.event_id for e in self.events])

    def test_min_level_filter_is_counted(self):
        result = ingest_file(SAMPLE, min_level=7)
        self.assertEqual(len(result.events), 6)
        self.assertEqual(result.below_min_level, 12)
        self.assertTrue(all(e.rule.level >= 7 for e in result.events))

    def test_store_round_trip(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "nested" / "events.jsonl"
            self.assertEqual(write_events(path, self.events), 18)
            self.assertEqual(read_events(path), self.events)


class InputFormatTests(unittest.TestCase):
    def setUp(self):
        self.alerts = sample_alerts()
        self.expected = [e.event_id for e in ingest_file(SAMPLE).events]

    def ids(self, text):
        result = ingest_text(text)
        self.assertEqual(result.issues, [])
        return [e.event_id for e in result.events]

    def test_json_array(self):
        self.assertEqual(self.ids(json.dumps(self.alerts)), self.expected)

    def test_pretty_printed_json_array(self):
        self.assertEqual(self.ids(json.dumps(self.alerts, indent=2)), self.expected)

    def test_indexer_search_response(self):
        response = {"took": 3, "hits": {"total": {"value": 18}, "hits": [
            {"_index": "wazuh-alerts-4.x-2026.11.14", "_id": str(i), "_source": a}
            for i, a in enumerate(self.alerts)
        ]}}
        self.assertEqual(self.ids(json.dumps(response)), self.expected)
        self.assertEqual(self.ids(json.dumps(response, indent=2)), self.expected)

    def test_source_wrapped_lines(self):
        text = "\n".join(json.dumps({"_id": str(i), "_source": a}) for i, a in enumerate(self.alerts))
        self.assertEqual(self.ids(text), self.expected)

    def test_single_pretty_printed_alert(self):
        result = ingest_text(json.dumps(self.alerts[0], indent=2))
        self.assertEqual(len(result.events), 1)
        self.assertEqual(result.issues, [])

    def test_indexer_timestamp_field(self):
        original = alert_with_rule(self.alerts, "5710")
        alert = copy.deepcopy(original)
        alert["@timestamp"] = "2026-11-14T18:14:02.118Z"
        del alert["timestamp"]
        event = normalize_alert(alert)
        self.assertEqual(event.event_id, normalize_alert(original).event_id)

    def test_blank_lines_and_windows_line_endings(self):
        text = "\r\n\r\n".join(json.dumps(a) for a in self.alerts) + "\r\n"
        self.assertEqual(self.ids(text), self.expected)

    def test_empty_input(self):
        for text in ("", "   \n\n"):
            result = ingest_text(text)
            self.assertEqual((result.seen, result.events, result.issues), (0, [], []))

    def test_utf16_and_bom_files_from_powershell(self):
        # Bytes are written directly so the test is identical on Windows and
        # Linux. "utf-16" and "utf-8-sig" both start with a byte-order mark.
        for line_ending in ("\n", "\r\n"):
            text = line_ending.join(json.dumps(a) for a in self.alerts) + line_ending
            with tempfile.TemporaryDirectory() as folder:
                for encoding in ("utf-16", "utf-8-sig", "utf-8"):
                    with self.subTest(encoding=encoding, line_ending=line_ending):
                        path = Path(folder) / f"export-{encoding}.json"
                        path.write_bytes(text.encode(encoding))
                        self.assertEqual(read_text(path), text)
                        result = ingest_file(path)
                        self.assertEqual(result.issues, [])
                        self.assertEqual([e.event_id for e in result.events], self.expected)


class BadInputTests(unittest.TestCase):
    def setUp(self):
        self.alerts = sample_alerts()

    def test_bad_lines_are_reported_not_dropped(self):
        lines = [json.dumps(a) for a in self.alerts[:3]]
        lines.insert(1, '{"timestamp": "2026-11-14T21:14:02.118+0300", "rule": {"le')  # truncated
        lines.append("42")
        lines.append('{"hello": "world"}')
        result = ingest_text("\n".join(lines))
        self.assertEqual(result.seen, 6)
        self.assertEqual(len(result.events), 3)
        self.assertEqual(
            [(i.where, i.reason) for i in result.issues],
            [
                ("line 2", "not valid JSON"),
                ("line 5", "expected a JSON object, got int"),
                ("line 6", "missing timestamp"),
            ],
        )

    def test_broken_first_line_does_not_hide_the_rest(self):
        lines = ["{broken"] + [json.dumps(a) for a in self.alerts[:2]]
        result = ingest_text("\n".join(lines))
        self.assertEqual(len(result.events), 2)
        self.assertEqual([i.where for i in result.issues], ["line 1"])

    def test_array_items_are_located(self):
        result = ingest_text(json.dumps([self.alerts[0], "oops", self.alerts[1]]))
        self.assertEqual(len(result.events), 2)
        self.assertEqual([i.where for i in result.issues], ["item 2"])

    def test_duplicates_are_counted_once(self):
        text = "\n".join(json.dumps(a) for a in self.alerts[:4] + self.alerts[:2])
        result = ingest_text(text)
        self.assertEqual(len(result.events), 4)
        self.assertEqual(result.duplicates, 2)

    def test_missing_essentials_raise_alert_error(self):
        cases = {
            "missing timestamp": lambda a: a.pop("timestamp"),
            "no timezone offset": lambda a: a.update(timestamp="2026-11-14T21:14:02"),
            "missing rule.id": lambda a: a["rule"].pop("id"),
            "rule.level is not an integer": lambda a: a["rule"].update(level="high"),
            "missing agent.id": lambda a: a.pop("agent"),
            "rule level must be an integer 0-16": lambda a: a["rule"].update(level=99),
        }
        for expected, damage in cases.items():
            with self.subTest(expected=expected):
                alert = alert_with_rule(self.alerts, "5710")
                damage(alert)
                with self.assertRaises(AlertError) as caught:
                    normalize_alert(alert)
                self.assertIn(expected, str(caught.exception))

    def test_non_object_alert(self):
        for bad in (None, [], "alert", 5):
            with self.subTest(bad=bad):
                with self.assertRaises(AlertError):
                    normalize_alert(bad)

    def test_odd_field_types_do_not_crash(self):
        alert = alert_with_rule(self.alerts, "5710")
        alert["data"] = "not a dict"
        alert["rule"]["groups"] = "sshd"
        alert["rule"]["mitre"] = ["T1110"]
        alert["agent"]["ip"] = None
        event = normalize_alert(alert)
        self.assertIsInstance(event, Event)
        self.assertEqual(event.rule.groups, ("sshd",))
        self.assertIsNone(event.network)
        self.assertIsNone(event.user)

    def test_alert_without_id_still_gets_a_stable_event_id(self):
        original = alert_with_rule(self.alerts, "5710")
        alert = copy.deepcopy(original)
        del alert["id"]
        first = normalize_alert(alert)
        second = normalize_alert(copy.deepcopy(alert))
        self.assertEqual(first.event_id, second.event_id)
        self.assertNotEqual(first.event_id, normalize_alert(original).event_id)

    def test_failed_logon_without_a_target_has_no_user(self):
        # Real Windows 4625 events can lack targetUserName. The subject is
        # then only the computer's own account, which is not who tried to log on.
        alert = alert_with_rule(self.alerts, "60122")
        del alert["data"]["win"]["eventdata"]["targetUserName"]
        alert["data"]["win"]["eventdata"]["subjectUserName"] = "WIN-LAPTOP$"
        event = normalize_alert(alert)
        self.assertIsNone(event.user)
        self.assertIsNone(event.target_user)

    def test_privilege_event_uses_the_subject_as_user(self):
        alert = alert_with_rule(self.alerts, "60106")
        alert["data"]["win"]["system"]["eventID"] = "4672"
        alert["data"]["win"]["eventdata"] = {"subjectUserName": "labuser", "privilegeList": "SeDebugPrivilege"}
        event = normalize_alert(alert)
        self.assertEqual((event.user, event.target_user), ("labuser", None))
        self.assertEqual(event.category, Category.AUTHENTICATION)

    def test_unusable_windows_event_time_falls_back_to_manager_time(self):
        for bad in ("not a time", "2026-11-14T05:02:11", 12345, None):
            with self.subTest(bad=bad):
                alert = alert_with_rule(self.alerts, "60122")
                alert["data"]["win"]["system"]["systemTime"] = bad
                event = normalize_alert(alert)
                self.assertEqual(event.timestamp, event.observed_at)

    def test_event_id_does_not_depend_on_the_event_time(self):
        original = alert_with_rule(self.alerts, "60122")
        alert = copy.deepcopy(original)
        del alert["data"]["win"]["system"]["systemTime"]
        self.assertEqual(normalize_alert(alert).event_id, normalize_alert(original).event_id)

    def test_undoubled_windows_paths_are_left_alone(self):
        alert = alert_with_rule(self.alerts, "92057")  # the Sysmon process alert
        alert["data"]["win"]["eventdata"]["image"] = "C:\\Tools\\x.exe"
        alert["data"]["win"]["eventdata"]["parentImage"] = "\\\\\\\\fileserver\\\\share\\\\run.exe"
        event = normalize_alert(alert)
        self.assertEqual(event.process.image, "C:\\Tools\\x.exe")
        self.assertEqual(event.process.parent_image, "\\\\fileserver\\share\\run.exe")

    def test_escaped_quotes_in_windows_command_lines(self):
        # As Wazuh delivers it:  \"C:\\Program Files\\a.exe\" /c \"x y\"
        alert = alert_with_rule(self.alerts, "92057")
        alert["data"]["win"]["eventdata"]["commandLine"] = (
            '\\"C:\\\\Program Files\\\\a.exe\\" /c \\"x y\\"'
        )
        event = normalize_alert(alert)
        self.assertEqual(event.process.command_line, '"C:\\Program Files\\a.exe" /c "x y"')

    def test_unescaped_values_with_quotes_are_left_alone(self):
        alert = alert_with_rule(self.alerts, "92057")
        for value in ('"C:\\Tools\\x.exe" -a', "C:\\Tools\\", "plain text", 'say "hi"'):
            with self.subTest(value=value):
                alert["data"]["win"]["eventdata"]["commandLine"] = value
                self.assertEqual(normalize_alert(alert).process.command_line, value)


if __name__ == "__main__":
    unittest.main()
