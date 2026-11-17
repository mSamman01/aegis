"""The Event contract: what a valid event is, and that bad ones are refused."""

import json
import unittest
from datetime import datetime, timedelta, timezone

from aegis.contracts import (
    Category,
    ContractError,
    Event,
    Host,
    Mitre,
    Network,
    Outcome,
    Process,
    Rule,
    format_ts,
    parse_ts,
)

UTC = timezone.utc


def make_event(**overrides):
    values = dict(
        event_id="evt-0123456789abcdef",
        timestamp=datetime(2026, 11, 14, 18, 14, 2, 118000, tzinfo=UTC),
        source="wazuh",
        source_ref="1794680042.14001",
        host=Host(agent_id="002", name="aegis-victim", ip="192.168.56.20"),
        rule=Rule(id="5710", level=5, description="sshd: non-existent user", groups=("sshd",)),
        category=Category.AUTHENTICATION,
        outcome=Outcome.FAILURE,
        mitre=Mitre(technique_ids=("T1110.001",), tactics=("Credential Access",)),
        user="admin",
        process=Process(image="/usr/sbin/sshd", pid=2210),
        network=Network(src_ip="192.168.56.1", src_port=51820),
        registry_key="HKLM\\Software\\Example",
        observed_at=datetime(2026, 11, 14, 18, 20, 2, 118000, tzinfo=UTC),
        raw={"id": "1794680042.14001", "nested": {"list": [1, 2]}},
    )
    values.update(overrides)
    return Event(**values)


class TimestampTests(unittest.TestCase):
    def test_wazuh_alert_file_format_is_converted_to_utc(self):
        parsed = parse_ts("2026-11-14T21:14:02.118+0300")
        self.assertEqual(parsed, datetime(2026, 11, 14, 18, 14, 2, 118000, tzinfo=UTC))
        self.assertEqual(parsed.utcoffset(), timedelta(0))

    def test_indexer_and_colon_offset_formats(self):
        expected = datetime(2026, 11, 14, 18, 14, 2, 118000, tzinfo=UTC)
        self.assertEqual(parse_ts("2026-11-14T18:14:02.118Z"), expected)
        self.assertEqual(parse_ts("2026-11-14T21:14:02.118+03:00"), expected)
        self.assertEqual(parse_ts("2026-11-14T13:14:02.118-0500"), expected)

    def test_no_fraction_and_long_fraction(self):
        self.assertEqual(parse_ts("2026-11-14T18:14:02Z").microsecond, 0)
        # Sysmon writes 7 fractional digits; extra precision is truncated.
        self.assertEqual(parse_ts("2026-11-14T18:14:02.1234567Z").microsecond, 123456)

    def test_timestamp_without_offset_is_rejected(self):
        with self.assertRaises(ContractError):
            parse_ts("2026-11-14T21:14:02.118")

    def test_garbage_is_rejected(self):
        for bad in ("", "yesterday", "2026-13-45T00:00:00Z", None, 1794680042):
            with self.subTest(bad=bad):
                with self.assertRaises(ContractError):
                    parse_ts(bad)

    def test_format_round_trip(self):
        text = "2026-11-14T18:14:02.118000Z"
        self.assertEqual(format_ts(parse_ts(text)), text)
        self.assertEqual(format_ts(parse_ts("2026-11-14T21:14:02.118+0300")), text)
        # sub-millisecond precision survives
        self.assertEqual(format_ts(parse_ts("2026-11-14T05:02:11.3301234Z")), "2026-11-14T05:02:11.330123Z")

    def test_format_refuses_naive_datetime(self):
        with self.assertRaises(ContractError):
            format_ts(datetime(2026, 11, 14))


class EventTests(unittest.TestCase):
    def test_round_trip_through_json(self):
        event = make_event()
        restored = Event.from_dict(json.loads(json.dumps(event.to_dict())))
        self.assertEqual(restored, event)

    def test_to_dict_uses_plain_json_types(self):
        data = make_event().to_dict()
        self.assertEqual(data["timestamp"], "2026-11-14T18:14:02.118000Z")
        self.assertEqual(data["category"], "authentication")
        self.assertEqual(data["outcome"], "failure")
        self.assertEqual(data["rule"]["groups"], ["sshd"])
        self.assertEqual(data["observed_at"], "2026-11-14T18:20:02.118000Z")
        self.assertEqual(data["schema_version"], 1)

    def test_bad_event_ids_are_rejected(self):
        for bad in ("", "evt-123", "EVT-0123456789abcdef", "evt-0123456789abcdeg", None):
            with self.subTest(bad=bad):
                with self.assertRaises(ContractError):
                    make_event(event_id=bad)

    def test_timestamp_must_be_aware_utc(self):
        with self.assertRaises(ContractError):
            make_event(timestamp=datetime(2026, 11, 14, 18, 14, 2))
        with self.assertRaises(ContractError):
            make_event(timestamp=datetime(2026, 11, 14, 21, 14, 2, tzinfo=timezone(timedelta(hours=3))))

    def test_observed_at_must_be_aware_utc_when_given(self):
        for bad in (datetime(2026, 11, 14, 18, 14, 2), "2026-11-14T18:14:02Z",
                    datetime(2026, 11, 14, 21, 14, 2, tzinfo=timezone(timedelta(hours=3)))):
            with self.subTest(bad=bad):
                with self.assertRaises(ContractError):
                    make_event(observed_at=bad)

    def test_delay(self):
        self.assertEqual(make_event().delay, timedelta(minutes=6))
        self.assertIsNone(make_event(observed_at=None).delay)

    def test_rule_level_bounds(self):
        for bad in (-1, 17, "5", 5.0, True):
            with self.subTest(bad=bad):
                with self.assertRaises(ContractError):
                    make_event(rule=Rule(id="1", level=bad, description=""))

    def test_category_must_be_enum(self):
        with self.assertRaises(ContractError):
            make_event(category="authentication")

    def test_events_are_immutable(self):
        event = make_event()
        with self.assertRaises(Exception):
            event.user = "someone-else"


class FromDictTests(unittest.TestCase):
    def test_unknown_top_level_field_is_rejected(self):
        data = make_event().to_dict()
        data["verdict"] = "malicious"
        with self.assertRaises(ContractError):
            Event.from_dict(data)

    def test_unknown_nested_field_is_rejected(self):
        data = make_event().to_dict()
        data["host"]["os"] = "linux"
        with self.assertRaises(ContractError):
            Event.from_dict(data)

    def test_missing_required_field_is_rejected(self):
        for key in ("event_id", "timestamp", "source", "host", "rule", "category"):
            with self.subTest(key=key):
                data = make_event().to_dict()
                del data[key]
                with self.assertRaises(ContractError):
                    Event.from_dict(data)

    def test_unknown_category_and_schema_version_are_rejected(self):
        data = make_event().to_dict()
        data["category"] = "magic"
        with self.assertRaises(ContractError):
            Event.from_dict(data)
        data = make_event().to_dict()
        data["schema_version"] = 99
        with self.assertRaises(ContractError):
            Event.from_dict(data)

    def test_non_object_is_rejected(self):
        for bad in (None, [], "event", 3):
            with self.subTest(bad=bad):
                with self.assertRaises(ContractError):
                    Event.from_dict(bad)


if __name__ == "__main__":
    unittest.main()
