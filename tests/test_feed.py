"""Milestone 6, part 2: the live feed - the manager's program and the watch command."""

import gzip
import importlib.machinery
import importlib.util
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock

from aegis import feed as feed_module
from aegis.contracts.event import format_ts
from aegis.feed import Feed, FeedError, FeedSettings
from aegis.snapshot import RunView, header
from aegis.store import read_events, read_incidents, write_events
from tests.test_act import run_cli

ROOT = Path(__file__).resolve().parent.parent
PROGRAM = ROOT / "lab" / "aegis-feed"
SAMPLE_LINES = (ROOT / "data" / "samples" / "wazuh_alerts_sample.jsonl").read_text(encoding="utf-8").splitlines()
SSH_LINES = [line for line in SAMPLE_LINES if '"aegis-victim"' in line]


def load_program():
    """lab/aegis-feed as a module (it has no .py name, and must not leave bytecode in lab/)."""
    loader = importlib.machinery.SourceFileLoader("aegis_feed_program", str(PROGRAM))
    spec = importlib.util.spec_from_loader("aegis_feed_program", loader)
    module = importlib.util.module_from_spec(spec)
    before, sys.dont_write_bytecode = sys.dont_write_bytecode, True
    try:
        loader.exec_module(module)
    finally:
        sys.dont_write_bytecode = before
    return module


program = load_program()


def lines(*texts):
    return "".join(t + "\n" for t in texts).encode("utf-8")


def append(path: Path, data: bytes) -> None:
    with path.open("ab") as handle:  # closed at once: Windows will not rename an open file
        handle.write(data)


def parse(output: bytes):
    """[("msg", {...}) or ("alert", b"...")] from the program's output."""
    items = []
    for line in output.splitlines(keepends=True):
        if line.startswith(program.MARK):
            items.append(("msg", json.loads(line[len(program.MARK):])))
        else:
            items.append(("alert", line))
    return items


class Clock:
    def __init__(self):
        self.now = 0.0
        self.hooks = {}  # sleep number -> function run during that sleep
        self.sleeps = 0

    def __call__(self):
        return self.now

    def sleep(self, seconds):
        self.sleeps += 1
        self.now += seconds
        hook = self.hooks.get(self.sleeps)
        if hook:
            hook()


class FeedProgramTests(unittest.TestCase):
    """The program on the manager: what it accepts, what it streams, how it survives rotation."""

    def setUp(self):
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        self.root = Path(folder.name)
        self.current = self.root / "alerts.json"
        self.clock = Clock()

    def stream(self, request, polls=4):
        out = io.BytesIO()
        code = program.Stream(out, str(self.root), sleep=self.clock.sleep, clock=self.clock).run(request, polls)
        return code, parse(out.getvalue())

    def alerts(self, items):
        return [data for kind, data in items if kind == "alert"]

    def messages(self, items, kind=None):
        return [data for k, data in items if k == "msg" and (kind is None or data["type"] == kind)]

    def test_anything_but_a_follow_request_is_refused(self):
        self.current.write_bytes(lines('{"a":1}'))
        for request in ("", "cat /etc/shadow", "follow", "follow now; id", "follow start extra",
                        "follow 0123456789abcdef", "follow 0123456789ABCDEF 5", "follow 0123456789abcdef -1",
                        "follow 0123456789abcdef 007", "follow ../../etc 5", "status"):
            with self.subTest(request=request):
                code, items = self.stream(request)
                self.assertEqual(code, 2)
                self.assertEqual([m["type"] for m in self.messages(items)], ["refused"])
                self.assertEqual(self.alerts(items), [])
        out = io.BytesIO()
        self.assertEqual(program.main(argv=["--root", "/etc"], environ={"SSH_ORIGINAL_COMMAND": "follow start"},
                                      out=out, root=str(self.root)), 2)
        self.assertIn(b"takes no arguments", out.getvalue())

    def test_follow_start_sends_complete_lines_only(self):
        self.current.write_bytes(lines('{"n":1}', '{"n":2}') + b'{"n":3')  # Wazuh is still writing line 3
        self.clock.hooks[1] = lambda: append(self.current, b'}\n')
        code, items = self.stream("follow start")
        self.assertEqual(code, 0)
        self.assertEqual(self.alerts(items), [b'{"n":1}\n', b'{"n":2}\n', b'{"n":3}\n'])
        hello, *_ = self.messages(items)
        self.assertEqual((hello["type"], hello["start"], hello["offset"]), ("hello", "start", 0))
        cursors = self.messages(items, "cursor")
        self.assertEqual([c["offset"] for c in cursors], [16, 24])
        self.assertEqual({c["file_id"] for c in cursors}, {hello["file_id"]})
        kinds = [m["type"] for m in self.messages(items)]
        self.assertEqual(kinds, ["hello", "cursor", "idle", "cursor", "idle"])

    def test_follow_now_starts_at_the_end(self):
        self.current.write_bytes(lines('{"old":1}', '{"old":2}'))
        self.clock.hooks[1] = lambda: append(self.current, lines('{"new":1}'))
        _, items = self.stream("follow now")
        self.assertEqual(self.alerts(items), [b'{"new":1}\n'])
        self.assertEqual(self.messages(items, "hello")[0]["offset"], 20)

    def test_a_cursor_carries_on_exactly_where_it_stopped(self):
        self.current.write_bytes(lines('{"n":1}', '{"n":2}', '{"n":3}'))
        file_id = program.identify(str(self.current))
        _, items = self.stream(f"follow {file_id} 8")
        self.assertEqual(self.alerts(items), [b'{"n":2}\n', b'{"n":3}\n'])

    def test_rotation_finishes_the_old_file_from_the_archive_first(self):
        self.current.write_bytes(lines('{"day":1,"n":1}'))
        old_id = program.identify(str(self.current))

        def rotate():
            append(self.current, lines('{"day":1,"n":2}'))  # written just before midnight
            archive = self.root / "2026" / "Nov"
            archive.mkdir(parents=True)
            os.replace(self.current, archive / "ossec-alerts-17.json")
            self.current.write_bytes(lines('{"day":2,"n":1}'))
        self.clock.hooks[1] = rotate
        _, items = self.stream("follow start", polls=6)
        self.assertEqual(self.alerts(items), [b'{"day":1,"n":1}\n', b'{"day":1,"n":2}\n', b'{"day":2,"n":1}\n'])
        rotated = self.messages(items, "rotated")[0]
        self.assertEqual((rotated["previous"], rotated["archive"]), (old_id, "ossec-alerts-17.json"))
        self.assertEqual(rotated["file_id"], program.identify(str(self.current)))
        self.assertEqual(self.messages(items, "gap"), [])

    def test_a_cursor_into_a_compressed_archive_is_finished_after_downtime(self):
        old = lines('{"day":1,"n":1}', '{"day":1,"n":2}', '{"day":1,"n":3}')
        archive = self.root / "2026" / "Nov"
        archive.mkdir(parents=True)
        with gzip.open(archive / "ossec-alerts-17.json.gz", "wb") as handle:
            handle.write(old)
        (archive / "ossec-alerts-16.json.gz").write_bytes(b"not gzip at all")  # damaged: must not stop the search
        old_id = program.identify(str(archive / "ossec-alerts-17.json.gz"))
        self.current.write_bytes(lines('{"day":2,"n":1}'))
        _, items = self.stream(f"follow {old_id} 16", polls=5)
        self.assertEqual(self.alerts(items), [b'{"day":1,"n":2}\n', b'{"day":1,"n":3}\n', b'{"day":2,"n":1}\n'])
        self.assertEqual(self.messages(items, "gap"), [])

    def test_a_missing_archive_is_reported_as_a_gap_then_the_new_file_is_read(self):
        self.current.write_bytes(lines('{"day":2,"n":1}'))
        polls = int(program.ARCHIVE_PATIENCE / program.POLL) + 4
        _, items = self.stream("follow 0123456789abcdef 500", polls=polls)
        gaps = self.messages(items, "gap")
        self.assertEqual(len(gaps), 1)
        self.assertEqual((gaps[0]["file_id"], gaps[0]["offset"]), ("0123456789abcdef", 500))
        self.assertIn("may be missing", gaps[0]["reason"])
        self.assertEqual(self.alerts(items), [b'{"day":2,"n":1}\n'])

    def test_a_truncated_file_is_reported_and_read_again_from_the_start(self):
        self.current.write_bytes(lines('{"n":1}'))
        file_id = program.identify(str(self.current))
        _, items = self.stream(f"follow {file_id} 400", polls=3)
        self.assertEqual(len(self.messages(items, "gap")), 1)
        self.assertEqual(self.alerts(items), [b'{"n":1}\n'])

    def test_heartbeats_while_idle(self):
        self.current.write_bytes(lines('{"n":1}'))
        _, items = self.stream("follow now", polls=int(program.HEARTBEAT / program.POLL) + 3)
        kinds = [m["type"] for m in self.messages(items)]
        self.assertEqual(kinds[:2], ["hello", "idle"])
        self.assertIn("heartbeat", kinds)
        self.assertEqual(self.alerts(items), [])

    def test_an_empty_or_missing_file_waits_for_its_first_line(self):
        _, items = self.stream("follow now", polls=2)
        self.assertEqual(self.messages(items, "hello")[0]["file_id"], None)
        self.clock.hooks[3] = lambda: self.current.write_bytes(lines('{"n":1}'))
        _, items = self.stream("follow start", polls=5)
        self.assertEqual(self.alerts(items), [b'{"n":1}\n'])

    def test_read_lines_handles_one_alert_longer_than_a_batch(self):
        path = self.root / "long.json"
        path.write_bytes(lines("x" * 50, "y"))
        data, offset, beyond = program.read_lines(str(path), 0, limit=10)
        self.assertEqual((data, offset, beyond), (lines("x" * 50), 51, False))
        self.assertEqual(program.read_lines(str(path), 999), (b"", 999, True))


# A stand-in for ssh: runs the real lab/aegis-feed locally, against a test folder, with the
# request Aegis would have sent. Fast polling so the tests do not wait.
WRAPPER = (
    "import importlib.machinery, importlib.util, sys; sys.dont_write_bytecode = True; "
    "l = importlib.machinery.SourceFileLoader('aegis_feed', sys.argv[1]); "
    "s = importlib.util.spec_from_loader('aegis_feed', l); m = importlib.util.module_from_spec(s); "
    "l.exec_module(m); m.POLL = 0.05; m.HEARTBEAT = 0.5; "
    "sys.exit(m.main(argv=[], environ={'SSH_ORIGINAL_COMMAND': sys.argv[3]}, root=sys.argv[2]))"
)


class FakeProcess:
    """What subprocess.Popen returns, with a scripted output."""

    def __init__(self, stdout: bytes = b"", stderr: bytes = b"", code: int = 0, hang: bool = False):
        self.returncode = None
        self.code = code
        if hang:  # a connection that stays open and says nothing
            read, self._write = os.pipe()
            self.stdout = os.fdopen(read, "rb")
        else:
            self._write = None
            self.stdout = io.BytesIO(stdout)
        self.stderr = io.BytesIO(stderr)
        self.killed = False

    def poll(self):
        return self.returncode

    def kill(self):
        self.killed = True
        if self._write is not None:
            os.close(self._write)
            self._write = None

    def wait(self, timeout=None):
        self.returncode = self.code
        return self.code


def msg(**fields):
    return b"#AEGIS-FEED " + json.dumps(fields).encode() + b"\n"


class WatchTests(unittest.TestCase):
    """The watch command: batches, the cursor, gaps, failures."""

    def setUp(self):
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        self.base = Path(folder.name)
        self.alerts = self.base / "alerts"
        self.alerts.mkdir()
        self.run_dir = self.base / "live"
        self.said = []

    def real(self, *args, **kwargs):
        command = args[0]
        return subprocess.Popen([sys.executable, "-c", WRAPPER, str(PROGRAM), str(self.alerts), command[-1]],
                                **kwargs)

    def feed(self, spawn=None, **settings):
        return Feed(self.run_dir, FeedSettings(**settings), spawn=spawn or self.real, say=self.said.append,
                    sleep=lambda s: None)

    def state(self):
        return json.loads((self.run_dir / "feed.json").read_text(encoding="utf-8"))

    def test_end_to_end_catch_up_then_carry_on_from_the_cursor(self):
        current = self.alerts / "alerts.json"
        current.write_text("\n".join(SAMPLE_LINES[:10]) + "\n", encoding="utf-8")
        self.assertEqual(self.feed().run(once=True, from_start=True), 0)
        state = self.state()
        self.assertEqual((state["status"], state["alerts"], state["events_added"]), ("stopped", 10, 10))
        self.assertEqual(state["offset"], current.stat().st_size)
        self.assertEqual(len(read_events(self.run_dir / "events.jsonl")), 10)
        with current.open("a", encoding="utf-8") as handle:
            handle.write("\n".join(SAMPLE_LINES[10:]) + "\n")
        self.said.clear()
        self.assertEqual(self.feed().run(once=True), 0)
        self.assertTrue(any(f"follow {state['file_id']} {state['offset']}" in s for s in self.said))
        events = read_events(self.run_dir / "events.jsonl")
        self.assertEqual(len(events), len(SAMPLE_LINES))
        self.assertEqual(len({e.event_id for e in events}), len(events))  # nothing read twice
        incidents = read_incidents(self.run_dir / "incidents.jsonl")
        self.assertIn("inc-dd29f3ede71f6a05", {i.incident_id for i in incidents})
        self.assertTrue(any("CRITICAL" in s and "inc-dd29f3ede71f6a05" in s for s in self.said))
        # The same data through the batch commands gives the same incidents.
        batch = self.base / "batch"
        exported = self.base / "export.jsonl"
        exported.write_text("\n".join(SAMPLE_LINES) + "\n", encoding="utf-8")
        run_cli("ingest", exported, "--dir", batch)
        run_cli("correlate", "--dir", batch)
        self.assertEqual({i.incident_id for i in read_incidents(batch / "incidents.jsonl")},
                         {i.incident_id for i in incidents})

    def test_a_grown_incident_is_recorded_and_the_dashboard_follows_it(self):
        current = self.alerts / "alerts.json"
        current.write_text("\n".join(SSH_LINES[:3]) + "\n", encoding="utf-8")
        self.feed().run(once=True, from_start=True)
        with current.open("a", encoding="utf-8") as handle:
            handle.write("\n".join(SSH_LINES[3:]) + "\n")
        self.feed().run(once=True)
        moves = [json.loads(line) for line in (self.run_dir / "superseded.jsonl").read_text().splitlines()]
        self.assertTrue(moves)
        snap = RunView(self.run_dir).current()
        self.assertIn(snap.successor(moves[0]["old"]), {i.incident_id for i in snap.incidents})

    def test_what_was_done_to_an_earlier_version_stays_done(self):
        from aegis import audit
        from aegis.approvals import Approved, add_approval
        from aegis.snapshot import incident_view
        current = self.alerts / "alerts.json"
        current.write_text("\n".join(SSH_LINES[:-2]) + "\n", encoding="utf-8")  # up to the guessed login
        self.feed().run(once=True, from_start=True)
        before = next(i for i in read_incidents(self.run_dir / "incidents.jsonl") if "svc_backup" in i.accounts)
        add_approval(self.run_dir, before.incident_id, "b10c7b",
                     Approved("lock_account", "svc_backup", "Mohammed", "2026-11-18T00:00:00.000000Z"))
        audit.append(self.run_dir / "audit.jsonl", "action_result", before.incident_id,
                     {"action": "lock_account", "target": "svc_backup", "ok": True, "host": "aegis-victim",
                      "address": "192.168.56.107", "message": "account locked and expired",
                      "before": "password=P", "after": "password=L"})
        with current.open("a", encoding="utf-8") as handle:  # later lines (here: the sudo) join the incident
            handle.write("\n".join(SSH_LINES[-2:]) + "\n")
        self.feed().run(once=True)
        snap = RunView(self.run_dir).current()
        after = snap.successor(before.incident_id)
        self.assertIsNotNone(after)
        self.assertNotEqual(after, before.incident_id)
        view = incident_view(snap, snap.find(after))
        lock = next(a for a in view["decide"]["actions"] if a["action"] == "lock_account")
        self.assertEqual(lock["status"], "done")
        self.assertIsNone(lock["approved"])  # the approval was for other evidence: it does not carry over
        self.assertEqual(lock["results"][0]["incident_id"], before.incident_id)
        self.assertEqual([e["incident_id"] for e in view["act"]["trail"]], [before.incident_id])
        self.assertEqual(view["act"]["earlier_approvals"][0]["incident_id"], before.incident_id)

    def test_the_cursor_is_saved_only_after_the_batch_is_written(self):
        current = self.alerts / "alerts.json"
        current.write_text(SAMPLE_LINES[0] + "\n", encoding="utf-8")
        self.feed().run(once=True, from_start=True)
        before = self.state()
        with current.open("a", encoding="utf-8") as handle:
            handle.write(SAMPLE_LINES[1] + "\n")
        with mock.patch.object(feed_module, "append_events", side_effect=OSError("disk full")):
            self.assertEqual(self.feed().run(once=True), 2)
        after = self.state()
        self.assertEqual((after["file_id"], after["offset"]), (before["file_id"], before["offset"]))
        self.assertEqual(self.feed().run(once=True), 0)  # the batch is read again, not skipped
        self.assertEqual(len(read_events(self.run_dir / "events.jsonl")), 2)

    def test_a_batch_cut_off_before_its_cursor_is_not_kept(self):
        output = msg(type="hello", version=1, start="now", file_id="0123456789abcdef", offset=0)
        output += SAMPLE_LINES[0].encode() + b"\n"  # the connection drops before the cursor line
        feed = self.feed(spawn=lambda *a, **k: FakeProcess(output, code=255))
        self.assertEqual(feed.run(once=True), 1)
        self.assertFalse((self.run_dir / "events.jsonl").exists())
        self.assertEqual(self.state()["offset"], 0)

    def test_gaps_and_unreadable_alerts_are_recorded_and_shown(self):
        output = msg(type="hello", version=1, start="now", file_id="0123456789abcdef", offset=0)
        output += b'{"not": "an alert"}\n' + SAMPLE_LINES[0].encode() + b"\n"
        output += msg(type="cursor", file_id="0123456789abcdef", offset=999)
        output += b"something else\n"
        output += msg(type="gap", file_id="0123456789abcdef", offset=999, reason="the previous file was not found")
        output += msg(type="idle", file_id="0123456789abcdef", offset=999)
        feed = self.feed(spawn=lambda *a, **k: FakeProcess(output))
        self.assertEqual(feed.run(once=True), 0)
        state = self.state()
        self.assertEqual(len(state["gaps"]), 1)
        self.assertEqual(state["issue_count"], 2)
        self.assertEqual(state["events_added"], 1)
        problems = header(RunView(self.run_dir).current())["problems"]
        self.assertTrue(any("Live feed gap" in p and "not found" in p for p in problems))
        self.assertTrue(any("could not be read" in p for p in problems))
        log = [json.loads(line)["kind"] for line in (self.run_dir / "feed.jsonl").read_text().splitlines()]
        self.assertIn("gap", log)

    def test_refusals_and_version_mismatches_stop_the_feed(self):
        for output, expected in (
            (msg(type="refused", reason="expected: follow now"), "refused the request"),
            (msg(type="hello", version=2, start="now", file_id=None, offset=0), "feed version 2"),
        ):
            with self.subTest(expected=expected):
                self.said.clear()
                if (self.run_dir / "feed.json").exists():
                    (self.run_dir / "feed.json").write_text("{}", encoding="utf-8")
                feed = self.feed(spawn=lambda *a, **k: FakeProcess(output))
                self.assertEqual(feed.run(), 2)
                self.assertTrue(any(expected in s for s in self.said), self.said)

    def test_a_failed_connection_explains_itself(self):
        feed = self.feed(spawn=lambda *a, **k: FakeProcess(stderr=b"Host key verification failed.\r\n", code=255))
        self.assertEqual(feed.run(once=True), 1)
        self.assertTrue(any("host key" in s for s in self.said))
        self.assertTrue(any("follow now" in s for s in self.said))

    def test_a_silent_connection_is_dropped(self):
        ticks = iter(range(0, 10_000, 40))
        process = FakeProcess(hang=True)
        feed = Feed(self.run_dir, FeedSettings(), spawn=lambda *a, **k: process, say=self.said.append,
                    clock=lambda: next(ticks), sleep=lambda s: None)
        self.assertEqual(feed.run(once=True), 1)
        self.assertTrue(process.killed)
        self.assertTrue(any("No word from the manager" in s for s in self.said))

    def test_what_is_asked_for_and_how(self):
        feed = self.feed()
        self.assertEqual(feed.request(from_start=False), "follow now")
        self.assertEqual(feed.request(from_start=True), "follow start")
        feed.state = {"started": True, "file_id": "0123456789abcdef", "offset": 42}
        self.assertEqual(feed.request(from_start=True), "follow 0123456789abcdef 42")
        feed.state = {"started": True, "file_id": None, "offset": 0}
        self.assertEqual(feed.request(from_start=False), "follow start")
        command = feed.command("follow now")
        for option in ("BatchMode=yes", "IdentitiesOnly=yes", "ServerAliveInterval=15"):
            self.assertIn(option, command)
        self.assertIn("-T", command)
        self.assertEqual(command[-2:], ["aegis-feed@192.168.56.105", "follow now"])
        for bad in ({"address": "-oProxyCommand=calc"}, {"address": "a b"}, {"user": "root;id"}):
            with self.subTest(bad=bad), self.assertRaises(FeedError):
                FeedSettings(**bad)

    def test_a_second_watch_or_another_manager_is_refused(self):
        self.run_dir.mkdir()
        recent = format_ts(datetime.now(timezone.utc) - timedelta(seconds=5))
        (self.run_dir / "feed.json").write_text(json.dumps(
            {"status": "connected", "last_contact": recent, "manager": "192.168.56.105", "started": True}))
        with self.assertRaisesRegex(FeedError, "seems to be running"):
            self.feed().load()
        (self.run_dir / "feed.json").write_text(json.dumps(
            {"status": "stopped", "manager": "10.0.0.5", "started": True}))
        with self.assertRaisesRegex(FeedError, "use another --dir"):
            self.feed().load()

    def test_watch_command_checks_its_arguments(self):
        for args in (("--manager=-oProxyCommand=calc",), ("--user", "root;id"), ("--window", "0")):
            with self.subTest(args=args):
                code, _, err = run_cli("watch", "--dir", self.run_dir, *args)
                self.assertEqual(code, 2)
                self.assertIn("error", err)


class DashboardFeedTests(unittest.TestCase):
    def setUp(self):
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        self.run_dir = Path(folder.name)

    def show(self, state, now):
        (self.run_dir / "feed.json").write_text(json.dumps(state), encoding="utf-8")
        return header(RunView(self.run_dir).current(), now)["feed"]

    def test_the_feed_state_is_shown_and_ages(self):
        now = datetime(2026, 11, 18, 12, 0, tzinfo=timezone.utc)
        contact = format_ts(now - timedelta(seconds=20))
        base = {"manager": "192.168.56.105", "last_contact": contact}
        self.assertEqual(self.show(dict(base, status="connected"), now)["state"], "connected")
        self.assertEqual(self.show(dict(base, status="connected"), now + timedelta(minutes=5))["state"], "silent")
        self.assertEqual(self.show(dict(base, status="disconnected"), now)["state"], "reconnecting")
        self.assertEqual(self.show(dict(base, status="stopped"), now)["state"], "stopped")
        self.assertIsNone(header(RunView(Path(tempfile.gettempdir()) / "no-feed-here").current())["feed"])


class AtomicStoreTests(unittest.TestCase):
    def test_files_are_replaced_whole_and_leave_nothing_behind(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "events.jsonl"
            path.write_text("old\n", encoding="utf-8")
            self.assertEqual(write_events(path, []), 0)
            self.assertEqual(path.read_text(encoding="utf-8"), "")
            self.assertEqual(sorted(p.name for p in Path(folder).iterdir()), ["events.jsonl"])


if __name__ == "__main__":
    unittest.main()
