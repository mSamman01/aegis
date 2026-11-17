"""Operator knowledge notes: shown only where they apply, and always recorded."""

import contextlib
import io
import json
import os
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock

from aegis.cli import main
from aegis.contracts import Category, ContractError, Event, Host, Process, Rule, VerdictLabel
from aegis.correlate import correlate
from aegis.evidence import EvidenceStore, build_pack
from aegis.ingest import ingest_file
from aegis.investigate import PROMPT_VERSION, SYSTEM_PROMPT, investigate
from aegis.knowledge import DEFAULT_NOTES_FILE, FIELDS, load_notes, matching_notes, notes_fingerprint
from aegis.store import read_verdicts
from tests.test_investigate import FakeOllama, answer_json, ollama_answer

SAMPLE = Path(__file__).resolve().parent.parent / "data" / "samples" / "wazuh_alerts_sample.jsonl"
NOW = datetime(2026, 11, 16, 16, 0, 0, tzinfo=timezone.utc)
AGENT = "C:\\Program Files (x86)\\ossec-agent\\wazuh-agent.exe"
POWERSHELL = "C:\\Windows\\SysWOW64\\WindowsPowerShell\\v1.0\\powershell.exe"


def process_event(n, image, parent_image=None, guid=None, parent_guid=None, command=None):
    return Event(
        event_id=f"evt-{n:016x}", timestamp=NOW + timedelta(seconds=n), source="test", source_ref=str(n),
        host=Host(agent_id="001", name="win"), rule=Rule(id="92021", level=3, description="powershell used"),
        category=Category.PROCESS, user="NT AUTHORITY\\SYSTEM",
        process=Process(image=image, parent_image=parent_image, guid=guid, parent_guid=parent_guid,
                        command_line=command),
    )


def agent_scan():
    """Two PowerShell processes started by the Wazuh agent, and one started by something else."""
    events = [
        process_event(1, POWERSHELL, AGENT, guid="a" * 8 + "-0000-0000-0000-000000000001",
                      parent_guid="f" * 8 + "-0000-0000-0000-000000000000", command="powershell secedit /export"),
        process_event(2, POWERSHELL, AGENT, guid="a" * 8 + "-0000-0000-0000-000000000002",
                      parent_guid="f" * 8 + "-0000-0000-0000-000000000000", command="powershell net user"),
        process_event(3, POWERSHELL, "C:\\Users\\x\\Downloads\\invoice.exe",
                      guid="a" * 8 + "-0000-0000-0000-000000000003",
                      parent_guid="e" * 8 + "-0000-0000-0000-000000000000", command="powershell -enc AAAA"),
    ]
    return events, EvidenceStore(events), correlate(events).incidents[0]


class NotesFileTests(unittest.TestCase):
    def write(self, folder, content):
        path = Path(folder) / "notes.json"
        path.write_text(content if isinstance(content, str) else json.dumps(content), encoding="utf-8")
        return path

    def test_project_notes_file_is_valid(self):
        notes = load_notes(DEFAULT_NOTES_FILE)
        self.assertEqual([note.id for note in notes], [
            "wazuh-agent-checks", "powershell-policy-test-file", "background-task-host", "com-surrogate"])
        self.assertIn("Wazuh security agent", notes[0].text)

    def test_project_notes_match_only_what_they_describe(self):
        notes = {note.id: note for note in load_notes(DEFAULT_NOTES_FILE)}

        def event(image, command=None, file=None, parent=None):
            return Event(
                event_id="evt-" + "1" * 16, timestamp=NOW, source="test", source_ref="1",
                host=Host(agent_id="001", name="win"), rule=Rule(id="1", level=12, description="r"),
                category=Category.PROCESS, file_path=file,
                process=Process(image=image, command_line=command, parent_image=parent),
            )

        bg = "C:\\Windows\\System32\\backgroundTaskHost.exe"
        com = "C:\\Windows\\SysWOW64\\dllhost.exe"
        guid = "{CA6CC9F1-867A-481E-951E-A28C5E4F01EA}"
        temp = "C:\\Users\\x\\AppData\\Local\\Temp\\"
        cases = [
            ("background-task-host", event(bg, f'"{bg}" -ServerName:App.AppXapskvk16gk8da8kch5g4qxh42vxccved.mca'), True),
            ("background-task-host", event(bg.upper(), "x -ServerName:App.Abc_1"), True),
            ("background-task-host", event("C:\\Users\\x\\backgroundTaskHost.exe", "x -ServerName:App.A"), False),
            ("background-task-host", event(bg, "x -ServerName:App.A & calc.exe"), False),
            ("background-task-host", event(bg, None), False),
            ("com-surrogate", event(com, f"{com} /Processid:{guid}"), True),
            ("com-surrogate", event("C:\\Windows\\System32\\dllhost.exe", f"x /Processid:{guid.lower()}"), True),
            ("com-surrogate", event("C:\\Temp\\dllhost.exe", f"x /Processid:{guid}"), False),
            ("com-surrogate", event(com, f"x /Processid:{guid} evil.dll"), False),
            ("powershell-policy-test-file", event("a.exe", file=temp + "__PSScriptPolicyTest_nzxf2csq.rni.ps1"), True),
            ("powershell-policy-test-file",
             event("a.exe", file="C:\\Windows\\SystemTemp\\__PSScriptPolicyTest_gbeju2hv.re2.ps1"), True),
            ("powershell-policy-test-file", event("a.exe", file=temp + "__PSScriptPolicyTest_evil.ps1"), False),
            ("powershell-policy-test-file",
             event("a.exe", file="C:\\Users\\x\\Desktop\\__PSScriptPolicyTest_nzxf2csq.rni.ps1"), False),
            ("powershell-policy-test-file", event("a.exe", file=temp + "__PSScriptPolicyTest_nzxf2csq.rni.ps1.exe"), False),
            ("wazuh-agent-checks", event("p.exe", parent="C:\\Program Files (x86)\\ossec-agent\\wazuh-agent.exe"), True),
            ("wazuh-agent-checks", event("p.exe", parent="C:\\Users\\x\\wazuh-agent.exe"), False),
        ]
        for note_id, probe, expected in cases:
            with self.subTest(note=note_id, image=probe.process.image, file=probe.file_path,
                              command=probe.process.command_line):
                self.assertIs(notes[note_id].matches(probe), expected)

    def test_fingerprint_changes_with_any_edit(self):
        notes = load_notes(DEFAULT_NOTES_FILE)
        self.assertRegex(notes_fingerprint(notes), r"^[0-9a-f]{6}$")
        self.assertEqual(notes_fingerprint(notes), notes_fingerprint(load_notes(DEFAULT_NOTES_FILE)))
        with tempfile.TemporaryDirectory() as folder:
            data = json.loads(DEFAULT_NOTES_FILE.read_text(encoding="utf-8"))
            data[1]["note"] += " Edited."
            edited = load_notes(self.write(folder, data))
        self.assertNotEqual(notes_fingerprint(edited), notes_fingerprint(notes))
        self.assertNotEqual(notes_fingerprint(notes[:1]), notes_fingerprint(notes))

    def test_matching_is_per_event_and_needs_every_condition(self):
        events, _, _ = agent_scan()
        with tempfile.TemporaryDirectory() as folder:
            notes = load_notes(self.write(folder, [
                {"id": "agent", "note": "Agent checks.", "applies_when": {"started_by": "ossec-agent\\\\WAZUH-agent\\.exe$"}},
                {"id": "agent-net", "note": "Agent lists users.",
                 "applies_when": {"started_by": "wazuh-agent", "command_line": "net user"}},
                {"id": "never", "note": "Not here.", "applies_when": {"file": "\\.docx$"}},
            ]))
        found = {note.id: matched for note, matched in matching_notes(notes, events)}
        self.assertEqual(found, {"agent": [events[0].event_id, events[1].event_id],
                                 "agent-net": [events[1].event_id]})
        self.assertEqual(matching_notes(notes, []), [])
        self.assertEqual(matching_notes([], events), [])

    def test_every_field_can_be_matched(self):
        event = ingest_file(SAMPLE).events
        registry = next(e for e in event if e.registry_key)
        for name, getter in FIELDS.items():
            value = getter(registry)
            if value:
                with self.subTest(field=name), tempfile.TemporaryDirectory() as folder:
                    notes = load_notes(self.write(folder, [
                        {"id": "probe", "note": "x", "applies_when": {name: "."}}]))
                    self.assertTrue(notes[0].matches(registry))

    def test_broken_notes_files_are_errors_not_ignored(self):
        good = {"id": "ok-note", "note": "text", "applies_when": {"program": "x"}}
        cases = [
            ("{oops", "not valid JSON"),
            ({"id": "x"}, "expected a list"),
            (["text"], "must be an object"),
            ([dict(good, extra=1)], "unknown key(s): extra"),
            ([dict(good, id="Bad Id")], "'id' must be lower-case"),
            ([good, good], "is used twice"),
            ([dict(good, note="  ")], "'note' must be text"),
            ([dict(good, applies_when={})], "must say when it applies"),
            ([{"id": "ok-note", "note": "text"}], "must say when it applies"),
            ([dict(good, applies_when={"mood": "x"})], "unknown field 'mood'"),
            ([dict(good, applies_when={"program": "("})], "bad pattern for 'program'"),
            ([dict(good, applies_when={"program": 5})], "must be text"),
        ]
        with tempfile.TemporaryDirectory() as folder:
            for content, expected in cases:
                with self.subTest(expected=expected):
                    with self.assertRaises(ContractError) as caught:
                        load_notes(self.write(folder, content))
                    self.assertIn(expected, str(caught.exception))


class NotesInTheEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.events, self.store, self.incident = agent_scan()
        self.notes = load_notes()

    def test_note_is_shown_with_the_events_it_matched(self):
        pack = build_pack(self.incident, self.store, notes=self.notes)
        self.assertEqual(pack.notes, ("wazuh-agent-checks",))
        self.assertIn("BACKGROUND FROM THE OPERATOR OF THIS MACHINE", pack.text)
        self.assertIn("K1  matches 2 events (E1, E2): The Wazuh security agent is installed on this machine.", pack.text)
        self.assertIsNone(pack.event_id("K1"))  # background cannot be cited
        self.assertEqual(pack.resolve("K1"), ())

    def test_no_note_no_section(self):
        self.assertEqual(build_pack(self.incident, self.store).notes, ())
        self.assertNotIn("BACKGROUND", build_pack(self.incident, self.store).text)
        sample = ingest_file(SAMPLE).events
        store = EvidenceStore(sample)
        for incident in correlate(sample).incidents:
            pack = build_pack(incident, store, notes=self.notes)
            self.assertEqual(pack.notes, ())
            self.assertNotIn("Wazuh security agent", pack.text)

    def test_the_instructions_carry_no_knowledge_of_the_site(self):
        # It used to be stated there for every incident, and the model then
        # blamed unrelated events on the agent.
        self.assertNotIn("ossec", SYSTEM_PROMPT.lower())
        self.assertNotIn("wazuh", SYSTEM_PROMPT.lower())
        self.assertIn("BACKGROUND FROM THE OPERATOR", SYSTEM_PROMPT)

    def run_it(self, notes):
        def client(request, *, timeout):
            self.request = request
            return ollama_answer(answer_json(verdict="benign", proposed_actions=[],
                                             findings=[{"claim": "Agent checks.", "evidence": ["E1"]}]))
        return investigate(self.incident, self.store, model="fake:1b", notes=notes, client=client, now=lambda: NOW)

    def test_verdict_records_whether_notes_were_in_use_and_which_were_shown(self):
        with_notes = self.run_it(self.notes).verdict
        self.assertIn("K1  matches 2 events", self.request["messages"][1]["content"])
        self.assertEqual((with_notes.run.knowledge, with_notes.notes_shown), (True, ("wazuh-agent-checks",)))
        self.assertEqual(with_notes.run.prompt_version, PROMPT_VERSION)
        self.assertEqual(with_notes.run.knowledge_id, notes_fingerprint(self.notes))

        without = self.run_it(None).verdict
        self.assertNotIn("BACKGROUND", self.request["messages"][1]["content"])
        self.assertEqual((without.run.knowledge, without.notes_shown, without.run.knowledge_id), (False, (), ""))

        in_use_but_no_match = self.run_it([]).verdict
        self.assertEqual((in_use_but_no_match.run.knowledge, in_use_but_no_match.notes_shown), (True, ()))
        self.assertNotEqual(with_notes.run.prompt_sha256, without.run.prompt_sha256)


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
        self.notes = Path(self.folder.name) / "my-notes.json"
        self.notes.write_text(json.dumps([{
            "id": "ssh-from-laptop", "note": "192.168.56.1 is the lab's own laptop.",
            "applies_when": {"rule": "^5710$"}}]), encoding="utf-8")

    def investigate(self, *args):
        with FakeOllama() as fake:
            with mock.patch.dict(os.environ, {"AEGIS_OLLAMA_URL": fake.url, "AEGIS_MODEL": "fake:1b"}):
                result = run_cli("investigate", "inc-dd29", "--dir", self.dir, *args)
        return result, fake.requests

    def test_notes_option_and_view(self):
        (code, out, err), requests = self.investigate("--knowledge", self.notes)
        self.assertEqual(code, 0, err)
        self.assertIn("K1  matches 2 events (E1, E2): 192.168.56.1 is the lab's own laptop.",
                      requests[0]["messages"][1]["content"])
        self.assertIn("Notes     ssh-from-laptop  (operator notes that matched; notes file ", out)

        (code, out, _), requests = self.investigate()  # the project's notes: nothing matches the sample
        self.assertEqual(code, 0)
        self.assertNotIn("BACKGROUND", requests[0]["messages"][1]["content"])
        self.assertIn("Notes     none matched this incident  (notes file ", out)

        (code, out, _), requests = self.investigate("--no-knowledge")
        self.assertEqual(code, 0)
        self.assertIn("Notes     none in use", out)

        # Each notes file, and running without notes, is its own setup: all three are kept.
        saved = read_verdicts(self.dir / "verdicts.jsonl")
        self.assertEqual(sorted((v.run.knowledge, v.notes_shown) for v in saved),
                         [(False, ()), (True, ()), (True, ("ssh-from-laptop",))])
        self.assertEqual(len({v.run.knowledge_id for v in saved}), 3)
        self.assertTrue(all(v.label is VerdictLabel.MALICIOUS for v in saved))

    def test_show_prompt_includes_the_notes(self):
        (code, out, _), requests = self.investigate("--knowledge", self.notes, "--show-prompt")
        self.assertEqual(code, 0)
        self.assertEqual(requests, [])
        self.assertIn("BACKGROUND FROM THE OPERATOR OF THIS MACHINE", out)

    def test_bad_or_missing_notes_file_stops_the_run(self):
        (code, _, err), requests = self.investigate("--knowledge", Path(self.folder.name) / "missing.json")
        self.assertEqual((code, requests), (2, []))
        self.assertIn("file not found", err)
        self.notes.write_text("[{}]", encoding="utf-8")
        (code, _, err), requests = self.investigate("--knowledge", self.notes)
        self.assertEqual((code, requests), (2, []))
        self.assertIn("cannot read", err)


if __name__ == "__main__":
    unittest.main()
