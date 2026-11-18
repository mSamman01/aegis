"""Agent mode: the model opens the evidence itself, one read-only tool at a time (D44).

No test here needs a real model: a script stands in for it, which also lets
us send hostile steps on purpose.
"""

import contextlib
import dataclasses
import io
import json
import re
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from aegis import agent, evalcases
from aegis import evaluate as evaluating
from aegis.agent import AGENT_SYSTEM_PROMPT, MAX_TOOL_CALLS, MODE, TOOLS, Desk, investigate_agent
from aegis.cli import main
from aegis.compare import variant_name
from aegis.contracts import ModelRun, VerdictLabel
from aegis.correlate import correlate
from aegis.decide import latest_verdict
from aegis.evidence import EvidenceStore, build_pack, build_parts
from aegis.export import export_run
from aegis.ingest import ingest_file
from aegis.investigate import SYSTEM_PROMPT, InvestigationError, check_answer, investigate, parts_for_model
from aegis.knowledge import Note
from aegis.policy import load_policy
from aegis.store import save_verdict
from tests.test_act import SAMPLE, SSH_INCIDENT

NOW = datetime(2026, 11, 18, 12, 0, tzinfo=timezone.utc)
POWERSHELL_INCIDENT = "inc-e38789075bf7616d"


def step(tool, label=""):
    return json.dumps({"01_next": "test", "02_tool": tool, "03_label": label})


def final(verdict="malicious", cite=("E1",), actions=()):
    return json.dumps({
        "01_what_happened": "w", "02_started_by": "s", "03_innocent_explanation": "i",
        "04_attack_explanation": "a", "05_against_innocent": "E1",
        "06_findings": [{"claim": "failed logins", "evidence": list(cite)}],
        "07_verdict": verdict, "08_confidence": "high", "09_summary": "summary", "10_techniques": ["T1110"],
        "11_proposed_actions": [{"action": a, "target": t, "reason": "r", "evidence": list(cite)} for a, t in actions],
    })


class Script:
    """A stand-in model: answers each step from a list, then gives the final answer."""

    def __init__(self, steps, answer=None, **extra):
        self.steps, self.answer, self.extra, self.requests = list(steps), answer or final(), extra, []

    def __call__(self, request, timeout=None):
        self.requests.append(request)
        if "02_tool" in request["format"]["properties"]:
            index = sum(1 for m in request["messages"] if m["role"] == "assistant")  # steps so far in this talk
            content = self.steps[index] if index < len(self.steps) else step("answer")
        else:
            content = self.answer
        answer = {"message": {"role": "assistant", "content": content}, "done_reason": "stop",
                  "total_duration": 1_000_000_000, "prompt_eval_count": 1200, "eval_count": 40}
        answer.update(self.extra)
        return answer


class Base(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.events = ingest_file(SAMPLE).events
        cls.store = EvidenceStore(cls.events)
        cls.incidents = correlate(cls.events).incidents
        cls.ssh = next(i for i in cls.incidents if i.incident_id == SSH_INCIDENT)
        cls.powershell = next(i for i in cls.incidents if i.incident_id == POWERSHELL_INCIDENT)

    def run_agent(self, incident=None, steps=(), answer=None, **options):
        script = Script(steps, answer)
        options.setdefault("now", lambda: NOW)
        result = investigate_agent(incident or self.ssh, self.store, model="fake", client=script, **options)
        return result, script


class SameEvidenceTests(Base):
    """Every tool hands out a piece of the single call's own pack, word for word."""

    def test_the_parts_join_into_the_single_calls_pack(self):
        for incident in self.incidents:
            for options in ({}, {"group_over": 0}, {"group_over": 0, "max_groups": 1, "max_context": 0}):
                self.assertEqual(build_parts(incident, self.store, **options).pack(),
                                 build_pack(incident, self.store, **options))

    def test_every_tool_result_is_a_slice_of_the_pack(self):
        for incident in self.incidents:
            for options in ({}, {"group_over": 0}):
                parts = build_parts(incident, self.store, **options)
                pack = parts.pack().text
                desk = Desk(parts)
                labels = [b.label for b in parts.blocks] + list(parts.label_of.values())
                for tool, label in [("get_event", label) for label in labels] + [(t, "") for t in TOOLS[1:]]:
                    result = desk.use(tool, label)
                    body = result.text.split("\n", 1)[1] if "\n" in result.text else ""
                    if body:  # refusals have no body
                        self.assertIn(body, pack, (incident.incident_id, tool, label))

    def test_the_rules_are_the_single_calls_rules(self):
        rules = SYSTEM_PROMPT[SYSTEM_PROMPT.index("3. A rule's name"):SYSTEM_PROMPT.index("8. Answer")]
        self.assertIn(rules, AGENT_SYSTEM_PROMPT)
        self.assertIn(SYSTEM_PROMPT[SYSTEM_PROMPT.index('{"01_what_happened"'):], AGENT_SYSTEM_PROMPT)

    def test_a_group_opens_whole_and_every_member_can_be_cited(self):
        parts = build_parts(self.ssh, self.store, group_over=0)
        desk = Desk(parts)
        result = desk.use("get_event", "E3")
        group = next(b for b in parts.blocks if parts.label_of and
                     any(parts.label_of[e] == "E3" for e in b.event_ids))
        self.assertTrue(result.text.startswith(f"get_event E3 (it is in group {group.label})"))
        desk.commit(result)
        self.assertEqual(set(desk.groups), {group.label})
        self.assertEqual(set(desk.labels.values()), set(group.event_ids))
        self.assertIn("(again)", desk.use("get_event", group.label).call)


class ToolTests(Base):
    def test_use_changes_nothing_until_commit(self):
        desk = Desk(parts_for_model(self.ssh, self.store))
        for tool, label in (("get_event", "E1"), ("nearby_events", ""), ("how_common", "")):
            desk.use(tool, label)
        self.assertEqual((desk.labels, desk.groups, desk.notes_shown, desk.open), ({}, {}, [], set()))

    def test_only_read_only_tools_are_offered(self):
        _, script = self.run_agent(steps=[step("answer")])
        enum = script.requests[0]["format"]["properties"]["02_tool"]["enum"]
        self.assertEqual(enum, ["get_event", "nearby_events", "how_common", "answer"])  # no origins in this one
        _, script = self.run_agent(self.powershell, steps=[step("answer")])
        self.assertEqual(script.requests[0]["format"]["properties"]["02_tool"]["enum"],
                         [*TOOLS, "answer"])

    def test_anything_else_gets_a_refusal_and_costs_a_tool(self):
        hostile = [step("lock_account", "root"), step("run_command", "id"), step("get_event", "../../etc/shadow"),
                   step("get_event", "E1; rm -rf /"), step("get_event", "C1"), step("get_event", "")]
        result, script = self.run_agent(steps=hostile)
        self.assertEqual(result.verdict.run.steps, (
            "lock_account (not a tool)", "run_command (not a tool)", "get_event ../../ETC/SHADOW (no such label)",
            "get_event E1; RM -RF / (no such label)", "get_event C1 (use nearby_events)", "get_event (no label)"))
        self.assertIn("There is no tool called 'lock_account'", script.requests[1]["messages"][-1]["content"])
        self.assertEqual(result.pack.labels, {})  # nothing was opened, so nothing can be cited
        self.assertIs(result.verdict.label, VerdictLabel.INCONCLUSIVE)

    def test_at_most_the_allowed_number_of_tools(self):
        result, script = self.run_agent(steps=[step("get_event", "E1")] * 50)
        self.assertEqual(len(result.verdict.run.steps), MAX_TOOL_CALLS)
        self.assertEqual(len(script.requests), MAX_TOOL_CALLS + 1)  # the steps, then the final answer
        self.assertIn(f"You have used all {MAX_TOOL_CALLS} tools", script.requests[-1]["messages"][-1]["content"])


class AnswerTests(Base):
    def test_only_opened_evidence_can_be_cited(self):
        result, script = self.run_agent(
            steps=[step("get_event", "E1"), step("nearby_events")],
            answer=final(cite=("E1", "E6", "C1"), actions=[("lock_account", "svc_backup")]))
        verdict = result.verdict
        self.assertEqual(verdict.run.steps, ("get_event E1", "nearby_events"))
        self.assertEqual(len(verdict.findings), 1)
        self.assertEqual(len(verdict.findings[0].evidence), 2)  # E1 and C1; E6 was never opened
        self.assertTrue(any("E6" in r.reason for r in verdict.rejected))
        self.assertEqual([a.target for a in verdict.proposed_actions], ["svc_backup"])
        self.assertIn("the only labels you can cite: E1, C1.", script.requests[-1]["messages"][-1]["content"])

    def test_the_same_checker_decides_what_survives(self):
        result, _ = self.run_agent(steps=[step("get_event", "E1")],
                                   answer=final(actions=[("lock_account", "mallory"), ("delete_user", "root")]))
        expected = check_answer(self.ssh, [self.store.get(e) for e in self.ssh.event_ids], result.pack,
                                final(actions=[("lock_account", "mallory"), ("delete_user", "root")]),
                                result.verdict.run, NOW)
        self.assertEqual(result.verdict, expected)
        self.assertEqual(result.verdict.proposed_actions, ())

    def test_answering_from_the_outline_alone_supports_nothing(self):
        result, script = self.run_agent(steps=[step("answer")])
        self.assertIs(result.verdict.label, VerdictLabel.INCONCLUSIVE)
        self.assertIn("You opened no evidence", script.requests[-1]["messages"][-1]["content"])

    def test_an_unreadable_step_goes_straight_to_the_answer(self):
        result, script = self.run_agent(steps=[step("get_event", "E1"), "this is not json"])
        self.assertEqual(len(script.requests), 3)
        self.assertTrue(any(r.kind == "answer" and "step 2" in r.reason for r in result.verdict.rejected))
        self.assertIs(result.verdict.label, VerdictLabel.MALICIOUS)  # E1 was opened before

    def test_notes_appear_when_a_matching_event_is_opened(self):
        events = [self.store.get(e) for e in self.powershell.event_ids]
        child = next(e for e in events if e.process and e.process.parent_image)
        note = Note("test-note", "PowerShell started by PowerShell is normal here.",
                    (("started_by", re.compile(r"powershell\.exe$", re.I)),))
        parts = parts_for_model(self.powershell, self.store, notes=[note])
        child_label = parts.label_of[child.event_id]
        other = next(label for label in parts.label_of.values() if label != child_label)
        result, script = self.run_agent(self.powershell, steps=[step("get_event", other),
                                                                step("get_event", child_label)], notes=[note])
        shown = [m["content"] for m in script.requests[-1]["messages"] if m["role"] == "user"]
        self.assertNotIn("BACKGROUND FROM THE OPERATOR", shown[1])
        self.assertIn("K1  matches 1 event", shown[2])
        self.assertEqual(result.verdict.notes_shown, ("test-note",))

    def test_no_room_left_stops_the_looking(self):
        result, script = self.run_agent(steps=[step("get_event", "E1")] + [step("get_event", f"E{n}")
                                                                           for n in range(2, 8)], num_ctx=2900)
        self.assertTrue(result.verdict.run.steps[-1].endswith("(no room)"))
        self.assertIn("no room left", script.requests[-1]["messages"][-1]["content"])

    def test_a_filled_window_makes_it_inconclusive(self):
        script = Script([step("get_event", "E1")], prompt_eval_count=8190)
        verdict = investigate_agent(self.ssh, self.store, model="fake", client=script, now=lambda: NOW).verdict
        self.assertIs(verdict.label, VerdictLabel.INCONCLUSIVE)
        self.assertIn("context window", verdict.summary)


class RecordingTests(Base):
    def test_record_then_replay_gives_the_same_verdict(self):
        with tempfile.TemporaryDirectory() as folder:
            live, _ = self.run_agent(steps=[step("get_event", "E1"), step("how_common")], recordings=Path(folder))
            self.assertTrue(live.recording.name.endswith(f".fake.{MODE}.json"))

            def refuse(request, timeout=None):
                raise AssertionError("a replay must not ask the model")

            again = investigate_agent(self.ssh, self.store, model="fake", recordings=Path(folder), replay=True,
                                      client=refuse)
            self.assertTrue(again.verdict.run.replayed)
            self.assertEqual(dataclasses.replace(again.verdict.run, replayed=False), live.verdict.run)
            self.assertEqual(again.verdict.findings, live.verdict.findings)

    def test_a_replay_refuses_a_prompt_it_was_not_made_for(self):
        with tempfile.TemporaryDirectory() as folder:
            self.run_agent(steps=[step("get_event", "E1")], recordings=Path(folder))
            other_note = [Note("x-note", "Something.", (("rule", re.compile("5710")),))]
            with self.assertRaisesRegex(InvestigationError, "different prompt"):
                investigate_agent(self.ssh, self.store, model="fake", recordings=Path(folder), replay=True,
                                  notes=other_note)

    def test_a_single_call_recording_is_never_read_as_an_agent_one(self):
        with tempfile.TemporaryDirectory() as folder:
            investigate(self.ssh, self.store, model="fake", recordings=Path(folder), client=Script([]),
                        now=lambda: NOW)
            with self.assertRaisesRegex(InvestigationError, "no agent recording"):
                investigate_agent(self.ssh, self.store, model="fake", recordings=Path(folder), replay=True)


class SetupTests(Base):
    def agent_verdict(self, created=NOW):
        result, _ = self.run_agent(steps=[step("get_event", "E1")], now=lambda: created)
        return result.verdict

    def test_the_setup_name_says_agent_mode(self):
        self.assertEqual(variant_name(self.agent_verdict().run), f"fake v4 {MODE}")

    def test_decide_keeps_using_the_single_call_while_agent_mode_is_an_experiment(self):
        single = investigate(self.ssh, self.store, model="fake", client=Script([]), now=lambda: NOW).verdict
        newer_agent = self.agent_verdict(NOW.replace(hour=13))
        self.assertIs(latest_verdict([single, newer_agent], SSH_INCIDENT), single)
        self.assertIs(latest_verdict([newer_agent], SSH_INCIDENT), newer_agent)

    def test_the_dashboard_shows_what_the_agent_opened(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            run_dir = root / "run"
            for args in (("ingest", SAMPLE), ("correlate",)):
                with contextlib.redirect_stdout(io.StringIO()):
                    main([str(a) for a in args] + ["--dir", str(run_dir)])
            save_verdict(run_dir / "verdicts.jsonl", self.agent_verdict())  # its only answer: shown in the box
            export_run(run_dir, root / "copy", label="t")
            page = (root / "copy" / f"incident-{SSH_INCIDENT}.html").read_text(encoding="utf-8")
            self.assertIn(f"fake v4 {MODE}", page)
            self.assertIn("Agent mode: ", page)
            self.assertIn("<code>get_event E1</code>", page)

    def test_the_command_line(self):
        with tempfile.TemporaryDirectory() as folder:
            run_dir = Path(folder)
            for args in (("ingest", SAMPLE), ("correlate",)):
                with contextlib.redirect_stdout(io.StringIO()):
                    self.assertEqual(main([str(a) for a in args] + ["--dir", str(run_dir)]), 0)
            out, err = io.StringIO(), io.StringIO()
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                code = main(["investigate", SSH_INCIDENT[:10], "--agent", "--show-prompt", "--dir", str(run_dir)])
            self.assertEqual(code, 0, err.getvalue())
            self.assertIn("THE INCIDENT'S EVENTS, ONE LINE EACH", out.getvalue())
            self.assertNotIn("log line:", out.getvalue())  # the details are opened, not given
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(err):
                code = main(["investigate", SSH_INCIDENT[:10], "--agent", "--think", "--dir", str(run_dir)])
            self.assertEqual(code, 2)


class EvaluationTests(unittest.TestCase):
    """Agent mode is asked about the same incidents and set beside the single call on those only."""

    def test_both_modes_side_by_side_on_the_incidents_both_answered(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            evalcases.build_all(root / "cases", runs=root / "no-runs")
            names = ("ssh-two-typos", "motd-changed")
            cases = [evaluating.prepare(f, s, root / "out") for f, s in evalcases.load_cases(root / "cases")
                     if s["name"] in names]
            single = Script([], final(verdict="suspicious"))
            evaluating.investigate_cases(cases, model="fake", repeat=2, notes=None, say=lambda t: None,
                                         client=single)
            only_one = [c for c in cases if c.name == "ssh-two-typos"]
            agent_model = Script([step("get_event", "E1")], final(verdict="benign"))
            asked = evaluating.investigate_cases(only_one, model="fake", repeat=2, notes=None,
                                                 say=lambda t: None, client=agent_model, mode=MODE)
            self.assertEqual(asked, 2)
            again = evaluating.investigate_cases(only_one, model="fake", repeat=2, notes=None, say=lambda t: None,
                                                 client=agent_model, mode=MODE)
            self.assertEqual(again, 0)  # replayed from the recordings
            rows = evaluating.compare_modes(cases, load_policy())
            self.assertEqual([(r.variant, r.incidents, r.runs) for r in rows],
                             [("fake v4", 1, 2), (f"fake v4 {MODE}", 1, 2)])  # motd-changed: single call only
            self.assertEqual((rows[0].twin_alarms, rows[1].twin_alarms), (2, 0))
            self.assertEqual((rows[1].tools, rows[1].opened_none), (2, 0))

    def test_a_leak_in_a_tool_result_of_an_agent_recording_is_caught(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            evalcases.build_all(root / "cases", runs=root / "no-runs")
            recordings = root / "out" / "motd-changed" / "recordings"
            recordings.mkdir(parents=True)
            (recordings / f"x.{MODE}.json").write_text(json.dumps({"request": {"messages": [
                {"role": "system", "content": "rules"}, {"role": "user", "content": "outline"},
                {"role": "assistant", "content": step("get_event", "E1")},
                {"role": "user", "content": "E1 ... a benign twin of the passwd story"}]}}), encoding="utf-8")
            prepared = [evaluating.prepare(f, s, root / "out") for f, s in evalcases.load_cases(root / "cases")]
            _, leaks = evaluating.check_leaks(prepared)
            self.assertTrue(any(f"x.{MODE}.json" in leak and "benign twin" in leak for leak in leaks), leaks)

    def test_the_probe_attacks_the_tool_channel_too(self):
        from aegis.probe import run_probe

        with tempfile.TemporaryDirectory() as folder:
            result = run_probe(Path(folder) / "probe")
        self.assertTrue(result.agent_ok)
        by_name = {r.name: r for r in result.agent_rows}
        self.assertEqual(by_name["never stops asking"].exchanges, MAX_TOOL_CALLS + 1)
        self.assertEqual(by_name["asks for tools that would change something"].refused, 4)
        self.assertTrue(all(r.proposal in ("denied by the policy", "removed by the checker")
                            for r in result.agent_rows))
        self.assertEqual(result.agent_gate_requests, 0)


class DemoTests(unittest.TestCase):
    def test_the_demo_replays_agent_mode_once_its_recordings_are_committed(self):
        import shutil
        from unittest import mock

        from aegis import demo
        from aegis.knowledge import DEFAULT_NOTES_FILE, load_notes

        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            recordings = root / "recordings"
            shutil.copytree(demo.RECORDINGS, recordings)
            evalcases.build_all(root / "cases", runs=root / "no-runs")
            prepared = [evaluating.prepare(f, s, root / "eval") for f, s in evalcases.load_cases(root / "cases")]
            evaluating.investigate_cases(prepared, model=demo.MODEL, repeat=demo.REPEAT,
                                         notes=load_notes(DEFAULT_NOTES_FILE), say=lambda t: None,
                                         client=Script([step("get_event", "E1")], final(verdict="suspicious")),
                                         mode=MODE)
            for case in prepared:  # what copying the laptop's agent recordings into the repository does
                for path in (case.run_dir / "recordings").glob(f"*.{MODE}*.json"):
                    shutil.copyfile(path, recordings / case.name / path.name)
            with mock.patch.object(demo, "RECORDINGS", recordings):
                demo.build_demo(root / "site")
                page = (root / "site" / "evaluation" / "index.html").read_text(encoding="utf-8")
                self.assertIn(f"qwen3:4b v4 {MODE}", page)
                next(recordings.glob(f"sample/*.{MODE}.r2.json")).unlink()
                with self.assertRaisesRegex(InvestigationError, "no recording"):
                    demo.build_demo(root / "site")


if __name__ == "__main__":
    unittest.main()
