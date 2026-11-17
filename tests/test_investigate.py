"""The AI investigator: evidence pack, model client, and the answer checker.

No test here needs a real model. A fake stands in for Ollama, which also lets
us feed the checker wrong answers on purpose.
"""

import contextlib
import io
import json
import os
import tempfile
import threading
import unittest
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from unittest import mock

from aegis import doctor
from aegis.cli import main
from aegis.contracts import (
    Category,
    Confidence,
    ContractError,
    Event,
    Finding,
    Host,
    ModelRun,
    Process,
    ProposedAction,
    Reasoning,
    Rejection,
    Rule,
    Verdict,
    VerdictLabel,
)
from aegis.correlate import correlate
from aegis.evidence import EvidenceError, EvidenceStore, build_pack, decode_powershell
from aegis.ingest import ingest_file
from aegis.investigate import (
    ANSWER_SCHEMA,
    SYSTEM_PROMPT,
    InvestigationError,
    build_request,
    check_answer,
    investigate,
    pack_for_model,
    recording_path,
)
from aegis.llm import LLMError, chat
from aegis.store import read_verdicts, save_verdict

SAMPLE = Path(__file__).resolve().parent.parent / "data" / "samples" / "wazuh_alerts_sample.jsonl"
NOW = datetime(2026, 11, 16, 16, 0, 0, tzinfo=timezone.utc)
RUN = ModelRun(model="fake:1b", mode="single_call", thinking=False, prompt_sha256="0" * 64)


def answer_json(**overrides):
    answer = {
        "verdict": "malicious",
        "confidence": "high",
        "summary": "Password guessing from one address, then a successful login and sudo.",
        "findings": [
            {"claim": "Repeated failed logins came from 192.168.56.1.", "evidence": ["E1", "E3", "E5"]},
            {"claim": "The same address then logged in as svc_backup.", "evidence": ["E6"]},
        ],
        "techniques": ["T1110", "T1078"],
        "proposed_actions": [
            {"action": "lock_account", "target": "svc_backup", "reason": "It was guessed.", "evidence": ["E6"]},
            {"action": "block_ip", "target": "192.168.56.1", "reason": "Source of the guessing.", "evidence": ["E1"]},
        ],
    }
    answer.update(overrides)
    return json.dumps(answer)


def ollama_answer(content, **extra):
    answer = {
        "model": "fake:1b",
        "message": {"role": "assistant", "content": content},
        "done": True,
        "done_reason": "stop",
        "total_duration": 12_300_000_000,
        "prompt_eval_count": 1500,
        "eval_count": 300,
    }
    answer.update(extra)
    return answer


class Base(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.events = ingest_file(SAMPLE).events
        cls.store = EvidenceStore(cls.events)
        cls.incidents = correlate(cls.events).incidents
        cls.ssh = next(i for i in cls.incidents if i.max_level == 10)
        cls.powershell = next(i for i in cls.incidents if i.max_level == 12)
        cls.ssh_events = [cls.store.get(e) for e in cls.ssh.event_ids]
        cls.pack = build_pack(cls.ssh, cls.store)

    def check(self, content, incident=None, problem=None):
        incident = incident or self.ssh
        pack = build_pack(incident, self.store)
        events = [self.store.get(e) for e in incident.event_ids]
        return check_answer(incident, events, pack, content, RUN, NOW, problem=problem)


class EvidencePackTests(Base):
    def test_labels_cover_the_incident_in_order_and_context_separately(self):
        incident_labels = [f"E{n}" for n in range(1, 8)]
        self.assertEqual([self.pack.labels[label] for label in incident_labels], list(self.ssh.event_ids))
        context = {label: event_id for label, event_id in self.pack.labels.items() if label.startswith("C")}
        self.assertEqual(len(context), 1)  # the /etc/passwd change 30 s later
        self.assertNotIn(context["C1"], self.ssh.event_ids)
        self.assertEqual(self.store.get(context["C1"]).rule.id, "550")
        self.assertEqual(self.pack.event_id(" e3 "), self.ssh.event_ids[2])
        self.assertIsNone(self.pack.event_id("E99"))

    def test_text_carries_what_an_analyst_needs(self):
        text = self.pack.text
        for expected in (
            f"INCIDENT {self.ssh.incident_id}",
            "Host: aegis-victim (agent 002)",
            "Highest rule level: 10 (scale 0-15)",
            "- 1 x level 10, rule 5763:",
            "account: svc_backup acting on root",
            "command line: /usr/bin/cat /etc/shadow",
            "from address: 192.168.56.1 port 51820",
            "result: failure",
            "log line: Nov 14 21:14:31 aegis-victim sshd[2231]: Accepted password for svc_backup",
            "grouped because: same account as E6",
            "- rule 5710 fired 2 times in total",
            "OTHER EVENTS ON THIS HOST WITHIN 2 MINUTES",
            "C1  18:15:40.882  level 7  rule 550: Integrity checksum changed.".replace("  ", " "),
        ):
            self.assertIn(expected, text)
        self.assertTrue(text.isascii())

    def test_context_is_what_happened_closest_in_time(self):
        host = Host(agent_id="009", name="big-host")
        def at(n, seconds, rule, level=3):
            return Event(event_id=f"evt-{n:016x}", timestamp=NOW + timedelta(seconds=seconds), source="test",
                         source_ref=str(n), host=host, rule=Rule(id=rule, level=level, description=f"rule {rule}"),
                         category=Category.OTHER)
        core = [at(1, 0, "900"), at(2, 10, "900")]                       # the incident: 0 s to 10 s
        near = [at(10 + i, 10 + 5 * i, f"91{i}") for i in range(1, 7)]   # 5 s ... 30 s after it
        loud_but_far = at(30, 100, "950", level=15)                      # severe, 90 s after
        too_far = at(31, 10 + 121, "960", level=15)                      # outside the 2 minutes
        before = at(32, -3, "970")                                       # 3 s before
        store = EvidenceStore(core + near + [loud_but_far, too_far, before])
        incident = next(i for i in correlate(core + near + [loud_but_far, too_far, before]).incidents
                        if len(i.event_ids) == 2)
        pack = build_pack(incident, store)
        context = [store.get(pack.labels[label]).rule.id for label in sorted(pack.labels) if label.startswith("C")]
        self.assertEqual(context, ["970", "911", "912", "913", "914"])  # nearest five, in time order
        self.assertIn("OTHER EVENTS ON THIS HOST WITHIN 2 MINUTES (not part of the incident)", pack.text)
        self.assertNotIn("rule 950", pack.text)
        self.assertNotIn("rule 960", pack.text)

    def test_pack_is_deterministic(self):
        self.assertEqual(build_pack(self.ssh, self.store), self.pack)

    def test_encoded_powershell_is_decoded_by_code(self):
        text = build_pack(self.powershell, self.store).text
        self.assertIn('decoded command (decoded by Aegis): Write-Host "aegis test"', text)
        self.assertIn("to address: updates.example.net / 203.0.113.50 port 443", text)
        self.assertIn("registry value written: C:\\Users\\labuser\\AppData\\Local\\Temp\\update.exe", text)
        self.assertIsNone(decode_powershell("powershell -ExecutionPolicy Bypass -File a.ps1"))
        self.assertIsNone(decode_powershell("powershell -enc not-base64-at-all!!"))
        self.assertIsNone(decode_powershell("cmd.exe /c dir"))
        self.assertIsNone(decode_powershell(None))

    def synthetic(self, events):
        return correlate(events).incidents[0], EvidenceStore(events)

    def event(self, n, *, rule="700", image="C:\\x\\noisy.exe", command=None, **process):
        return Event(
            event_id=f"evt-{n:016x}", timestamp=NOW + timedelta(seconds=n), source="test", source_ref=str(n),
            host=Host(agent_id="009", name="big-host"), rule=Rule(id=rule, level=8, description=f"rule {rule}"),
            category=Category.PROCESS, user="NT AUTHORITY\\SYSTEM",
            process=Process(image=image, command_line=command, **process),
        )

    def scan_incident(self):
        """Like the real agent scan: agent -> powershell -> (a file, and secedit), five times."""
        agent, ps, sec = "C:\\agent\\agent.exe", "C:\\win\\powershell.exe", "C:\\win\\secedit.exe"
        events = []
        for i in range(5):
            p_guid, s_guid = f"{i:08d}-0000-0000-0000-00000000000a", f"{i:08d}-0000-0000-0000-00000000000b"
            events.append(self.event(3 * i + 1, rule="701", image=ps, command=f"powershell check {i}",
                                     guid=p_guid, parent_guid="99999999-0000-0000-0000-000000000000", parent_image=agent))
            file_event = self.event(3 * i + 2, rule="702", image=ps, guid=p_guid)
            events.append(Event.from_dict(dict(file_event.to_dict(), category="file", file_path=f"C:\\tmp\\t{i}.ps1")))
            events.append(self.event(3 * i + 3, rule="703", image=sec, command="secedit /export",
                                     guid=s_guid, parent_guid=p_guid, parent_image=ps))
        return self.synthetic(events)

    def test_small_incident_is_listed_event_by_event(self):
        self.assertEqual(self.pack.groups, {})
        self.assertEqual(self.pack.omitted, 0)
        self.assertIn("EVENTS OF THE INCIDENT (oldest first)", self.pack.text)
        self.assertEqual(self.pack.resolve("e3"), (self.ssh.event_ids[2],))
        self.assertEqual(self.pack.resolve("G1"), ())
        self.assertEqual(self.pack.resolve("E99"), ())

    def test_large_incident_is_shown_as_groups_with_every_event_citable(self):
        incident, store = self.scan_incident()
        pack = build_pack(incident, store)
        ids = incident.event_ids
        self.assertEqual(pack.omitted, 0)
        self.assertEqual(list(pack.groups), ["G1", "G2", "G3"])
        self.assertEqual(pack.resolve("G1"), tuple(ids[0::3]))
        self.assertEqual(pack.resolve(" g2 "), tuple(ids[1::3]))
        self.assertEqual([pack.labels[f"E{n}"] for n in range(1, 16)], list(ids))
        text = pack.text
        for expected in (
            "EVENTS OF THE INCIDENT, IN 3 GROUPS OF SIMILAR EVENTS (oldest group first)",
            "G1  5 events: E1 E4 E7 E10 E13  from ",
            "    command line: 5 different values, for example",
            "      E1: powershell check 0",
            "      E7: powershell check 2",
            "G2  5 events: E2 E5 E8 E11 E14  from ",
            "    done by the processes started in: G1",
            "    file: 5 different values, for example",
            "G3  5 events: E3 E6 E9 E12 E15  from ",
            "    command line: secedit /export",  # the same for all five, so shown once
            "    started by: C:\\win\\powershell.exe",
        ):
            self.assertIn(expected, text)
        self.assertNotIn("E10: powershell check 3", text)  # only three examples

    def test_origin_of_the_activity_is_worked_out_from_process_ids(self):
        incident, store = self.scan_incident()
        text = build_pack(incident, store).text
        self.assertIn("WHERE THE ACTIVITY CAME FROM (worked out by Aegis from process ids)", text)
        self.assertIn(
            "- C:\\agent\\agent.exe started 5 processes in this incident (E1, E4, E7, E10, E13). "
            "It is outside the incident: no rule fired on it.", text)
        self.assertIn("- 5 more processes were started by processes that are inside the incident.", text)
        # an incident with no process information has no such section
        self.assertNotIn("WHERE THE ACTIVITY CAME FROM", self.pack.text)

    def many_kinds(self, count=40):
        return self.synthetic([
            # one process (so correlation joins them) tripping a different rule each time
            self.event(n, rule=str(700 + n), command="tool.exe --flag " + "x" * 400,
                       guid="aaaaaaaa-0000-0000-0000-00000000000c")
            for n in range(1, count + 1)
        ])

    def test_groups_beyond_the_limit_are_left_out_and_said_so(self):
        incident, store = self.many_kinds(40)
        pack = build_pack(incident, store, max_groups=25)
        self.assertEqual(len(pack.groups), 25)
        self.assertEqual(pack.omitted, 15)
        self.assertIn("... 15 more groups with 15 events are not shown (", pack.text)
        self.assertIn("They cannot be cited.", pack.text)
        self.assertEqual(pack.resolve("E25"), (incident.event_ids[24],))
        self.assertEqual(pack.resolve("E26"), ())  # not shown, so it cannot be cited
        self.assertEqual(pack.resolve("G26"), ())
        self.assertIn("command line: tool.exe --flag " + "x" * 281 + "...", pack.text)

    def test_pack_is_shrunk_to_fit_the_context_window(self):
        incident, store = self.many_kinds(40)
        roomy = pack_for_model(incident, store, num_ctx=65536)
        tight = pack_for_model(incident, store, num_ctx=4096)
        self.assertEqual(roomy.omitted, 15)
        self.assertGreater(tight.omitted, roomy.omitted)
        self.assertLess(len(tight.text), len(roomy.text) // 3)
        self.assertLessEqual(len(tight.text), 4000)
        # a normal incident is not touched
        self.assertEqual(pack_for_model(self.ssh, self.store), self.pack)

    def test_store_lookups(self):
        with self.assertRaises(EvidenceError):
            self.store.get("evt-ffffffffffffffff")
        self.assertEqual(len(self.store), 18)
        self.assertEqual(self.store.rule_count("002", "5710"), 2)
        self.assertEqual(self.store.rule_count("001", "5710"), 0)
        ps = "c:\\windows\\system32\\windowspowershell\\v1.0\\POWERSHELL.exe"
        self.assertEqual(self.store.program_count("001", ps), 2)
        around = self.store.around("001", NOW - timedelta(days=30), NOW)
        self.assertTrue(all(e.category not in (Category.CONFIG_ASSESSMENT, Category.VULNERABILITY) for e in around))


class CheckerTests(Base):
    def test_good_answer_becomes_a_verdict_with_real_event_ids(self):
        verdict = self.check(answer_json())
        ids = self.ssh.event_ids
        self.assertEqual(verdict.label, VerdictLabel.MALICIOUS)
        self.assertEqual(verdict.confidence, Confidence.HIGH)
        self.assertEqual(verdict.incident_id, self.ssh.incident_id)
        self.assertEqual(verdict.findings[0].evidence, (ids[0], ids[2], ids[4]))
        self.assertEqual(verdict.findings[1].evidence, (ids[5],))
        self.assertEqual(verdict.technique_ids, ("T1110", "T1078"))
        self.assertEqual(
            [(a.action, a.target, a.evidence) for a in verdict.proposed_actions],
            [("lock_account", "svc_backup", (ids[5],)), ("block_ip", "192.168.56.1", (ids[0],))],
        )
        self.assertEqual(verdict.rejected, ())
        self.assertEqual(Verdict.from_dict(json.loads(json.dumps(verdict.to_dict()))), verdict)

    def test_numbered_answer_keys_and_reasoning(self):
        answer = json.loads(answer_json())
        numbered = {
            "01_what_happened": "Many failed SSH logins, then a success and a sudo.",
            "02_started_by": "A remote address, 192.168.56.1.",
            "03_innocent_explanation": "An administrator mistyping a password.",
            "04_attack_explanation": "Password guessing followed by access.",
            "05_against_innocent": "A mistyped password does not explain three different account names (E1, E2, E3).",
            "06_findings": answer["findings"],
            "07_verdict": answer["verdict"],
            "08_confidence": answer["confidence"],
            "09_summary": answer["summary"],
            "10_techniques": answer["techniques"],
            "11_proposed_actions": answer["proposed_actions"],
        }
        self.assertEqual(sorted(numbered), list(ANSWER_SCHEMA["properties"]))
        self.assertEqual(ANSWER_SCHEMA["required"], list(ANSWER_SCHEMA["properties"]))
        verdict = self.check(json.dumps(numbered))
        plain = self.check(answer_json())
        self.assertEqual(verdict.label, VerdictLabel.MALICIOUS)
        self.assertEqual(verdict.findings, plain.findings)
        self.assertEqual(verdict.proposed_actions, plain.proposed_actions)
        self.assertEqual(verdict.reasoning.what_happened, "Many failed SSH logins, then a success and a sudo.")
        self.assertEqual(verdict.reasoning.attack_explanation, "Password guessing followed by access.")
        self.assertIn("three different account names", verdict.reasoning.against_innocent)
        self.assertEqual(verdict.rejected, ())
        self.assertEqual(plain.reasoning, Reasoning())
        self.assertEqual(Verdict.from_dict(json.loads(json.dumps(verdict.to_dict()))), verdict)
        # the working is written before the verdict in the instructions too
        self.assertLess(SYSTEM_PROMPT.index("05_against_innocent"), SYSTEM_PROMPT.index("07_verdict"))
        for key in ANSWER_SCHEMA["properties"]:
            self.assertIn(f'"{key}"', SYSTEM_PROMPT)

    def test_alarm_without_evidence_against_the_innocent_reading_is_flagged_not_changed(self):
        for nothing in ("nothing", "Nothing.", "none", " N/A "):
            with self.subTest(nothing=nothing):
                verdict = self.check(answer_json(verdict="suspicious", against_innocent=nothing))
                self.assertEqual(verdict.label, VerdictLabel.SUSPICIOUS)  # the label stays the model's
                self.assertEqual(
                    [(r.kind, r.text, r.reason) for r in verdict.rejected],
                    [("verdict", "suspicious",
                      "kept, but the model named no evidence that its innocent explanation cannot account for")],
                )
        # naming something, saying benign, or not answering the question raises no flag
        self.assertEqual(self.check(answer_json(against_innocent="E6 follows five failures.")).rejected, ())
        self.assertEqual(self.check(answer_json(verdict="benign", against_innocent="nothing",
                                                proposed_actions=[])).rejected, ())
        self.assertEqual(self.check(answer_json()).rejected, ())

    def test_a_group_can_be_cited_and_stands_for_all_its_events(self):
        incident, store = EvidencePackTests.scan_incident(EvidencePackTests("scan_incident"))
        pack = build_pack(incident, store)
        events = [store.get(e) for e in incident.event_ids]
        content = json.dumps({
            "verdict": "benign", "confidence": "high", "summary": "The agent's own scan.",
            "findings": [
                {"claim": "The agent started every PowerShell.", "evidence": ["G1"]},
                {"claim": "secedit only exported settings.", "evidence": ["g3", "E3", "G9"]},
                {"claim": "Cites a group that does not exist.", "evidence": ["G7"]},
            ],
            "techniques": [], "proposed_actions": [],
        })
        verdict = check_answer(incident, events, pack, content, RUN, NOW)
        ids = incident.event_ids
        self.assertEqual(verdict.label, VerdictLabel.BENIGN)
        self.assertEqual(verdict.findings[0].evidence, tuple(ids[0::3]))
        self.assertEqual(verdict.findings[1].evidence, tuple(ids[2::3]))
        self.assertEqual([r.reason for r in verdict.rejected], [
            "kept, but its citation of G9 was removed (not in the evidence)",
            "it cites G7, which is not in the evidence",
        ])

    def test_finding_that_cites_nothing_real_is_removed_and_recorded(self):
        verdict = self.check(answer_json(findings=[
            {"claim": "Malware was downloaded.", "evidence": ["E42"]},
            {"claim": "No citation at all.", "evidence": []},
            {"claim": "", "evidence": ["E1"]},
            {"claim": "Failed logins from one address.", "evidence": ["E1"]},
        ]))
        self.assertEqual([f.claim for f in verdict.findings], ["Failed logins from one address."])
        self.assertEqual(
            [(r.kind, r.reason) for r in verdict.rejected],
            [("finding", "it cites E42, which is not in the evidence"),
             ("finding", "it cites nothing, which is not in the evidence"),
             ("finding", "it has no claim")],
        )
        self.assertEqual(verdict.rejected[0].text, "Malware was downloaded.")
        self.assertEqual(verdict.label, VerdictLabel.MALICIOUS)

    def test_partly_valid_citations_keep_the_finding_and_note_the_removal(self):
        verdict = self.check(answer_json(findings=[{"claim": "Failed logins.", "evidence": ["E1", "E77", "E1"]}]))
        self.assertEqual(verdict.findings[0].evidence, (self.ssh.event_ids[0],))
        self.assertIn("citation of E77 was removed", verdict.rejected[0].reason)

    def test_verdict_with_no_surviving_finding_becomes_inconclusive(self):
        verdict = self.check(answer_json(findings=[{"claim": "Trust me.", "evidence": ["E99"]}]))
        self.assertEqual(verdict.label, VerdictLabel.INCONCLUSIVE)
        self.assertEqual(verdict.confidence, Confidence.LOW)
        self.assertEqual(verdict.findings, ())
        self.assertEqual(verdict.proposed_actions, ())  # nothing may be proposed without support
        kinds = [r.kind for r in verdict.rejected]
        self.assertEqual(kinds, ["finding", "verdict", "action", "action"])
        self.assertIn("malicious", verdict.rejected[1].text)

    def test_citation_forms_that_are_accepted(self):
        ids = self.ssh.event_ids
        context_id = self.pack.labels["C1"]
        verdict = self.check(answer_json(findings=[
            {"claim": "Lower case label.", "evidence": ["e2"]},
            {"claim": "Full event id.", "evidence": [ids[3]]},
            {"claim": "Context event.", "evidence": ["C1"]},
        ]))
        self.assertEqual([f.evidence for f in verdict.findings], [(ids[1],), (ids[3],), (context_id,)])
        self.assertEqual(verdict.rejected, ())

    def test_an_event_from_another_incident_cannot_be_cited(self):
        other = self.powershell.event_ids[0]
        verdict = self.check(answer_json(findings=[{"claim": "Unrelated.", "evidence": [other]}]))
        self.assertEqual(verdict.label, VerdictLabel.INCONCLUSIVE)

    def test_techniques_are_format_checked(self):
        verdict = self.check(answer_json(techniques=["t1110.001", "T1110.001", "brute force", "T99", 5]))
        self.assertEqual(verdict.technique_ids, ("T1110.001",))
        self.assertEqual([r.kind for r in verdict.rejected], ["technique"] * 3)

    def test_proposed_actions_are_checked_against_catalog_and_evidence(self):
        verdict = self.check(answer_json(proposed_actions=[
            {"action": "lock_account", "target": "AEGIS-VICTIM\\SVC_BACKUP", "reason": "ok", "evidence": ["E6"]},
            {"action": "lock_account", "target": "administrator", "reason": "not in incident", "evidence": ["E6"]},
            {"action": "format_disk", "target": "aegis-victim", "reason": "not in catalog", "evidence": ["E6"]},
            {"action": "block_ip", "target": "8.8.8.8", "reason": "address not in incident", "evidence": ["E1"]},
            {"action": "block_ip", "target": "192.168.56.1", "reason": "no real evidence", "evidence": ["E50"]},
            {"action": "isolate_host", "target": "Aegis-Victim", "reason": "ok", "evidence": ["E7"]},
            {"action": "kill_process", "target": "C:\\evil.exe", "reason": "no such program", "evidence": ["E7"]},
            {"action": "quarantine_file", "target": "/etc/passwd", "reason": "file is only in context", "evidence": ["C1"]},
            "not an object",
        ]))
        self.assertEqual(
            [(a.action, a.target) for a in verdict.proposed_actions],
            [("lock_account", "svc_backup"), ("isolate_host", "aegis-victim")],
        )
        reasons = [r.reason for r in verdict.rejected if r.kind == "action"]
        self.assertEqual(reasons, [
            "the target does not appear in the incident's events",
            "the action is not in the catalog",
            "the target does not appear in the incident's events",
            "it cites no event that is in the evidence",
            "the target does not appear in the incident's events",
            "the target does not appear in the incident's events",
        ])

    def test_actions_are_refused_for_benign_and_inconclusive_verdicts(self):
        for label in ("benign", "inconclusive"):
            with self.subTest(label=label):
                verdict = self.check(answer_json(verdict=label))
                self.assertEqual(verdict.label.value, label)
                self.assertEqual(verdict.proposed_actions, ())
                self.assertEqual(
                    [r.reason for r in verdict.rejected],
                    [f"actions are not accepted with a {label} verdict"] * 2,
                )

    def test_file_and_program_targets(self):
        verdict = self.check(
            answer_json(
                findings=[{"claim": "PowerShell ran an encoded command.", "evidence": ["E1"]}],
                proposed_actions=[{
                    "action": "kill_process",
                    "target": "c:\\windows\\system32\\windowspowershell\\v1.0\\powershell.exe",
                    "reason": "encoded command", "evidence": ["E1"],
                }],
            ),
            incident=self.powershell,
        )
        self.assertEqual(
            verdict.proposed_actions[0].target,
            "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        )

    def test_unusable_answers_become_inconclusive_and_keep_the_text(self):
        cases = {
            "it was not a JSON object": ["", "I think this is fine.", "[1, 2]", '"malicious"', "{broken"],
            "unknown verdict": [answer_json(verdict="probably bad"), "{}", answer_json(verdict=None)],
        }
        for reason, contents in cases.items():
            for content in contents:
                with self.subTest(content=content[:30]):
                    verdict = self.check(content)
                    self.assertEqual(verdict.label, VerdictLabel.INCONCLUSIVE)
                    self.assertEqual(verdict.findings, ())
                    self.assertEqual(verdict.rejected[0].kind, "answer")
                    self.assertIn(reason, verdict.rejected[0].reason)
                    self.assertIn("could not be used", verdict.summary)

    def test_json_wrapped_in_other_text_is_still_read(self):
        wrapped = "Here is my answer:\n```json\n" + answer_json() + "\n```\nThanks."
        self.assertEqual(self.check(wrapped).label, VerdictLabel.MALICIOUS)

    def test_odd_shapes_do_not_crash(self):
        verdict = self.check(answer_json(findings="none", techniques="T1110", proposed_actions=None,
                                         confidence="very", summary=None, verdict="INCONCLUSIVE "))
        self.assertEqual(verdict.label, VerdictLabel.INCONCLUSIVE)
        self.assertEqual(verdict.confidence, Confidence.LOW)
        self.assertEqual(verdict.summary, "")
        self.assertEqual([r.kind for r in verdict.rejected], ["verdict"])

    def test_long_text_is_clipped(self):
        verdict = self.check(answer_json(summary="word " * 500,
                                         findings=[{"claim": "claim " * 200, "evidence": ["E1"]}]))
        self.assertLessEqual(len(verdict.summary), 600)
        self.assertLessEqual(len(verdict.findings[0].claim), 400)

    def test_a_known_problem_overrides_the_answer(self):
        verdict = self.check(answer_json(), problem="part of the evidence may have been cut off")
        self.assertEqual(verdict.label, VerdictLabel.INCONCLUSIVE)
        self.assertIn("cut off", verdict.rejected[0].reason)


class VerdictContractTests(Base):
    def setUp(self):
        self.verdict = self.check(answer_json())

    def rebuilt(self, **changes):
        data = self.verdict.to_dict()
        data.update(changes)
        return Verdict.from_dict(json.loads(json.dumps(data)))

    def test_round_trip(self):
        self.assertEqual(self.rebuilt(), self.verdict)
        self.assertEqual(self.verdict.to_dict()["label"], "malicious")

    def test_invalid_verdicts_are_rejected(self):
        event_id = self.ssh.event_ids[0]
        bad = {
            "unsupported verdict": dict(findings=[]),
            "unknown label": dict(label="evil"),
            "unknown confidence": dict(confidence="certain"),
            "bad incident id": dict(incident_id="inc-1"),
            "finding without evidence": dict(findings=[{"claim": "x", "evidence": []}]),
            "finding cites a label": dict(findings=[{"claim": "x", "evidence": ["E1"]}]),
            "finding without claim": dict(findings=[{"claim": " ", "evidence": [event_id]}]),
            "action outside catalog": dict(proposed_actions=[{"action": "rm_rf", "target": "x", "reason": "", "evidence": [event_id]}]),
            "action without target": dict(proposed_actions=[{"action": "block_ip", "target": "", "reason": "", "evidence": [event_id]}]),
            "action with benign verdict": dict(label="benign"),
            "bad technique": dict(technique_ids=["brute force"]),
            "bad rejection kind": dict(rejected=[{"kind": "mood", "text": "", "reason": ""}]),
            "naive time": dict(created_at="2026-11-16T16:00:00"),
            "unknown field": dict(risk_score=99),
            "reasoning not text": dict(reasoning={"what_happened": 5}),
            "unknown reasoning field": dict(reasoning={"vibes": "bad"}),
            "future schema": dict(schema_version=9),
            "no model": dict(run={"model": "", "mode": "single_call", "thinking": False, "prompt_sha256": ""}),
            "attempt zero": dict(run={"model": "m", "mode": "single_call", "thinking": False,
                                      "prompt_sha256": "", "attempt": 0}),
        }
        for name, changes in bad.items():
            with self.subTest(name=name):
                with self.assertRaises(ContractError):
                    self.rebuilt(**changes)

    def test_inconclusive_needs_no_findings(self):
        verdict = self.rebuilt(label="inconclusive", findings=[], proposed_actions=[])
        self.assertEqual(verdict.label, VerdictLabel.INCONCLUSIVE)

    def test_saving_replaces_the_verdict_for_the_same_incident_and_model(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "runs" / "verdicts.jsonl"
            self.assertEqual(read_verdicts(path), [])
            save_verdict(path, self.verdict)
            save_verdict(path, self.rebuilt(summary="second run"))
            other_model = self.rebuilt(run=dict(self.verdict.to_dict()["run"], model="other:8b"))
            save_verdict(path, other_model)
            saved = read_verdicts(path)
            self.assertEqual([(v.run.model, v.summary) for v in saved],
                             [("fake:1b", "second run"), ("other:8b", self.verdict.summary)])


class InvestigateTests(Base):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.addCleanup(self.folder.cleanup)
        self.recordings = Path(self.folder.name) / "recordings"
        self.calls = []

    def client(self, content=None, **extra):
        def fake(request, *, timeout):
            self.calls.append((request, timeout))
            return ollama_answer(answer_json() if content is None else content, **extra)
        return fake

    def run_it(self, **kwargs):
        kwargs.setdefault("client", self.client())
        return investigate(self.ssh, self.store, model="fake:1b", recordings=self.recordings,
                           now=lambda: NOW, **kwargs)

    def test_request_sent_to_the_model(self):
        result = self.run_it(timeout=42)
        request, timeout = self.calls[0]
        self.assertEqual(timeout, 42)
        self.assertEqual(request["model"], "fake:1b")
        self.assertIs(request["stream"], False)
        self.assertIs(request["think"], False)
        self.assertEqual(request["format"], ANSWER_SCHEMA)
        self.assertEqual(request["options"]["temperature"], 0)
        self.assertEqual(request["options"]["num_ctx"], 8192)
        self.assertEqual([m["role"] for m in request["messages"]], ["system", "user"])
        self.assertEqual(request["messages"][0]["content"], SYSTEM_PROMPT)
        self.assertEqual(request["messages"][1]["content"], result.pack.text)
        # evidence text never leaks into the instructions
        self.assertNotIn("svc_backup", request["messages"][0]["content"])

    def test_verdict_and_run_details(self):
        verdict = self.run_it().verdict
        self.assertEqual(verdict.label, VerdictLabel.MALICIOUS)
        self.assertEqual(verdict.created_at, NOW)
        self.assertEqual((verdict.run.model, verdict.run.mode, verdict.run.thinking, verdict.run.replayed),
                         ("fake:1b", "single_call", False, False))
        self.assertEqual((verdict.run.duration_ms, verdict.run.prompt_tokens, verdict.run.output_tokens),
                         (12300, 1500, 300))
        self.assertEqual(len(verdict.run.prompt_sha256), 64)

    def test_recording_and_replay(self):
        live = self.run_it()
        self.assertEqual(live.recording, recording_path(self.recordings, self.ssh.incident_id, "fake:1b", False))
        saved = json.loads(live.recording.read_text(encoding="utf-8"))
        self.assertEqual(saved["answer"]["message"]["content"], answer_json())
        self.assertEqual(saved["request"]["messages"][1]["content"], live.pack.text)

        def must_not_be_called(request, *, timeout):
            raise AssertionError("replay must not call the model")

        replayed = self.run_it(replay=True, client=must_not_be_called).verdict
        self.assertTrue(replayed.run.replayed)
        expected = live.verdict.to_dict()
        expected["run"]["replayed"] = True
        self.assertEqual(replayed.to_dict(), expected)

    def test_replay_without_a_recording(self):
        with self.assertRaises(InvestigationError) as caught:
            self.run_it(replay=True)
        self.assertIn("no recording", str(caught.exception))

    def test_replay_refuses_a_recording_made_for_a_different_prompt(self):
        self.run_it()
        with self.assertRaises(InvestigationError) as caught:
            self.run_it(replay=True, num_ctx=16384)  # a different request
        self.assertIn("different prompt", str(caught.exception))

    def test_asking_again_is_a_separate_attempt_with_its_own_recording(self):
        first = self.run_it()
        second = self.run_it(attempt=2, client=self.client(answer_json(verdict="suspicious")))
        self.assertEqual((first.verdict.run.attempt, second.verdict.run.attempt), (1, 2))
        self.assertEqual(first.verdict.run.prompt_sha256, second.verdict.run.prompt_sha256)  # same question
        self.assertNotEqual(first.recording, second.recording)
        self.assertTrue(second.recording.name.endswith(".fake-1b.r2.json"))
        replayed = self.run_it(attempt=2, replay=True)
        self.assertEqual(replayed.verdict.label, VerdictLabel.SUSPICIOUS)
        with self.assertRaises(InvestigationError) as caught:
            self.run_it(attempt=3, replay=True)
        self.assertIn("(attempt 3)", str(caught.exception))
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "verdicts.jsonl"
            for result in (first, second, first):
                save_verdict(path, result.verdict)
            self.assertEqual([v.run.attempt for v in read_verdicts(path)], [2, 1])

    def test_thinking_run_is_recorded_separately(self):
        result = self.run_it(think=True)
        self.assertTrue(result.recording.name.endswith(".fake-1b.think.json"))
        self.assertIs(self.calls[0][0]["think"], True)
        self.assertTrue(result.verdict.run.thinking)

    def test_model_name_is_made_safe_for_a_file_name(self):
        path = recording_path(Path("r"), "inc-0000000000000000", "hf.co/some/model:Q4_K_M", False)
        self.assertEqual(path.name, "inc-0000000000000000.hf.co-some-model-Q4_K_M.json")

    def test_prompt_that_fills_the_context_window_is_not_trusted(self):
        verdict = self.run_it(client=self.client(prompt_eval_count=8192)).verdict
        self.assertEqual(verdict.label, VerdictLabel.INCONCLUSIVE)
        self.assertIn("cut off", verdict.rejected[0].reason)

    def test_answer_cut_short_is_not_trusted(self):
        verdict = self.run_it(client=self.client(done_reason="length")).verdict
        self.assertEqual(verdict.label, VerdictLabel.INCONCLUSIVE)
        self.assertIn("ran out of output space", verdict.rejected[0].reason)

    def test_model_failure_is_an_investigation_error_and_leaves_no_recording(self):
        def failing(request, *, timeout):
            raise LLMError("Ollama not reachable")
        with self.assertRaises(InvestigationError):
            self.run_it(client=failing)
        self.assertFalse(self.recordings.exists())

    def test_build_request_is_stable(self):
        self.assertEqual(build_request(self.pack, "m"), build_request(self.pack, "m"))
        self.assertNotEqual(build_request(self.pack, "m"), build_request(self.pack, "m", think=True))


class FakeOllama:
    """A local web server that answers like Ollama, for the client and the CLI."""

    def __init__(self, content=None, status=200, body=None, delay=0.0, version="0.99.0"):
        self.requests = []
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def _send(self, code, payload):
                data = payload if isinstance(payload, bytes) else json.dumps(payload).encode()
                try:
                    self.send_response(code)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(data)))
                    self.end_headers()
                    self.wfile.write(data)
                except OSError:
                    pass  # the client gave up waiting (the timeout test)

            def do_GET(self):
                if self.path == "/api/tags":
                    self._send(200, {"models": [{"name": "fake:1b", "size": 2_500_000_000}]})
                elif self.path == "/api/version" and version:
                    self._send(200, {"version": version})
                else:
                    self._send(404, {"error": "not found"})

            def do_POST(self):
                length = int(self.headers.get("Content-Length", 0))
                outer.requests.append(json.loads(self.rfile.read(length)))
                if delay:
                    threading.Event().wait(delay)
                if body is not None:
                    self._send(status, body)
                else:
                    self._send(status, ollama_answer(answer_json() if content is None else content))

            def log_message(self, *args):
                pass

        self.server = HTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}"

    def __enter__(self):
        threading.Thread(target=self.server.serve_forever, kwargs={"poll_interval": 0.02}, daemon=True).start()
        return self

    def __exit__(self, *exc):
        self.server.shutdown()
        self.server.server_close()


class OllamaClientTests(unittest.TestCase):
    REQUEST = {"model": "fake:1b", "messages": [{"role": "user", "content": "hi"}], "stream": False}

    def test_success(self):
        with FakeOllama(content="hello") as fake:
            answer = chat(self.REQUEST, url=fake.url)
        self.assertEqual(answer["message"]["content"], "hello")
        self.assertEqual(fake.requests, [self.REQUEST])

    def test_missing_model_says_how_to_get_it(self):
        with FakeOllama(status=404, body={"error": "model 'fake:1b' not found"}) as fake:
            with self.assertRaises(LLMError) as caught:
                chat(self.REQUEST, url=fake.url)
        self.assertIn("ollama pull fake:1b", str(caught.exception))

    def test_server_errors_and_bad_answers(self):
        cases = [
            (dict(status=500, body={"error": "out of memory"}), "HTTP 500: out of memory"),
            (dict(status=500, body=b"<html>boom</html>"), "HTTP 500: <html>boom</html>"),
            (dict(body=b"not json"), "was not JSON"),
            (dict(body=[1, 2]), "not a JSON object"),
            (dict(body={"error": "something broke"}), "reported an error: something broke"),
            (dict(body={"message": {"role": "assistant"}}), "no message content"),
            (dict(body={"done": True}), "no message content"),
        ]
        for kwargs, expected in cases:
            with self.subTest(expected=expected):
                with FakeOllama(**kwargs) as fake:
                    with self.assertRaises(LLMError) as caught:
                        chat(self.REQUEST, url=fake.url)
                self.assertIn(expected, str(caught.exception))

    def test_timeout(self):
        with FakeOllama(delay=0.8) as fake:
            with self.assertRaises(LLMError) as caught:
                chat(self.REQUEST, url=fake.url, timeout=0.3)
        self.assertIn("no answer from the model within 0.3 s", str(caught.exception))

    def test_not_running(self):
        with FakeOllama() as fake:
            dead = fake.url
        with self.assertRaises(LLMError) as caught:
            chat(self.REQUEST, url=dead, timeout=2)
        self.assertIn("not reachable", str(caught.exception))

    def test_slow_refusal_is_still_reported_as_not_running(self):
        # On Windows a closed port can take seconds to refuse, so the connection
        # attempt times out instead. That must not read as "the model is slow".
        with mock.patch("aegis.llm.socket.create_connection", side_effect=TimeoutError("timed out")) as probe:
            with self.assertRaises(LLMError) as caught:
                chat(self.REQUEST, url="http://127.0.0.1:9", timeout=300)
        self.assertIn("Ollama not reachable at http://127.0.0.1:9", str(caught.exception))
        self.assertNotIn("no answer from the model", str(caught.exception))
        self.assertEqual(probe.call_args.kwargs["timeout"], 5.0)  # never the long model timeout

    def test_doctor_reports_the_ollama_version(self):
        with FakeOllama(version="0.12.3") as fake:
            self.assertIn("Ollama 0.12.3 at", doctor.check_ollama(fake.url).message)
        with FakeOllama(version=None) as fake:
            check = doctor.check_ollama(fake.url)
            self.assertEqual(check.status, doctor.OK)
            self.assertIn("Ollama at", check.message)


def run_cli(*args):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = main([str(a) for a in args])
    return code, out.getvalue(), err.getvalue()


class InvestigateCommandTests(Base):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.addCleanup(self.folder.cleanup)
        root = Path(self.folder.name)
        self.paths = ["--incidents", root / "incidents.jsonl", "--events", root / "events.jsonl",
                      "--out", root / "verdicts.jsonl", "--recordings", root / "recordings"]
        self.verdicts = root / "verdicts.jsonl"
        self.assertEqual(run_cli("ingest", SAMPLE, "--out", root / "events.jsonl")[0], 0)
        self.assertEqual(run_cli("correlate", root / "events.jsonl", "--out", root / "incidents.jsonl")[0], 0)

    def cli(self, *args, url):
        with mock.patch.dict(os.environ, {"AEGIS_OLLAMA_URL": url, "AEGIS_MODEL": "fake:1b"}):
            return run_cli("investigate", *args, *self.paths)

    def test_one_incident_end_to_end(self):
        content = answer_json(**{"01_what_happened": "Failed logins, then a success.",
                                 "04_attack_explanation": "Password guessing."})
        with FakeOllama(content=content) as fake:
            code, out, err = self.cli(self.ssh.incident_id[:10], url=fake.url)
        self.assertEqual(code, 0, err)
        self.assertEqual(len(fake.requests), 1)
        self.assertEqual(fake.requests[0]["model"], "fake:1b")
        for expected in (
            f"Incident  {self.ssh.incident_id}  (level 10, 7 events, aegis-victim)",
            "Model     fake:1b, single call, thinking off  (12.3 s, 1500 prompt + 300 answer tokens)",
            "Verdict   MALICIOUS   (confidence: high)",
            "Reasoning  (the model's working before it chose; not checked)",
            "  What happened:    Failed logins, then a success.",
            "  Attack reading:   Password guessing.",
            "  Innocent reading: (none)",
            "1. Repeated failed logins came from 192.168.56.1.",
            f"evidence: E1 {self.ssh.event_ids[0]}, E3 {self.ssh.event_ids[2]}, E5 {self.ssh.event_ids[4]}",
            "ATT&CK    T1110, T1078",
            "- lock_account svc_backup: It was guessed.",
            "AI-written",
        ):
            self.assertIn(expected, out)
        self.assertNotIn("by the checker", out)
        self.assertTrue(out.isascii())
        saved = read_verdicts(self.verdicts)
        self.assertEqual([(v.incident_id, v.label) for v in saved], [(self.ssh.incident_id, VerdictLabel.MALICIOUS)])

    def test_removed_items_are_shown(self):
        content = answer_json(findings=[{"claim": "Real.", "evidence": ["E1"]}, {"claim": "Made up.", "evidence": ["E88"]}])
        with FakeOllama(content=content) as fake:
            code, out, _ = self.cli(self.ssh.incident_id, url=fake.url)
        self.assertEqual(code, 0)
        self.assertIn("Removed or flagged by the checker", out)
        self.assertIn('- finding: "Made up." - it cites E88, which is not in the evidence', out)

    def test_replay_works_with_the_model_switched_off(self):
        with FakeOllama() as fake:
            self.cli(self.ssh.incident_id, url=fake.url)
            dead = fake.url
        code, out, err = self.cli(self.ssh.incident_id, "--replay", url=dead)
        self.assertEqual(code, 0, err)
        self.assertIn("[replayed from a recording]", out)
        self.assertIn("Verdict   MALICIOUS", out)

    def test_all_investigates_every_serious_incident(self):
        benign = json.dumps({"verdict": "benign", "confidence": "medium", "summary": "Routine.",
                             "findings": [{"claim": "Normal activity.", "evidence": ["E1"]}],
                             "techniques": [], "proposed_actions": []})
        with FakeOllama(content=benign) as fake:
            code, out, err = self.cli("--all", url=fake.url)
        self.assertEqual(code, 0, err)
        self.assertEqual(len(fake.requests), 4)
        self.assertIn("[4/4]", out)
        self.assertIn("-> BENIGN (medium confidence), 1 finding, 0 removed by the checker, 12.3 s", out)
        self.assertIn("Read one in full:  python -m aegis investigate inc-", out)
        self.assertIn("Verdicts  4 benign", out)
        self.assertEqual(len(read_verdicts(self.verdicts)), 4)

    def test_show_prompt_does_not_call_the_model(self):
        with FakeOllama() as fake:
            code, out, _ = self.cli(self.ssh.incident_id, "--show-prompt", url=fake.url)
        self.assertEqual(code, 0)
        self.assertEqual(fake.requests, [])
        self.assertEqual(out.strip(), build_pack(self.ssh, self.store).text.strip())
        self.assertFalse(self.verdicts.exists())

    def test_errors(self):
        with FakeOllama() as fake:
            dead = fake.url
        code, _, err = self.cli(self.ssh.incident_id, url=dead)
        self.assertEqual(code, 2)
        self.assertIn("Ollama not reachable", err)
        self.assertFalse(self.verdicts.exists())
        for args, expected in (
            ((), "give one incident id, or --all"),
            ((self.ssh.incident_id, "--all"), "give one incident id, or --all"),
            (("zzzz",), "no incident id starts with"),
            ((self.ssh.incident_id, "--num-ctx", "512"), "--num-ctx must be at least 2048"),
            ((self.ssh.incident_id, "--replay"), "no recording"),
        ):
            with self.subTest(args=args):
                code, _, err = self.cli(*args, url=dead)
                self.assertEqual(code, 2)
                self.assertIn(expected, err)

    def test_run_folder_keeps_data_sets_apart(self):
        folder = Path(self.folder.name) / "sample-run"
        self.assertEqual(run_cli("ingest", SAMPLE, "--dir", folder)[0], 0)
        code, out, _ = run_cli("correlate", "--dir", folder)
        self.assertEqual(code, 0)
        self.assertIn(f"--dir {folder}", out)
        self.assertEqual(run_cli("show", self.ssh.incident_id[:9], "--dir", folder)[0], 0)
        with FakeOllama() as fake:
            with mock.patch.dict(os.environ, {"AEGIS_OLLAMA_URL": fake.url, "AEGIS_MODEL": "fake:1b"}):
                code, out, err = run_cli("investigate", self.ssh.incident_id, "--dir", folder)
        self.assertEqual(code, 0, err)
        self.assertEqual(sorted(p.name for p in folder.iterdir()),
                         ["events.jsonl", "incidents.jsonl", "recordings", "verdicts.jsonl"])
        self.assertEqual(len(list((folder / "recordings").iterdir())), 1)

    def test_single_event_incident_reads_naturally(self):
        single = next(i for i in self.incidents if i.max_level == 7)
        benign = json.dumps({"verdict": "benign", "confidence": "low", "summary": "ok",
                             "findings": [{"claim": "A file changed.", "evidence": ["E1"]}],
                             "techniques": [], "proposed_actions": []})
        with FakeOllama(content=benign) as fake:
            code, out, _ = self.cli(single.incident_id, url=fake.url)
        self.assertEqual(code, 0)
        self.assertIn("(level 7, 1 event, aegis-victim)", out)

    def test_nothing_to_investigate(self):
        with FakeOllama() as fake:
            code, out, _ = self.cli("--all", "--min-level", "15", url=fake.url)
        self.assertEqual(code, 0)
        self.assertIn("No incidents at level 15 or above.", out)
        self.assertEqual(fake.requests, [])


if __name__ == "__main__":
    unittest.main()
