"""Compare: lining up and scoring saved verdicts."""

import contextlib
import io
import json
import os
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest import mock

from aegis.cli import main
from aegis.compare import compare, load_labels, render, variant_name
from aegis.contracts import (
    Confidence,
    ContractError,
    Finding,
    ModelRun,
    Rejection,
    Verdict,
    VerdictLabel,
)
from aegis.correlate import correlate
from aegis.ingest import ingest_file
from aegis.knowledge import DEFAULT_NOTES_FILE, load_notes, notes_fingerprint
from aegis.store import read_verdicts
from tests.test_investigate import FakeOllama, answer_json

ROOT = Path(__file__).resolve().parent.parent
SAMPLE = ROOT / "data" / "samples" / "wazuh_alerts_sample.jsonl"
SAMPLE_LABELS = ROOT / "data" / "samples" / "labels_sample.json"
FP = notes_fingerprint(load_notes(DEFAULT_NOTES_FILE))
NOW = datetime(2026, 11, 16, 16, 0, 0, tzinfo=timezone.utc)


def run_cli(*args):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = main([str(a) for a in args])
    return code, out.getvalue(), err.getvalue()


class CompareTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        events = ingest_file(SAMPLE).events
        cls.incidents = correlate(events).incidents
        by_level = {i.max_level: i for i in cls.incidents if i.max_level >= 7}
        cls.powershell, cls.ssh, cls.logons, cls.passwd = (by_level[n] for n in (12, 10, 8, 7))
        cls.labels = load_labels(SAMPLE_LABELS)

    def verdict(self, incident, label, model="qwen3:4b", think=False, attempt=1, seconds=8.0, rejected=(),
                version=4, knowledge=False, knowledge_id=""):
        findings = () if label == "inconclusive" else (Finding("claim", (incident.event_ids[0],)),)
        return Verdict(
            incident_id=incident.incident_id, label=VerdictLabel(label), confidence=Confidence.MEDIUM,
            summary="", created_at=NOW, findings=findings, rejected=tuple(rejected),
            run=ModelRun(model=model, mode="single_call", thinking=think, prompt_sha256="0" * 64,
                         attempt=attempt, duration_ms=int(seconds * 1000),
                         prompt_version=version, knowledge=knowledge, knowledge_id=knowledge_id),
        )

    def test_sample_labels_match_the_sample_incidents(self):
        self.assertEqual(set(self.labels), {i.incident_id for i in self.incidents})
        self.assertEqual(self.labels[self.ssh.incident_id], "attack")
        self.assertEqual(self.labels[self.logons.incident_id], "benign")
        self.assertEqual(sorted(self.labels.values()).count("attack"), 5)

    def test_scoring(self):
        v = self.verdict
        verdicts = [
            # qwen3:4b, three runs each
            v(self.ssh, "malicious"), v(self.ssh, "malicious", attempt=2), v(self.ssh, "suspicious", attempt=3),
            v(self.powershell, "benign"), v(self.powershell, "suspicious", attempt=2), v(self.powershell, "inconclusive", attempt=3),
            v(self.logons, "suspicious"), v(self.logons, "benign", attempt=2), v(self.logons, "benign", attempt=3, seconds=20),
            # qwen3:4b with thinking, one run each
            v(self.ssh, "malicious", think=True, rejected=[Rejection("finding", "x", "y")]),
            v(self.logons, "benign", think=True),
        ]
        result = compare(self.incidents, reversed(verdicts), self.labels)
        self.assertEqual(result.variants, ["qwen3:4b v4", "qwen3:4b v4 +think"])
        self.assertEqual([row.incident.incident_id for row in result.rows],
                         [self.powershell.incident_id, self.ssh.incident_id, self.logons.incident_id])
        ssh_row = result.rows[1]
        self.assertEqual(ssh_row.expected, "attack")
        self.assertEqual([l.value for l in ssh_row.cells["qwen3:4b v4"]], ["malicious", "malicious", "suspicious"])

        plain, think = result.scores
        self.assertEqual((plain.runs, plain.incidents), (9, 3))
        self.assertEqual((plain.attack_runs, plain.caught, plain.missed), (6, 4, 1))
        self.assertEqual((plain.benign_runs, plain.benign_correct, plain.false_alarms), (3, 2, 1))
        self.assertEqual(plain.inconclusive, 1)
        self.assertEqual(plain.unstable, 3)
        self.assertEqual(plain.with_removals, 0)
        self.assertAlmostEqual(plain.average_seconds, (8 * 8 + 20) / 9)
        self.assertEqual((think.runs, think.caught, think.benign_correct, think.unstable, think.with_removals),
                         (2, 1, 1, 0, 1))

        text = render(result)
        for expected in (
            "B benign   S suspicious   M malicious   ? inconclusive",
            "really   qwen3:4b v4  qwen3:4b v4 +think  title",
            f"{self.ssh.incident_id[:13]}  10   7  attack   M M S        M  ",
            f"{self.powershell.incident_id[:13]}  12   2  attack   B S ?        -  ",
            "    runs              9 on 3 incidents, 9.3 s on average",
            "    verdicts          2 malicious, 3 suspicious, 3 benign, 1 inconclusive",
            "    really benign     2 of 3 called benign (67%), 1 false alarm",
            "    really attacks    4 of 6 caught (67%), 1 missed, 1 inconclusive",
            "    changed its mind  on 3 of 3 incidents when asked again",
            "    checker stepped in  on 1 of 2 runs",
        ):
            self.assertIn(expected, text)
        self.assertEqual(text.count("changed its mind"), 1)  # not shown for the single-run variant

    def test_default_expectation_and_no_labels(self):
        verdicts = [self.verdict(self.ssh, "suspicious"), self.verdict(self.passwd, "benign")]
        scored = compare(self.incidents, verdicts, {self.ssh.incident_id: "attack"}, default_expected="benign")
        self.assertEqual([row.expected for row in scored.rows], ["attack", "benign"])
        self.assertEqual((scored.scores[0].caught, scored.scores[0].benign_correct), (1, 1))
        unscored = compare(self.incidents, verdicts)
        self.assertEqual([row.expected for row in unscored.rows], [None, None])
        self.assertIn("No labels given, so nothing is scored.", render(unscored))
        self.assertNotIn("really benign", render(unscored))

    def test_verdicts_for_incidents_of_another_run_are_left_out_and_counted(self):
        stranger = self.verdict(self.ssh, "benign").to_dict()
        stranger["incident_id"] = "inc-" + "0" * 16
        result = compare(self.incidents, [Verdict.from_dict(stranger), self.verdict(self.ssh, "malicious")])
        self.assertEqual((len(result.rows), result.unknown_incidents), (1, 1))
        self.assertIn("1 saved verdicts belong to incidents that are not in the incidents file", render(result))

    def test_nothing_to_compare(self):
        self.assertIn("No verdicts yet", render(compare(self.incidents, [])))

    def test_variant_names(self):
        self.assertEqual(variant_name(self.verdict(self.ssh, "benign", model="qwen3:8b").run), "qwen3:8b v4")
        self.assertEqual(variant_name(self.verdict(self.ssh, "benign", think=True).run), "qwen3:4b v4 +think")
        self.assertEqual(variant_name(self.verdict(self.ssh, "benign", knowledge=True).run), "qwen3:4b v4 +notes")
        self.assertEqual(variant_name(self.verdict(self.ssh, "benign", knowledge=True, knowledge_id="ab12cd").run),
                         "qwen3:4b v4 +notes:ab12cd")
        self.assertEqual(variant_name(self.verdict(self.ssh, "benign", version=0).run), "qwen3:4b v0")

    def test_verdicts_made_under_different_instructions_are_separate_columns(self):
        verdicts = [self.verdict(self.ssh, "benign", version=3), self.verdict(self.ssh, "malicious", version=4),
                    self.verdict(self.ssh, "malicious", version=4, knowledge=True)]
        result = compare(self.incidents, verdicts, self.labels)
        self.assertEqual(result.variants, ["qwen3:4b v3", "qwen3:4b v4", "qwen3:4b v4 +notes"])
        self.assertEqual([score.missed for score in result.scores], [1, 0, 0])

    def test_bad_label_files(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "labels.json"
            for content, expected in (("{oops", "not valid JSON"), ("[1]", "expected an object"),
                                      ('{"inc-1": "evil"}', "use 'attack' or 'benign'")):
                with self.subTest(content=content):
                    path.write_text(content, encoding="utf-8")
                    with self.assertRaises(ContractError) as caught:
                        load_labels(path)
                    self.assertIn(expected, str(caught.exception))
            path.write_text('{"_about": "a note", "inc-1": "benign"}', encoding="utf-8")
            self.assertEqual(load_labels(path), {"inc-1": "benign"})


class CommandTests(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.addCleanup(self.folder.cleanup)
        self.dir = Path(self.folder.name) / "run"
        self.assertEqual(run_cli("ingest", SAMPLE, "--dir", self.dir)[0], 0)
        self.assertEqual(run_cli("correlate", "--dir", self.dir)[0], 0)

    def investigate(self, *args, content=None, model="fake:1b"):
        with FakeOllama(content=content) as fake:
            with mock.patch.dict(os.environ, {"AEGIS_OLLAMA_URL": fake.url, "AEGIS_MODEL": model}):
                code, out, err = run_cli("investigate", *args, "--dir", self.dir)
        self.assertEqual(code, 0, err)
        return out, fake.requests

    def test_repeat_then_compare_with_the_sample_labels(self):
        benign = json.dumps({"verdict": "benign", "confidence": "high", "summary": "Routine.",
                             "findings": [{"claim": "Normal.", "evidence": ["E1"]}],
                             "techniques": [], "proposed_actions": []})
        out, requests = self.investigate("--all", "--repeat", "2", content=benign)
        self.assertEqual(len(requests), 8)  # 4 incidents x 2
        self.assertEqual(out.count("-> BENIGN"), 8)
        self.assertIn("Verdicts  8 benign", out)
        self.assertIn(f"Side by side:      python -m aegis compare --dir {self.dir}", out)
        self.assertEqual(sorted(v.run.attempt for v in read_verdicts(self.dir / "verdicts.jsonl")), [1] * 4 + [2] * 4)
        self.assertEqual(len(list((self.dir / "recordings").iterdir())), 8)

        self.investigate("--all", "--think", content=answer_json(findings=[{"claim": "Bad.", "evidence": ["E1"]}],
                                                                 proposed_actions=[]))
        code, out, err = run_cli("compare", "--dir", self.dir, "--labels", SAMPLE_LABELS)
        self.assertEqual(code, 0, err)
        for expected in (
            f"fake:1b v4 +notes:{FP}  fake:1b v4 +think +notes:{FP}",
            "attack   B B                       M ",
            "benign   B B                       M ",
            "    really benign     2 of 2 called benign (100%), 0 false alarms",
            "    really attacks    0 of 6 caught (0%), 6 missed",
            "    really benign     0 of 1 called benign (0%), 1 false alarm",
            "    really attacks    3 of 3 caught (100%), 0 missed",
            "    changed its mind  on 0 of 4 incidents when asked again",
        ):
            self.assertIn(expected, out)
        self.assertTrue(out.isascii())

    def test_single_incident_repeat_prints_the_first_in_full_and_the_rest_in_a_line(self):
        out, requests = self.investigate("inc-dd29", "--repeat", "3")
        self.assertEqual(len(requests), 3)
        self.assertEqual(out.count("Verdict   MALICIOUS"), 1)
        self.assertIn("Asked again (2 of 3)  -> MALICIOUS (high confidence)", out)
        self.assertIn("Asked again (3 of 3)  -> MALICIOUS", out)

    def test_labels_file_in_the_run_folder_is_picked_up_and_expect_fills_the_rest(self):
        self.investigate("--all")
        (self.dir / "labels.json").write_text(json.dumps({"inc-dd29f3ede71f6a05": "attack"}), encoding="utf-8")
        code, out, _ = run_cli("compare", "--dir", self.dir, "--expect", "benign")
        self.assertEqual(code, 0)
        self.assertIn("labels.json", out.splitlines()[0])
        self.assertIn("    really attacks    1 of 1 caught (100%), 0 missed", out)
        self.assertIn("    really benign     0 of 3 called benign (0%), 3 false alarms", out)

    def test_compare_errors(self):
        code, _, err = run_cli("compare", "--dir", Path(self.folder.name) / "nope")
        self.assertEqual(code, 2)
        self.assertIn("correlate", err)
        code, out, _ = run_cli("compare", "--dir", self.dir)
        self.assertEqual(code, 0)
        self.assertIn("No verdicts yet", out)
        code, _, err = run_cli("compare", "--dir", self.dir, "--labels", self.dir / "missing.json")
        self.assertEqual(code, 2)
        self.assertIn("file not found", err)
        for bad in ("0", "21"):
            code, _, err = run_cli("investigate", "--all", "--repeat", bad, "--dir", self.dir)
            self.assertEqual(code, 2)
            self.assertIn("--repeat must be between 1 and 20", err)


if __name__ == "__main__":
    unittest.main()
