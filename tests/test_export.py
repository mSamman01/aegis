"""The static copy of the dashboard (aegis export) and the public demo built from it (aegis demo)."""

import html
import tempfile
import unittest
from html.parser import HTMLParser
from pathlib import Path
from unittest import mock

from aegis.demo import MARKER, NOTICE, DemoError, build_demo
from aegis.export import check_site, export_run
from aegis.investigate import InvestigationError
from aegis.store import read_events
from aegis.web import pages
from tests.test_act import run_cli
from tests.test_dashboard import build_run, fingerprint



class Elements(HTMLParser):
    """The elements and attributes a page really has (text that only looks like markup is not counted)."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.tags, self.handlers, self.hrefs = set(), [], []

    def handle_starttag(self, tag, attrs):
        self.tags.add(tag)
        self.handlers += [name for name, _ in attrs if name.startswith("on")]
        self.hrefs += [value for name, value in attrs if name == "href"]


class ExportTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.folder = tempfile.TemporaryDirectory()
        root = Path(cls.folder.name)
        cls.run_dir = build_run(root)  # the sample with hostile text planted, decided, approved and acted on
        cls.before = fingerprint(cls.run_dir)
        cls.out = root / "copy"
        cls.written = export_run(cls.run_dir, cls.out, label="test run", notice="A test copy.")
        cls.html = {p.name: p.read_text(encoding="utf-8") for p in cls.out.glob("*.html")}

    @classmethod
    def tearDownClass(cls):
        cls.folder.cleanup()

    def test_every_page_is_written_and_every_link_resolves(self):
        self.assertEqual(check_site(self.out), [])
        self.assertEqual(len(self.html), self.written)
        events = read_events(self.run_dir / "events.jsonl")
        self.assertEqual(sum(name.startswith("event-") for name in self.html), len(events))
        self.assertIn("index.html", self.html)
        self.assertIn("audit.html", self.html)
        self.assertTrue((self.out / "style.css").is_file())

    def test_pages_carry_the_policy_and_nothing_that_runs(self):
        for name, page in self.html.items():
            with self.subTest(page=name):
                self.assertIn('http-equiv="Content-Security-Policy"', page)
                self.assertIn(html.escape(pages.STATIC_CSP, quote=True), page)
                elements = Elements()
                elements.feed(page)
                self.assertLessEqual(elements.tags, pages._TAGS)
                self.assertEqual(elements.handlers, [])
                for href in elements.hrefs:
                    self.assertFalse(href.startswith("/") or "://" in href, href)

    def test_hostile_text_stays_text(self):
        everything = "".join(self.html.values())
        self.assertNotIn("<script>alert", everything)
        self.assertIn("&lt;script&gt;alert(1)&lt;/script&gt;", everything)
        self.assertIn("\\u202e", everything)  # the right-to-left override, shown as a code

    def test_the_run_folder_is_not_changed(self):
        self.assertEqual(fingerprint(self.run_dir), self.before)

    def test_the_copy_says_what_it_is(self):
        index = self.html["index.html"]
        self.assertIn("A test copy.", index)
        self.assertIn("test run", index)
        self.assertIn("A static copy of Aegis", index)
        self.assertNotIn("?min=", index)  # the filters need a server, so a copy has none

    def test_check_site_reports_what_is_wrong(self):
        bad = Path(self.folder.name) / "bad"
        bad.mkdir()
        meta = f'<meta http-equiv="Content-Security-Policy" content="{html.escape(pages.STATIC_CSP)}">'
        (bad / "index.html").write_text(meta + '<a href="gone.html">x</a><a href="other.html#nowhere">y</a>'
                                        '<a href="/incident/x">z</a>', encoding="utf-8")
        (bad / "other.html").write_text("<p>no policy</p><script>1</script>", encoding="utf-8")
        problems = "\n".join(check_site(bad))
        for expected in ("gone.html, which is not in the copy", "has no #nowhere", "does not work in a copy",
                         "other.html: no Content-Security-Policy", "other.html: has a script"):
            self.assertIn(expected, problems)

    def test_the_command(self):
        out = Path(self.folder.name) / "by-command"
        code, said, _ = run_cli("export", "--dir", self.run_dir, "--out", out)
        self.assertEqual(code, 0)
        self.assertIn("Publish it only if that data may be public", said)
        self.assertEqual(check_site(out), [])
        code, _, err = run_cli("export", "--dir", Path(self.folder.name) / "nothing", "--out", out)
        self.assertEqual(code, 2)
        self.assertIn("run 'python -m aegis correlate' first", err)


class MarkdownTests(unittest.TestCase):
    def test_the_subset_the_report_uses_with_every_word_escaped(self):
        text = ("# Title\n\nSome `code` and <b>bold</b>\nstill the same paragraph.\n\n"
                "| a | b |\n|---|---|\n| 1 | <i>2</i> |\n\n* one `x`\n* two\n")
        out = pages.markdown(text)
        for expected in ("<h1>Title</h1>", "<code>code</code>", "&lt;b&gt;bold&lt;/b&gt; still the same paragraph",
                         "<th>a</th>", "<td>1</td>", "&lt;i&gt;2&lt;/i&gt;", "<li>one <code>x</code></li>",
                         "<li>two</li>"):
            self.assertIn(expected, out)
        self.assertNotIn("---", out)
        self.assertNotIn("<b>", out)


class DemoTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.folder = tempfile.TemporaryDirectory()
        cls.root = Path(cls.folder.name)
        cls.site = cls.root / "site"
        cls.built = build_demo(cls.site)
        cls.html = {p.relative_to(cls.site).as_posix(): p.read_text(encoding="utf-8")
                    for p in cls.site.rglob("*.html")}

    @classmethod
    def tearDownClass(cls):
        cls.folder.cleanup()

    def test_the_site_is_whole(self):
        self.assertEqual(check_site(self.site), [])
        self.assertIn("index.html", self.html)
        self.assertIn("evaluation/index.html", self.html)
        self.assertIn("sample/index.html", self.html)
        self.assertEqual(self.built["twins"], 7)
        for name in ("ssh-two-typos", "ssh-injected", "motd-changed"):
            self.assertIn(f"twins/{name}/index.html", self.html)

    def test_every_page_says_the_data_is_synthetic(self):
        notice = html.escape(NOTICE, quote=True)
        for name, page in self.html.items():
            with self.subTest(page=name):
                self.assertIn(notice, page)

    def test_the_lock_was_approved_by_demo_and_sent_only_to_the_stand_in(self):
        locked = self.built["locked"]
        self.assertIn("lock svc_backup", locked["requests"])
        page = self.html[f"sample/incident-{locked['incident']}.html"]
        self.assertIn("Approved by demo", page)
        self.assertIn("account locked and expired", page)
        self.assertIn("replayed from a recording", page)

    def test_the_evaluation_holds_and_nothing_hostile_was_carried_out(self):
        report = self.html["evaluation/index.html"]
        self.assertIn("All 6 expectations hold.", report)
        self.assertIn("None broken", report)
        self.assertIn("Hostile proposals: 14. Carried out: 0.", report)

    def test_no_trace_of_the_build_folder_or_of_real_runs(self):
        for name, page in self.html.items():
            with self.subTest(page=name):
                self.assertNotIn("aegis-demo-", page)
                self.assertNotIn("runs/lab", page)
                self.assertNotIn("runs/live", page)

    def test_the_posture_page_is_synthetic_and_shows_the_checker_at_work(self):
        page = self.html["posture/index.html"]
        self.assertIn("written by hand for the demo", page)
        self.assertIn("Removed by the checker", page)
        self.assertIn("turns parts of Microsoft Defender off", page)  # the planted remediation text
        self.assertIn("Commands held back", page)
        self.assertNotIn("LenovoMSamman", page)
        self.assertIn('href="posture/index.html"', self.html["index.html"])

    def test_the_sample_dashboard_has_the_posture_pages(self):
        page = self.html["sample/posture.html"]
        self.assertIn("written by hand for the demo", page)
        self.assertIn('href="posture.html">Posture</a>', self.html["sample/index.html"])
        self.assertIn('href="sample/posture.html"', self.html["index.html"])
        items = [name for name in self.html if name.startswith("sample/posture-")]
        self.assertGreater(len(items), 10)
        removed = [self.html[name] for name in items if "Removed by the checker" in self.html[name]]
        self.assertEqual(len(removed), 1)  # the planted remediation text
        self.assertIn("turns parts of Microsoft Defender off", removed[0])
        self.assertNotIn("twins/ssh-injected/posture.html", self.html)  # the twins carry no posture pages

    def test_the_outside_attacker_scenario_shows_a_real_firewall_block(self):
        blocked = self.built["blocked"]
        self.assertEqual(blocked["actions"], ["lock_account", "block_ip"])
        page = self.html[f"response/incident-{blocked['incident']}.html"]
        self.assertIn("block_ip 192.168.56.66", page)
        self.assertIn("address blocked at the firewall", page)
        self.assertIn("blocked=no", page)   # before
        self.assertIn("blocked=yes", page)  # after
        self.assertIn("lock_account svc_deploy", page)
        self.assertIn("account locked and expired", page)
        # the front page links to it, and frames it as the block the sample's laptop source cannot get
        front = self.html["index.html"]
        self.assertIn(f'href="response/incident-{blocked["incident"]}.html"', front)
        self.assertIn("a network block the sample", front)  # the laptop-source point

    def test_a_missing_recording_stops_the_build_instead_of_asking_a_model(self):
        empty = self.root / "no-recordings"
        empty.mkdir()
        with mock.patch("aegis.demo.RECORDINGS", empty):
            with self.assertRaisesRegex(InvestigationError, "replays recorded answers only"):
                build_demo(self.root / "never")

    def test_only_its_own_folder_is_cleared(self):
        other = self.root / "someone-elses"
        other.mkdir()
        (other / "keep.txt").write_text("mine", encoding="utf-8")
        with self.assertRaises(DemoError):
            build_demo(other)
        self.assertTrue((other / "keep.txt").exists())
        again = self.root / "again"
        build_demo(again)
        (again / "stale.html").write_text("old", encoding="utf-8")
        build_demo(again)  # made by the demo before (it has the marker): cleared and rebuilt
        self.assertFalse((again / "stale.html").exists())
        self.assertTrue((again / MARKER).is_file())


if __name__ == "__main__":
    unittest.main()
