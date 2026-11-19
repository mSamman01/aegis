"""The posture pages on the read-only dashboard and in a static copy (D48).

Built on data/samples/posture_sample.json with hostile text planted where a PC can put it (a program's
name) and where a manager's policy file can (a check's title). Nothing here needs Wazuh or a model.
"""

import json
import os
import re
import tempfile
import threading
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock

from aegis import posture as P
from aegis import server
from aegis.export import check_site, export_run
from aegis.web import pages
from tests.test_act import run_cli
from tests.test_dashboard import HOSTILE, PAGE_TAGS, build_run, fingerprint, parse

SAMPLE = Path(__file__).resolve().parent.parent / "data" / "samples" / "posture_sample.json"


def hostile_export(folder: Path, name: str = "aegis-posture-001.json", made_at: str | None = None) -> Path:
    data = json.loads(SAMPLE.read_text(encoding="utf-8"))
    data["vulnerabilities"][0]["package"]["name"] = HOSTILE  # a program's name comes from the PC
    first = next(iter(data["sca_checks"].values()))[0]
    first["title"] = "Ensure 'Enable insecure guest logons' " + HOSTILE
    first["rationale"] = HOSTILE
    if made_at:
        data["made_at"] = made_at
    path = folder / name
    path.write_text(json.dumps(data), encoding="utf-8")
    return path


class Served:
    """A dashboard with posture pages on a free port."""

    def __init__(self, test: unittest.TestCase, run: Path, posture_dir: Path | None):
        self.httpd = server.make_server(run, 0, None, quiet=True, posture_dir=posture_dir)
        self.port = self.httpd.server_address[1]
        thread = threading.Thread(target=self.httpd.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
        thread.start()

        def stop():
            self.httpd.shutdown()
            self.httpd.server_close()
            thread.join(5)
        test.addCleanup(stop)

    def get(self, path: str):
        import http.client

        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        conn.request("GET", path, headers={"Host": f"127.0.0.1:{self.port}"})
        response = conn.getresponse()
        body = response.read()
        conn.close()
        return response.status, response.headers, body

    def json(self, path: str):
        status, _, body = self.get(path)
        assert status == 200, (path, status, body[:200])
        return json.loads(body)


class PostureDashboardTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.folder = tempfile.TemporaryDirectory()
        root = Path(cls.folder.name)
        cls.run_dir = build_run(root)
        cls.posture_dir = root / "posture"
        cls.posture_dir.mkdir()
        cls.export = hostile_export(cls.posture_dir)
        cls.state = P.load(cls.export)
        cls.advice = P.rank(cls.state)

    @classmethod
    def tearDownClass(cls):
        cls.folder.cleanup()

    def setUp(self):
        self.web = Served(self, self.run_dir, self.posture_dir)

    def paths(self) -> list[str]:
        overview = self.web.json("/api/posture")
        paths = ["/posture", "/api/posture"] + [f"/posture?show={name}" for name in P.SHOW]
        paths += [f"/posture?area={a['slug']}" for a in overview["areas"]]
        paths += [f"/posture/{row['slug']}" for row in overview["items"]]
        paths += [f"/api/posture/{row['slug']}" for row in overview["items"]]
        return paths

    def test_every_posture_page_answers_with_the_security_headers_and_no_script(self):
        for path in self.paths():
            with self.subTest(path=path):
                status, headers, body = self.web.get(path)
                self.assertEqual(status, 200, body[:300])
                self.assertEqual(headers["Content-Security-Policy"], server.CSP)
                if path.startswith("/api/"):
                    self.assertTrue(headers["Content-Type"].startswith("application/json"))
                    self.assertNotIn(b"<", body)
                else:
                    self.assertNotIn(b"<script", body.lower())
                    self.assertIn(b'href="/posture">Posture</a>', body)

    def test_hostile_text_from_the_pc_is_only_text(self):
        overview = self.web.json("/api/posture")
        planted = [row for row in overview["items"] if HOSTILE in row["title"]]
        self.assertEqual(len(planted), 2)  # the program and the check
        for path in ["/posture"] + [f"/posture/{row['slug']}" for row in planted]:
            with self.subTest(path=path):
                _, _, body = self.web.get(path)
                page = body.decode("utf-8")
                self.assertNotIn("<script>", page)
                self.assertNotIn("<img", page)
                self.assertIn("&lt;script&gt;alert(1)&lt;/script&gt;", page)
                self.assertIn("\\u202e", page)  # the right-to-left override, shown as a code
                self.assertIn("\\U000e0069", page)  # the hidden tag characters too
                parsed = parse(body)
                self.assertTrue(set(parsed.tags) <= PAGE_TAGS)
                for name, value in parsed.attrs:
                    if name == "href":
                        self.assertRegex(value, r"^(/(?!/)|#)", "only links inside the dashboard")

    def test_a_program_name_never_goes_into_a_link(self):
        slugs = P.advice_slugs(self.advice)
        self.assertEqual(len(set(slugs)), len(slugs))
        self.assertTrue(all(P.valid_slug(slug) for slug in slugs))
        for item, slug in zip(self.advice, slugs):
            if item.kind == "program":
                self.assertRegex(slug, r"^program-[0-9a-f]{12}$")
            else:
                self.assertEqual(slug, "check-" + item.item.split()[1])
        self.assertEqual(P.advice_slugs(P.rank(P.load(self.export))), slugs)  # the same after a reload

    def test_the_api_is_the_same_advice_as_the_report(self):
        overview = self.web.json("/api/posture")
        self.assertEqual([row["title"] for row in overview["items"]], [a.title for a in self.advice])
        self.assertEqual([row["score"] for row in overview["items"]], [a.score for a in self.advice])
        self.assertEqual(overview["counts"]["failed"], len(self.state.checks))
        self.assertEqual(overview["counts"]["held"], sum(bool(a.held) for a in self.advice))
        for row, advice in zip(overview["items"], self.advice):
            item = self.web.json(f"/api/posture/{row['slug']}")
            self.assertEqual([(s["kind"], s["text"]) for s in item["steps"]], [(s.kind, s.text) for s in advice.steps])
            self.assertEqual(item["rank"], row["rank"])

    def test_a_held_back_command_is_not_shown(self):
        held = [(slug, a) for slug, a in zip(P.advice_slugs(self.advice), self.advice) if a.held]
        self.assertTrue(held)
        for slug, advice in held:
            for path in (f"/posture/{slug}", f"/api/posture/{slug}"):
                _, _, body = self.web.get(path)
                for command, _ in advice.held:
                    self.assertNotIn(command, body.decode("utf-8"))
                    self.assertNotIn(json.dumps(command)[1:-1], body.decode("utf-8"))
            self.assertIn("Command held back", self.web.get(f"/posture/{slug}")[2].decode("utf-8"))

    def test_the_checkers_removals_are_shown_as_removed(self):
        removed = [(slug, a) for slug, a in zip(P.advice_slugs(self.advice), self.advice) if a.removed]
        self.assertTrue(removed)
        for slug, advice in removed:
            page = self.web.get(f"/posture/{slug}")[2].decode("utf-8")
            self.assertIn("Removed by the checker", page)
            self.assertIn("Do not run them.", page)
            for text, _ in advice.removed:
                self.assertNotIn('<pre class="command"><code>' + pages.text(text), page)  # never as a command

    def test_reading_writes_nothing(self):
        before = fingerprint(self.run_dir, self.posture_dir)
        for path in self.paths() + ["/posture/check-1", "/posture/../../etc/passwd", "/api/posture/nope"]:
            self.web.get(path)
        self.assertEqual(fingerprint(self.run_dir, self.posture_dir), before)

    def test_bad_ids_and_filters(self):
        for path in ("/posture/check-1", "/posture/CHECK-90001", "/posture/program-zz", "/posture/../x",
                     "/posture/check-90001/more", "/api/posture/check-90001/more", "/api/posture/nope"):
            with self.subTest(path=path):
                status, headers, body = self.web.get(path)
                self.assertEqual(status, 404)
                self.assertEqual(headers["Content-Security-Policy"], server.CSP)
        filters = self.web.json("/api/posture?area=%3Cscript%3E&show=everything-evil")["filters"]
        self.assertEqual(filters, {"area": None, "show": None})
        printing = self.web.json("/api/posture?area=printing&show=commands")
        self.assertTrue(all(r["area"] == "Printing" and r["action"] == "command" for r in printing["items"]))


class PostureFolderTests(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.addCleanup(self.folder.cleanup)
        root = Path(self.folder.name)
        self.run_dir = root / "run"
        self.run_dir.mkdir()
        self.posture_dir = root / "posture"
        self.posture_dir.mkdir()

    def test_no_export_yet_says_how_to_make_one(self):
        web = Served(self, self.run_dir, self.posture_dir)
        status, _, body = web.get("/posture")
        self.assertEqual(status, 200)
        self.assertIn(b"There is no posture export in", body)
        self.assertFalse(web.json("/api/posture")["ready"])

    def test_a_newer_export_shows_without_a_restart(self):
        web = Served(self, self.run_dir, self.posture_dir)
        first = hostile_export(self.posture_dir, "a.json", "2026-11-01T00:00:00+00:00")
        self.assertEqual(web.json("/api/posture")["file"], "a.json")
        second = hostile_export(self.posture_dir, "b.json", "2026-11-19T00:00:00+00:00")
        later = first.stat().st_mtime + 60
        os.utime(second, (later, later))
        data = web.json("/api/posture")
        self.assertEqual((data["file"], data["made_at"]), ("b.json", "2026-11-19T00:00:00+00:00"))

    def test_a_damaged_export_is_reported_not_a_crash(self):
        (self.posture_dir / "broken.json").write_text('{"aegis_posture_export": 1, "sca_checks": [1, 2]}',
                                                      encoding="utf-8")
        web = Served(self, self.run_dir, self.posture_dir)
        status, _, body = web.get("/posture")
        self.assertEqual(status, 200)
        self.assertIn(b"The newest export could not be read", body)
        (self.posture_dir / "broken.json").write_text("not json", encoding="utf-8")
        self.assertIn("cannot be read as JSON", web.json("/api/posture")["error"])

    def test_an_old_export_is_flagged(self):
        hostile_export(self.posture_dir, made_at="2026-11-01T00:00:00Z")
        loaded = P.PostureView(self.posture_dir).current()
        made = datetime(2026, 11, 1, tzinfo=timezone.utc)
        self.assertFalse(P.overview_data(loaded, now=made + timedelta(days=2))["stale"])
        old = P.overview_data(loaded, now=made + timedelta(days=P.STALE_DAYS + 1))
        self.assertTrue(old["stale"])
        page = pages.posture_page(dict(old, header=_header())).decode("utf-8")
        self.assertIn("so export again for the current state", page)

    def test_the_commands_say_where_the_posture_comes_from(self):
        with mock.patch.object(server.DashboardServer, "serve_forever", side_effect=KeyboardInterrupt):
            code, out, _ = run_cli("serve", "--dir", self.run_dir, "--port", "0", "--posture-dir", self.posture_dir)
        self.assertEqual(code, 0)
        self.assertIn("Posture   no export in", out)
        hostile_export(self.posture_dir)
        with mock.patch.object(server.DashboardServer, "serve_forever", side_effect=KeyboardInterrupt):
            code, out, _ = run_cli("serve", "--dir", self.run_dir, "--port", "0", "--posture-dir", self.posture_dir)
        self.assertIn("Posture   aegis-posture-001.json: win-laptop", out)

    def test_without_a_posture_folder_there_are_no_posture_pages(self):
        web = Served(self, self.run_dir, None)
        self.assertEqual(web.get("/posture")[0], 404)
        self.assertEqual(web.get("/api/posture")[0], 404)
        self.assertNotIn(b"Posture</a>", web.get("/")[2])


class PostureCopyTests(unittest.TestCase):
    def test_a_static_copy_has_every_posture_page_and_every_link_resolves(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            run = build_run(root)
            loaded = P.read_loaded(hostile_export(root))
            out = root / "copy"
            written = export_run(run, out, label="test run", notice="A test copy.", posture=loaded)
            names = {p.name for p in out.glob("*.html")}
            self.assertEqual(len(names), written)
            self.assertIn("posture.html", names)
            self.assertEqual({n for n in names if n.startswith("posture-")},
                             {f"posture-{slug}.html" for slug in loaded.slugs})
            self.assertEqual(check_site(out), [])
            index = (out / "index.html").read_text(encoding="utf-8")
            self.assertIn('href="posture.html">Posture</a>', index)
            page = (out / "posture.html").read_text(encoding="utf-8")
            self.assertNotIn('class="filters"', page)  # filters need the server
            self.assertNotIn("<script>", page)
            self.assertNotIn("days ago", page)  # a copy gives the date, not an age that would go wrong

            empty = root / "empty"
            empty.mkdir()
            code, _, err = run_cli("export", "--dir", run, "--out", root / "c2", "--posture-dir", empty)
            self.assertEqual(code, 2)
            self.assertIn("no usable posture export", err)
            code, out_text, _ = run_cli("export", "--dir", run, "--out", root / "c3", "--posture-dir",
                                        loaded.folder)
            self.assertEqual(code, 0, out_text)
            self.assertTrue((root / "c3" / "posture.html").is_file())


def _header() -> dict:
    return {"run_dir": "test", "policy": {"id": "p"}, "audit": {"ok": True, "entries": 0}, "problems": [],
            "version": "v", "posture": True}


if __name__ == "__main__":
    unittest.main()
