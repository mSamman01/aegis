"""lab/aegis-posture: the read-only export of one agent's posture, run on the manager.

A local stand-in plays the Wazuh API and the indexer (plain http), and a
temporary folder plays the alert archive.
"""

import base64
import contextlib
import gzip
import importlib.machinery
import importlib.util
import io
import json
import os
import stat
import sys
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from unittest import mock
from urllib.parse import parse_qs, urlsplit

PROGRAM = Path(__file__).resolve().parent.parent / "lab" / "aegis-posture"
PASSWORD = "s3cret-api-password"
TOKEN = "TOKEN-123"


def load_program():
    loader = importlib.machinery.SourceFileLoader("aegis_posture_program", str(PROGRAM))
    spec = importlib.util.spec_from_loader("aegis_posture_program", loader)
    module = importlib.util.module_from_spec(spec)
    sys.dont_write_bytecode, before = True, sys.dont_write_bytecode
    try:
        loader.exec_module(module)
    finally:
        sys.dont_write_bytecode = before
    return module


CHECKS = [{"id": 26000 + n, "title": f"Ensure check {n}", "result": "failed" if n % 2 else "passed",
           "remediation": "Set it.", "rules": [{"type": "registry", "rule": "r:HKLM\\X -> V -> 1"}]}
          for n in range(5)]
VULNERABILITIES = [{"agent": {"id": "001"}, "package": {"name": "pip", "version": "25.0.1", "type": "pypi"},
                    "vulnerability": {"id": "CVE-2026-1703", "severity": "Low", "score": {"base": 2.6}}}]


class Stand(BaseHTTPRequestHandler):
    seen = []
    empty = False  # the inventory holds nothing for agent 001

    def log_message(self, *args):
        pass

    def answer(self, code, body):
        raw = body.encode() if isinstance(body, str) else json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(raw)

    def do_POST(self):
        url = urlsplit(self.path)
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length) if length else b""
        Stand.seen.append(("POST", url.path, self.headers.get("Authorization")))
        if url.path == "/security/user/authenticate":
            good = "Basic " + base64.b64encode(f"wazuh:{PASSWORD}".encode()).decode()
            return self.answer(200, TOKEN) if self.headers.get("Authorization") == good else \
                self.answer(401, {"title": "Unauthorized"})
        if url.path == "/wazuh-states-vulnerabilities-*/_search":
            query = json.loads(body)
            if "aggs" in query:
                return self.answer(200, {"hits": {"total": {"value": 1}, "hits": []}, "aggregations": {
                    "agents": {"buckets": [{"key": "002", "doc_count": 7}]}}})
            assert query["query"] == {"term": {"agent.id": "001"}}
            hits = [] if Stand.empty else [{"_source": VULNERABILITIES[0]}]
            return self.answer(200, {"hits": {"total": {"value": len(hits)}, "hits": hits}})
        self.answer(404, {"title": "no"})

    def do_GET(self):
        url = urlsplit(self.path)
        query = {k: v[0] for k, v in parse_qs(url.query).items()}
        Stand.seen.append(("GET", url.path, self.headers.get("Authorization")))
        if url.path == "/_cat/indices/wazuh-states-*":
            return self.answer(200, [{"index": "wazuh-states-vulnerabilities-lab", "docs.count": "7"}])
        if self.headers.get("Authorization") != "Bearer " + TOKEN:
            return self.answer(401, {"title": "Unauthorized"})
        if url.path == "/agents":
            return self.answer(200, {"data": {"affected_items": [
                {"id": "001", "name": "LAPTOP-TEST", "os": {"name": "Microsoft Windows 11"}}], "total_affected_items": 1}})
        offset, limit = int(query.get("offset", 0)), int(query.get("limit", 500))
        if url.path == "/sca/001":
            items = [{"policy_id": "cis_win11_enterprise", "name": "CIS Windows 11", "pass": 2, "fail": 3}]
        elif url.path == "/sca/001/checks/cis_win11_enterprise":
            items = CHECKS
        else:
            return self.answer(404, {"title": "no"})
        self.answer(200, {"data": {"affected_items": items[offset:offset + limit], "total_affected_items": len(items)}})


def alert(agent, cve, condition, when, package="Python 3.12.10 (64-bit)"):
    return json.dumps({"timestamp": when, "agent": {"id": agent}, "rule": {"id": "23504"},
                       "data": {"vulnerability": {"cve": cve, "status": "Active", "package": {
                           "name": package, "version": "3.12.10150.0", "condition": condition}}}})


class ExportTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.program = load_program()
        cls.program.PAGE = 2  # so the paging is exercised
        cls.server = HTTPServer(("127.0.0.1", 0), Stand)
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()
        cls.url = f"http://127.0.0.1:{cls.server.server_port}"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.root = Path(self.folder.name)
        alerts = self.root / "alerts"
        (alerts / "2026" / "Nov").mkdir(parents=True)
        (alerts / "alerts.json").write_text("\n".join([
            alert("001", "CVE-2026-6019", "Package less than 3.13.14", "2026-11-18T10:00:00.000+0000"),
            alert("002", "CVE-2026-9999", "Package less than 9", "2026-11-18T10:00:00.000+0000"),
            json.dumps({"agent": {"id": "001"}, "rule": {"id": "5710"}, "data": {}}),
            '{"broken "vulnerability" "cve"',
        ]) + "\n", encoding="utf-8")
        with gzip.open(alerts / "2026" / "Nov" / "ossec-alerts-17.json.gz", "wt", encoding="utf-8") as handle:
            handle.write(alert("001", "CVE-2026-6019", "Package less than 3.13.14", "2026-11-17T10:00:00.000+0000") + "\n")
            handle.write(alert("001", "CVE-2026-3087", "Package less than or equal to 3.14.4",
                               "2026-11-17T11:00:00.000+0000") + "\n")
        self.out = self.root / "export.json"
        self.args = ["--agent", "001", "--out", str(self.out), "--api-url", self.url, "--indexer-url", self.url,
                     "--alerts", str(alerts)]

    def tearDown(self):
        self.folder.cleanup()

    def run_program(self, password=PASSWORD):
        said = io.StringIO()
        with mock.patch.dict(os.environ, {"AEGIS_API_PASSWORD": password}), contextlib.redirect_stdout(said), \
                contextlib.redirect_stderr(io.StringIO()):
            code = self.program.main(self.args)
        return code, said.getvalue(), json.loads(self.out.read_text(encoding="utf-8"))

    def test_everything_is_collected_as_wazuh_gives_it(self):
        code, said, export = self.run_program()
        self.assertEqual(export["problems"], ["1 vulnerability alert lines were not valid JSON and were left out"])
        self.assertEqual(code, 1)  # a problem is reported, never hidden
        self.assertEqual(export["agent"]["name"], "LAPTOP-TEST")
        self.assertEqual([c["id"] for c in export["sca_checks"]["cis_win11_enterprise"]], [c["id"] for c in CHECKS])
        self.assertEqual(export["vulnerabilities"], VULNERABILITIES)
        bounds = {(a["vulnerability"]["cve"], a["vulnerability"]["package"]["condition"])
                  for a in export["vulnerability_alerts"]}
        self.assertEqual(bounds, {("CVE-2026-6019", "Package less than 3.13.14"),
                                  ("CVE-2026-3087", "Package less than or equal to 3.14.4")})  # agent 001 only
        newest = next(a for a in export["vulnerability_alerts"] if a["vulnerability"]["cve"] == "CVE-2026-6019")
        self.assertTrue(newest["timestamp"].startswith("2026-11-18"))  # the same alert twice: the newest kept
        self.assertIn("SCA          1 policies, 5 checks, 2 failed", said)

    def test_the_file_is_private_and_holds_no_password(self):
        self.run_program()
        text = self.out.read_text(encoding="utf-8")
        self.assertNotIn(PASSWORD, text)
        self.assertNotIn(TOKEN, text)
        if os.name == "posix":
            self.assertEqual(stat.S_IMODE(self.out.stat().st_mode), 0o600)

    def test_only_reads(self):
        Stand.seen.clear()
        self.run_program()
        self.assertEqual({m for m, _, _ in Stand.seen}, {"GET", "POST"})
        self.assertEqual({(m, p) for m, p, _ in Stand.seen if m == "POST"},
                         {("POST", "/security/user/authenticate"), ("POST", "/wazuh-states-vulnerabilities-*/_search")})

    def test_a_wrong_password_is_a_problem_not_a_crash(self):
        code, said, export = self.run_program(password="wrong")
        self.assertEqual(code, 1)
        self.assertTrue(any(p.startswith("SCA not read: ") and "HTTP 401" in p and "not the login password" in p
                            for p in export["problems"]))
        self.assertEqual(export["vulnerabilities"], VULNERABILITIES)  # the rest is still collected
        self.assertIn("PROBLEM", said)

    def test_an_unreachable_indexer_is_a_problem(self):
        self.args[self.args.index("--indexer-url") + 1] = "http://127.0.0.1:9"
        _, _, export = self.run_program()
        self.assertTrue(any(p.startswith("vulnerability inventory not read") for p in export["problems"]))

    def test_a_second_run_replaces_the_first_file(self):
        self.run_program(password="wrong")
        code, _, export = self.run_program()
        self.assertEqual(export["agent"]["name"], "LAPTOP-TEST")
        self.assertEqual([p.name for p in self.root.iterdir() if p.name.startswith(".aegis-posture-")], [])

    def test_an_empty_inventory_is_explained(self):
        Stand.empty = True
        try:
            _, _, export = self.run_program()
        finally:
            Stand.empty = False
        problem = next(p for p in export["problems"] if p.startswith("vulnerability inventory: no record"))
        self.assertIn("wazuh-states-vulnerabilities-lab (7 records)", problem)
        self.assertIn("agents in wazuh-states-vulnerabilities-*: 002 (7)", problem)

    def test_a_bad_agent_id_is_refused(self):
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(self.program.main(["--agent", "1; rm -rf /"]), 2)


if __name__ == "__main__":
    unittest.main()
