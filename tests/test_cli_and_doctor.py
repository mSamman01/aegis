"""The command line and the environment checks."""

import contextlib
import io
import json
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

from aegis import doctor
from aegis.cli import main
from aegis.store import read_events

SAMPLE = Path(__file__).resolve().parent.parent / "data" / "samples" / "wazuh_alerts_sample.jsonl"


def run_cli(*args):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = main([str(a) for a in args])
    return code, out.getvalue(), err.getvalue()


class FakeOllama:
    """A tiny local web server that answers /api/tags like Ollama does."""

    def __init__(self, body, status=200):
        payload = body if isinstance(body, bytes) else json.dumps(body).encode()

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(status if self.path == "/api/tags" else 404)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(payload)

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


class IngestCommandTests(unittest.TestCase):
    def test_ingest_writes_events_and_prints_a_summary(self):
        with tempfile.TemporaryDirectory() as folder:
            out_path = Path(folder) / "events.jsonl"
            code, out, err = run_cli("ingest", SAMPLE, "--out", out_path)
            self.assertEqual(code, 0, err)
            self.assertEqual(len(read_events(out_path)), 18)
        self.assertIn("18 found, 18 normalized, 0 rejected", out)
        self.assertIn("2026-11-14 05:02:11  to  2026-11-14 18:15:40", out)
        self.assertIn("Delayed   3 of 18 events", out)
        self.assertIn("longest delay 12 h 00 min", out)
        self.assertIn("aegis-victim (agent 002)", out)
        self.assertIn("authentication", out)
        self.assertTrue(out.isascii())

    def test_min_level(self):
        with tempfile.TemporaryDirectory() as folder:
            out_path = Path(folder) / "events.jsonl"
            code, out, _ = run_cli("ingest", SAMPLE, "--out", out_path, "--min-level", "10")
            self.assertEqual(code, 0)
            self.assertEqual(len(read_events(out_path)), 3)
        self.assertIn("15 below min level", out)
        self.assertNotIn("Delayed", out)

    def test_rejected_alerts_are_listed(self):
        with tempfile.TemporaryDirectory() as folder:
            bad = Path(folder) / "alerts.json"
            bad.write_text(SAMPLE.read_text(encoding="utf-8") + "{oops\n", encoding="utf-8")
            code, out, _ = run_cli("ingest", bad, "--out", Path(folder) / "events.jsonl")
        self.assertEqual(code, 0)
        self.assertIn("1 rejected", out)
        self.assertIn("line 19: not valid JSON", out)

    def test_missing_file_is_a_clean_error(self):
        with tempfile.TemporaryDirectory() as folder:
            code, out, err = run_cli("ingest", Path(folder) / "nope.json", "--out", Path(folder) / "e.jsonl")
        self.assertEqual(code, 2)
        self.assertIn("file not found", err)
        self.assertEqual(out, "")

    def test_undecodable_file_is_a_clean_error(self):
        with tempfile.TemporaryDirectory() as folder:
            bad = Path(folder) / "alerts.json"
            bad.write_bytes(b'{"timestamp": "\x80\x81"}')
            code, _, err = run_cli("ingest", bad, "--out", Path(folder) / "e.jsonl")
        self.assertEqual(code, 2)
        self.assertIn("cannot read", err)


class DoctorTests(unittest.TestCase):
    def test_python_version_check(self):
        self.assertEqual(doctor.check_python((3, 12, 10)).status, doctor.OK)
        self.assertEqual(doctor.check_python((3, 10, 0)).status, doctor.OK)
        self.assertEqual(doctor.check_python((3, 9, 18)).status, doctor.FAIL)

    def test_ollama_models_are_listed(self):
        body = {"models": [
            {"name": "qwen3:8b", "size": 5200000000},
            {"name": "qwen3:4b", "size": 2500000000},
        ]}
        with FakeOllama(body) as fake:
            check = doctor.check_ollama(fake.url)
        self.assertEqual(check.status, doctor.OK)
        self.assertIn("2 model(s)", check.message)
        self.assertIn("qwen3:8b (5.2 GB)", check.message)
        self.assertIn("qwen3:4b (2.5 GB)", check.message)

    def test_ollama_without_models_is_a_warning(self):
        with FakeOllama({"models": []}) as fake:
            self.assertEqual(doctor.check_ollama(fake.url).status, doctor.WARN)

    def test_ollama_unexpected_answers_fail(self):
        with FakeOllama(b"<html>not ollama</html>") as fake:
            self.assertEqual(doctor.check_ollama(fake.url).status, doctor.FAIL)
        with FakeOllama({"something": "else"}) as fake:
            self.assertEqual(doctor.check_ollama(fake.url).status, doctor.FAIL)
        with FakeOllama({"error": "boom"}, status=500) as fake:
            self.assertEqual(doctor.check_ollama(fake.url).status, doctor.FAIL)

    def test_ollama_not_running_fails_fast(self):
        with FakeOllama({"models": []}) as fake:
            dead_url = fake.url  # the port is closed again after the block
        check = doctor.check_ollama(dead_url, timeout=1)
        self.assertEqual(check.status, doctor.FAIL)
        self.assertIn("not reachable", check.message)


if __name__ == "__main__":
    unittest.main()
