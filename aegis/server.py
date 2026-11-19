"""The read-only dashboard and API:  python -m aegis serve --dir runs\\lab

Read-only by construction, not by promise:

  * It listens on 127.0.0.1 only. There is no option to change that.
  * It answers GET and nothing else; every other method gets 405.
  * Nothing it calls writes a file. It reads the run folder and the policy
    (aegis.snapshot) and renders them. It does not even add to the audit log,
    so looking at an incident leaves no trace in the evidence.
  * There is no approve or act button and no endpoint that could act.
    Approving and acting stay on the command line.

Evidence comes from monitored machines and may be written by an attacker, so
the pages carry no JavaScript at all, every response has a Content-Security-
Policy of ``default-src 'none'`` (only the one stylesheet is allowed), and
aegis.web.pages escapes every piece of text. The Host header must name
127.0.0.1 or localhost, so a web page elsewhere cannot read the dashboard
through the browser by pointing its own domain name at 127.0.0.1 (DNS
rebinding).

The posture pages (D48) read the newest export in the posture folder
(data/posture by default) the same way: read, rank, render, never write.

Pages:  /   /incident/<id>   /event/<id>   /audit   /posture   /posture/<item>
API:    /api/overview   /api/incident/<id>   /api/event/<id>   /api/audit   /api/posture   /api/posture/<item>
"""

from __future__ import annotations

import json
import os
import re
import socketserver
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

from aegis import posture as posturing
from aegis import snapshot
from aegis.contracts.decision import BANDS
from aegis.web import pages

LOOPBACK = "127.0.0.1"
DEFAULT_PORT = 8765
WEB_DIR = Path(__file__).resolve().parent / "web"
STATIC = {"/static/style.css": ("style.css", "text/css; charset=utf-8")}
HTML = "text/html; charset=utf-8"
JSON = "application/json; charset=utf-8"
TEXT = "text/plain; charset=utf-8"
AUDIT_PAGE_ROWS = 100
REFRESH_CHOICES = (10, 30, 60)

CSP = ("default-src 'none'; style-src 'self'; img-src 'none'; base-uri 'none'; form-action 'none'; "
       "frame-ancestors 'none'")
SECURITY_HEADERS = (
    ("Content-Security-Policy", CSP),
    ("X-Content-Type-Options", "nosniff"),
    ("X-Frame-Options", "DENY"),
    ("Referrer-Policy", "no-referrer"),
    ("Cache-Control", "no-store"),
    ("Cross-Origin-Resource-Policy", "same-origin"),
    ("Cross-Origin-Opener-Policy", "same-origin"),
)


class BadRequest(ValueError):
    pass


def route(view: snapshot.RunView, target: str,
          posture: posturing.PostureView | None = None) -> tuple[int, str, bytes]:
    """Answer one GET: ``(status, content type, body)``. Reads only."""
    parts = urlsplit(target)
    path = parts.path
    try:
        query = parse_qs(parts.query, max_num_fields=20)
    except ValueError as exc:
        raise BadRequest(str(exc)) from exc
    if path in STATIC:
        name, content_type = STATIC[path]
        return 200, content_type, (WEB_DIR / name).read_bytes()

    snap = view.current()
    head = snapshot.header(snap)
    api = path.startswith("/api/")
    if posture is not None:
        head["posture"] = True  # the Posture link in every page's header

    def page(data: dict) -> dict:
        if posture is not None:
            data["header"] = dict(data["header"], posture=True)
        return data

    if posture is not None and (path in ("/posture", "/api/posture") or path.startswith(("/posture/",
                                                                                         "/api/posture/"))):
        return _posture(posture, path, query, head, api)
    if path in ("/", "/api/overview"):
        min_band = _one(query, "min", lambda v: v in BANDS)
        host = _one(query, "host", lambda v: re.fullmatch(r"[A-Za-z0-9_\-]{1,32}", v) is not None)
        data = snapshot.overview(snap, min_band, host)
        if api:
            return 200, JSON, json_body(data)
        refresh = _one(query, "refresh", lambda v: v in {str(s) for s in REFRESH_CHOICES})
        return 200, HTML, pages.overview_page(page(data), int(refresh) if refresh else None)

    match = re.fullmatch(r"/(api/)?incident/([A-Za-z0-9\-]{1,40})", path)
    if match:
        incident = snap.find(match.group(2))
        if incident is None:
            successor = snap.successor(match.group(2))
            if successor:
                message = ("This incident has grown since this link was made: more events joined it, so it is now "
                           "a different set of evidence with a new id. An approval given for the old id does not "
                           "carry over.")
                if api:
                    return 404, JSON, json_body({"error": message, "now": successor})
                return 404, HTML, pages.message_page("This incident has grown", message, head,
                                                     (f"/incident/{successor}", f"Open {successor}"))
            return _not_found(api, head, "No incident has this id, or more than one starts with it.")
        data = snapshot.incident_view(snap, incident)
        return (200, JSON, json_body(data)) if api else (200, HTML, pages.incident_page(page(data)))

    match = re.fullmatch(r"/(api/)?event/(evt-[0-9a-f]{16})", path)
    if match:
        event = snap.events.get(match.group(2))
        if event is None:
            return _not_found(api, head, "No event with this id is in the events file.")
        data = snapshot.event_view(snap, event)
        return (200, JSON, json_body(data)) if api else (200, HTML, pages.event_page(page(data)))

    if path in ("/audit", "/api/audit"):
        show_all = api or query.get("all") == ["1"]
        data = snapshot.audit_view(snap, None if show_all else AUDIT_PAGE_ROWS)
        return (200, JSON, json_body(data)) if api else (200, HTML, pages.audit_page(page(data), show_all))

    return _not_found(api, head, "There is no page here.")


def _posture(posture: posturing.PostureView, path: str, query: dict, head: dict,
             api: bool) -> tuple[int, str, bytes]:
    loaded = posture.current()
    if path in ("/posture", "/api/posture"):
        area = _one(query, "area", lambda v: re.fullmatch(r"[a-z0-9\-]{1,60}", v) is not None)
        show = _one(query, "show", lambda v: v in posturing.SHOW)
        data = posturing.overview_data(loaded, area, show)
        return (200, JSON, json_body(data)) if api else (200, HTML, pages.posture_page(dict(data, header=head)))
    slug = path.split("/")[-1]
    data = posturing.item_data(loaded, slug) if path.count("/") == (3 if api else 2) and posturing.valid_slug(slug) \
        else None
    if data is None:
        return _not_found(api, head, "No posture item has this id in the newest export. The export may have "
                                     "changed since this link was made.")
    return (200, JSON, json_body(data)) if api else (200, HTML, pages.posture_item_page(dict(data, header=head)))


def _one(query: dict, name: str, valid) -> str | None:
    """A filter value if it is one of the allowed ones; anything else means no filter."""
    values = query.get(name)
    if not values or len(values) != 1 or not valid(values[0]):
        return None
    return values[0]


def _not_found(api: bool, head: dict, message: str) -> tuple[int, str, bytes]:
    if api:
        return 404, JSON, json_body({"error": message})
    return 404, HTML, pages.message_page("Not found", message, head)


def json_body(data) -> bytes:
    """JSON with <, > and & written as \\u escapes, so it can never be read as HTML."""
    text = json.dumps(data, ensure_ascii=True, indent=1)
    return (text.replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026") + "\n").encode("ascii")


class DashboardHandler(BaseHTTPRequestHandler):
    server_version = "Aegis"
    sys_version = ""
    timeout = 30  # a connection that sends nothing is closed, not kept forever
    error_content_type = TEXT
    error_message_format = "%(code)d %(message)s\n"

    def do_GET(self) -> None:
        if not self._host_allowed():
            port = self.server.server_address[1]
            self._send(403, TEXT, f"Open the dashboard at http://127.0.0.1:{port}/ - other host names are "
                                  "refused.\n".encode("ascii"))
            return
        try:
            status, content_type, body = route(self.server.view, self.path, self.server.posture)
        except BadRequest as exc:
            status, content_type, body = 400, TEXT, f"bad request: {exc}\n".encode("ascii", "replace")
        except Exception as exc:  # never show a traceback to the browser; the console gets it
            self.log_error("error answering %s: %r", self.path, exc)
            status, content_type, body = 500, TEXT, b"internal error; see the console running 'aegis serve'\n"
        self._send(status, content_type, body)

    def _refuse(self) -> None:
        self._send(405, TEXT, b"The Aegis dashboard is read-only: it answers GET and nothing else.\n", allow=True)

    do_POST = do_PUT = do_DELETE = do_PATCH = do_OPTIONS = do_HEAD = do_TRACE = do_CONNECT = _refuse

    def _host_allowed(self) -> bool:
        values = self.headers.get_all("Host") or []
        port = self.server.server_address[1]
        return len(values) == 1 and values[0].strip().lower() in (f"127.0.0.1:{port}", f"localhost:{port}")

    def _send(self, status: int, content_type: str, body: bytes, allow: bool = False) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        if allow:
            self.send_header("Allow", "GET")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def end_headers(self) -> None:
        for name, value in SECURITY_HEADERS:  # on every response, error pages included
            self.send_header(name, value)
        super().end_headers()

    def log_message(self, format: str, *args) -> None:
        if getattr(self.server, "quiet", False):
            return
        line = f"{self.log_date_time_string()}  {format % args}"
        sys.stderr.write(line.encode("ascii", "backslashreplace").decode("ascii") + "\n")


class DashboardServer(ThreadingHTTPServer):
    daemon_threads = True
    # On Windows SO_REUSEADDR would let another program bind the same port and
    # take over the dashboard's traffic; elsewhere it only allows a quick restart.
    allow_reuse_address = os.name != "nt"

    def __init__(self, view: snapshot.RunView, port: int, quiet: bool = False,
                 posture: posturing.PostureView | None = None):
        self.view = view
        self.posture = posture
        self.quiet = quiet
        super().__init__((LOOPBACK, port), DashboardHandler)

    def server_bind(self) -> None:
        # HTTPServer would look up the address's host name, which can stall on Windows.
        socketserver.TCPServer.server_bind(self)
        self.server_name, self.server_port = self.server_address[:2]

    def handle_error(self, request, client_address) -> None:
        if isinstance(sys.exc_info()[1], (ConnectionError, TimeoutError)):
            return  # the browser went away mid-answer
        super().handle_error(request, client_address)


def make_server(run_dir: Path | str, port: int = DEFAULT_PORT, policy_path: Path | str | None = None,
                quiet: bool = False, posture_dir: Path | str | None = None) -> DashboardServer:
    """A dashboard on 127.0.0.1:<port> for one run folder (port 0 picks a free one).

    With ``posture_dir``, the posture pages show the newest export in it (D48); without, there are none.
    """
    return DashboardServer(snapshot.RunView(run_dir, policy_path), port, quiet,
                           posturing.PostureView(posture_dir) if posture_dir is not None else None)
