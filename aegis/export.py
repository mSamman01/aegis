"""Export: a static copy of the dashboard for one run folder, as plain files.

``python -m aegis export --dir runs\\sample --out site\\sample`` writes the
pages ``serve`` shows - the incidents, each incident stage by stage, every
event, the audit log - as .html files with relative links and one
stylesheet, so the folder can be opened from disk or published as it is.
Every page carries the dashboard's Content-Security-Policy as a meta tag,
because a static host sends no headers, and no JavaScript, as served pages
carry none.

A copy shows what the run folder holds, real alerts included. Publish only
data you may publish (D8); the public demo is built from the synthetic
sample (aegis.demo).
"""

from __future__ import annotations

import shutil
from html.parser import HTMLParser
from pathlib import Path

from aegis import snapshot
from aegis.web import pages

WEB_DIR = Path(__file__).resolve().parent / "web"


def export_run(run_dir: Path | str, out: Path | str, *, label: str, notice: str | None = None,
               site_home: str | None = None, policy_path: Path | str | None = None, posture=None,
               posture_notice: str | None = None) -> int:
    """Write every page of one run folder into ``out``. Returns the number of pages.

    With ``posture`` (an aegis.posture.Loaded export), the posture page and one page per item too (D48).
    """
    from aegis import posture as posturing

    snap = snapshot.RunView(run_dir, policy_path).current()
    out = Path(out)
    out.mkdir(parents=True, exist_ok=True)
    extra = {"run_dir": label, "notice": notice, "site_home": site_home, "feed": None,
             "posture": posture is not None and posture.posture is not None}

    def with_header(data: dict) -> dict:
        data["header"] = dict(data["header"], **extra)
        return data

    written = 0

    def write(name: str, content: bytes) -> None:
        nonlocal written
        (out / name).write_bytes(content)
        written += 1

    links = pages.FileLinks()
    with pages.link_style(links):
        write(links.home(), pages.overview_page(with_header(snapshot.overview(snap))))
        write(links.audit(), pages.audit_page(with_header(snapshot.audit_view(snap)), True))
        for incident in snap.incidents:
            write(links.incident(incident.incident_id),
                  pages.incident_page(with_header(snapshot.incident_view(snap, incident))))
        for event in snap.events.values():
            write(links.event(event.event_id), pages.event_page(with_header(snapshot.event_view(snap, event))))
        if extra["posture"]:
            head = dict(snapshot.header(snap), **dict(extra, notice=posture_notice or notice))
            write(links.posture(), pages.posture_page(dict(posturing.overview_data(posture), header=head)))
            for slug in posture.slugs:
                write(links.posture_item(slug),
                      pages.posture_item_page(dict(posturing.item_data(posture, slug), header=head)))
    shutil.copyfile(WEB_DIR / "style.css", out / links.stylesheet())
    return written


class _Page(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.links: list[str] = []
        self.ids: set[str] = set()
        self.csp = False
        self.scripts = 0

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if "id" in attrs:
            self.ids.add(attrs["id"])
        if tag in ("a", "link") and attrs.get("href"):
            self.links.append(attrs["href"])
        if tag == "meta" and (attrs.get("http-equiv") or "").lower() == "content-security-policy":
            self.csp = attrs.get("content") == pages.STATIC_CSP
        if tag == "script":
            self.scripts += 1


def check_site(folder: Path | str) -> list[str]:
    """Problems in an exported folder: links to files or anchors that do not exist, pages without the
    Content-Security-Policy, any script. An empty list means the copy is whole."""
    folder = Path(folder)
    parsed: dict[Path, _Page] = {}
    for path in sorted(folder.rglob("*.html")):
        page = _Page()
        page.feed(path.read_text(encoding="utf-8"))
        parsed[path.resolve()] = page
    problems = []
    for path, page in parsed.items():
        where = path.relative_to(folder.resolve()).as_posix()
        if not page.csp:
            problems.append(f"{where}: no Content-Security-Policy")
        if page.scripts:
            problems.append(f"{where}: has a script")
        for href in page.links:
            if href in pages.EXTERNAL:
                continue
            target, _, anchor = href.partition("#")
            if href.startswith("/") or "://" in href:
                problems.append(f"{where}: link {href} does not work in a copy")
                continue
            file = (path.parent / target).resolve() if target else path
            if not file.exists():
                problems.append(f"{where}: link to {href}, which is not in the copy")
            elif anchor and file.suffix == ".html" and anchor not in parsed.get(file, _Page()).ids:
                problems.append(f"{where}: link to {href}, but that page has no #{anchor}")
    return problems
