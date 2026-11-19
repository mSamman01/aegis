"""HTML pages for the dashboard, built from the plain data in aegis.snapshot.

There is no JavaScript anywhere, and text is escaped by default: ``tag()``
escapes every piece of text it is given, and only markup that ``tag()``
itself built passes through as markup. Text from a monitored machine can
therefore only ever become text on the page. The Content-Security-Policy the
server sends (``default-src 'none'``) is the second wall: a browser would not
run a script even if one got onto a page.

Invisible and control characters - bidirectional overrides, zero-width
characters, Unicode tag characters that can hide instructions from a human
reader - are shown as visible codes such as \\u202e, so what a person reads is
what the evidence says.
"""

from __future__ import annotations

import contextlib
import html
import json
import re
from typing import Any

from aegis.contracts.decision import BANDS

STYLESHEET = "/static/style.css"
# Content-Security-Policy for an exported page, which no server sends headers for (frame-ancestors
# cannot be set this way; a static page offers nothing to frame-jack anyway).
STATIC_CSP = "default-src 'none'; style-src 'self'; img-src 'none'; base-uri 'none'; form-action 'none'"
INLINE_RAW_LIMIT = 150  # bigger incidents link to each raw alert instead of embedding them all

_INVISIBLE = re.compile(
    "[\x00-\x08\x0b-\x1f\x7f-\x9f­͏؜ᅟᅠ឴឵᠋-᠏"
    "​-‏ -‮⁠-⁯ㅤ︀-️﻿ﾠ￰-￻"
    "\ud800-\udfff\U0001d173-\U0001d17a\U000e0000-\U000e0fff]"
)
_TAGS = frozenset(
    "html head body meta title link header nav main footer section div p span strong em small code pre a "
    "h1 h2 h3 h4 table thead tbody tr th td ul ol li dl dt dd details summary meter br".split()
)
_VOID = frozenset({"meta", "link", "br"})
_ATTRS = frozenset({"class", "id", "href", "title", "colspan", "min", "max", "low", "high", "optimum",
                    "value", "open", "lang", "charset", "name", "content", "rel", "http-equiv"})
# A path on this server, an anchor on this page, or (in an exported copy) a relative file a
# folder or two up or down. "//host" would leave the site, so a path may not start with two slashes.
_HREF = re.compile(r"^(/(?!/)[A-Za-z0-9/_.\-]*(\?[A-Za-z0-9_=&\-]*)?|#[A-Za-z][A-Za-z0-9_\-]*"
                   r"|(\.\./){0,3}([A-Za-z0-9][A-Za-z0-9_\-]*/){0,2}[A-Za-z0-9][A-Za-z0-9._\-]*\.(html|css)"
                   r"(#[A-Za-z][A-Za-z0-9_\-]*)?)$")
# The only addresses outside Aegis a page may link to: fixed here, never taken from data.
EXTERNAL = frozenset({"https://github.com/mSamman01/aegis",
                      "https://github.com/mSamman01/aegis/blob/main/docs/eval-results.md",
                      "https://github.com/mSamman01/aegis/blob/main/DECISIONS.md",
                      "https://github.com/CS-Abuhelal/sentinel"})
_ID = re.compile(r"^[A-Za-z][A-Za-z0-9_\-]*$")
_SAFE_ARG = re.compile(r"^[A-Za-z0-9._@:\-]+$")  # can be pasted into a shell as it is
_AGENT = re.compile(r"^[A-Za-z0-9_\-]{1,32}$")


class Markup(str):
    """HTML that is already safe: made by ``tag()`` or ``text()``, never by hand."""

    __slots__ = ()


def text(value: Any) -> Markup:
    """Escape text for HTML, showing invisible and control characters as codes."""
    s = "" if value is None else str(value)
    out, last = [], 0
    for match in _INVISIBLE.finditer(s):
        out.append(html.escape(s[last:match.start()], quote=True))
        point = ord(match.group())
        code = f"\\u{point:04x}" if point <= 0xFFFF else f"\\U{point:08x}"
        out.append(f'<span class="hidden-char" title="invisible or control character">{code}</span>')
        last = match.end()
    out.append(html.escape(s[last:], quote=True))
    return Markup("".join(out))


def _render(child: Any) -> str:
    if child is None or child is False:
        return ""
    if isinstance(child, Markup):
        return child
    if isinstance(child, (list, tuple)):
        return "".join(_render(c) for c in child)
    return text(child)


def frag(*children: Any) -> Markup:
    return Markup(_render(children))


def tag(element: str, /, *children: Any, **attrs: Any) -> Markup:
    """One element. Tag and attribute names are fixed in code; every value is escaped."""
    if element not in _TAGS:
        raise ValueError(f"tag not allowed: {element}")
    out = ["<", element]
    for key, value in attrs.items():
        key = key.rstrip("_").replace("_", "-")
        if key not in _ATTRS:
            raise ValueError(f"attribute not allowed: {key}")
        if value is None or value is False:
            continue
        if key == "href" and not (_HREF.match(str(value)) or str(value) in EXTERNAL):
            raise ValueError(f"not an internal link: {value!r}")
        if key == "id" and not _ID.match(str(value)):
            raise ValueError(f"not a plain id: {value!r}")
        out.append(f" {key}" if value is True else f' {key}="{html.escape(str(value), quote=True)}"')
    out.append(">")
    if element in _VOID:
        if children:
            raise ValueError(f"{element} cannot have content")
        return Markup("".join(out))
    out += [_render(children), f"</{element}>"]
    return Markup("".join(out))


# --------------------------------------------------------------------------
# Where links point: paths on the server, or files in an exported folder
# --------------------------------------------------------------------------

class Links:
    """Links for pages served by ``aegis serve``."""

    static = False

    def home(self) -> str:
        return "/"

    def audit(self, everything: bool = False) -> str:
        return "/audit?all=1" if everything else "/audit"

    def incident(self, incident_id: str) -> str:
        return f"/incident/{incident_id}"

    def event(self, event_id: str) -> str:
        return f"/event/{event_id}"

    def posture(self, query: str = "") -> str:
        return "/posture" + (f"?{query}" if query else "")

    def posture_item(self, slug: str) -> str:
        return f"/posture/{slug}"

    def stylesheet(self) -> str:
        return STYLESHEET


class FileLinks(Links):
    """Links for a folder of exported pages (``aegis export``): plain relative file names."""

    static = True

    def home(self) -> str:
        return "index.html"

    def audit(self, everything: bool = False) -> str:
        return "audit.html"

    def incident(self, incident_id: str) -> str:
        return f"incident-{incident_id}.html"

    def event(self, event_id: str) -> str:
        return f"event-{event_id}.html"

    def posture(self, query: str = "") -> str:
        return "posture.html"  # a copy has one posture page: no filters

    def posture_item(self, slug: str) -> str:
        return f"posture-{slug}.html"

    def stylesheet(self) -> str:
        return "style.css"


_links: Links = Links()


@contextlib.contextmanager
def link_style(links: Links):
    """Render pages with these links (the export uses FileLinks)."""
    global _links
    before, _links = _links, links
    try:
        yield
    finally:
        _links = before


# --------------------------------------------------------------------------
# Small pieces
# --------------------------------------------------------------------------

def _when(iso: str | None, ms: bool = False) -> str:
    match = re.match(r"^(\d{4}-\d{2}-\d{2})T(\d{2}:\d{2}:\d{2})(\.\d{3})?", iso or "")
    if not match:
        return iso or ""
    return f"{match.group(1)} {match.group(2)}" + ((match.group(3) or "") if ms else "")


def _clock(iso: str, with_date: bool) -> str:
    full = _when(iso, ms=True)
    return full if with_date else full[11:]


def _times(n: int) -> str:
    return {1: "once", 2: "twice"}.get(n, f"{n} times")


def _duration(seconds: int | None) -> str:
    seconds = int(seconds or 0)
    if seconds < 60:
        return f"{seconds} s"
    minutes = seconds // 60
    return f"{minutes // 60} h {minutes % 60:02d} min" if minutes >= 60 else f"{minutes} min"


def _band(band: str) -> Markup:
    return tag("span", band.upper(), class_=f"band band-{band}" if band in BANDS else "band")


_OUTCOME_TEXT = {"needs_approval": "needs approval", "allow": "allow", "deny": "deny"}
_STATUS_TEXT = {"done": "done", "failed": "FAILED", "approved": "approved, not run yet",
                "waiting": "waiting for a human", "denied": "denied", "allowed": "allowed"}


def _outcome(outcome: str) -> Markup:
    return tag("span", _OUTCOME_TEXT.get(outcome, outcome), class_=f"chip outcome-{outcome}")


def _status(status: str) -> Markup:
    return tag("span", _STATUS_TEXT.get(status, status), class_=f"chip status-{status}")


def _ai_label(label: str | None) -> Markup:
    if not label:
        return tag("span", "not asked", class_="muted")
    return tag("span", label, class_=f"chip ai-chip label-{label}", title="AI-written")


def _badge(kind: str) -> Markup:
    words = {"code": "worked out by code", "ai": "AI-written", "human": "human sign-off, carried out by code",
             "evidence": "from the monitored machine - untrusted text"}
    return tag("span", words[kind], class_=f"badge badge-{kind}")


def _meter(score: int) -> Markup:
    return tag("meter", min="0", max="100", low="25", high="75", optimum="0", value=str(score),
               title=f"risk {score} of 100")


def _refs(refs: list[dict], limit: int = 40) -> Markup:
    parts = []
    for ref in refs[:limit]:
        if ref["label"]:
            parts.append(tag("a", ref["label"], href=f"#{ref['label']}", class_="ref"))
        elif ref["known"]:
            parts.append(tag("a", ref["event_id"], href=_links.event(ref["event_id"]), class_="ref ref-outside",
                             title="an event outside this incident"))
        else:
            parts.append(tag("span", f"{ref['event_id']} (not in the events file)", class_="ref ref-missing"))
    if len(refs) > limit:
        parts.append(tag("span", f"+{len(refs) - limit} more", class_="muted"))
    return tag("span", [frag(p, " ") for p in parts], class_="refs")


def _dl(rows: list[tuple[str, Any]], cls: str = "fields") -> Markup:
    items = [frag(tag("dt", name), tag("dd", value)) for name, value in rows if value not in (None, "", [], ())]
    return tag("dl", items, class_=cls) if items else frag()


def _cmd_dir(run_dir: str) -> str | None:
    """`` --dir <folder>`` for a command hint, or None if the folder is not safe to paste."""
    if run_dir in ("runs", "runs/", "runs\\"):
        return ""
    if re.fullmatch(r"[A-Za-z0-9_.:\\/\-]+", run_dir):
        return f" --dir {run_dir}"
    if re.fullmatch(r"[A-Za-z0-9 _.:\\/\-]+", run_dir):
        return f' --dir "{run_dir}"'
    return None


def _command(*parts: str, run_dir: str) -> Markup:
    """A command to type, shown only when every part is safe to paste into a shell."""
    folder = _cmd_dir(run_dir)
    if folder is None or not all(_SAFE_ARG.match(p) or p == "<your name>" for p in parts[3:]):
        return tag("p", "Type the command yourself: a value here is not safe to paste into a shell.",
                   class_="muted")
    return tag("pre", " ".join(parts) + folder, class_="command")


# --------------------------------------------------------------------------
# The page frame
# --------------------------------------------------------------------------

def document(title: str, header: dict, body: Any, refresh: int | None = None) -> bytes:
    head = tag(
        "head",
        tag("meta", charset="utf-8"),
        tag("meta", http_equiv="Content-Security-Policy", content=STATIC_CSP) if _links.static else None,
        tag("meta", name="viewport", content="width=device-width, initial-scale=1"),
        tag("meta", name="referrer", content="no-referrer"),
        tag("meta", http_equiv="refresh", content=str(int(refresh))) if refresh else None,
        tag("title", title),
        tag("link", rel="stylesheet", href=_links.stylesheet()),
    )
    page = tag("html", head, tag("body", _top(header), _notice(header), _problems(header), tag("main", body),
                                  _footer(header)), lang="en")
    return ("<!DOCTYPE html>\n" + page + "\n").encode("utf-8", "replace")


def _top(header: dict) -> Markup:
    audit = header["audit"]
    if audit["ok"]:
        audit_text = f"{audit['entries']} entries, chain intact" if audit["entries"] else "no entries yet"
    else:
        audit_text = f"BROKEN after entry {audit['entries']}"
    return tag(
        "header",
        tag("div", tag("a", "Aegis", href=header.get("site_home") or _links.home(), class_="brand"), " ",
            tag("span", "read-only", class_="badge badge-ro"), class_="brand-line"),
        tag("nav", tag("a", "Incidents", href=_links.home()), " ", tag("a", "Audit log", href=_links.audit()),
            frag(" ", tag("a", "Posture", href=_links.posture())) if header.get("posture") else None),
        tag("div",
            "run folder ", tag("code", header["run_dir"]),
            " · policy ", tag("code", header["policy"]["id"] or "not read"),
            " · audit log ", tag("a", audit_text, href=_links.audit(), class_="ok" if audit["ok"] else "bad"),
            _feed_fact(header.get("feed")),
            class_="facts"),
        class_="top",
    )


def _feed_fact(feed: dict | None) -> Markup:
    if not feed:
        return frag()
    age = feed["age_seconds"]
    when = f"{_duration(age)} ago" if age is not None else "never"
    words = {
        "connected": (f"connected to {feed['manager']} (last contact {when})", "ok"),
        "silent": (f"no contact for {_duration(age) if age is not None else 'a while'} - is watch still running?",
                   "bad"),
        "reconnecting": (f"reconnecting to {feed['manager']}" + (f" ({feed['message']})" if feed["message"] else ""),
                         "bad"),
        "stopped": (f"stopped (last contact {when})", "muted"),
    }
    text, cls = words.get(feed["state"], (f"state unknown ({feed['status']})", "bad"))
    return frag(" · live feed ", tag("span", text, class_=cls))


def _notice(header: dict) -> Markup:
    """A banner for exported copies, saying what the reader is looking at."""
    if not header.get("notice"):
        return frag()
    home = header.get("site_home")
    return tag("section", tag("p", header["notice"], " ",
                              tag("a", "About this demo", href=home) if home else None), class_="notice")


def _problems(header: dict) -> Markup:
    if not header["problems"]:
        return frag()
    return tag("section", tag("h2", "Not everything could be read"),
               tag("ul", [tag("li", p) for p in header["problems"]]), class_="problems")


def _footer(header: dict) -> Markup:
    if _links.static:
        said = ("A static copy of Aegis's read-only dashboard, made with python -m aegis export. Nothing on these "
                "pages can approve or run an action; that is done on the command line, with python -m aegis "
                "approve and act.")
    else:
        said = ("Read-only: nothing on these pages can approve or run an action. That is done on the command "
                "line, with python -m aegis approve and act. Decisions are worked out again from the events and "
                "the current policy whenever the data changes.")
    return tag(
        "footer",
        tag("p", said),
        tag("p", f"data version {header['version']}", class_="muted"),
    )


# --------------------------------------------------------------------------
# Incidents list
# --------------------------------------------------------------------------

def overview_page(data: dict, refresh: int | None = None) -> bytes:
    counts, filters = data["counts"], data["filters"]
    bands = counts["bands"]
    tiles = tag(
        "div",
        _tile("Incidents", counts["incidents"], f"from {counts['events']} events"),
        [_tile(band.capitalize(), bands[band], "risk band", f"tile band-{band}") for band in reversed(BANDS)],
        _tile("Waiting for a human", counts["waiting_for_approval"], "approve on the command line"),
        _tile("Actions carried out", counts["done"],
              f"{counts['failed']} failed" if counts["failed"] else "on the lab host"),
        _tile("AI verdicts", counts["verdicts"], "saved; not used by the score", "tile tile-ai"),
        class_="tiles",
    )
    body = [
        tag("h1", "Incidents"),
        tag("p", "Most dangerous first. Risk is worked out by fixed rules from each incident's evidence and the "
                 "current policy; the AI's verdict is shown beside it and is not part of it.", class_="lead"),
        tiles,
        _filters(data, refresh) if not _links.static else None,
        _incident_table(data["incidents"], counts),
    ]
    return document("Aegis - incidents", data["header"], body, refresh)


def _tile(name: str, value: Any, note: str | None, cls: str = "tile") -> Markup:
    return tag("div", tag("div", value, class_="tile-value"), tag("div", name, class_="tile-name"),
               tag("div", note, class_="tile-note") if note else None, class_=cls)


def _query(min_band: str | None, host: str | None, refresh: int | None) -> str:
    parts = [f"min={min_band}" if min_band else "", f"host={host}" if host else "",
             f"refresh={refresh}" if refresh else ""]
    joined = "&".join(p for p in parts if p)
    return "/" + (f"?{joined}" if joined else "")


def _filters(data: dict, refresh: int | None) -> Markup:
    current_band, current_host = data["filters"]["min_band"], data["filters"]["host"]

    def link(label: str, href: str, on: bool) -> Markup:
        return tag("a", label, href=href, class_="on" if on else None)

    band_links = [link("all", _query(None, current_host, refresh), current_band is None)]
    band_links += [link(f"{band} and above", _query(band, current_host, refresh), current_band == band)
                   for band in ("medium", "high", "critical")]
    host_links = [link("all", _query(current_band, None, refresh), current_host is None)]
    host_links += [link(f"{h['name']} ({h['mode']})", _query(current_band, h["agent_id"], refresh),
                        current_host == h["agent_id"])
                   for h in data["hosts"] if _AGENT.match(h["agent_id"])]
    refresh_links = [link("off", _query(current_band, current_host, None), not refresh)]
    refresh_links += [link(f"every {s} s", _query(current_band, current_host, s), refresh == s) for s in (10, 30)]
    return tag(
        "div",
        tag("div", tag("span", "Risk", class_="filter-name"), [frag(" ", a) for a in band_links]),
        tag("div", tag("span", "Host", class_="filter-name"), [frag(" ", a) for a in host_links]),
        tag("div", tag("span", "Reload", class_="filter-name"), [frag(" ", a) for a in refresh_links]),
        class_="filters",
    )


def _incident_table(rows: list[dict], counts: dict) -> Markup:
    if not rows:
        message = "No incidents yet." if not counts["incidents"] else "No incidents match these filters."
        return tag("p", message, class_="empty")
    head = tag("thead", tag("tr", [tag("th", h) for h in (
        "Risk", "Host", "Level", "Events", "First seen (UTC)", "Lasted", "Incident", "Actions", "AI said")]))
    body = []
    for row in rows:
        risk = row["risk"]
        risk_cell = (frag(_meter(risk["score"]), " ", tag("strong", risk["score"]), " ", _band(risk["band"]))
                     if risk else tag("span", "not decided", class_="bad", title=row["problem"] or ""))
        actions = tag("ul", [tag("li", f"{a['action']} {a['target']} ", _status(a["status"]))
                             for a in row["actions"]], class_="plain") if row["actions"] else tag("span", "-",
                                                                                                  class_="muted")
        body.append(tag(
            "tr",
            tag("td", risk_cell, class_="nowrap"),
            tag("td", row["host"]["name"], tag("br"), tag("small", f"agent {row['host']['agent_id']}, "
                                                                     f"{row['host_mode']}", class_="muted")),
            tag("td", f"L{row['max_level']}", class_="num"),
            tag("td", row["event_count"], class_="num"),
            tag("td", _when(row["first_seen"]), class_="nowrap"),
            tag("td", _duration(row["duration_seconds"]), class_="nowrap"),
            tag("td", tag("a", row["title"], href=_links.incident(row["incident_id"])), tag("br"),
                tag("small", row["incident_id"], class_="muted mono")),
            tag("td", actions),
            tag("td", _ai_label(row["ai"]["label"])),
            class_=f"row-{risk['band']}" if risk else None,
        ))
    shown = "" if counts["shown"] == counts["incidents"] else f" (showing {counts['shown']} of {counts['incidents']})"
    return frag(tag("p", f"{counts['shown']} incidents{shown}", class_="muted"),
                tag("table", head, tag("tbody", body), class_="incidents"))


# --------------------------------------------------------------------------
# One incident, stage by stage
# --------------------------------------------------------------------------

def incident_page(data: dict) -> bytes:
    inc = data["incident"]
    short = inc["incident_id"][4:12]
    run_dir = "runs" if _links.static else data["header"]["run_dir"]  # a reader of a copy has their own folder
    events = data["events"]
    multi_day = bool(events) and _when(events[0]["timestamp"])[:10] != _when(events[-1]["timestamp"])[:10]
    body = [
        tag("p", tag("a", "← all incidents", href=_links.home()), class_="back"),
        tag("h1", inc["title"]),
        tag("p", tag("code", inc["incident_id"]), class_="muted"),
        tag("p", data["problem"], class_="problem-line") if data["problem"] else None,
        _summary(data),
        tag("nav", [tag("a", name, href=f"#{anchor}") for anchor, name in (
            ("ingest", "1 Ingest"), ("correlate", "2 Correlate"), ("investigate", "3 Investigate (AI)"),
            ("decide", "4 Decide"), ("act", "5 Act"), ("evidence", "Evidence"))], class_="stages"),
        _stage_ingest(data),
        _stage_correlate(data),
        _stage_investigate(data, short, run_dir),
        _stage_decide(data),
        _stage_act(data, short, run_dir),
        _evidence(events, multi_day, inline_raw=len(events) <= INLINE_RAW_LIMIT),
    ]
    return document(f"Aegis - {inc['incident_id']}", data["header"], body)


def _summary(data: dict) -> Markup:
    inc, dec, inv = data["incident"], data["decide"], data["investigate"]
    host = inc["host"]
    risk = (frag(_meter(dec["risk"]["score"]), " ", tag("strong", f"{dec['risk']['score']} / 100"), " ",
                 _band(dec["risk"]["band"])) if dec else tag("span", "not decided", class_="bad"))
    actions = (tag("ul", [tag("li", f"{a['action']} {a['target']} ", _status(a["status"])) for a in dec["actions"]],
                   class_="plain") if dec and dec["actions"] else "none")
    verdict = inv["verdict"]
    return _dl([
        ("Host", f"{host['name']} (agent {host['agent_id']}), {inc['host_mode']} host"),
        ("When (UTC)", f"{_when(inc['first_seen'])}  to  {_when(inc['last_seen'])}  ({_duration(inc['duration_seconds'])})"),
        ("Events", f"{len(inc['event_ids'])}, highest rule level {inc['max_level']}"),
        ("Risk", risk),
        ("Actions", actions),
        ("AI verdict", frag(_ai_label(verdict["label"] if verdict else None),
                            " " if verdict else "", _badge("ai") if verdict else "")),
    ], cls="fields summary")


def _stage(number: int, anchor: str, title: str, kind: str, *content: Any) -> Markup:
    return tag("section", tag("h2", tag("span", number, class_="num"), " ", title, " ", _badge(kind)),
               *content, id=anchor, class_=f"stage stage-{kind}")


def _stage_ingest(data: dict) -> Markup:
    inc, ingest = data["incident"], data["ingest"]
    host = inc["host"]
    rules = tag("table", tag("thead", tag("tr", [tag("th", h) for h in ("Count", "Level", "Rule", "Description")])),
                tag("tbody", [tag("tr", tag("td", r["count"], class_="num"), tag("td", f"L{r['level']}", class_="num"),
                                  tag("td", tag("code", r["rule_id"])), tag("td", r["description"]))
                              for r in ingest["rules"]]), class_="compact")
    delayed = ingest["delayed"]
    return _stage(
        1, "ingest", "Ingest: what Wazuh reported", "code",
        tag("p", f"{ingest['event_count']} alerts from agent {host['agent_id']} ({host['name']}), turned into "
                 "events once, at ingest. Times are when the activity happened, in UTC. Each event keeps the "
                 "untouched alert; see Evidence below."),
        tag("p", f"Only {ingest['events_found']} of the {ingest['event_count']} events are in the events file.",
            class_="bad") if ingest["events_found"] < ingest["event_count"] else None,
        tag("p", f"{delayed['count']} events reached Wazuh more than {delayed['threshold_minutes']} min after they "
                 f"happened (longest delay {_duration(delayed['longest_seconds'])}).")
        if delayed["count"] else None,
        rules,
    )


def _stage_correlate(data: dict) -> Markup:
    inc, corr = data["incident"], data["correlate"]
    reasons = tag("table", tag("thead", tag("tr", [tag("th", h) for h in ("Why joined", "Links", "What they share")])),
                  tag("tbody", [tag("tr", tag("td", r["text"]), tag("td", r["count"], class_="num"),
                                    tag("td", [frag(tag("code", v), f" ×{c}  ") for v, c in r["values"]],
                                        tag("span", f"+{r['more_values']} more", class_="muted")
                                        if r["more_values"] else None))
                                for r in corr["reasons"]]), class_="compact") if corr["reasons"] else tag(
        "p", "A single event: nothing to join.", class_="muted")
    techniques = ", ".join(inc["technique_ids"]) + (f"  ({', '.join(inc['tactics'])})" if inc["tactics"] else "")
    return _stage(
        2, "correlate", "Correlate: why these events are one incident", "code",
        tag("p", "Events on one host are joined when, within the correlation window, they share a process tree, "
                 "a remote address, an account or a rule. Every link is kept with its reason; each event below "
                 "says why it is here."),
        reasons,
        _dl([("Accounts", ", ".join(inc["accounts"])), ("Source addresses", ", ".join(inc["source_ips"])),
             ("Programs", tag("ul", [tag("li", tag("code", p)) for p in inc["processes"]], class_="plain")
              if inc["processes"] else None),
             ("ATT&CK", techniques if inc["technique_ids"] else None),
             ("Categories", ", ".join(inc["categories"]))]),
        tag("p", f"The incident id is a hash of these {len(inc['event_ids'])} event ids. Different evidence would "
                 "be a different incident, which nobody has decided on or approved.", class_="muted"),
    )


def _stage_investigate(data: dict, short: str, run_dir: str) -> Markup:
    inv = data["investigate"]
    verdict = inv["verdict"]
    if verdict is None:
        return _stage(
            3, "investigate", "Investigate: the AI investigator's verdict", "ai",
            tag("p", "The model has not been asked about this incident. Nothing depends on it: the risk score and "
                     "the policy work from the evidence alone."),
            tag("p", "To ask it (on the laptop, with Ollama running):", class_="muted"),
            _command("python", "-m", "aegis", "investigate", short, run_dir=run_dir),
        )
    reasoning = verdict["reasoning"]
    findings = tag("ol", [tag("li", tag("span", f["claim"], class_="ai-text"), tag("br"),
                              tag("small", "cites ", _refs(f["evidence"]), " ",
                                  tag("span", "(checked by code: these events exist)", class_="code-note")))
                          for f in verdict["findings"]]) if verdict["findings"] else tag("p", "(none)", class_="muted")
    proposals = tag("ul", [tag("li", tag("code", f"{a['action']} {a['target']}"), ": ",
                               tag("span", a["reason"] or "(no reason given)", class_="ai-text"), tag("br"),
                               tag("small", "cites ", _refs(a["evidence"]), " ",
                                   tag("span", "(the policy decides in stage 4)", class_="code-note")))
                           for a in verdict["proposed_actions"]]) if verdict["proposed_actions"] else tag(
        "p", "(none)", class_="muted")
    rejected = tag("table", tag("thead", tag("tr", tag("th", "What"), tag("th", "The model wrote (AI)"),
                                         tag("th", "Why the checker removed or flagged it (code)"))),
                   tag("tbody", [tag("tr", tag("td", r["kind"]), tag("td", r["text"], class_="ai-text"),
                                     tag("td", r["reason"])) for r in verdict["rejected"]]),
                   class_="compact") if verdict["rejected"] else tag("p", "Nothing was removed.", class_="muted")
    how = f"{verdict['model']}, attempt {verdict['attempt']}, {_when(verdict['created_at'])} UTC"
    if verdict["duration_ms"] is not None:
        how += f", {verdict['duration_ms'] / 1000:.1f} s"
    if verdict["replayed"]:
        how += ", replayed from a recording"
    box = tag(
        "div",
        tag("p", tag("strong", "Written by the model"), f" ({how}). It does not feed the risk score and cannot "
                 "start an action. Lines marked code were checked by Aegis, not by the model.", class_="ai-note"),
        tag("p", "Verdict ", _ai_label(verdict["label"]), f"  confidence: {verdict['confidence']}",
            class_="verdict-line"),
        tag("p", tag("strong", "Agent mode: "), "the model opened the evidence itself, in this order: ",
            tag("code", "; ".join(verdict["steps"])) if verdict["steps"] else "nothing (it answered from the "
            "outline alone)", ". Only what it opened could be cited.", class_="muted")
        if verdict["mode"] != "single_call" else None,
        tag("h3", "Summary"), tag("p", verdict["summary"] or "(none)", class_="ai-text"),
        tag("h3", "Its working before it chose (not checked)"),
        _dl([("What happened", reasoning["what_happened"]), ("Started by", reasoning["started_by"]),
             ("Innocent reading", reasoning["innocent_explanation"]),
             ("Attack reading", reasoning["attack_explanation"]),
             ("Against the innocent reading", reasoning["against_innocent"])], cls="fields ai-text"),
        tag("h3", "Findings"), findings,
        tag("p", "ATT&CK: ", ", ".join(verdict["technique_ids"])) if verdict["technique_ids"] else None,
        tag("h3", "Proposed actions"), proposals,
        tag("h3", "Removed by the checker"), rejected,
        tag("p", "Operator notes shown to the model: ", ", ".join(verdict["notes_shown"]), class_="muted")
        if verdict["notes_shown"] else None,
        class_="ai-box",
    )
    answers = inv["answers"]
    others = tag("details", tag("summary", f"All {len(answers)} saved answers for this incident"),
                 tag("p", "A small model does not always answer the same way twice. Decide uses the latest single-call "
                          "answer; an agent-mode answer only where there is none (agent mode is still an "
                          "experiment, D44).", class_="muted"),
                 tag("table", tag("thead", tag("tr", [tag("th", h) for h in (
                     "Model setup", "Attempt", "Label (AI)", "Confidence", "When (UTC)")])),
                     tag("tbody", [tag("tr", tag("td", a["model"]), tag("td", a["attempt"], class_="num"),
                                       tag("td", _ai_label(a["label"])), tag("td", a["confidence"]),
                                       tag("td", _when(a["created_at"]))) for a in answers]),
                     class_="compact")) if len(answers) > 1 else None
    return _stage(3, "investigate", "Investigate: the AI investigator's verdict", "ai", box, others)


_SOURCE = {"rules": "risk rules", "model": "the AI model", "rules+model": "risk rules and the AI model"}


def _stage_decide(data: dict) -> Markup:
    dec = data["decide"]
    if dec is None:
        return _stage(4, "decide", "Decide: risk score and policy", "code",
                      tag("p", data["problem"] or "Not decided: the policy could not be read.", class_="bad"))
    risk = dec["risk"]
    factors = tag("table", tag("thead", tag("tr", [tag("th", h) for h in ("Points", "Rule", "Why", "Evidence")])),
                  tag("tbody", [tag("tr", tag("td", f"{f['points']:+d}", class_="num"), tag("td", tag("code", f["id"])),
                                    tag("td", f["reason"]), tag("td", _refs(f["evidence"])))
                                for f in risk["factors"]]), class_="compact") if risk["factors"] else tag(
        "p", "No rule found anything: score 0.", class_="muted")
    actions = tag("table", tag("thead", tag("tr", [tag("th", h) for h in (
        "Policy says", "Action", "Suggested by", "Why", "Status")])),
                  tag("tbody", [tag("tr", tag("td", _outcome(a["outcome"])),
                                    tag("td", tag("code", f"{a['action']} {a['target']}")),
                                    tag("td", tag("span", _SOURCE.get(a["source"], a["source"]),
                                                  class_="ai-text" if "model" in a["source"] else None)),
                                    tag("td", tag("ul", [tag("li", r) for r in a["reasons"]], class_="plain")),
                                    tag("td", _status(a["status"])))
                                for a in dec["actions"]]), class_="compact") if dec["actions"] else tag(
        "p", "No action was suggested by the risk rules or the model.", class_="muted")
    ai = dec["ai"]
    return _stage(
        4, "decide", "Decide: risk score and policy", "code",
        tag("p", f"Decided now, from the {len(data['incident']['event_ids'])} events and policy {dec['policy_id']}, "
                 "the way act decides before it runs anything. Saved decisions are not used."),
        tag("p", f"Host: {dec['host_mode']} - {dec['host_reason']}"),
        tag("p", _meter(risk["score"]), " ", tag("strong", f"{risk['score']} / 100", class_="big"), " ",
            _band(risk["band"]), class_="risk-line"),
        factors,
        tag("h3", "Candidate actions"),
        actions,
        tag("p", "The AI said ", _ai_label(ai["model_label"]), f" ({ai['model_run']}): shown for information, "
                 "not used by the score.", class_="muted") if ai["model_label"] else None,
    )


def _stage_act(data: dict, short: str, run_dir: str) -> Markup:
    dec, act = data["decide"], data["act"]
    this = data["incident"]["incident_id"]

    def earlier(incident_id: str) -> str:
        return "" if incident_id == this else (f" - for an earlier version of this incident ({incident_id}), "
                                               "before more events joined it")
    items = []
    for a in (dec["actions"] if dec else []):
        if a["outcome"] == "deny" and not a["results"]:
            continue
        lines = [tag("p", tag("code", f"{a['action']} {a['target']}"), " ", _status(a["status"]))]
        if a["approved"]:
            ok = a["approved"]["counts"]
            lines.append(tag("p", f"Approved by {a['approved']['by']} at {_when(a['approved']['at'])} UTC under "
                                  f"policy {a['approved']['policy_id']}: ",
                             tag("span", "counts under the current policy" if ok else
                                 "does not count, the policy has changed since", class_="ok" if ok else "bad")))
        for result in a["results"]:
            d = result["data"]
            lines.append(tag("p", f"Carried out at {_when(result['time'])} UTC on {d.get('host')} "
                                  f"({d.get('address')}): {d.get('message')}{earlier(result['incident_id'])}",
                             class_="ok" if d.get("ok") else "bad"))
            lines.append(_dl([("Before", tag("code", d.get("before"))), ("After", tag("code", d.get("after")))]))
        if a["status"] == "waiting":
            lines.append(tag("p", "To approve, on the command line:", class_="muted"))
            lines.append(_command("python", "-m", "aegis", "approve", short, "--action", a["action"],
                                  "--target", a["target"], "--by", "<your name>", run_dir=run_dir))
        if a["status"] == "approved":
            lines.append(tag("p", "To carry it out, on the command line:", class_="muted"))
            lines.append(_command("python", "-m", "aegis", "act", short, run_dir=run_dir))
        items.append(tag("div", lines, class_="action-card"))
    approval = act["approval"]
    trail = tag("table", tag("thead", tag("tr", [tag("th", h) for h in (
        "Entry", "Time (UTC)", "Kind", "Detail", "Version")])),
                tag("tbody", [tag("tr", tag("td", e["seq"], class_="num"), tag("td", _when(e["time"])),
                                  tag("td", e["kind"]), tag("td", e["summary"]),
                                  tag("td", "this one" if e["incident_id"] == this else
                                      tag("span", f"earlier: {e['incident_id']}", class_="muted mono")))
                              for e in act["trail"]]),
                class_="compact") if act["trail"] else tag("p", "No approval or action is recorded for this "
                                                                "incident.", class_="muted")
    earlier_approvals = [tag("p", f"Approved for an earlier version ({a['incident_id']}): "
                                  + ", ".join(f"{x['action']} {x['target']} by {x['by']} at {_when(x['at'])} UTC"
                                              for x in a["actions"])
                         + ". An approval does not carry over to new evidence; to act on this version, approve it "
                           "again.", class_="muted") for a in act["earlier_approvals"]]
    return _stage(
        5, "act", "Act: approvals and what was carried out", "human",
        tag("p", "Approving and acting happen only on the command line. act decides again from scratch and runs "
                 "only what the policy allows and a human approved, recording the target's state before and "
                 "after in the audit log."),
        items or tag("p", "Nothing here can be carried out: every candidate action is denied, or there is none.",
                     class_="muted"),
        tag("p", f"The approval file was made under policy {approval['policy_id']}, but the policy is now "
                 f"{approval['current_policy']}, so it does not count.", class_="bad")
        if approval and not approval["counts"] else None,
        earlier_approvals,
        tag("h3", "Audit trail for this incident"),
        tag("p", f"This incident grew from {act['earlier_versions']} earlier versions as events arrived; their "
                 "entries are included and marked.", class_="muted") if act["earlier_versions"] else None,
        trail,
        tag("p", f"decide was run {_times(act['decisions_recorded'])} for this incident on the command line "
                 f"(last at {_when(act['last_decided'])} UTC).", class_="muted") if act["decisions_recorded"] else None,
    )


# --------------------------------------------------------------------------
# Evidence
# --------------------------------------------------------------------------

def _evidence(events: list[dict], multi_day: bool, inline_raw: bool) -> Markup:
    return tag(
        "section",
        tag("h2", f"Evidence: the {len(events)} events, oldest first ", _badge("evidence")),
        tag("p", "This text comes from the monitored machine and may have been written by an attacker. It is "
                 "shown as text only; invisible and control characters appear as codes such as \\u202e.",
            class_="warning"),
        [_event_details(e, multi_day, inline_raw) for e in events],
        id="evidence", class_="evidence",
    )


def _short_detail(e: dict) -> str:
    parts = []
    if e.get("user"):
        parts.append(f"user={e['user']}" + (f" -> {e['target_user']}" if e.get("target_user") else ""))
    net = e.get("network") or {}
    if net.get("src_ip"):
        parts.append(f"from={net['src_ip']}")
    if net.get("dst_ip") or net.get("dst_host"):
        parts.append(f"to={net.get('dst_host') or net.get('dst_ip')}" +
                     (f":{net['dst_port']}" if net.get("dst_port") else ""))
    proc = e.get("process") or {}
    if proc.get("command_line"):
        line = " ".join(str(proc["command_line"]).split())
        parts.append("cmd=" + (line if len(line) <= 110 else line[:107] + "..."))
    elif proc.get("image"):
        parts.append(f"process={proc['image']}")
    if e.get("file_path"):
        parts.append(f"file={e['file_path']}")
    if e.get("registry_key"):
        parts.append(f"key={e['registry_key']}")
    return "  ".join(parts)


def _event_fields(e: dict) -> Markup:
    net, proc, rule, mitre = e.get("network") or {}, e.get("process") or {}, e["rule"], e.get("mitre") or {}
    seen = _when(e.get("observed_at"), ms=True)
    if seen and e.get("delay_seconds") and e["delay_seconds"] >= 60:
        seen += f"  ({_duration(e['delay_seconds'])} after it happened)"
    source = f"{net.get('src_ip')}" + (f":{net['src_port']}" if net.get("src_port") else "") if net.get("src_ip") else None
    target = net.get("dst_host") or net.get("dst_ip")
    if target and net.get("dst_port"):
        target += f":{net['dst_port']}"
    return _dl([
        ("Event id", tag("a", e["event_id"], href=_links.event(e["event_id"]), class_="mono")),
        ("Happened (UTC)", _when(e["timestamp"], ms=True)),
        ("Reached Wazuh", seen),
        ("Rule", f"{rule['id']}, level {rule['level']}: {rule['description']}"),
        ("Rule groups", ", ".join(rule.get("groups") or ())),
        ("Category", f"{e['category']}" + (f", {e['outcome']}" if e.get("outcome") not in (None, "unknown") else "")),
        ("ATT&CK", ", ".join(mitre.get("technique_ids") or ())),
        ("User", (e.get("user") or "") + (f" -> {e['target_user']}" if e.get("target_user") else "")),
        ("Source", source),
        ("Destination", target),
        ("Protocol", net.get("protocol")),
        ("Program", tag("code", proc["image"]) if proc.get("image") else None),
        ("Command line", tag("pre", proc["command_line"], class_="untrusted") if proc.get("command_line") else None),
        ("Parent", tag("code", proc["parent_image"]) if proc.get("parent_image") else None),
        ("Parent command", tag("pre", proc["parent_command_line"], class_="untrusted")
         if proc.get("parent_command_line") else None),
        ("Process id", proc.get("pid")),
        ("SHA-256", tag("code", proc["sha256"]) if proc.get("sha256") else None),
        ("File", tag("code", e["file_path"]) if e.get("file_path") else None),
        ("Registry key", tag("code", e["registry_key"]) if e.get("registry_key") else None),
        ("Registry value", tag("code", e["registry_value"]) if e.get("registry_value") else None),
        ("Source record", f"{e['source']} {e.get('source_ref') or ''}".strip()),
    ])


def _event_details(e: dict, multi_day: bool, inline_raw: bool) -> Markup:
    level = e["rule"]["level"]
    bucket = "hi" if level >= 12 else "mid" if level >= 7 else "lo"
    why = [frag(link["text"], " ", tag("code", link["value"]) if link["reason"] not in (
        "same_process", "parent_process", "same_parent_process") else "", " as ",
        tag("a", link["linked_label"], href=f"#{link['linked_label']}") if link["linked_label"]
        else link["linked_to"]) for link in e["links"]]
    raw = json.dumps(e.get("raw") or {}, indent=2, ensure_ascii=False)
    summary = tag("summary",
                  tag("span", e["label"], class_="lbl"), " ",
                  tag("span", _clock(e["timestamp"], multi_day), class_="time"), " ",
                  tag("span", f"L{level}", class_=f"lvl lvl-{bucket}"), " ",
                  tag("code", e["rule"]["id"]), " ",
                  tag("span", e["rule"]["description"], class_="desc"), " ",
                  tag("span", _short_detail(e), class_="detail"))
    return tag(
        "details",
        summary,
        tag("div",
            _event_fields(e),
            tag("p", tag("strong", "Why it is in this incident: "),
                [frag(w, "; ") for w in why[:-1]], why[-1] if why else "it is the first event of the story",
                class_="why"),
            frag(tag("h4", "Log line"), tag("pre", e["message"], class_="untrusted")) if e.get("message") else None,
            frag(tag("h4", "Raw alert"), tag("pre", raw, class_="untrusted raw")) if inline_raw else
            tag("p", tag("a", "Raw alert", href=_links.event(e["event_id"])), class_="muted"),
            class_="event-body"),
        id=e["label"] or None, class_="event",
    )


def event_page(data: dict) -> bytes:
    e = data["event"]
    e.setdefault("label", "")
    e.setdefault("links", [])
    raw = json.dumps(e.get("raw") or {}, indent=2, ensure_ascii=False)
    body = [
        tag("p", tag("a", "← all incidents", href=_links.home()), class_="back"),
        tag("h1", "Event ", tag("code", e["event_id"])),
        tag("p", "In incident ", [frag(tag("a", i, href=_links.incident(i)), " ") for i in data["incidents"]])
        if data["incidents"] else tag("p", "Not part of any incident (posture findings are set aside).",
                                      class_="muted"),
        tag("section",
            tag("h2", e["rule"]["description"], " ", _badge("evidence")),
            tag("p", "This text comes from the monitored machine and may have been written by an attacker. It is "
                     "shown as text only.", class_="warning"),
            _event_fields(e),
            frag(tag("h3", "Log line"), tag("pre", e["message"], class_="untrusted")) if e.get("message") else None,
            tag("h3", "Raw alert"), tag("pre", raw, class_="untrusted raw"),
            class_="evidence"),
    ]
    return document(f"Aegis - {e['event_id']}", data["header"], body)


# --------------------------------------------------------------------------
# Audit log, and errors
# --------------------------------------------------------------------------

def audit_page(data: dict, showing_all: bool) -> bytes:
    audit = data["header"]["audit"]
    if audit["ok"]:
        state = tag("p", tag("strong", "Chain intact", class_="ok"),
                    f": {audit['entries']} entries, each linked to the hash of the one before it.")
    else:
        state = tag("p", tag("strong", "BROKEN", class_="bad"),
                    f": {audit['problem']}. The {audit['entries']} entries before that are intact; the entries "
                    "after it are marked as not verified.")
    rows = [tag("tr", tag("td", e["seq"], class_="num"), tag("td", _when(e["time"])), tag("td", e["kind"]),
                tag("td", tag("a", e["incident_id"][:13], href=_links.incident(e["incident_id"]), class_="mono")
                    if e.get("incident_known") and re.fullmatch(r"inc-[0-9a-f]{16}", str(e["incident_id"]))
                    else tag("span", str(e["incident_id"])[:13], class_="mono muted",
                             title="not in the current incidents file")),
                tag("td", e["summary"]),
                tag("td", "yes" if e["verified"] else "NO", class_="ok" if e["verified"] else "bad"),
                class_=None if e["verified"] else "unverified")
            for e in data["entries"]]
    more = data["total"] - len(data["entries"])
    body = [
        tag("h1", "Audit log"),
        state,
        tag("p", "Last hash ", tag("code", audit["last_hash"])),
        tag("p", "Write the last hash down somewhere else: someone who deletes entries from the end leaves a valid "
                 "chain, but not one ending in this hash. Viewing this page writes nothing to the log.",
            class_="muted"),
        tag("p", f"Newest first. Showing {len(data['entries'])} of {data['total']}. ",
            None if _links.static else
            tag("a", "show all", href=_links.audit(True)) if more else
            (tag("a", "show the last 100", href=_links.audit()) if showing_all and data["total"] > 100 else None)),
        tag("table", tag("thead", tag("tr", [tag("th", h) for h in (
            "Entry", "Time (UTC)", "Kind", "Incident", "Detail", "Verified")])), tag("tbody", rows),
            class_="compact") if rows else tag("p", "No entries yet.", class_="empty"),
    ]
    return document("Aegis - audit log", data["header"], body)


def message_page(title: str, message: str, header: dict, link: tuple[str, str] | None = None) -> bytes:
    body = [tag("p", tag("a", "← all incidents", href=_links.home()), class_="back"), tag("h1", title),
            tag("p", message),
            tag("p", tag("a", link[1], href=link[0])) if link else None]
    return document(f"Aegis - {title}", header, body)


# --------------------------------------------------------------------------
# Posture: the PC's weak spots, ranked, with fix steps worked out by code (D47, D48)
# --------------------------------------------------------------------------

_STEP_TEXT = {"run": "Run, in a terminal opened as administrator", "check": "Then check that it took", "do": "Do"}
_ACTION_CLASS = {"update": "outcome-needs_approval", "command": "outcome-allow", "held back": "outcome-deny",
                 "CIS text only": ""}


def _times_word(n: int, word: str) -> str:
    return f"{n} {word}{'' if n == 1 else 's'}"


def _priority(score: int) -> Markup:
    return tag("meter", min="0", max="100", low="25", high="60", optimum="0", value=str(score),
               title=f"priority {score} of 100")


def _what_to_do(action: str) -> Markup:
    return tag("span", action, class_=f"chip {_ACTION_CLASS.get(action, '')}".strip())


def _posture_query(area: str | None, show: str | None) -> str:
    return "&".join(part for part in (f"show={show}" if show else "", f"area={area}" if area else "") if part)


def _posture_filters(data: dict) -> Markup:
    from aegis.posture import SHOW

    area, show = data["filters"]["area"], data["filters"]["show"]

    def link(label: str, query: str, on: bool) -> Markup:
        return tag("a", label, href=_links.posture(query), class_="on" if on else None)

    show_links = [link("everything", _posture_query(area, None), show is None)]
    show_links += [link(label, _posture_query(area, name), show == name) for name, label in SHOW.items()]
    area_links = [link("all", _posture_query(None, show), area is None)]
    area_links += [link(f"{a['area']} ({a['items']})", _posture_query(a["slug"], show), area == a["slug"])
                   for a in data["areas"]]
    return tag("div", tag("div", tag("span", "Show", class_="filter-name"), [frag(" ", a) for a in show_links]),
               tag("div", tag("span", "Area", class_="filter-name"), [frag(" ", a) for a in area_links]),
               class_="filters")


def posture_page(data: dict) -> bytes:
    header = data["header"]
    body = [tag("h1", "Posture"),
            tag("p", "This PC's weak spots from Wazuh - vulnerable programs and failed CIS checks - ranked by fixed "
                     "rules, each with fix steps. ", _badge("code"), " No AI model wrote any of it. Advice only: "
                     "Aegis never changes this PC, the policy denies every action on it (D7).", class_="lead")]
    if not data["ready"]:
        if data["error"]:
            body.append(tag("section", tag("h2", "The newest export could not be read"), tag("p", data["error"]),
                            class_="problems"))
        else:
            body.append(tag("p", "There is no posture export in ", tag("code", data["folder"]), " yet. Make one on "
                                 "the manager with lab/aegis-posture and copy it into that folder (README, "
                                 "\"Posture advice\"); this page picks it up without a restart.", class_="empty"))
        return document("Aegis - posture", header, body)
    counts, policy = data["counts"], data["policy"]
    age = data["age_days"]
    when = (f"{age:.0f} days ago" if age is not None and age >= 2 else
            "today" if age is not None and age < 1 else "yesterday" if age is not None else "at an unknown time")
    if _links.static:  # a copy is read later: an age worked out now would go wrong
        freshness = tag("span", f"exported {data['made_at']}")
    elif data["stale"]:
        freshness = tag("span", f"exported {when} ({data['made_at']}) - older than {data['stale_days']} days, so "
                                "export again for the current state", class_="bad")
    else:
        freshness = tag("span", f"exported {when} ({data['made_at']})")
    body.append(tag("p", tag("strong", data["agent"]["name"] or "agent " + data["agent"]["id"]),
                    f" (agent {data['agent']['id']}), {data['os'] or 'unknown system'} · ", freshness,
                    " · file ", tag("code", data["file"]), class_="facts"))
    body.append(tag("p", f"{policy.get('name') or 'No CIS policy'}: score {policy.get('score', '?')}% - "
                         f"{_times_word(counts['passed'], 'check')} passed, {counts['failed']} failed, "
                         f"{counts['not_applicable']} not applicable.", class_="muted"))
    body.append(tag(
        "div",
        _tile("Failed CIS checks", counts["failed"], f"{counts['passed']} passed"),
        _tile("With a checked command", counts["with_command"], "one reg add each, tested against the check"),
        _tile("Commands held back", counts["held"], "could lock you out or break everyday use", "tile band-medium"),
        _tile("Vulnerable programs", counts["programs"], f"{counts['cves']} active CVEs", "tile band-high"),
        _tile("Removed by the checker", counts["removed"], "steps that would weaken the PC"),
        _tile("Not on Windows 11 Home", counts["not_on_home"], "listed, with a note"),
        class_="tiles"))
    if not _links.static:
        body.append(_posture_filters(data))
    rows = []
    for row in data["items"]:
        rows.append(tag(
            "tr",
            tag("td", row["rank"], class_="num"),
            tag("td", _priority(row["score"]), " ", tag("strong", row["score"]), class_="nowrap"),
            tag("td", tag("a", row["title"], href=_links.posture_item(row["slug"])),
                tag("br"), tag("small", row["detail"], class_="muted") if row["detail"] else None),
            tag("td", row["area"], tag("br", ) if row["not_on_home"] else None,
                tag("small", "not on Home", class_="muted") if row["not_on_home"] else None),
            tag("td", _what_to_do(row["action"])),
        ))
    if rows:
        shown = (f"{counts['shown']} items" if counts["shown"] == counts["items"]
                 else f"{counts['shown']} of {counts['items']} items")
        body.append(tag("p", shown + ", most important first", class_="muted"))
        body.append(tag("table", tag("thead", tag("tr", [tag("th", h) for h in (
            "#", "Priority", "Item", "Area", "What to do")])), tag("tbody", rows), class_="posture"))
    else:
        body.append(tag("p", "Nothing matches these filters.", class_="empty"))
    if data["problems"]:
        body.append(tag("section", tag("h2", "What Aegis could not read"),
                        tag("ul", [tag("li", p) for p in data["problems"]]), class_="problems"))
    return document("Aegis - posture", header, body)


def posture_item_page(data: dict) -> bytes:
    header = data["header"]
    program, check = data["program"], data["check"]
    body = [tag("p", tag("a", "← all posture advice", href=_links.posture()), class_="back"),
            tag("h1", data["title"]),
            tag("p", f"Number {data['rank']} of {data['of']} · priority ", _priority(data["score"]), " ",
                tag("strong", data["score"]), f" · {data['area']} · ", _what_to_do(data["action"]), " ",
                _badge("code"), class_="facts")]
    if program:
        body.append(_dl([("Installed", tag("code", program["version"])),
                         ("Package type", program["type"] or None),
                         ("Fixed by", program["fix"])]))
    body.append(tag("h2", "Why it is here"))
    body.append(tag("ul", [tag("li", tag("strong", f"{'+' if r['points'] >= 0 else ''}{r['points']}"), " ",
                                r["why"]) for r in data["reasons"]], class_="plain"))
    if data["detail"]:
        body += [tag("h2", "What is wrong"), tag("p", data["detail"])]
    for note in data["notes"]:
        body.append(tag("p", note, class_="warning"))
    body.append(tag("h2", "What to do"))
    steps = []
    for step in data["steps"]:
        source = step["source"] != "Aegis"
        label = frag(tag("strong", _STEP_TEXT.get(step["kind"], step["kind"])),
                     frag(" ", tag("span", f"text from {step['source']}", class_="badge badge-evidence"))
                     if source else None)
        if step["kind"] in ("run", "check"):
            steps.append(tag("li", label, tag("pre", tag("code", step["text"]), class_="command")))
        else:
            steps.append(tag("li", label, tag("p", step["text"], class_="untrusted") if source else
                             tag("p", _inline(step["text"]))))
    body.append(tag("ol", steps) if steps else tag("p", "No steps.", class_="empty"))
    if data["held"]:
        body.append(tag("h2", "Command held back"))
        body.append(tag("p", "CIS recommends this, but Aegis gives no command for it: ",
                         "; ".join(h["why"] for h in data["held"]), ". Change it only if that is fine for you; "
                         "CIS's text above says how."))
    if data["removed"]:
        body.append(tag("h2", "Removed by the checker"))
        body.append(tag("p", "These steps came with the data but would weaken the PC, so they are not advice. "
                             "Do not run them."))
        body.append(tag("ul", [tag("li", r["why"], tag("details", tag("summary", "show the removed text"),
                                                      tag("pre", r["text"], class_="untrusted")))
                               for r in data["removed"]]))
    if check:
        body.append(tag("h2", "What Wazuh checks"))
        if check["targets"]:
            body.append(tag("table", tag("thead", tag("tr", [tag("th", h) for h in ("Registry key", "Value",
                                                                                   "Must be")])),
                            tag("tbody", [tag("tr", tag("td", tag("code", t["key"])), tag("td", tag("code", t["value"])),
                                              tag("td", tag("code", t["wanted"]))) for t in check["targets"]]),
                            class_="compact"))
        else:
            body.append(tag("p", "Its rules are not one plain registry value, so Aegis made no command: ",
                             check["why_no_target"] or "see CIS's text above", "."))
        body.append(_dl([("CIS section", check["cis"] or None), ("Check", f"{check['policy']} {check['id']}"),
                         ("Rationale", tag("span", check["rationale"], class_="untrusted") if check["rationale"]
                          else None)]))
    if program:
        body.append(tag("h2", f"CVEs ({len(program['cves'])})"))
        body.append(tag("table", tag("thead", tag("tr", [tag("th", h) for h in (
            "CVE", "Severity", "CVSS", "Wazuh's bound", "Over the network, no sign-in", "With the advised version")])),
            tag("tbody", [tag("tr", tag("td", tag("code", c["id"])), tag("td", c["severity"]),
                              tag("td", "under evaluation" if c["under_evaluation"] else
                                  c["score"] if c["score"] is not None else "-", class_="num"),
                              tag("td", c["condition"] or "-"),
                              tag("td", ("yes" + (", no click" if c["no_interaction"] else "")
                                         if c["network"] and c["no_privileges"] else "no") if c["vector_known"]
                                  else tag("span", "unknown", class_="muted")),
                              tag("td", c["status"], class_="ok" if c["status"].startswith("fixed") else
                                  "bad" if c["status"].startswith("NOT") else "muted"))
                          for c in program["cves"]]), class_="compact"))
    if data["links"]:
        body.append(tag("h2", "References"))
        body.append(tag("p", "Shown as text, not links: copy one into your browser. Only addresses on known sites "
                             "(CIS, Microsoft, NVD, CVE, Wazuh ...) are kept.", class_="muted"))
        body.append(tag("ul", [tag("li", tag("code", link)) for link in data["links"]], class_="plain"))
    return document(f"Aegis - posture - {data['title'][:60]}", header, body)


# --------------------------------------------------------------------------
# Plain pages: the demo's front page and a Markdown report
# --------------------------------------------------------------------------

def simple_document(title: str, body: Any, notice: str | None = None, home: str | None = None) -> bytes:
    """A page outside any run folder: no run facts in the header, no links into a run."""
    head = tag(
        "head",
        tag("meta", charset="utf-8"),
        tag("meta", http_equiv="Content-Security-Policy", content=STATIC_CSP) if _links.static else None,
        tag("meta", name="viewport", content="width=device-width, initial-scale=1"),
        tag("meta", name="referrer", content="no-referrer"),
        tag("title", title),
        tag("link", rel="stylesheet", href=_links.stylesheet()),
    )
    top = tag("header", tag("div", tag("a", "Aegis", href=home or _links.home(), class_="brand"), " ",
                            tag("span", "read-only", class_="badge badge-ro"), class_="brand-line"), class_="top")
    notice_box = tag("section", tag("p", notice), class_="notice") if notice else None
    page = tag("html", head, tag("body", top, notice_box, tag("main", body)), lang="en")
    return ("<!DOCTYPE html>\n" + page + "\n").encode("utf-8", "replace")


def markdown(text: str) -> Markup:
    """A small subset of Markdown - headings, paragraphs, bullets, tables, `code` - with every word escaped."""
    lines = text.splitlines()
    blocks, i = [], 0
    while i < len(lines):
        line = lines[i]
        if not line.strip():
            i += 1
        elif line.startswith("#"):
            level = min(4, len(line) - len(line.lstrip("#")))
            blocks.append(tag(f"h{level}", _inline(line.lstrip("#").strip())))
            i += 1
        elif line.startswith("|"):
            rows = []
            while i < len(lines) and lines[i].startswith("|"):
                rows.append([cell.strip() for cell in lines[i].strip().strip("|").split("|")])
                i += 1
            body = [r for r in rows[1:] if not all(re.fullmatch(r":?-{3,}:?", c) for c in r)]
            blocks.append(tag("table", tag("thead", tag("tr", [tag("th", _inline(c)) for c in rows[0]])),
                              tag("tbody", [tag("tr", [tag("td", _inline(c)) for c in r]) for r in body]),
                              class_="compact report"))
        elif line.startswith("* "):
            items = []
            while i < len(lines) and lines[i].startswith("* "):
                items.append(lines[i][2:])
                i += 1
            blocks.append(tag("ul", [tag("li", _inline(item)) for item in items]))
        else:
            words = []
            while i < len(lines) and lines[i].strip() and not lines[i].startswith(("#", "|", "* ")):
                words.append(lines[i].strip())
                i += 1
            blocks.append(tag("p", _inline(" ".join(words))))
    return frag(blocks)


def _inline(text: str) -> Markup:
    return frag([tag("code", part[1:-1]) if len(part) > 1 and part[0] == part[-1] == "`" else part
                 for part in re.split(r"(`[^`]+`)", text)])
