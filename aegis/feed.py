"""The live feed: new Wazuh alerts, pulled from the manager as they happen.

``python -m aegis watch`` keeps one SSH connection open to the Wazuh manager as
the account aegis-feed, whose key can run exactly one program, lab/aegis-feed,
and that program only reads the alert files (D37). Aegis pulls; nothing is
pushed to it and it listens on no port, so the feed adds no way into Aegis.
One long connection rather than a login every few seconds: every SSH login
makes alerts of its own on the manager, which the feed would then read.

Each batch of alerts goes through the same ingest and correlation as an
export: new events are appended to events.jsonl, incidents are worked out
again from all events, and only then is the position in the manager's file
(the cursor) saved. A crash or a dropped connection therefore means reading
some alerts twice - recognised by their event ids - and never skipping any.
Gaps the manager reports and alerts that cannot be read are recorded in
feed.json and feed.jsonl and shown on the dashboard.

When an incident grows its id changes (D12); superseded.jsonl records which
incident each old id became, so a link to it still leads somewhere.
"""

from __future__ import annotations

import json
import os
import queue
import re
import subprocess
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Callable

from aegis.contracts.event import ContractError, format_ts, parse_ts
from aegis.correlate import CorrelationConfig, correlate
from aegis.ingest.wazuh import ingest_text
from aegis.risk import assess
from aegis.store import append_events, read_events, read_incidents, write_incidents, write_json

MARK = b"#AEGIS-FEED "
PROTOCOL_VERSION = 1
EVENTS_NAME = "events.jsonl"
INCIDENTS_NAME = "incidents.jsonl"
STATE_NAME = "feed.json"
LOG_NAME = "feed.jsonl"
SUPERSEDED_NAME = "superseded.jsonl"
BACKOFF = (5, 10, 20, 40, 60)  # seconds before reconnecting, growing while connecting keeps failing
BATCH_LIMIT = 8 << 20  # work through a backlog in batches of about this many bytes
BUSY = 60.0  # another watch that made contact this recently is probably still running
KEEP_ISSUES = 20

_FILE_ID = re.compile(r"^[0-9a-f]{16}$")
_HOST = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.\-:]*$")
_USER = re.compile(r"^[a-z_][a-z0-9_-]{0,31}$")


class FeedError(RuntimeError):
    """The feed cannot start or go on."""


@dataclass(frozen=True)
class FeedSettings:
    address: str = "192.168.56.105"
    user: str = "aegis-feed"
    key: str = "~/.ssh/aegis_feed"
    min_level: int = 0
    window: timedelta = timedelta(minutes=30)
    silence: float = 90.0  # seconds without a single line before the connection counts as dead

    def __post_init__(self) -> None:
        if not _HOST.match(self.address):
            raise FeedError(f"not a host name or address: {self.address!r}")
        if not _USER.match(self.user):
            raise FeedError(f"not a plain user name: {self.user!r}")


class _Session:
    def __init__(self) -> None:
        self.pending: list[bytes] = []
        self.size = 0
        self.cursor: tuple | None = None
        self.hello = False
        self.caught_up = False


class Feed:
    def __init__(self, run_dir: Path | str, settings: FeedSettings = FeedSettings(), *,
                 spawn: Callable = subprocess.Popen, clock: Callable[[], float] = time.monotonic,
                 now: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
                 say: Callable[[str], None] = print, sleep: Callable[[float], None] = time.sleep) -> None:
        self.run_dir = Path(run_dir)
        self.settings = settings
        self.spawn = spawn
        self.clock = clock
        self.now = now
        self.say = say
        self.sleep = sleep
        self.events: dict = {}
        self.incidents: list = []
        self.state: dict = {}
        self._last_saved: dict = {}

    # ------------------------------------------------------------------ files

    def path(self, name: str) -> Path:
        return self.run_dir / name

    def load(self) -> None:
        """Read what the run folder already holds. A damaged folder stops the feed."""
        try:
            if self.path(EVENTS_NAME).exists():
                self.events = {e.event_id: e for e in read_events(self.path(EVENTS_NAME))}
            if self.path(INCIDENTS_NAME).exists():
                self.incidents = read_incidents(self.path(INCIDENTS_NAME))
            if self.path(STATE_NAME).exists():
                state = json.loads(self.path(STATE_NAME).read_text(encoding="utf-8"))
                if not isinstance(state, dict):
                    raise FeedError(f"{self.path(STATE_NAME)} is not a feed state")
                self.state = state
                self._last_saved = dict(state)
        except (OSError, UnicodeError, ValueError, ContractError) as exc:
            raise FeedError(f"cannot read the run folder {self.run_dir}: {exc}") from exc
        manager = self.state.get("manager")
        if self.state.get("started") and manager and manager != self.settings.address:
            raise FeedError(f"{self.run_dir} holds the feed from {manager}, not {self.settings.address}; "
                            "use another --dir")
        if self.state.get("status") == "connected" and self._age(self.state.get("last_contact")) < BUSY:
            raise FeedError(f"another watch on {self.run_dir} made contact {self._age(self.state['last_contact']):.0f} s "
                            "ago and seems to be running; stop it first, or wait a minute")
        if self.state.get("file_id") is not None and not _FILE_ID.match(str(self.state["file_id"])):
            raise FeedError(f"{self.path(STATE_NAME)} is damaged (file_id)")

    def _age(self, iso: str | None) -> float:
        if not iso:
            return float("inf")
        try:
            return (self.now() - parse_ts(iso)).total_seconds()
        except ContractError:
            return float("inf")

    def _save(self, **changes) -> None:
        self.state.update(changes)
        self.state["manager"] = self.settings.address
        self.state["updated"] = format_ts(self.now())
        write_json(self.path(STATE_NAME), self.state)
        self._last_saved = dict(self.state)  # what is on disk: the cursor there is always safe

    def _log(self, kind: str, **fields) -> None:
        entry = {"time": format_ts(self.now()), "kind": kind, **fields}
        self.run_dir.mkdir(parents=True, exist_ok=True)
        with self.path(LOG_NAME).open("a", encoding="utf-8", newline="\n") as handle:
            handle.write(json.dumps(entry, sort_keys=True, ensure_ascii=False) + "\n")

    # --------------------------------------------------------------- talking

    def request(self, from_start: bool) -> str:
        """What to ask the manager for: carry on from the cursor, or start."""
        if self.state.get("started"):
            if self.state.get("file_id"):
                return f"follow {self.state['file_id']} {int(self.state.get('offset') or 0)}"
            return "follow start"  # the file was empty when the feed began
        return "follow start" if from_start else "follow now"

    def command(self, request: str) -> list[str]:
        return [
            "ssh", "-i", str(Path(os.path.expanduser(self.settings.key))), "-T",
            "-o", "BatchMode=yes",          # never wait for a password or a question
            "-o", "ConnectTimeout=10",
            "-o", "IdentitiesOnly=yes",     # use this key, and only this key
            "-o", "ServerAliveInterval=15",  # notice a dead connection
            "-o", "ServerAliveCountMax=3",
            f"{self.settings.user}@{self.settings.address}", request,
        ]

    def run(self, once: bool = False, from_start: bool = False) -> int:
        self.load()
        failures = 0
        try:
            while True:
                outcome, hello = self.session(self.request(from_start), once)
                if outcome == "caught_up":
                    self._save(status="stopped", message="caught up (--once)")
                    return 0
                if outcome == "stop":
                    return 2
                if once:
                    self._save(status="disconnected", message="could not catch up")
                    return 1
                failures = 0 if hello else failures + 1
                delay = BACKOFF[min(failures, len(BACKOFF) - 1)]
                self._save(status="disconnected", message=f"reconnecting in {delay} s")
                self.say(f"Reconnecting in {delay} s.")
                self.sleep(delay)
        except KeyboardInterrupt:
            self._save(status="stopped", message="stopped by the user")
            self._log("stopped")
            self.say("Stopped.")
            return 0
        except OSError as exc:  # the run folder cannot be written: stop, and keep the old cursor
            self.say(f"error: cannot write to {self.run_dir}: {exc}")
            try:
                write_json(self.path(STATE_NAME), dict(self._last_saved, status="stopped",
                                                       message=f"stopped: cannot write ({exc})"))
            except OSError:
                pass
            return 2

    def session(self, request: str, once: bool) -> tuple[str, bool]:
        """One connection. Returns (outcome, whether the manager said hello)."""
        target = f"{self.settings.user}@{self.settings.address}"
        self._save(status="connecting", message=f"connecting to {target}")
        self.say(f"Connecting to {target}  ({request})")
        try:
            process = self.spawn(self.command(request), stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE)
        except FileNotFoundError:
            self._save(status="disconnected", message="the ssh program was not found")
            self.say("error: the ssh program was not found on this computer")
            return "failed", False
        lines: queue.Queue = queue.Queue()
        errors: list[str] = []
        threading.Thread(target=_pump, args=(process.stdout, lines), daemon=True).start()
        threading.Thread(target=_drain, args=(process.stderr, errors), daemon=True).start()
        session = _Session()
        last_line = self.clock()
        outcome = None
        try:
            while outcome is None:
                try:
                    line = lines.get(timeout=1.0)
                except queue.Empty:
                    if self.clock() - last_line > self.settings.silence:
                        self.say(f"No word from the manager for {self.settings.silence:.0f} s; reconnecting.")
                        self._log("silent", seconds=self.settings.silence)
                        outcome = "silent"
                    continue
                if line is None:
                    outcome = "ended"
                    break
                last_line = self.clock()
                if line.startswith(MARK):
                    outcome = self._control(line, session, lines, once)
                elif line.startswith(b"{"):
                    session.pending.append(line)
                    session.size += len(line)
                elif line.strip():
                    self._issue("the manager sent a line that is neither an alert nor a feed message")
        finally:
            if process.poll() is None:
                process.kill()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                pass
        if outcome == "ended":
            self._ended(session, process.returncode, errors)
        return outcome, session.hello

    def _ended(self, session: _Session, code, errors: list[str]) -> None:
        last = errors[-1] if errors else f"exit code {code}"
        if session.hello:
            self.say(f"The connection to the manager closed ({last}).")
        else:
            self.say(f"Could not start the feed: {last}")
            for hint in _hints(" ".join(errors), self.settings):
                self.say(f"  {hint}")
        self._log("ended", hello=session.hello, code=code, detail=last)

    def _control(self, line: bytes, session: _Session, lines: queue.Queue, once: bool) -> str | None:
        try:
            message = json.loads(line[len(MARK):].decode("ascii"))
            kind = message["type"]
        except (ValueError, KeyError, TypeError):
            self._issue("the manager sent a feed message that could not be read")
            return None
        if kind == "hello":
            if message.get("version") != PROTOCOL_VERSION:
                self.say(f"error: the manager speaks feed version {message.get('version')}, this Aegis "
                         f"{PROTOCOL_VERSION}; copy the matching lab/aegis-feed to the manager")
                return "stop"
            session.hello = True
            self._save(status="connected", started=True, file_id=message.get("file_id"),
                       offset=int(message.get("offset") or 0), last_contact=format_ts(self.now()),
                       message="")
            self._log("connected", start=message.get("start"), file_id=message.get("file_id"),
                      offset=message.get("offset"))
            self.say(f"Connected. Reading from {message.get('start')} "
                     f"(file {message.get('file_id') or '(empty)'}, offset {message.get('offset')}).")
        elif kind == "cursor":
            session.cursor = (message.get("file_id"), int(message.get("offset") or 0))
            if lines.empty() or session.size >= BATCH_LIMIT:
                self._flush(session)
        elif kind in ("idle", "heartbeat"):
            self._flush(session)
            self._save(last_contact=format_ts(self.now()))
            if kind == "idle" and not session.caught_up:
                session.caught_up = True
                self.say(f"Caught up: {len(self.events)} events, {len(self.incidents)} incidents. Waiting for "
                         "new alerts.")
                if once:
                    return "caught_up"
        elif kind == "rotated":
            self._flush(session)
            self._save(file_id=message.get("file_id"), offset=0)
            self._log("rotated", previous=message.get("previous"), archive=message.get("archive"))
            self.say(f"Wazuh started a new alerts file; finished the old one from {message.get('archive')}.")
        elif kind == "gap":
            self._flush(session)
            gap = {"time": format_ts(self.now()), "reason": str(message.get("reason")),
                   "file_id": message.get("file_id"), "offset": message.get("offset")}
            self._save(gaps=self.state.get("gaps", []) + [gap])
            self._log("gap", **gap)
            self.say(f"WARNING  gap in the feed: {gap['reason']}")
        elif kind in ("refused", "error"):
            reason = str(message.get("reason"))
            self._save(status="stopped", message=f"the manager's feed program said: {reason}")
            self._log(kind, reason=reason)
            self.say(f"error: the manager's feed program {'refused the request' if kind == 'refused' else 'failed'}: "
                     f"{reason}")
            return "stop"
        else:
            self._issue(f"the manager sent an unknown feed message ({kind!r})")
        return None

    # --------------------------------------------------------------- batches

    def _flush(self, session: _Session) -> None:
        """Ingest the alerts received up to the last cursor, save them, then save the cursor."""
        if session.cursor is None:
            return
        file_id, offset = session.cursor
        texts = []
        for number, raw in enumerate(session.pending, 1):
            try:
                texts.append(raw.decode("utf-8"))
            except UnicodeDecodeError:
                self._issue(f"alert {number} of a batch ending at {file_id}:{offset} is not valid UTF-8")
        result = ingest_text("".join(texts), self.settings.min_level)
        for issue in result.issues:
            self._issue(f"{issue.where} of a batch ending at {file_id}:{offset}: {issue.reason}")
        new = [event for event in result.events if event.event_id not in self.events]
        notable: list[str] = []
        if new:
            append_events(self.path(EVENTS_NAME), new)
            for event in new:
                self.events[event.event_id] = event
            notable = self._correlate(new)
        counts = {
            "alerts": int(self.state.get("alerts", 0)) + result.seen,
            "events_added": int(self.state.get("events_added", 0)) + len(new),
            "already_had": int(self.state.get("already_had", 0)) + len(result.events) - len(new),
            "below_min_level": int(self.state.get("below_min_level", 0)) + result.below_min_level,
        }
        self._save(file_id=file_id, offset=offset, last_contact=format_ts(self.now()), **counts)
        if session.pending:
            self._log("batch", alerts=result.seen, new_events=len(new), already_had=len(result.events) - len(new),
                      issues=len(result.issues), file_id=file_id, offset=offset)
        if new:
            self.say(f"{self.now():%H:%M:%S} UTC  +{len(new)} new events  "
                     f"({len(self.events)} events, {len(self.incidents)} incidents)")
            for line in notable:
                self.say(line)
        session.pending.clear()
        session.size = 0
        session.cursor = None

    def _correlate(self, new: list) -> list[str]:
        """Work out the incidents again; returns a line for each touched incident above low risk."""
        before = {incident.incident_id: incident for incident in self.incidents}
        result = correlate(self.events.values(), CorrelationConfig(window=self.settings.window))
        write_incidents(self.path(INCIDENTS_NAME), result.incidents)
        self.incidents = result.incidents
        home = {event_id: incident for incident in result.incidents for event_id in incident.event_ids}
        current = {incident.incident_id for incident in result.incidents}
        moves = []
        for old_id, old in before.items():
            if old_id in current:
                continue
            successor = next((home[e].incident_id for e in old.event_ids if e in home), None)
            if successor:
                moves.append({"old": old_id, "new": successor, "time": format_ts(self.now())})
        if moves:
            with self.path(SUPERSEDED_NAME).open("a", encoding="utf-8", newline="\n") as handle:
                handle.write("".join(json.dumps(m, sort_keys=True) + "\n" for m in moves))
        touched = {home[e.event_id].incident_id for e in new if e.event_id in home}
        notable = []
        for incident in result.incidents:
            if incident.incident_id not in touched:
                continue
            risk = assess(incident, [self.events[e] for e in incident.event_ids]).risk
            if risk.band != "low":
                notable.append(f"  {risk.band.upper():<8} risk {risk.score:>3}  {incident.incident_id}  "
                               f"{incident.host.name}  {incident.title[:70]}")
        return notable

    def _issue(self, text: str) -> None:
        issues = (self.state.get("issues") or [])[-(KEEP_ISSUES - 1):] + [{"time": format_ts(self.now()), "text": text}]
        self._save(issues=issues, issue_count=int(self.state.get("issue_count", 0)) + 1)
        self._log("issue", text=text)
        self.say(f"NOTE  {text}")


def _pump(stream, lines: queue.Queue) -> None:
    try:
        for line in iter(stream.readline, b""):
            lines.put(line)
    finally:
        lines.put(None)


def _drain(stream, errors: list) -> None:
    for line in iter(stream.readline, b""):
        text = line.decode("utf-8", "replace").strip()
        if text:
            errors.append(text[:300])
            del errors[:-20]


def _hints(errors: str, settings: FeedSettings) -> list[str]:
    key = settings.key.replace("~/", "$HOME\\").replace("/", "\\")
    first = f"ssh -i {key} {settings.user}@{settings.address} follow now"
    if "Host key verification failed" in errors:
        return ["This computer does not know the manager's host key yet. Connect once by hand, answer 'yes',",
                f"then press Ctrl+C:  {first}"]
    if "Permission denied" in errors:
        return [f"The manager did not accept the key {settings.key} for {settings.user}. Was lab/setup-manager.sh "
                "run with this key's .pub file, and is this computer 192.168.56.1?"]
    if "timed out" in errors or "No route" in errors or "refused" in errors:
        return [f"Is the Wazuh manager VM running, and reachable at {settings.address}?"]
    if "Identity file" in errors or "no such identity" in errors.lower():
        return [f"The key {settings.key} was not found. Create it with:  ssh-keygen -t ed25519 -f {key} -N \"\""]
    return []


def read_status(run_dir: Path | str) -> dict | None:
    """The feed's state for the dashboard, or None if this folder has no feed. Read-only."""
    path = Path(run_dir) / STATE_NAME
    try:
        state = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return None
    except (OSError, UnicodeError, ValueError):
        return {"status": "unreadable", "message": f"cannot read {path}", "gaps": [], "issues": []}
    return state if isinstance(state, dict) else None


def read_superseded(run_dir: Path | str) -> dict:
    """old incident id -> the incident it became. Read-only; unreadable lines are skipped."""
    path = Path(run_dir) / SUPERSEDED_NAME
    moves: dict = {}
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeError):
        return moves
    for line in lines:
        try:
            move = json.loads(line)
            moves[str(move["old"])] = str(move["new"])
        except (ValueError, KeyError, TypeError):
            continue
    return moves
