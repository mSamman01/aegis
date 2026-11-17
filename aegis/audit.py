"""The audit log: a hash-chained record of what Aegis decided and did.

One JSON object per line. Each entry holds the hash of the entry before it,
and its own hash covers everything in it, including that link:

    {"seq": 3, "time": "...", "kind": "approval", "incident_id": "...",
     "data": {...}, "prev": "<hash of entry 2>", "hash": "<sha256 of this entry>"}

Changing, inserting, removing or reordering any entry breaks the chain from
that point on, and ``verify`` says where. What a chain cannot show is entries
cut off the end; for that, ``verify`` prints the last hash, which can be
written down somewhere else and compared later.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from aegis.contracts.event import format_ts

GENESIS = "0" * 64
KINDS = ("decision", "approval", "action_refused", "action_started", "action_result")


@dataclass(frozen=True)
class Verification:
    ok: bool
    entries: int
    last_hash: str
    problem: str = ""


def entry_hash(entry: dict) -> str:
    body = {key: value for key, value in entry.items() if key != "hash"}
    canonical = json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def append(path: Path | str, kind: str, incident_id: str, data: dict,
           now: Callable[[], datetime] = lambda: datetime.now(timezone.utc)) -> dict:
    """Add one entry. Refuses to extend a log whose chain is already broken."""
    if kind not in KINDS:
        raise ValueError(f"unknown audit entry kind {kind!r}")
    path = Path(path)
    state = verify(path)
    if not state.ok:
        raise ValueError(f"the audit log {path} is damaged ({state.problem}); not adding to it")
    entry: dict[str, Any] = {
        "seq": state.entries + 1,
        "time": format_ts(now()),
        "kind": kind,
        "incident_id": incident_id,
        "data": data,
        "prev": state.last_hash,
    }
    entry["hash"] = entry_hash(entry)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8", newline="\n") as handle:
        handle.write(json.dumps(entry, sort_keys=True, ensure_ascii=True) + "\n")
    return entry


def read_entries(path: Path | str) -> list[dict]:
    path = Path(path)
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def verify(path: Path | str) -> Verification:
    path = Path(path)
    if not path.exists():
        return Verification(True, 0, GENESIS)
    previous = GENESIS
    count = 0
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        try:
            entry = json.loads(line)
        except json.JSONDecodeError:
            return Verification(False, count, previous, f"line {number} is not valid JSON")
        if not isinstance(entry, dict):
            return Verification(False, count, previous, f"line {number} is not an entry")
        if entry.get("seq") != count + 1:
            return Verification(False, count, previous,
                                f"line {number}: expected entry {count + 1}, found {entry.get('seq')!r}")
        if entry.get("prev") != previous:
            return Verification(False, count, previous,
                                f"entry {count + 1} does not follow entry {count} (an entry was removed, "
                                "inserted or moved)")
        if entry.get("hash") != entry_hash(entry):
            return Verification(False, count, previous, f"entry {count + 1} was changed after it was written")
        previous = entry["hash"]
        count += 1
    return Verification(True, count, previous)
