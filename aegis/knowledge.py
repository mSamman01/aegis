"""Knowledge notes: what the operator knows about this environment.

A model cannot know that a given program is the site's own monitoring agent.
A human can, and writes it down once in ``knowledge/notes.json``:

    {"id": "wazuh-agent-checks",
     "note": "The Wazuh security agent ... starts PowerShell, secedit ...",
     "applies_when": {"started_by": "\\\\ossec-agent\\\\wazuh-agent\\.exe$"}}

Code - not the model - decides when a note is relevant: it is shown only for
incidents in which at least one event matches ``applies_when``, together with
the events it matched. A note that is always shown gets applied to everything;
that was tried, and the model began blaming unrelated events on the agent.

``applies_when`` maps field names to regular expressions (case-insensitive,
matched anywhere in the value). All of them must match the same event.

A note is background, not evidence. Results obtained with notes are marked as
such, because part of the answer then comes from what a human wrote.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterable, Sequence

from aegis.contracts.event import ContractError, Event

DEFAULT_NOTES_FILE = Path(__file__).resolve().parent.parent / "knowledge" / "notes.json"

# The fields a note can match on, named as they appear in the evidence.
FIELDS: dict[str, Callable[[Event], str | None]] = {
    "rule": lambda e: e.rule.id,
    "account": lambda e: e.user,
    "program": lambda e: e.process.image if e.process else None,
    "command_line": lambda e: e.process.command_line if e.process else None,
    "started_by": lambda e: e.process.parent_image if e.process else None,
    "started_by_command_line": lambda e: e.process.parent_command_line if e.process else None,
    "file": lambda e: e.file_path,
    "registry_key": lambda e: e.registry_key,
}

_ID_RE = re.compile(r"^[a-z0-9][a-z0-9-]{1,48}$")


@dataclass(frozen=True)
class Note:
    id: str
    text: str
    patterns: tuple  # ((field, compiled regex), ...)

    def matches(self, event: Event) -> bool:
        for name, pattern in self.patterns:
            value = FIELDS[name](event)
            if not value or not pattern.search(value):
                return False
        return True


def load_notes(path: Path | str = DEFAULT_NOTES_FILE) -> list[Note]:
    """Read and validate a notes file. A broken file is an error, never ignored."""
    path = Path(path)
    try:
        data = json.loads(path.read_text(encoding="utf-8-sig"))
    except json.JSONDecodeError as exc:
        raise ContractError(f"{path}: not valid JSON ({exc.msg}, line {exc.lineno})") from exc
    if not isinstance(data, list):
        raise ContractError(f"{path}: expected a list of notes")
    notes: list[Note] = []
    seen: set[str] = set()
    for position, item in enumerate(data, 1):
        where = f"{path}, note {position}"
        if not isinstance(item, dict):
            raise ContractError(f"{where}: must be an object")
        unknown = sorted(set(item) - {"id", "note", "applies_when"})
        if unknown:
            raise ContractError(f"{where}: unknown key(s): {', '.join(unknown)}")
        note_id, text, conditions = item.get("id"), item.get("note"), item.get("applies_when")
        if not isinstance(note_id, str) or not _ID_RE.match(note_id):
            raise ContractError(f"{where}: 'id' must be lower-case letters, digits and dashes")
        if note_id in seen:
            raise ContractError(f"{where}: the id {note_id!r} is used twice")
        seen.add(note_id)
        if not isinstance(text, str) or not text.strip():
            raise ContractError(f"{where}: 'note' must be text")
        if not isinstance(conditions, dict) or not conditions:
            raise ContractError(
                f"{where}: 'applies_when' needs at least one condition; a note must say when it applies"
            )
        patterns = []
        for name, expression in conditions.items():
            if name not in FIELDS:
                raise ContractError(f"{where}: unknown field {name!r}; use one of: {', '.join(FIELDS)}")
            if not isinstance(expression, str) or not expression:
                raise ContractError(f"{where}: the pattern for {name!r} must be text")
            try:
                patterns.append((name, re.compile(expression, re.IGNORECASE)))
            except re.error as exc:
                raise ContractError(f"{where}: bad pattern for {name!r}: {exc}") from exc
        notes.append(Note(note_id, " ".join(text.split()), tuple(patterns)))
    return notes


def notes_fingerprint(notes: Sequence[Note]) -> str:
    """A short id for this exact set of notes. Any edit to any note changes it."""
    canonical = json.dumps(
        [[note.id, note.text, [[name, pattern.pattern] for name, pattern in note.patterns]] for note in notes],
        separators=(",", ":"),
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:6]


def matching_notes(notes: Sequence[Note], events: Iterable[Event]) -> list[tuple[Note, list[str]]]:
    """The notes that apply to these events, each with the ids of the events it matched."""
    events = list(events)
    found = []
    for note in notes:
        matched = [event.event_id for event in events if note.matches(event)]
        if matched:
            found.append((note, matched))
    return found
