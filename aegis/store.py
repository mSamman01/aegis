"""Reading and writing Events as JSON Lines (one event per line).

Whole files are replaced in one step - written to a temporary file beside
them, then swapped in - so a reader such as the dashboard never sees half a
file while the live feed or a command is rewriting it. Events from the live
feed are appended in one write per batch.
"""

from __future__ import annotations

import json
import os
import time
from pathlib import Path
from typing import Iterable

from aegis.contracts.event import ContractError, Event
from aegis.contracts.decision import Decision
from aegis.contracts.incident import Incident
from aegis.contracts.verdict import Verdict


def replace_lines(path: Path | str, lines: Iterable[str]) -> int:
    """Replace a file with these lines, in one step. Returns the count."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_name(path.name + ".tmp")
    count = 0
    with temp.open("w", encoding="utf-8", newline="\n") as handle:
        for line in lines:
            handle.write(line)
            handle.write("\n")
            count += 1
    _swap(temp, path)
    return count


def write_json(path: Path | str, data) -> None:
    """Replace a small JSON file in one step."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_name(path.name + ".tmp")
    temp.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")
    _swap(temp, path)


def _swap(temp: Path, path: Path, attempts: int = 60) -> None:
    for attempt in range(attempts):
        try:
            os.replace(temp, path)
            return
        except PermissionError:  # Windows: another program is reading the file at this moment
            if attempt == attempts - 1:
                raise
            time.sleep(0.05)


def _event_line(event: Event) -> str:
    return json.dumps(event.to_dict(), ensure_ascii=False, sort_keys=True)


def write_events(path: Path | str, events: Iterable[Event]) -> int:
    """Write events to ``path`` (parent folders are created). Returns the count."""
    return replace_lines(path, (_event_line(event) for event in events))


def append_events(path: Path | str, events: Iterable[Event]) -> int:
    """Add events at the end of ``path`` in a single write. Returns the count."""
    lines = [_event_line(event) for event in events]
    if not lines:
        return 0
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8", newline="\n") as handle:
        handle.write("\n".join(lines) + "\n")
    return len(lines)


def read_events(path: Path | str) -> list[Event]:
    """Read events back. Any line that breaks the contract raises ContractError."""
    events: list[Event] = []
    with Path(path).open("r", encoding="utf-8") as handle:
        for number, line in enumerate(handle, 1):
            if not line.strip():
                continue
            try:
                events.append(Event.from_dict(json.loads(line)))
            except json.JSONDecodeError as exc:
                raise ContractError(f"{path}, line {number}: not valid JSON") from exc
            except ContractError as exc:
                raise ContractError(f"{path}, line {number}: {exc}") from exc
    return events


def write_incidents(path: Path | str, incidents: Iterable[Incident]) -> int:
    """Write incidents to ``path`` as JSON lines. Returns the count."""
    return replace_lines(path, (json.dumps(i.to_dict(), ensure_ascii=False, sort_keys=True) for i in incidents))


def read_incidents(path: Path | str) -> list[Incident]:
    """Read incidents back. A line that breaks the contract raises ContractError."""
    incidents: list[Incident] = []
    with Path(path).open("r", encoding="utf-8") as handle:
        for number, line in enumerate(handle, 1):
            if not line.strip():
                continue
            try:
                incidents.append(Incident.from_dict(json.loads(line)))
            except json.JSONDecodeError as exc:
                raise ContractError(f"{path}, line {number}: not valid JSON") from exc
            except ContractError as exc:
                raise ContractError(f"{path}, line {number}: {exc}") from exc
    return incidents


def read_verdicts(path: Path | str) -> list[Verdict]:
    """Read verdicts; a missing file is simply no verdicts yet."""
    path = Path(path)
    if not path.exists():
        return []
    verdicts: list[Verdict] = []
    with path.open("r", encoding="utf-8") as handle:
        for number, line in enumerate(handle, 1):
            if not line.strip():
                continue
            try:
                verdicts.append(Verdict.from_dict(json.loads(line)))
            except json.JSONDecodeError as exc:
                raise ContractError(f"{path}, line {number}: not valid JSON") from exc
            except ContractError as exc:
                raise ContractError(f"{path}, line {number}: {exc}") from exc
    return verdicts


def save_verdict(path: Path | str, verdict: Verdict) -> None:
    """Add a verdict, replacing an earlier one for the same incident, model setup and attempt."""

    def key(item: Verdict) -> tuple:
        run = item.run
        return (item.incident_id, run.model, run.mode, run.thinking, run.attempt, run.prompt_version,
                run.knowledge, run.knowledge_id)

    kept = [item for item in read_verdicts(path) if key(item) != key(verdict)]
    kept.append(verdict)
    replace_lines(path, (json.dumps(item.to_dict(), ensure_ascii=False, sort_keys=True) for item in kept))


def read_decisions(path: Path | str) -> list[Decision]:
    """Read decisions; a missing file is simply no decisions yet."""
    path = Path(path)
    if not path.exists():
        return []
    decisions: list[Decision] = []
    with path.open("r", encoding="utf-8") as handle:
        for number, line in enumerate(handle, 1):
            if not line.strip():
                continue
            try:
                decisions.append(Decision.from_dict(json.loads(line)))
            except json.JSONDecodeError as exc:
                raise ContractError(f"{path}, line {number}: not valid JSON") from exc
            except ContractError as exc:
                raise ContractError(f"{path}, line {number}: {exc}") from exc
    return decisions


def save_decisions(path: Path | str, new: Iterable[Decision]) -> None:
    """Add decisions, replacing earlier ones for the same incident under the same policy."""
    new = list(new)
    replaced = {(d.incident_id, d.policy_id) for d in new}
    kept = [d for d in read_decisions(path) if (d.incident_id, d.policy_id) not in replaced] + new
    replace_lines(path, (json.dumps(item.to_dict(), ensure_ascii=False, sort_keys=True) for item in kept))
