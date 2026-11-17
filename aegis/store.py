"""Reading and writing Events as JSON Lines (one event per line)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Iterable

from aegis.contracts.event import ContractError, Event
from aegis.contracts.decision import Decision
from aegis.contracts.incident import Incident
from aegis.contracts.verdict import Verdict


def write_events(path: Path | str, events: Iterable[Event]) -> int:
    """Write events to ``path`` (parent folders are created). Returns the count."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    count = 0
    with path.open("w", encoding="utf-8", newline="\n") as handle:
        for event in events:
            handle.write(json.dumps(event.to_dict(), ensure_ascii=False, sort_keys=True))
            handle.write("\n")
            count += 1
    return count


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
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    count = 0
    with path.open("w", encoding="utf-8", newline="\n") as handle:
        for incident in incidents:
            handle.write(json.dumps(incident.to_dict(), ensure_ascii=False, sort_keys=True))
            handle.write("\n")
            count += 1
    return count


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
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="\n") as handle:
        for item in kept:
            handle.write(json.dumps(item.to_dict(), ensure_ascii=False, sort_keys=True))
            handle.write("\n")


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
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="\n") as handle:
        for item in kept:
            handle.write(json.dumps(item.to_dict(), ensure_ascii=False, sort_keys=True))
            handle.write("\n")
