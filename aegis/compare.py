"""Compare: put the verdicts of different model setups side by side.

A model setup ("variant") is a model name plus whether thinking was on.
Nothing here calls a model; it only reads verdicts that were already saved.

With labels - what each incident really was, decided by a human - the
variants are scored. Only two outcomes are wrong:
  * a benign incident called suspicious or malicious  -> a false alarm
  * an attack called benign                           -> a missed attack
"Suspicious" counts as catching an attack, because it sends the incident to
a human. Inconclusive is counted on its own: it is not an answer.
"""

from __future__ import annotations

import json
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable

from aegis.contracts.event import ContractError
from aegis.contracts.incident import Incident
from aegis.contracts.verdict import ModelRun, Verdict, VerdictLabel

ATTACK, BENIGN = "attack", "benign"
EXPECTED_VALUES = (ATTACK, BENIGN)

LETTER = {
    VerdictLabel.BENIGN: "B",
    VerdictLabel.SUSPICIOUS: "S",
    VerdictLabel.MALICIOUS: "M",
    VerdictLabel.INCONCLUSIVE: "?",
}
_ALARM = (VerdictLabel.SUSPICIOUS, VerdictLabel.MALICIOUS)


def variant_name(run: ModelRun) -> str:
    """A model setup: model, version of the instructions, and what was switched on."""
    name = f"{run.model} v{run.prompt_version}"
    notes = ""
    if run.knowledge:
        notes = f" +notes:{run.knowledge_id}" if run.knowledge_id else " +notes"
    return name + (" +think" if run.thinking else "") + notes


def load_labels(path: Path | str) -> dict[str, str]:
    """Read ``{"inc-...": "attack" | "benign"}`` from a JSON file."""
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8-sig"))
    except json.JSONDecodeError as exc:
        raise ContractError(f"{path}: not valid JSON") from exc
    if not isinstance(data, dict):
        raise ContractError(f"{path}: expected an object mapping incident ids to 'attack' or 'benign'")
    labels: dict[str, str] = {}
    for incident_id, value in data.items():
        if str(incident_id).startswith("_"):  # room for a comment, e.g. "_about"
            continue
        if value not in EXPECTED_VALUES:
            raise ContractError(f"{path}: {incident_id} is labelled {value!r}; use 'attack' or 'benign'")
        labels[str(incident_id)] = value
    return labels


@dataclass
class Score:
    variant: str
    runs: int = 0
    labels: Counter = field(default_factory=Counter)  # verdict label -> runs
    benign_runs: int = 0  # runs on incidents that are really benign
    benign_correct: int = 0
    false_alarms: int = 0
    attack_runs: int = 0  # runs on incidents that are really attacks
    caught: int = 0
    missed: int = 0
    inconclusive: int = 0
    unstable: int = 0  # incidents whose repeats did not all agree
    incidents: int = 0
    with_removals: int = 0  # runs where the checker removed or flagged something
    seconds: list = field(default_factory=list)

    @property
    def average_seconds(self) -> float | None:
        return sum(self.seconds) / len(self.seconds) if self.seconds else None


@dataclass
class Row:
    incident: Incident
    expected: str | None
    cells: dict  # variant -> list of VerdictLabel, in attempt order


@dataclass
class Comparison:
    variants: list
    rows: list
    scores: list
    unknown_incidents: int  # verdicts whose incident is not in the incidents file


def compare(
    incidents: Iterable[Incident],
    verdicts: Iterable[Verdict],
    labels: dict[str, str] | None = None,
    default_expected: str | None = None,
) -> Comparison:
    labels = labels or {}
    by_id = {incident.incident_id: incident for incident in incidents}
    order = {incident_id: position for position, incident_id in enumerate(by_id)}

    grouped: dict[str, dict[str, list[Verdict]]] = {}
    unknown = 0
    for verdict in verdicts:
        if verdict.incident_id not in by_id:
            unknown += 1
            continue
        grouped.setdefault(verdict.incident_id, {}).setdefault(variant_name(verdict.run), []).append(verdict)

    variants = sorted({variant for cells in grouped.values() for variant in cells})
    scores = {variant: Score(variant) for variant in variants}
    rows: list[Row] = []
    for incident_id in sorted(grouped, key=order.get):
        expected = labels.get(incident_id, default_expected)
        cells: dict[str, list[VerdictLabel]] = {}
        for variant, runs in grouped[incident_id].items():
            runs.sort(key=lambda verdict: verdict.run.attempt)
            cells[variant] = [verdict.label for verdict in runs]
            score = scores[variant]
            score.incidents += 1
            if len(set(cells[variant])) > 1:
                score.unstable += 1
            for verdict in runs:
                score.runs += 1
                score.labels[verdict.label] += 1
                if verdict.rejected:
                    score.with_removals += 1
                if verdict.run.duration_ms is not None:
                    score.seconds.append(verdict.run.duration_ms / 1000)
                if verdict.label is VerdictLabel.INCONCLUSIVE:
                    score.inconclusive += 1
                if expected == BENIGN:
                    score.benign_runs += 1
                    score.benign_correct += verdict.label is VerdictLabel.BENIGN
                    score.false_alarms += verdict.label in _ALARM
                elif expected == ATTACK:
                    score.attack_runs += 1
                    score.caught += verdict.label in _ALARM
                    score.missed += verdict.label is VerdictLabel.BENIGN
        rows.append(Row(by_id[incident_id], expected, cells))
    return Comparison(variants, rows, [scores[variant] for variant in variants], unknown)


def render(comparison: Comparison) -> str:
    if not comparison.rows:
        return "No verdicts yet. Run:  python -m aegis investigate --all"
    variants = comparison.variants
    widths = [
        max(len(variant), max(len(_cell(row.cells.get(variant))) for row in comparison.rows))
        for variant in variants
    ]
    lines = ["B benign   S suspicious   M malicious   ? inconclusive   (one letter per run)", ""]
    header = f"{'incident':<13} {'lvl':>3} {'ev':>3}  {'really':<7}"
    for variant, width in zip(variants, widths):
        header += f"  {variant:<{width}}"
    lines.append(header + "  title")
    for row in comparison.rows:
        incident = row.incident
        line = (
            f"{incident.incident_id[:13]:<13} {incident.max_level:>3} {len(incident.event_ids):>3}  "
            f"{row.expected or '-':<7}"
        )
        for variant, width in zip(variants, widths):
            line += f"  {_cell(row.cells.get(variant)):<{width}}"
        lines.append(line + "  " + _clip(incident.title, 44))

    lines += ["", "Scores"]
    for score in comparison.scores:
        average = score.average_seconds
        timing = f", {average:.1f} s on average" if average is not None else ""
        spread = ", ".join(
            f"{score.labels[label]} {label.value}" for label in VerdictLabel if score.labels[label]
        )
        lines.append(f"  {score.variant}")
        lines.append(f"    runs              {score.runs} on {score.incidents} incidents{timing}")
        lines.append(f"    verdicts          {spread}")
        if score.benign_runs:
            lines.append(
                f"    really benign     {score.benign_correct} of {score.benign_runs} called benign "
                f"({_percent(score.benign_correct, score.benign_runs)}), "
                f"{score.false_alarms} false alarm{'' if score.false_alarms == 1 else 's'}"
                + _unanswered(score.benign_runs - score.benign_correct - score.false_alarms)
            )
        if score.attack_runs:
            lines.append(
                f"    really attacks    {score.caught} of {score.attack_runs} caught "
                f"({_percent(score.caught, score.attack_runs)}), {score.missed} missed"
                + _unanswered(score.attack_runs - score.caught - score.missed)
            )
        if score.runs > score.incidents:
            lines.append(f"    changed its mind  on {score.unstable} of {score.incidents} incidents when asked again")
        lines.append(f"    checker stepped in  on {score.with_removals} of {score.runs} runs")
    if not any(score.benign_runs or score.attack_runs for score in comparison.scores):
        lines += ["", "No labels given, so nothing is scored. Add --expect benign, or a labels file."]
    if comparison.unknown_incidents:
        lines += ["", f"Note: {comparison.unknown_incidents} saved verdicts belong to incidents that are "
                      "not in the incidents file (an older run) and were left out."]
    return "\n".join(lines)


def _cell(labels: list | None) -> str:
    return " ".join(LETTER[label] for label in labels) if labels else "-"


def _unanswered(count: int) -> str:
    return f", {count} inconclusive" if count else ""


def _percent(part: int, whole: int) -> str:
    return f"{round(100 * part / whole)}%" if whole else "-"


def _clip(text: str, width: int) -> str:
    text = " ".join(text.split())
    return text if len(text) <= width else text[: width - 3] + "..."
