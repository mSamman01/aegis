"""Evaluation: how Aegis does on labelled cases, and whether anything unsafe gets through.

``python -m aegis evaluate`` builds the cases (aegis.evalcases) and, for each:

  1. ingests and correlates its alerts into runs/eval/<case>, so every case
     can be opened in the dashboard like any run
  2. decides every incident from its evidence and the current policy, and
     scores that against the labels: attacks flagged, false alarms, and
     whether a human would be asked to act on something harmless
  3. checks the case's own expectations (for the lab attack: the guessed
     account is locked only with approval, and the laptop is never blocked)
  4. checks what must hold everywhere, whatever the data: nothing allowed
     without a human, nothing on an advice host, nothing against a protected
     account, address or path
  5. scores the model's saved verdicts the way ``compare`` does, adding how
     many of its citations and proposals survived the checks
  6. for real runs, checks that every action the audit log says was carried
     out had a human's approval before it

then runs the safety probe (aegis.probe). Without ``--investigate`` nothing
here calls the model, and nothing here can reach a lab VM.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

from aegis import audit
from aegis.compare import compare, variant_name
from aegis.contracts.decision import ActionOutcome, Decision
from aegis.contracts.verdict import Verdict
from aegis.correlate import correlate
from aegis.decide import decide, latest_verdict
from aegis.evalcases import ATTACK, BANDS, BENIGN, PROJECT, label_of, load_cases
from aegis.evidence import EvidenceStore, target_key
from aegis.ingest.wazuh import ingest_text, read_text
from aegis.policy import Policy
from aegis.store import read_verdicts, replace_lines, save_verdict, write_events, write_incidents, write_json

DEFAULT_OUT = PROJECT / "runs" / "eval"
MODEL_LEVEL = 7  # in real data, the model is asked about incidents at this level or above, and about attacks


@dataclass
class Prepared:
    name: str
    spec: dict
    folder: Path  # the case folder (alerts, case.json)
    run_dir: Path  # runs/eval/<case>
    events: list
    incidents: list
    verdicts: list
    issues: int = 0  # alerts that could not be read


@dataclass
class IncidentResult:
    incident_id: str
    host: str
    host_mode: str
    label: str | None
    level: int
    title: str
    score: int
    band: str
    actions: list  # (action, target, outcome, source)
    model: str | None  # the latest verdict's label, if any


@dataclass
class ModelResult:
    variant: str
    runs: int = 0
    attack_runs: int = 0
    caught: int = 0
    missed: int = 0
    benign_runs: int = 0
    benign_correct: int = 0
    false_alarms: int = 0
    inconclusive: int = 0
    unlabelled_runs: int = 0
    unstable: int = 0
    findings_kept: int = 0
    findings_removed: int = 0
    citations_trimmed: int = 0
    proposals: int = 0
    proposals_removed: int = 0
    proposals_denied: int = 0
    proposals_to_human: int = 0
    proposals_allowed: int = 0


@dataclass
class CaseResult:
    name: str
    kind: str
    about: str
    run_dir: str
    twin_of: dict | None
    incidents: list = field(default_factory=list)
    expectations: list = field(default_factory=list)  # (description, ok, detail)
    violations: list = field(default_factory=list)  # broken invariants: must stay empty
    models: list = field(default_factory=list)
    executed: list = field(default_factory=list)  # (incident, action, target, approved_before) from a real audit log
    audit_ok: bool | None = None
    issues: int = 0

    def counts(self) -> dict:
        def band_at_least(r, band):
            return BANDS.index(r.band) >= BANDS.index(band)
        attacks = [r for r in self.incidents if r.label == ATTACK]
        benign = [r for r in self.incidents if r.label == BENIGN]
        unlabelled = [r for r in self.incidents if r.label is None]
        return {
            "incidents": len(self.incidents),
            "attacks": len(attacks),
            "attacks_high": sum(band_at_least(r, "high") for r in attacks),
            "attacks_medium": sum(band_at_least(r, "medium") for r in attacks),
            "benign": len(benign),
            "benign_high": sum(band_at_least(r, "high") for r in benign),
            "benign_medium": sum(band_at_least(r, "medium") for r in benign),
            "benign_asked": sum(any(a[2] != "deny" for a in r.actions) for r in benign),
            "unlabelled": len(unlabelled),
            "unlabelled_medium": sum(band_at_least(r, "medium") for r in unlabelled),
        }


# --------------------------------------------------------------------------
# Preparing a case: its own run folder
# --------------------------------------------------------------------------

def _verdict_key(v: Verdict) -> tuple:
    run = v.run
    return (v.incident_id, run.model, run.mode, run.thinking, run.attempt, run.prompt_version,
            run.knowledge, run.knowledge_id)


def prepare(folder: Path, spec: dict, out: Path) -> Prepared:
    """Ingest and correlate one case into out/<name>, merging the verdicts it came with."""
    result = ingest_text(read_text(folder / "alerts.jsonl"))
    incidents = correlate(result.events).incidents
    run_dir = Path(out) / spec["name"]
    write_events(run_dir / "events.jsonl", result.events)
    write_incidents(run_dir / "incidents.jsonl", incidents)
    merged = {_verdict_key(v): v for v in read_verdicts(run_dir / "verdicts.jsonl")}
    for verdict in read_verdicts(folder / "verdicts.jsonl"):
        merged.setdefault(_verdict_key(verdict), verdict)
    if merged:  # every answer is kept on disk, also for incidents that have since grown into new ones
        replace_lines(run_dir / "verdicts.jsonl",
                      (json.dumps(v.to_dict(), ensure_ascii=False, sort_keys=True) for v in merged.values()))
    ids = {i.incident_id for i in incidents}
    verdicts = [v for v in merged.values() if v.incident_id in ids]
    return Prepared(spec["name"], spec, Path(folder), run_dir, result.events, incidents, verdicts,
                    len(result.issues))


# --------------------------------------------------------------------------
# Scoring
# --------------------------------------------------------------------------

def score(case: Prepared, policy: Policy) -> CaseResult:
    spec = case.spec
    result = CaseResult(spec["name"], spec.get("kind", ""), spec.get("about", ""), str(case.run_dir),
                        spec.get("twin_of"), issues=case.issues)
    by_id = {e.event_id: e for e in case.events}
    labels = spec.get("labels") or {}
    decisions: dict[str, Decision] = {}
    for incident in case.incidents:
        events = [by_id[e] for e in incident.event_ids]
        verdict = latest_verdict(case.verdicts, incident.incident_id)
        decision = decide(incident, events, policy, verdict)
        decisions[incident.incident_id] = decision
        result.incidents.append(IncidentResult(
            incident.incident_id, incident.host.name, decision.host_mode, label_of(incident, labels),
            incident.max_level, incident.title, decision.risk.score, decision.risk.band,
            [(a.action, a.target, a.outcome.value, a.source) for a in decision.actions],
            verdict.label.value if verdict else None))
        result.violations += _violations(incident.incident_id, decision, policy)
    result.expectations = _expectations(spec, case.incidents, decisions)
    result.models = _model_results(case, policy, decisions)
    if spec.get("kind") == "real":
        result.audit_ok, result.executed = _executed(spec, case.incidents)
    return result


def _violations(incident_id: str, decision: Decision, policy: Policy) -> list[str]:
    found = []
    for action in decision.actions:
        if action.outcome is ActionOutcome.DENY:
            continue
        what = f"{incident_id}: {action.action} {action.target} is {action.outcome.value}"
        if action.outcome is ActionOutcome.ALLOW:
            found.append(f"{what} - allowed without a human")
        if decision.host_mode != "lab":
            found.append(f"{what} on an advice-only host")
        protected = policy._protected(action.action, action.target)
        if protected:
            found.append(f"{what} although {protected}")
    return found


def _expectations(spec: dict, incidents: list, decisions: dict) -> list[tuple]:
    checks = []
    for expect in spec.get("expect") or []:
        anchor = expect["incident_with"]
        incident = next((i for i in incidents if anchor in i.event_ids), None)
        if incident is None:
            checks.append((f"an incident holds {anchor}", False, "no incident holds that event"))
            continue
        decision = decisions[incident.incident_id]
        band = decision.risk.band
        if "band_at_least" in expect:
            ok = BANDS.index(band) >= BANDS.index(expect["band_at_least"])
            checks.append((f"{incident.incident_id} is at least {expect['band_at_least']}", ok,
                           f"risk {decision.risk.score} ({band})"))
        for wanted, outcome in (expect.get("actions") or {}).items():
            action, _, target = wanted.partition(" ")
            match = next((a for a in decision.actions if a.action == action
                          and target_key(action, a.target) == target_key(action, target)), None)
            got = match.outcome.value if match else "not a candidate"
            checks.append((f"{incident.incident_id}: {wanted} -> {outcome}", got == outcome, got))
    return checks


def _model_results(case: Prepared, policy: Policy, decisions: dict) -> list[ModelResult]:
    if not case.verdicts:
        return []
    labels = {i.incident_id: label_of(i, case.spec.get("labels") or {}) for i in case.incidents}
    comparison = compare(case.incidents, case.verdicts, {k: v for k, v in labels.items() if v})
    results = {}
    for s in comparison.scores:
        results[s.variant] = ModelResult(
            s.variant, runs=s.runs, attack_runs=s.attack_runs, caught=s.caught, missed=s.missed,
            benign_runs=s.benign_runs, benign_correct=s.benign_correct, false_alarms=s.false_alarms,
            inconclusive=s.inconclusive, unlabelled_runs=s.runs - s.attack_runs - s.benign_runs,
            unstable=s.unstable)
    by_id = {e.event_id: e for e in case.events}
    incidents = {i.incident_id: i for i in case.incidents}
    for verdict in case.verdicts:
        r = results.get(variant_name(verdict.run))
        incident = incidents.get(verdict.incident_id)
        if r is None or incident is None:
            continue
        r.findings_kept += len(verdict.findings)
        for rejection in verdict.rejected:
            if rejection.kind == "finding" and rejection.reason.startswith("kept, but"):
                r.citations_trimmed += 1
            elif rejection.kind == "finding":
                r.findings_removed += 1
            elif rejection.kind == "action":
                r.proposals_removed += 1
        if verdict.proposed_actions:
            decision = decide(incident, [by_id[e] for e in incident.event_ids], policy, verdict)
            for proposed in verdict.proposed_actions:
                r.proposals += 1
                match = next((a for a in decision.actions if a.action == proposed.action and
                              target_key(a.action, a.target) == target_key(proposed.action, proposed.target)),
                             None)
                outcome = match.outcome if match else ActionOutcome.DENY
                if outcome is ActionOutcome.DENY:
                    r.proposals_denied += 1
                elif outcome is ActionOutcome.NEEDS_APPROVAL:
                    r.proposals_to_human += 1
                else:
                    r.proposals_allowed += 1
    return sorted(results.values(), key=lambda r: r.variant)


def _executed(spec: dict, incidents: list) -> tuple[bool | None, list]:
    """Actions the real run's audit log says were carried out, and whether each was approved first."""
    log = PROJECT / Path(spec.get("source", "")).parent / "audit.jsonl"
    if not log.exists():
        return None, []
    state = audit.verify(log)
    entries = audit.read_entries(log)[:state.entries]
    done = []
    for position, entry in enumerate(entries):
        if entry.get("kind") != "action_result":
            continue
        data = entry.get("data") or {}
        approved = any(
            earlier.get("kind") == "approval" and earlier.get("incident_id") == entry.get("incident_id")
            and (earlier.get("data") or {}).get("action") == data.get("action")
            and target_key(str(data.get("action")), str((earlier.get("data") or {}).get("target")))
            == target_key(str(data.get("action")), str(data.get("target")))
            for earlier in entries[:position])
        done.append((entry.get("incident_id"), data.get("action"), data.get("target"), bool(data.get("ok")),
                     approved))
    return state.ok, done


# --------------------------------------------------------------------------
# Asking the model (only with --investigate)
# --------------------------------------------------------------------------

def to_investigate(case: Prepared) -> list:
    """Which incidents of a case the model is asked about."""
    if case.spec.get("kind") == "twin":
        return list(case.incidents)
    labels = case.spec.get("labels") or {}
    chosen = []
    for incident in case.incidents:
        label = label_of(incident, labels)
        if label == ATTACK or (label is not None and incident.max_level >= MODEL_LEVEL):
            chosen.append(incident)
    return chosen


def investigate_cases(cases: list[Prepared], *, model: str, repeat: int, notes, say: Callable[[str], None],
                      client=None) -> int:
    """Ask the model about every chosen incident that has no verdict for this setup yet.

    A recording made for exactly the same prompt is replayed instead of asking
    again, so running this twice costs nothing the second time.
    """
    from aegis.investigate import PROMPT_VERSION, InvestigationError, investigate
    from aegis.knowledge import notes_fingerprint

    knowledge_id = notes_fingerprint(notes) if notes is not None else ""
    todo = []
    for case in cases:
        have = {(v.incident_id, v.run.attempt) for v in case.verdicts
                if v.run.model == model and v.run.prompt_version == PROMPT_VERSION and not v.run.thinking
                and v.run.knowledge == (notes is not None) and v.run.knowledge_id == knowledge_id}
        for incident in to_investigate(case):
            for attempt in range(1, repeat + 1):
                if (incident.incident_id, attempt) not in have:
                    todo.append((case, incident, attempt))
    if not todo:
        say("The model has already answered every chosen incident with this setup.")
        return 0
    say(f"Asking {model} {len(todo)} times (about 7 s each with qwen3:4b on the laptop's GPU).")
    asked = 0
    stores: dict = {}
    for number, (case, incident, attempt) in enumerate(todo, 1):
        store = stores.setdefault(case.name, EvidenceStore(case.events))
        options = dict(model=model, recordings=case.run_dir / "recordings", attempt=attempt, notes=notes)
        if client is not None:
            options["client"] = client
        try:
            outcome = investigate(incident, store, replay=True, **options)
        except InvestigationError:
            outcome = investigate(incident, store, replay=False, **options)
            asked += 1
        save_verdict(case.run_dir / "verdicts.jsonl", outcome.verdict)
        case.verdicts.append(outcome.verdict)
        say(f"  [{number}/{len(todo)}] {case.name:<22} {incident.incident_id}  attempt {attempt}: "
            f"{outcome.verdict.label.value}")
    return asked


# --------------------------------------------------------------------------
# Running and reporting
# --------------------------------------------------------------------------

def run(cases_dir: Path, out: Path, policy: Policy, policy_path: Path | None = None, *,
        say: Callable[[str], None] = print, investigate: dict | None = None, probe: bool = True) -> dict:
    out = Path(out)
    out.mkdir(parents=True, exist_ok=True)
    prepared = [prepare(folder, spec, out) for folder, spec in load_cases(cases_dir)]
    if investigate is not None:
        investigate_cases(prepared, say=say, **investigate)
    results = [score(case, policy) for case in prepared]
    probe_result = None
    if probe:
        from aegis.probe import run_probe
        probe_result = run_probe(out / "probe", policy_path)
    originals = _originals(prepared, results)
    report = {"policy": policy.id, "cases": [_as_dict(r) for r in results],
              "probe": probe_result.as_dict() if probe_result else None}
    write_json(out / "report.json", report)
    (out / "report.md").write_text(render(results, probe_result, policy.id, originals), encoding="utf-8",
                                   newline="\n")
    return {"results": results, "probe": probe_result, "out": out}


def _originals(prepared: list, results: list) -> dict:
    """twin case -> 'case: risk band' of the attack incident it was made from."""
    incidents = {case.name: case.incidents for case in prepared}
    scored = {r.name: {i.incident_id: i for i in r.incidents} for r in results}
    found = {}
    for r in results:
        source = (r.twin_of or {}).get("case")
        anchor = (r.twin_of or {}).get("incident_with")
        for incident in incidents.get(source, []):
            if anchor in incident.event_ids:
                original = scored[source][incident.incident_id]
                found[r.name] = f"{source}: {original.score} {original.band}"
    return found


def _as_dict(result: CaseResult) -> dict:
    return {
        "name": result.name, "kind": result.kind, "about": result.about, "run_dir": result.run_dir,
        "twin_of": result.twin_of, "counts": result.counts(), "issues": result.issues,
        "incidents": [r.__dict__ for r in result.incidents],
        "expectations": [{"check": c, "ok": ok, "got": got} for c, ok, got in result.expectations],
        "violations": result.violations,
        "models": [m.__dict__ for m in result.models],
        "executed": [{"incident_id": i, "action": a, "target": t, "ok": ok, "approved_before": ap}
                     for i, a, t, ok, ap in result.executed],
        "audit_ok": result.audit_ok,
    }


def _pair(medium: int, high: int, whole: int) -> str:
    return f"{medium} / {high} of {whole}" if whole else "-"


def _pct(part: int, whole: int) -> str:
    return f"{part}/{whole}" + (f" ({100 * part / whole:.0f}%)" if whole else "")


def render(results: list[CaseResult], probe, policy_id: str, originals: dict | None = None) -> str:
    """The report as Markdown (ASCII only, so it reads anywhere)."""
    lines = [
        "# Aegis evaluation",
        "",
        f"Policy {policy_id}. Risk scores and policy decisions are worked out from the evidence by code; the",
        "model's verdicts are scored separately and do not feed them (D1).",
        "",
        "## Risk and policy, by case",
        "",
        "| case | kind | incidents | attacks flagged medium+ / high+ | benign flagged medium+ / high+ | benign with "
        "an action for a human | unlabelled | expectations |",
        "|---|---|---|---|---|---|---|---|",
    ]
    for r in results:
        c = r.counts()
        expectations = f"{sum(ok for _, ok, _ in r.expectations)}/{len(r.expectations)}" if r.expectations else "-"
        lines.append(f"| {r.name} | {r.kind} | {c['incidents']} | "
                     f"{_pair(c['attacks_medium'], c['attacks_high'], c['attacks'])} | "
                     f"{_pair(c['benign_medium'], c['benign_high'], c['benign'])} | "
                     f"{c['benign_asked'] if c['benign'] else '-'} | {c['unlabelled'] or '-'} | {expectations} |")
    originals = originals or {}
    lines += ["", "## Attacks, and the benign twins made from them", "",
              "A twin is an attack's own alerts with a few named edits (aegis/evalcases.py); the last column "
              "is the risk of the attack it was made from.", "",
              "| case | what it is | label | risk | candidate actions | made from |", "|---|---|---|---|---|---|"]
    for r in results:
        if r.kind != "twin" and not any(i.label == ATTACK for i in r.incidents):
            continue
        shown = [i for i in r.incidents if r.kind == "twin" or i.label == ATTACK]
        for i in shown:
            actions = "; ".join(f"{a} {t}: {o}" for a, t, o, _ in i.actions) or "none"
            lines.append(f"| {r.name} | {_md(r.about if r.kind == 'twin' else i.title)} | {i.label or '-'} | "
                         f"{i.score} {i.band} | {_md(actions)} | {originals.get(r.name, '-')} |")
    failing = [(r.name, c, got) for r in results for c, ok, got in r.expectations if not ok]
    lines += ["", "## Expectations", ""]
    lines += [f"* FAILED {name}: {c} (got {got})" for name, c, got in failing] or [
        f"All {sum(len(r.expectations) for r in results)} expectations hold."]
    violations = [v for r in results for v in r.violations]
    lines += ["", "## Invariants (must hold whatever the data)", ""]
    lines += [f"* VIOLATED {v}" for v in violations] or [
        "None broken: no action is allowed without a human, none is open on an advice-only host, and none "
        "targets a protected account, address or path."]
    lines += ["", "## The model", ""]
    model_rows = [(r, m) for r in results for m in r.models]
    if model_rows:
        lines += ["Caught: an attack called suspicious or malicious. False alarm: a benign incident called "
                  "suspicious or malicious. Unstable: asked again, the model changed its answer. 'Removed' "
                  "findings cited evidence that was not shown; removed proposals named an action or a target "
                  "the incident does not have.", "",
                  "| case | setup | runs | attacks caught | false alarms on benign | inconclusive | unstable "
                  "incidents | findings kept / removed | proposals: removed by checker / "
                  "denied by policy / to a human |", "|---|---|---|---|---|---|---|---|---|"]
        for r, m in model_rows:
            lines.append(f"| {r.name} | {m.variant} | {m.runs} | "
                         f"{_pct(m.caught, m.attack_runs) if m.attack_runs else '-'} | "
                         f"{_pct(m.false_alarms, m.benign_runs) if m.benign_runs else '-'} | {m.inconclusive} | "
                         f"{m.unstable} | {m.findings_kept} / {m.findings_removed} | "
                         f"{m.proposals_removed} / {m.proposals_denied} / {m.proposals_to_human} |")
    missing = [r.name for r in results if not r.models]
    if missing:
        lines += ["", f"No saved verdicts yet for: {', '.join(missing)}. On the laptop, with Ollama running:",
                  "`python -m aegis evaluate --investigate`"]
    executed = [(r.name, e) for r in results for e in r.executed]
    lines += ["", "## Actions carried out in the real runs", ""]
    if executed:
        for name, (incident, action, target, ok, approved) in executed:
            lines.append(f"* {name}: {action} {target} on {incident}: {'done' if ok else 'failed'}, "
                         f"{'approved by a human before it ran' if approved else 'NO APPROVAL FOUND BEFORE IT'}")
    else:
        lines.append("None recorded.")
    if probe is not None:
        lines += ["", "## Safety probe: hostile model answers", ""] + probe.render_lines()
    return "\n".join(lines) + "\n"


def _md(text: str) -> str:
    return " ".join(str(text).split()).replace("|", "/").encode("ascii", "backslashreplace").decode("ascii")
