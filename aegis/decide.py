"""Decide: risk score + policy -> one Decision per incident.

Candidate actions come from two places: the risk rules' own suggestions, and
the actions the model proposed in its verdict. Both go through exactly the
same policy checks; where they come from is recorded and changes nothing.
The model's verdict label is copied into the Decision for display and is not
read by anything that decides.
"""

from __future__ import annotations

from typing import Iterable

from aegis.compare import variant_name
from aegis.contracts.decision import ActionDecision, Decision
from aegis.contracts.event import Event
from aegis.contracts.incident import Incident
from aegis.contracts.verdict import Verdict
from aegis.evidence import target_key
from aegis.policy import Policy
from aegis.risk import assess


def decide(incident: Incident, events: Iterable[Event], policy: Policy, verdict: Verdict | None = None) -> Decision:
    events = list(events)
    assessment = assess(incident, events)
    band = assessment.risk.band

    candidates: dict[tuple, dict] = {}
    for suggestion in assessment.suggestions:
        key = (suggestion.action, target_key(suggestion.action, suggestion.target) or suggestion.target.lower())
        candidates[key] = {"action": suggestion.action, "target": suggestion.target,
                           "sources": {"rules"}, "evidence": list(suggestion.evidence)}
    if verdict is not None:
        for proposed in verdict.proposed_actions:
            key = (proposed.action, target_key(proposed.action, proposed.target) or proposed.target.lower())
            entry = candidates.setdefault(key, {"action": proposed.action, "target": proposed.target,
                                                "sources": set(), "evidence": []})
            entry["sources"].add("model")
            entry["evidence"] += [e for e in proposed.evidence if e not in entry["evidence"]]

    decisions = []
    for entry in candidates.values():
        outcome, reasons, target = policy.evaluate(entry["action"], entry["target"], incident, events, band)
        source = "+".join(sorted(entry["sources"], key=["rules", "model"].index))
        decisions.append(ActionDecision(entry["action"], target, source, outcome, reasons, tuple(entry["evidence"])))
    decisions.sort(key=lambda d: (["needs_approval", "allow", "deny"].index(d.outcome.value), d.action, d.target))

    mode, _ = policy.host_mode(incident.host)
    return Decision(
        incident_id=incident.incident_id,
        host=incident.host,
        host_mode=mode,
        policy_id=policy.id,
        risk=assessment.risk,
        actions=tuple(decisions),
        model_label=verdict.label.value if verdict else "",
        model_run=variant_name(verdict.run) if verdict else "",
    )


def latest_verdict(verdicts: Iterable[Verdict], incident_id: str) -> Verdict | None:
    """The most recent saved verdict for an incident, if any."""
    mine = [v for v in verdicts if v.incident_id == incident_id]
    return max(mine, key=lambda v: (v.created_at, v.run.attempt)) if mine else None
