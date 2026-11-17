"""The Decision contract: what code decided about one incident, and why.

A Decision holds the risk score - computed from the evidence by fixed rules,
each point with its reason and the events behind it - and, for every
candidate action, what the policy allows: ``allow``, ``needs_approval`` or
``deny``, with the reasons.

The model's verdict is copied in only so a human can see it next to the
score. It is not an input to the score or to any action decision.

There is deliberately no timestamp: the same incident, events and policy
always give an identical Decision. When something was decided is recorded by
the audit log (milestone 5).
"""

from __future__ import annotations

from dataclasses import dataclass, fields
from enum import Enum
from typing import Any, Mapping

from aegis.contracts.event import _EVENT_ID_RE, ContractError, Host, _build, _plain
from aegis.contracts.incident import _INCIDENT_ID_RE, _list, _strings
from aegis.contracts.verdict import ACTION_CATALOG

DECISION_SCHEMA_VERSION = 1

BANDS = ("low", "medium", "high", "critical")
HOST_MODES = ("advice", "lab")
ACTION_SOURCES = ("rules", "model", "rules+model")


def band_for(score: int) -> str:
    if score >= 75:
        return "critical"
    if score >= 50:
        return "high"
    if score >= 25:
        return "medium"
    return "low"


class ActionOutcome(str, Enum):
    ALLOW = "allow"  # may run without a human (no action is set up this way by default)
    NEEDS_APPROVAL = "needs_approval"  # may run only after a human approves this exact action
    DENY = "deny"  # will not run


@dataclass(frozen=True)
class RiskFactor:
    id: str
    points: int
    reason: str
    evidence: tuple[str, ...]  # event ids


@dataclass(frozen=True)
class RiskScore:
    score: int  # 0-100: the sum of the factors' points, capped
    band: str
    factors: tuple[RiskFactor, ...]

    def __post_init__(self) -> None:
        total = sum(factor.points for factor in self.factors)
        if self.score != max(0, min(100, total)):
            raise ContractError(f"risk score {self.score} is not the sum of its factors ({total}, capped 0-100)")
        if self.band != band_for(self.score):
            raise ContractError(f"risk band {self.band!r} does not match score {self.score}")
        for factor in self.factors:
            if not isinstance(factor, RiskFactor) or not factor.id or not factor.reason:
                raise ContractError("a risk factor needs an id and a reason")
            if isinstance(factor.points, bool) or not isinstance(factor.points, int):
                raise ContractError("risk points must be whole numbers")
            _check_ids(factor.evidence, f"risk factor {factor.id}")


@dataclass(frozen=True)
class ActionDecision:
    action: str
    target: str
    source: str  # who suggested it: the risk rules, the model, or both
    outcome: ActionOutcome
    reasons: tuple[str, ...]
    evidence: tuple[str, ...]

    def __post_init__(self) -> None:
        if self.action not in ACTION_CATALOG:
            raise ContractError(f"action not in the catalog: {self.action!r}")
        if not self.target:
            raise ContractError("an action needs a target")
        if self.source not in ACTION_SOURCES:
            raise ContractError(f"unknown action source {self.source!r}")
        if not isinstance(self.outcome, ActionOutcome):
            raise ContractError("outcome must be an ActionOutcome")
        if not self.reasons:
            raise ContractError("every action decision needs at least one reason")
        _check_ids(self.evidence, f"action {self.action}")


@dataclass(frozen=True)
class Decision:
    incident_id: str
    host: Host
    host_mode: str  # from the policy: "advice" denies everything, "lab" may act
    policy_id: str  # fingerprint of the policy file used
    risk: RiskScore
    actions: tuple[ActionDecision, ...] = ()
    model_label: str = ""  # the model's verdict, for display only
    model_run: str = ""  # which model and setup said it
    schema_version: int = DECISION_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if not isinstance(self.incident_id, str) or not _INCIDENT_ID_RE.match(self.incident_id):
            raise ContractError(f"bad incident_id: {self.incident_id!r}")
        if self.host_mode not in HOST_MODES:
            raise ContractError(f"unknown host mode {self.host_mode!r}")
        if self.host_mode == "advice" and any(a.outcome is not ActionOutcome.DENY for a in self.actions):
            raise ContractError("on an advice-only host every action must be denied")
        if not self.policy_id:
            raise ContractError("policy_id is required")
        if self.schema_version != DECISION_SCHEMA_VERSION:
            raise ContractError(f"unsupported decision schema_version {self.schema_version!r}")

    def to_dict(self) -> dict[str, Any]:
        return _plain(self)

    @classmethod
    def from_dict(cls, data: Any) -> "Decision":
        if not isinstance(data, Mapping):
            raise ContractError("decision must be a JSON object")
        unknown = sorted(set(data) - {f.name for f in fields(cls)})
        if unknown:
            raise ContractError(f"unknown decision field(s): {', '.join(unknown)}")
        try:
            risk = data["risk"]
            return cls(
                incident_id=data["incident_id"],
                host=_build(Host, data["host"]),
                host_mode=data["host_mode"],
                policy_id=data["policy_id"],
                risk=RiskScore(
                    score=risk["score"],
                    band=risk["band"],
                    factors=tuple(_build(RiskFactor, f) for f in _list(risk.get("factors"), "factors")),
                ),
                actions=tuple(_action(item) for item in _list(data.get("actions"), "actions")),
                model_label=data.get("model_label", ""),
                model_run=data.get("model_run", ""),
                schema_version=data.get("schema_version", DECISION_SCHEMA_VERSION),
            )
        except ContractError:
            raise
        except (KeyError, TypeError, ValueError, AttributeError) as exc:
            raise ContractError(f"invalid decision: {exc}") from exc


def _action(data: Any) -> ActionDecision:
    if not isinstance(data, Mapping):
        raise ContractError("action decision must be a JSON object")
    expected = {f.name for f in fields(ActionDecision)}
    if set(data) != expected:
        raise ContractError(f"action decision needs exactly: {', '.join(sorted(expected))}")
    return ActionDecision(
        action=data["action"], target=data["target"], source=data["source"],
        outcome=ActionOutcome(data["outcome"]),
        reasons=_strings(data["reasons"], "reasons"), evidence=_strings(data["evidence"], "evidence"),
    )


def _check_ids(evidence: Any, what: str) -> None:
    if not isinstance(evidence, tuple):
        raise ContractError(f"{what}: evidence must be a list of event ids")
    for event_id in evidence:
        if not isinstance(event_id, str) or not _EVENT_ID_RE.match(event_id):
            raise ContractError(f"{what}: not an event id: {event_id!r}")
