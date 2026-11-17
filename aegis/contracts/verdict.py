"""The Verdict contract.

A Verdict is what the AI investigator concluded about one incident, *after*
deterministic code has checked it. The model writes; the checker decides what
survives:

  * every finding must cite events that exist in the evidence it was shown
  * a proposed action must come from the fixed catalog and name a target that
    appears in the incident
  * anything that fails is moved to ``rejected`` with the reason - it is never
    silently dropped, and never silently kept
  * a verdict left with no supported finding becomes ``inconclusive``

A Verdict is advice. It does not feed the risk score and cannot trigger an
action: the policy engine (milestone 4) decides, from evidence.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, fields
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Mapping

from aegis.contracts.event import _EVENT_ID_RE, ContractError, _build, _plain, parse_ts
from aegis.contracts.incident import _INCIDENT_ID_RE, _list, _strings

VERDICT_SCHEMA_VERSION = 1

# What the model may propose. Proposing is all it can do.
ACTION_CATALOG = ("lock_account", "block_ip", "kill_process", "quarantine_file", "isolate_host")

_TECHNIQUE_RE = re.compile(r"^T\d{4}(\.\d{3})?$")
REJECTION_KINDS = ("answer", "verdict", "finding", "technique", "action")


class VerdictLabel(str, Enum):
    MALICIOUS = "malicious"  # the evidence shows an attack or compromise
    SUSPICIOUS = "suspicious"  # not explained as normal activity; needs a human
    BENIGN = "benign"  # the evidence shows normal activity
    INCONCLUSIVE = "inconclusive"  # not enough evidence, or no usable answer


class Confidence(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


@dataclass(frozen=True)
class Finding:
    claim: str
    evidence: tuple[str, ...]  # event ids that support the claim


@dataclass(frozen=True)
class ProposedAction:
    action: str  # one of ACTION_CATALOG
    target: str
    reason: str
    evidence: tuple[str, ...]


@dataclass(frozen=True)
class Reasoning:
    """The model's working, written before it chose a verdict.

    Free text, AI-written and not checkable against evidence. It is kept so a
    human can see how the verdict was reached - and where it went wrong.
    """

    what_happened: str = ""
    started_by: str = ""
    innocent_explanation: str = ""
    attack_explanation: str = ""
    against_innocent: str = ""  # evidence the innocent explanation cannot account for


@dataclass(frozen=True)
class Rejection:
    """Something the model wrote that the checker removed, and why."""

    kind: str  # one of REJECTION_KINDS
    text: str
    reason: str


@dataclass(frozen=True)
class ModelRun:
    """How the answer was produced - enough to reproduce or compare it."""

    model: str
    mode: str  # "single_call" for now
    thinking: bool
    prompt_sha256: str
    replayed: bool = False  # True if the answer came from a recording
    attempt: int = 1  # 1, 2, 3 ... when the same question is asked several times
    prompt_version: int = 0  # which version of the instructions was used
    knowledge: bool = False  # True if operator knowledge notes were in use
    knowledge_id: str = ""  # which version of the notes file (see knowledge.notes_fingerprint)
    duration_ms: int | None = None
    prompt_tokens: int | None = None
    output_tokens: int | None = None


@dataclass(frozen=True)
class Verdict:
    incident_id: str
    label: VerdictLabel
    confidence: Confidence
    summary: str
    run: ModelRun
    created_at: datetime
    reasoning: Reasoning = Reasoning()
    findings: tuple[Finding, ...] = ()
    technique_ids: tuple[str, ...] = ()
    proposed_actions: tuple[ProposedAction, ...] = ()
    rejected: tuple[Rejection, ...] = ()
    notes_shown: tuple[str, ...] = ()  # ids of the knowledge notes shown for this incident
    schema_version: int = VERDICT_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if not isinstance(self.incident_id, str) or not _INCIDENT_ID_RE.match(self.incident_id):
            raise ContractError(f"bad incident_id: {self.incident_id!r}")
        if not isinstance(self.label, VerdictLabel):
            raise ContractError("label must be a VerdictLabel")
        if not isinstance(self.confidence, Confidence):
            raise ContractError("confidence must be a Confidence")
        if not isinstance(self.summary, str):
            raise ContractError("summary must be text")
        if not isinstance(self.reasoning, Reasoning) or not all(
            isinstance(getattr(self.reasoning, f.name), str) for f in fields(Reasoning)
        ):
            raise ContractError("reasoning must be a Reasoning made of text")
        if not isinstance(self.run, ModelRun) or not self.run.model:
            raise ContractError("run with a model name is required")
        attempt = self.run.attempt
        if isinstance(attempt, bool) or not isinstance(attempt, int) or attempt < 1:
            raise ContractError(f"run attempt must be a whole number from 1, got {attempt!r}")
        if not isinstance(self.created_at, datetime) or self.created_at.utcoffset() != timedelta(0):
            raise ContractError("created_at must be an aware UTC datetime")
        for finding in self.findings:
            if not isinstance(finding, Finding) or not finding.claim.strip():
                raise ContractError("a finding needs a claim")
            _check_evidence(finding.evidence, "finding")
        if self.label is not VerdictLabel.INCONCLUSIVE and not self.findings:
            raise ContractError(f"a {self.label.value} verdict needs at least one supported finding")
        for action in self.proposed_actions:
            if not isinstance(action, ProposedAction) or action.action not in ACTION_CATALOG:
                raise ContractError(f"action is not in the catalog: {getattr(action, 'action', action)!r}")
            if not action.target.strip():
                raise ContractError("a proposed action needs a target")
            _check_evidence(action.evidence, "proposed action")
        if self.proposed_actions and self.label not in (VerdictLabel.MALICIOUS, VerdictLabel.SUSPICIOUS):
            raise ContractError("only a malicious or suspicious verdict can propose actions")
        for technique in self.technique_ids:
            if not isinstance(technique, str) or not _TECHNIQUE_RE.match(technique):
                raise ContractError(f"not an ATT&CK technique id: {technique!r}")
        for rejection in self.rejected:
            if not isinstance(rejection, Rejection) or rejection.kind not in REJECTION_KINDS:
                raise ContractError("rejected entries must be Rejection objects of a known kind")
        if self.schema_version != VERDICT_SCHEMA_VERSION:
            raise ContractError(
                f"unsupported verdict schema_version {self.schema_version!r} "
                f"(this build understands {VERDICT_SCHEMA_VERSION})"
            )

    def to_dict(self) -> dict[str, Any]:
        return _plain(self)

    @classmethod
    def from_dict(cls, data: Any) -> "Verdict":
        if not isinstance(data, Mapping):
            raise ContractError("verdict must be a JSON object")
        allowed = {f.name for f in fields(cls)}
        unknown = sorted(set(data) - allowed)
        if unknown:
            raise ContractError(f"unknown verdict field(s): {', '.join(unknown)}")
        for key in ("incident_id", "label", "confidence", "summary", "run", "created_at"):
            if key not in data:
                raise ContractError(f"missing required verdict field: {key}")
        try:
            return cls(
                incident_id=data["incident_id"],
                label=VerdictLabel(data["label"]),
                confidence=Confidence(data["confidence"]),
                summary=data["summary"],
                run=_build(ModelRun, data["run"]),
                created_at=parse_ts(data["created_at"]),
                reasoning=_build(Reasoning, data.get("reasoning") or {}),
                findings=tuple(_build(Finding, item) for item in _list(data.get("findings"), "findings")),
                technique_ids=_strings(data.get("technique_ids"), "technique_ids"),
                proposed_actions=tuple(
                    _build(ProposedAction, item)
                    for item in _list(data.get("proposed_actions"), "proposed_actions")
                ),
                rejected=tuple(_build(Rejection, item) for item in _list(data.get("rejected"), "rejected")),
                notes_shown=_strings(data.get("notes_shown"), "notes_shown"),
                schema_version=data.get("schema_version", VERDICT_SCHEMA_VERSION),
            )
        except ContractError:
            raise
        except (TypeError, ValueError, AttributeError) as exc:
            raise ContractError(f"invalid verdict: {exc}") from exc


def _check_evidence(evidence: Any, what: str) -> None:
    if not isinstance(evidence, tuple) or not evidence:
        raise ContractError(f"a {what} must cite at least one event")
    for event_id in evidence:
        if not isinstance(event_id, str) or not _EVENT_ID_RE.match(event_id):
            raise ContractError(f"a {what} cites something that is not an event id: {event_id!r}")
