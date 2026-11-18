"""Agent mode: the model opens the evidence itself, one read-only tool at a time.

The single call (aegis.investigate) shows the model the whole evidence pack
at once. Here the model starts from the incident's outline - the rules that
fired and the first line of each event - and opens the rest itself, one
choice per turn:

    E3 (or G2)      everything the pack shows about one event (or one group)
    where_from      which programs outside the incident started its processes
    nearby_events   the other events on the host just before and after (C1 ...)
    how_common      how often these rules and programs appear on the host
    answer          stop looking and write the answer

Each turn's choice comes from a list of what is still unopened (agent2,
D45): the first version let the model name a tool and a label separately,
and on its first real run it asked for nearby_events "of E6" ten times.

Every tool returns a section of the very pack the single call is given
(aegis.evidence.PackParts), word for word and under the same labels, so the
two modes differ only in who chooses what to read, and in what order.

No tool changes anything. Each one returns text that code has already
built from the loaded events; there is no other function the model can
reach. The step's JSON schema lists only what is still unopened, code checks
the choice again, and anything else gets a refusal and costs the model one
of its tool calls. At most MAX_TOOL_CALLS are allowed.

The final answer has the single call's shape and goes through the single
call's checker (investigate.check_answer) unchanged. Only evidence the
model opened counts as shown: a finding citing an event it saw only as a
line of the outline is removed, like any citation of evidence never shown.
"""

from __future__ import annotations

import dataclasses
import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Sequence

from aegis.contracts.event import format_ts, parse_ts
from aegis.contracts.incident import Incident
from aegis.contracts.verdict import ModelRun, Rejection
from aegis.evidence import NOTES_SUBTITLE, NOTES_TITLE, ORIGINS_TITLE, EvidencePack, EvidenceStore, PackParts
from aegis.investigate import (
    ANSWER_SCHEMA,
    CHARS_PER_TOKEN,
    DEFAULT_NUM_CTX,
    PROMPT_VERSION,
    SYSTEM_PROMPT,
    Investigation,
    InvestigationError,
    _clip,
    _int_or_none,
    _nanos_to_ms,
    _parse_json_object,
    check_answer,
    parts_for_model,
    prompt_hash,
)
from aegis.knowledge import Note, notes_fingerprint
from aegis.llm import LLMError, chat

# The version of the agent's protocol (its instructions, tools and messages). The
# rules for judging evidence are the single call's, so prompt_version stays theirs.
MODE = "agent2"  # agent1 (D44) named a tool and a label separately and looped on its first run (D45)
MAX_TOOL_CALLS = 10
STEP_PREDICT = 256  # output allowance for one step: a sentence and a tool name
ANSWER_PREDICT = 1500  # the same allowance as the single call's answer
TOOLS = ("get_event", "where_from", "nearby_events", "how_common")
DONE = "answer"
STEP_KEY = "02_open"  # the step's choice; a request whose schema has it asks for a step


def _replace_once(text: str, old: str, new: str) -> str:
    if text.count(old) != 1:
        raise AssertionError(f"the single call's instructions changed; agent mode expects {old[:60]!r}")
    return text.replace(old, new)


_SINGLE_INTRO = """\
You are the investigation assistant inside Aegis, a security operations tool.
You are given the evidence for ONE incident from a monitored machine. Work out
what happened and decide what it most likely is.
"""

_AGENT_INTRO = f"""\
You are the investigation assistant inside Aegis, a security operations tool.
You are investigating ONE incident from a monitored machine. Work out what
happened and decide what it most likely is.

You do not see the evidence all at once. You are shown the incident's outline:
the rules that fired and one line per event. You open the evidence yourself,
one piece per turn. Each turn, choose one of these:
  E3             an event's label: everything recorded about that event
                 (where events are grouped, a group's label, such as G2)
  where_from     which programs outside the incident started its processes
  nearby_events  all the other events on this host within minutes of the
                 incident, at once (labelled C1, C2 ...)
  how_common     how often these rules and programs appear on this host
  answer         stop looking; you are then asked for your final answer
Each one can be opened once. After every result you are told what is not
opened yet. Each turn, reply with one JSON object and nothing else:
{{"01_next": "what you want to find out with this step, or why you have seen enough",
 "02_open": "E3|where_from|nearby_events|how_common|answer"}}
Only evidence you have opened can be cited: a line of the outline is not
evidence. You can open at most {MAX_TOOL_CALLS} things. Open what you need to judge
the incident, then choose answer.
"""

AGENT_SYSTEM_PROMPT = _replace_once(SYSTEM_PROMPT, _SINGLE_INTRO, _AGENT_INTRO)
AGENT_SYSTEM_PROMPT = _replace_once(
    AGENT_SYSTEM_PROMPT,
    "Only labels\n   that appear in the evidence exist.",
    "Only labels\n   of evidence you have opened count.",
)
AGENT_SYSTEM_PROMPT = _replace_once(
    AGENT_SYSTEM_PROMPT,
    "8. Answer with one JSON object and nothing else, with exactly these keys:",
    "8. When you choose answer, you are asked for your final answer: one JSON\n"
    "   object and nothing else, with exactly these keys:",
)


def step_schema(choices: Sequence[str]) -> dict:
    """One choice from what is still unopened, so the same request cannot be made twice."""
    return {
        "type": "object",
        "properties": {"01_next": {"type": "string"}, STEP_KEY: {"type": "string", "enum": list(choices)}},
        "required": ["01_next", STEP_KEY],
    }


# --------------------------------------------------------------------------
# The desk: the read-only tools over one incident's evidence
# --------------------------------------------------------------------------

@dataclass(frozen=True)
class ToolResult:
    text: str  # what the model is shown
    call: str  # how the step is recorded, e.g. "get_event E3" or "lock_account (not a tool)"
    labels: dict = field(default_factory=dict)  # labels this opens: E3 / C1 -> event id
    groups: dict = field(default_factory=dict)  # groups this opens: G2 -> event ids
    notes: tuple = ()  # operator notes this shows (PackNote)
    done: str = ""  # a block label or tool name that is now open


class Desk:
    """The agent's tools over one incident, and what the model has opened so far.

    Every tool only reads the PackParts it was given; ``use`` works out a
    result without changing anything, and ``commit`` records it as shown once
    it has really been sent to the model.
    """

    def __init__(self, parts: PackParts) -> None:
        self.parts = parts
        self.blocks = {block.label: block for block in parts.blocks}
        self.block_of = {event_id: block for block in parts.blocks for event_id in block.event_ids}
        self.event_of = {label: event_id for event_id, label in parts.label_of.items()}
        self.labels: dict[str, str] = {}
        self.groups: dict[str, tuple] = {}
        self.notes_shown: list[str] = []
        self.open: set[str] = set()
        self.texts: list[str] = []

    def available(self) -> tuple:
        return tuple(tool for tool in TOOLS if tool != "where_from" or self.parts.origins)

    def unopened(self) -> list:
        """What the model can still open: blocks (E3 or G2), then the other sections."""
        return ([block.label for block in self.parts.blocks if block.label not in self.open]
                + [tool for tool in self.available() if tool != "get_event" and tool not in self.open])

    def choose(self, choice: str) -> ToolResult:
        """A step's choice: a label opens that event or group; a name is one of the other tools."""
        text = choice.strip()
        if re.fullmatch(r"[EGCK]\d{1,6}", text.upper()):
            return self.use("get_event", text)
        return self.use(text.lower(), "")

    def outline(self, max_tools: int) -> str:
        parts = self.parts
        lines = list(parts.head)
        if parts.grouped:
            lines += ["", f"THE INCIDENT'S EVENTS, IN {len(parts.blocks)} GROUPS OF SIMILAR EVENTS (open a group with "
                          "get_event and its label, such as G1; only opened events can be cited)",
                      *parts.events_title[1:]]
            for block in parts.blocks:
                lines += block.lines[:2]
        else:
            lines += ["", "THE INCIDENT'S EVENTS, ONE LINE EACH (open one with get_event and its label; only "
                          "opened events can be cited)"]
            for block in parts.blocks:
                lines += block.lines[:1]
        if parts.hidden:
            lines.append(parts.hidden)
        lines += ["", "YOU CAN OPEN: " + ", ".join(self.unopened()) + f"; or choose {DONE}"]
        if "where_from" not in self.available():
            lines.append("(where_from is left out: no process in this incident has a known parent.)")
        lines.append(f"You can open {max_tools} things. Choose your first step.")
        text = "\n".join(lines)
        self.texts.append(text)
        return text

    def use(self, tool: str, label: str) -> ToolResult:
        tool = tool.strip()
        if tool == "get_event":
            return self._get_event(label)
        if tool not in TOOLS:
            shown = _clip(tool, 40) or "(empty)"
            return ToolResult(f"There is nothing called {shown!r} to open. You can open: "
                              f"{', '.join(self.unopened())}; or choose {DONE}.", f"{shown} (not a tool)")
        if tool in self.open:
            return ToolResult(f"{tool} is already shown above.", f"{tool} (again)")
        parts = self.parts
        if tool == "where_from":
            if not parts.origins:
                return ToolResult("where_from has nothing for this incident: no process in it has a known parent.",
                                  "where_from (nothing)", done=tool)
            return ToolResult("\n".join(("where_from", ORIGINS_TITLE, *parts.origins)), tool, done=tool)
        if tool == "nearby_events":
            lines = [line for _, _, line in parts.context] or ["(none)"]
            return ToolResult("\n".join(("nearby_events", parts.context_title, *lines)), tool,
                              labels={label: event_id for label, event_id, _ in parts.context}, done=tool)
        return ToolResult("\n".join(("how_common", parts.common_title, *parts.common)), tool, done=tool)

    def _get_event(self, label: str) -> ToolResult:
        key = label.strip().upper()
        shown = _clip(key, 20)
        if not key:
            return ToolResult("get_event needs a label, such as E1.", "get_event (no label)")
        block = self.blocks.get(key)
        if block is None and key in self.event_of:
            block = self.block_of.get(self.event_of[key])
            if block is None:
                return ToolResult(f"{shown} is in a part of this incident too large to show; it cannot be "
                                  "opened or cited.", f"get_event {shown} (not shown)")
        if block is None:
            if re.fullmatch(r"C\d+", key):
                return ToolResult(f"{shown} is one of the nearby events: open them with nearby_events.",
                                  f"get_event {shown} (use nearby_events)")
            return ToolResult(f"There is no event or group {shown!r} in this incident. Its labels are "
                              f"{self._label_range()}.", f"get_event {shown} (no such label)")
        if block.label in self.open:
            return ToolResult(f"{key} is already open above.", f"get_event {key} (again)")
        where = f" (it is in group {block.label})" if block.label != key else ""
        lines = [f"get_event {key}{where}", *block.lines]
        notes = tuple(note for note in self.parts.notes
                      if note.note_id not in self.notes_shown and set(note.event_ids) & set(block.event_ids))
        if notes:
            lines += ["", NOTES_TITLE, NOTES_SUBTITLE, *(note.line for note in notes)]
        labels = {self.parts.label_of[event_id]: event_id for event_id in block.event_ids}
        groups = {block.label: block.event_ids} if self.parts.grouped else {}
        return ToolResult("\n".join(lines), f"get_event {key}", labels=labels, groups=groups, notes=notes,
                          done=block.label)

    def commit(self, result: ToolResult) -> None:
        self.labels.update(result.labels)
        self.groups.update(result.groups)
        self.notes_shown += [note.note_id for note in result.notes]
        if result.done:
            self.open.add(result.done)
        self.texts.append(result.text)

    def _label_range(self) -> str:
        names = [block.label for block in self.parts.blocks]
        return f"{names[0]} to {names[-1]}" if len(names) > 1 else names[0]

    def citable(self) -> str:
        """What the model may cite, for the request for its final answer."""
        if not self.labels:
            return "You opened no evidence, so there is nothing you can cite."
        if self.groups:
            names = sorted(self.groups, key=_label_order) + [label for label in sorted(self.labels, key=_label_order)
                                                              if label.startswith("C")]
            return ("Evidence you opened, the only labels you can cite: " + ", ".join(names)
                    + " (and the events inside the groups you opened).")
        return "Evidence you opened, the only labels you can cite: " + ", ".join(sorted(self.labels, key=_label_order)) + "."

    def shown_pack(self) -> EvidencePack:
        """What the model was shown, in the form the single call's checker reads."""
        return EvidencePack(self.parts.incident_id, "\n\n".join(self.texts), dict(self.labels), dict(self.groups),
                            self.parts.omitted, tuple(self.notes_shown))


def _label_order(label: str) -> tuple:
    return ("EGC".index(label[0]) if label[0] in "EGC" else 3, int(label[1:]) if label[1:].isdigit() else 0)


def opened_events(steps: Sequence[str], parts: PackParts) -> set:
    """Which of the incident's events a recorded run opened (for the evaluation)."""
    desk = Desk(parts)
    for step in steps:
        tool, _, rest = step.partition(" ")
        if tool == "get_event" and rest and "(" not in rest:
            desk.commit(desk.use(tool, rest))
    return {event_id for label, event_id in desk.labels.items() if label.startswith("E")}


# --------------------------------------------------------------------------
# Talking to the model: live (and recorded), or replayed from a recording
# --------------------------------------------------------------------------

class _Live:
    def __init__(self, client: Callable[..., dict], timeout: float) -> None:
        self.client, self.timeout, self.exchanges = client, timeout, []

    def __call__(self, request: dict) -> dict:
        try:
            answer = self.client(request, timeout=self.timeout)
        except LLMError as exc:
            raise InvestigationError(str(exc)) from exc
        self.exchanges.append({"prompt_sha256": prompt_hash(request), "answer": answer})
        return answer


class _Replay:
    """Gives back the recorded answers, refusing any request the recording was not made for."""

    def __init__(self, path: Path) -> None:
        try:
            recording = json.loads(path.read_text(encoding="utf-8"))
            self.exchanges = list(recording["exchanges"])
            self.recorded_at = parse_ts(recording["recorded_at"])
            if recording.get("mode") != MODE or not all(
                    isinstance(x, dict) and isinstance(x.get("answer"), dict) for x in self.exchanges):
                raise ValueError("not an agent recording of this version")
        except (OSError, ValueError, KeyError, TypeError) as exc:
            raise InvestigationError(f"recording {path} cannot be read: {exc}") from exc
        self.name, self.position = path.name, 0

    def __call__(self, request: dict) -> dict:
        if self.position >= len(self.exchanges):
            raise InvestigationError(f"recording {self.name} ends after {len(self.exchanges)} exchanges and this "
                                     "run needs more (the evidence or the instructions changed since); run it "
                                     "again without --replay")
        recorded = self.exchanges[self.position]
        self.position += 1
        if recorded.get("prompt_sha256") != prompt_hash(request):
            raise InvestigationError(f"recording {self.name} was made for a different prompt at exchange "
                                     f"{self.position} (the evidence or the instructions changed since); run it "
                                     "again without --replay")
        return recorded["answer"]

    def finished(self) -> None:
        if self.position != len(self.exchanges):
            raise InvestigationError(f"recording {self.name} has {len(self.exchanges)} exchanges and this run "
                                     f"used {self.position}; run it again without --replay")


def recording_path(folder: Path, incident_id: str, model: str, attempt: int = 1) -> Path:
    safe_model = re.sub(r"[^A-Za-z0-9._-]+", "-", model)
    return Path(folder) / f"{incident_id}.{safe_model}.{MODE}{f'.r{attempt}' if attempt > 1 else ''}.json"


def _request(model: str, messages: list, schema: dict, num_ctx: int, predict: int) -> dict:
    return {
        "model": model,
        "messages": [dict(message) for message in messages],
        "format": schema,
        "stream": False,
        "think": False,
        "options": {"temperature": 0, "seed": 7, "num_ctx": num_ctx, "num_predict": predict},
    }


def _estimated_tokens(messages: list) -> int:
    """A cautious estimate: instructions at about 4 characters a token, evidence at CHARS_PER_TOKEN."""
    system = sum(len(m["content"]) for m in messages if m["role"] == "system")
    rest = sum(len(m["content"]) for m in messages if m["role"] != "system")
    return int(system / 4 + rest / CHARS_PER_TOKEN) + 8 * len(messages)


# --------------------------------------------------------------------------
# One investigation in agent mode
# --------------------------------------------------------------------------

def investigate_agent(
    incident: Incident,
    store: EvidenceStore,
    *,
    model: str,
    num_ctx: int = DEFAULT_NUM_CTX,
    recordings: Path | None = None,
    replay: bool = False,
    attempt: int = 1,
    notes: Sequence[Note] | None = None,
    timeout: float = 300.0,
    client: Callable[..., dict] = chat,
    now: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
    max_tools: int = MAX_TOOL_CALLS,
) -> Investigation:
    parts = parts_for_model(incident, store, num_ctx, notes or ())
    desk = Desk(parts)
    path = recording_path(recordings, incident.incident_id, model, attempt) if recordings else None
    if replay:
        if path is None or not path.exists():
            raise InvestigationError(
                f"no agent recording for {incident.incident_id} with model {model!r}"
                + (f" (attempt {attempt})" if attempt > 1 else "") + "; run it once without --replay")
        talk: Any = _Replay(path)
    else:
        talk = _Live(client, timeout)

    messages = [{"role": "system", "content": AGENT_SYSTEM_PROMPT},
                {"role": "user", "content": desk.outline(max_tools)}]
    answers: list[dict] = []
    steps: list[str] = []
    extra: list[Rejection] = []
    used = 0
    reason = "answer"
    while True:
        if used >= max_tools:
            reason = "limit"
            break
        if not desk.unopened():
            reason = "all"
            break
        request = _request(model, messages, step_schema([*desk.unopened(), DONE]), num_ctx, STEP_PREDICT)
        answer = talk(request)
        answers.append(answer)
        content = _content(answer)
        messages.append({"role": "assistant", "content": content})
        step = None if answer.get("done_reason") == "length" else _parse_json_object(content)
        if step is None:
            extra.append(Rejection("answer", _clip(content, 300),
                                   f"step {len(answers)} was not a usable tool request, so the model was asked "
                                   "for its answer"))
            reason = "unusable"
            break
        step = {re.sub(r"^\d+_", "", str(key)): value for key, value in step.items()}
        choice = str(step.get("open") or "").strip()
        if choice.lower() == DONE:
            break
        used += 1
        result = desk.choose(choice)
        left = [label for label in desk.unopened() if label != result.done]
        reply = (f"{result.text}\n\nYou can open {max_tools - used} more. "
                 + (f"Not opened yet: {', '.join(left)}." if left else f"Everything is open: choose {DONE}."))
        if _estimated_tokens(messages + [{"role": "user", "content": reply}]) + STEP_PREDICT + ANSWER_PREDICT \
                + 120 > num_ctx:
            steps.append(f"{result.call} (no room)")
            reason = "room"
            break
        desk.commit(result)
        steps.append(result.call)
        messages.append({"role": "user", "content": reply})

    opening = {"answer": "", "all": "You have opened everything. ",
               "limit": f"You have opened as much as you can ({max_tools}). ",
               "room": "There is no room left in this conversation for more evidence. ",
               "unusable": "Your last reply was not a step in the format asked for. "}[reason]
    messages.append({"role": "user", "content": opening + "Write your final answer now: one JSON object with "
                     "exactly the keys given in rule 8, following rules 1 to 7.\n" + desk.citable()})
    final_request = _request(model, messages, ANSWER_SCHEMA, num_ctx, ANSWER_PREDICT)
    final = talk(final_request)
    answers.append(final)
    digest = prompt_hash(final_request)

    if replay:
        talk.finished()
        created_at = talk.recorded_at
    else:
        created_at = now().replace(microsecond=0)
        if path is not None:
            path.parent.mkdir(parents=True, exist_ok=True)
            recording = {"incident_id": incident.incident_id, "mode": MODE, "prompt_sha256": digest,
                         "recorded_at": format_ts(created_at), "steps": steps, "request": final_request,
                         "exchanges": talk.exchanges}
            path.write_text(json.dumps(recording, indent=2, ensure_ascii=False), encoding="utf-8", newline="\n")

    durations = [_nanos_to_ms(a.get("total_duration")) for a in answers]
    outputs = [_int_or_none(a.get("eval_count")) for a in answers]
    prompts = [_int_or_none(a.get("prompt_eval_count")) for a in answers]
    run = ModelRun(
        model=model,
        mode=MODE,
        thinking=False,
        prompt_sha256=digest,
        replayed=replay,
        attempt=attempt,
        prompt_version=PROMPT_VERSION,
        knowledge=notes is not None,
        knowledge_id=notes_fingerprint(notes) if notes is not None else "",
        duration_ms=sum(durations) if all(d is not None for d in durations) else None,
        prompt_tokens=prompts[-1],
        output_tokens=sum(outputs) if all(o is not None for o in outputs) else None,
        steps=tuple(steps),
    )
    problem = None
    filled = [count for count in prompts if count is not None and count >= num_ctx - 8]
    if filled:
        problem = (f"a prompt filled the model's whole context window ({max(filled)} of {num_ctx} tokens), so "
                   "part of the evidence may have been cut off")
    elif final.get("done_reason") == "length":
        problem = "the model ran out of output space before finishing its answer"
    events = [store.get(event_id) for event_id in incident.event_ids]
    verdict = check_answer(incident, events, desk.shown_pack(), _content(final), run, created_at, problem=problem)
    if extra:
        verdict = dataclasses.replace(verdict, rejected=tuple(extra) + verdict.rejected)
    return Investigation(verdict, desk.shown_pack(), path)


def _content(answer: dict) -> str:
    message = answer.get("message") if isinstance(answer.get("message"), dict) else {}
    return message.get("content") if isinstance(message.get("content"), str) else ""
