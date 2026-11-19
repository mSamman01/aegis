"""The public demo: the dashboard and the evaluation, built from synthetic data only.

``python -m aegis demo --out site`` makes a folder of static pages that
GitHub Pages can publish as it is:

    site/index.html             what Aegis is, and where to start
    site/sample/                the dashboard for the synthetic sample, after a
                                simulated approval and lock of svc_backup
    site/response/              an outside attacker: the account locked and the
                                attacker's address blocked at the firewall
    site/twins/<name>/          the dashboard for each benign twin (and the
                                injected attack)
    site/evaluation/index.html  the evaluation report for those cases

Everything is rebuilt from what is in git: the synthetic alerts
(data/samples), the policy, the operator notes, and the model's answers,
recorded once with qwen3:4b (data/samples/recordings) and replayed here - in
the single call, and in agent mode once its recordings are there (D44). A
prompt without a recording stops the build instead of asking a model, so the
build needs no Ollama, no VM and no network, and it fails when the code has
changed what the model would be asked - then the recordings must be made
again on the laptop (``python -m aegis evaluate --investigate`` without real
runs present, D43).

The approval is given by "demo" while the site is built, and ``act`` runs
against a stand-in for the lab VM (probe.RecordingGate) that records the
request and connects to nothing. The pages say so on every page.
"""

from __future__ import annotations

import contextlib
import io
import shutil
import tempfile
from pathlib import Path
from typing import Callable

from aegis import evalcases
from aegis import evaluate as evaluating
from aegis import posture as posturing
from aegis.agent import MODE as AGENT_MODE
from aegis.execute import GateExecutor
from aegis.export import WEB_DIR, check_site, export_run
from aegis.investigate import InvestigationError
from aegis.knowledge import DEFAULT_NOTES_FILE, load_notes
from aegis.policy import DEFAULT_POLICY_FILE, load_policy
from aegis.probe import RecordingGate
from aegis.store import read_incidents
from aegis.web import pages
from aegis.web.pages import tag

RECORDINGS = evalcases.PROJECT / "data" / "samples" / "recordings"
POSTURE_SAMPLE = evalcases.PROJECT / "data" / "samples" / "posture_sample.json"
BLOCK_SCENARIO = evalcases.PROJECT / "data" / "samples" / "block_scenario.jsonl"

MODEL = "qwen3:4b"
REPEAT = 3
REVIEWER = "demo"
MARKER = ".aegis-site"
NOTICE = ("Synthetic data: these alerts were written for this demo, not taken from a real network. The model's "
          "answers are recordings replayed while the site was built, and the lab VM that carried out the "
          "approved lock and firewall block is a stand-in that connects to nothing.")
REPO = "https://github.com/mSamman01/aegis"
POSTURE_NOTICE = (NOTICE + " The posture export was written by hand for the demo too: the programs and CVE ids are "
                  "made up, and one remediation text is planted to show the checker. Advice only; no AI model wrote "
                  "it.")


class DemoError(RuntimeError):
    """The demo could not be built as it should be."""


def cli_main(args) -> int:
    from aegis import cli

    return cli.main([str(a) for a in args])


def _no_model(request, timeout=None):
    raise InvestigationError("the demo replays recorded answers only, and this prompt has no recording "
                             "(the prompt or the evidence changed): record the answers again (D43)")


def build_demo(out: Path | str, *, policy_path: Path | str | None = None,
               say: Callable[[str], None] = lambda text: None) -> dict:
    """Build the whole site into ``out``. Returns what went into it."""
    out = Path(out)
    _fresh(out)
    policy_file = Path(policy_path) if policy_path else DEFAULT_POLICY_FILE
    policy = load_policy(policy_file)
    notes = load_notes(DEFAULT_NOTES_FILE)
    with tempfile.TemporaryDirectory(prefix="aegis-demo-") as tmp:
        work = Path(tmp)
        (work / "no-runs").mkdir()  # no real runs: only the sample and its twins become cases
        specs = evalcases.build_all(work / "cases", runs=work / "no-runs")
        evals = work / "eval"
        for spec in specs:
            _copy_recordings(spec["name"], evals / spec["name"] / "recordings")
        setups = [{"model": MODEL, "repeat": REPEAT, "notes": notes, "client": _no_model}]
        if agent_recorded():  # once any agent answer is committed, every one must be there
            setups.append(dict(setups[0], mode=AGENT_MODE))
        say(f"Replaying the recorded answers for {len(specs)} cases"
            + (" (single call and agent mode)" if len(setups) > 1 else ""))
        outcome = evaluating.run(work / "cases", evals, policy, policy_file, say=lambda text: None,
                                 investigate=setups, posture_dir=None)  # from git only: no real export
        broken = [f"{r.name}: {c}" for r in outcome["results"] for c, ok, _ in r.expectations if not ok]
        broken += [v for r in outcome["results"] for v in r.violations]
        if broken or outcome["leaks"][1]:
            raise DemoError("the evaluation of the synthetic cases does not hold: " +
                            "; ".join(broken + outcome["leaks"][1]))
        say("Approving and carrying out the lock of svc_backup, against a stand-in for the lab VM")
        locked = _respond(evals / "sample", policy_file,
                          lambda incs: next(i for i in incs if "svc_backup" in i.accounts
                                            and i.host.agent_id == "002"),
                          [("lock_account", "svc_backup")])

        say("An outside attacker: locking the account and blocking the address at the firewall")
        block_run = work / "block-run"
        for args in (("ingest", str(BLOCK_SCENARIO), "--dir", str(block_run)),
                     ("correlate", "--dir", str(block_run))):
            said = io.StringIO()
            with contextlib.redirect_stdout(said), contextlib.redirect_stderr(said):
                if cli_main(args) != 0:
                    raise DemoError(f"the block scenario could not be built: {said.getvalue().strip()[-300:]}")
        blocked = _respond(block_run, policy_file, lambda incs: max(incs, key=lambda i: len(i.event_ids)),
                           [("lock_account", "svc_deploy"), ("block_ip", "192.168.56.66")])

        say(f"Writing the pages into {out}")
        sample_home = "../index.html"
        pages_written = export_run(evals / "sample", out / "sample", label="sample (synthetic)", notice=NOTICE,
                                   site_home=sample_home, policy_path=policy_file,
                                   posture=posturing.read_loaded(POSTURE_SAMPLE), posture_notice=POSTURE_NOTICE)
        pages_written += export_run(block_run, out / "response", label="outside attacker (synthetic)",
                                    notice=NOTICE, site_home="../index.html", policy_path=policy_file)
        twins = [s for s in specs if s["kind"] == "twin"]
        for spec in twins:
            pages_written += export_run(evals / spec["name"], out / "twins" / spec["name"],
                                        label=f"twin {spec['name']} (synthetic)", notice=NOTICE,
                                        site_home="../../index.html", policy_path=policy_file)
        say("Writing the posture advice for the synthetic PC")
        sample_posture = posturing.load(POSTURE_SAMPLE)
        posturing.write_report(out / "posture", sample_posture, posturing.rank(sample_posture),
                               notice=POSTURE_NOTICE, home="../index.html")
        pages_written += 1
        report = (evals / "report.md").read_text(encoding="utf-8")
        if tmp in report or str(work.resolve()) in report:
            raise DemoError("the report names the build's temporary folder")
        links = pages.FileLinks()
        with pages.link_style(links):
            (out / "evaluation").mkdir()
            (out / "evaluation" / "index.html").write_bytes(pages.simple_document(
                "Aegis evaluation (synthetic cases)", pages.markdown(report), NOTICE, "../index.html"))
            (out / "index.html").write_bytes(pages.simple_document(
                "Aegis: a demo on synthetic data", _front(specs, locked, blocked), NOTICE, "index.html"))
        for folder in (out, out / "evaluation"):
            shutil.copyfile(WEB_DIR / "style.css", folder / links.stylesheet())
        pages_written += 2
    problems = check_site(out)
    if problems:
        raise DemoError(f"{len(problems)} problems in the site, first: {problems[0]}")
    return {"pages": pages_written, "cases": len(specs), "twins": len(twins), "locked": locked,
            "blocked": blocked, "out": out}


def agent_recorded() -> bool:
    """True if agent-mode answers have been recorded for the demo (data/samples/recordings)."""
    return any(RECORDINGS.glob(f"*/*.{AGENT_MODE}*.json"))


def _fresh(out: Path) -> None:
    """An empty folder, or one this builder made before (it is cleared). Anything else is left alone."""
    if out.exists() and any(out.iterdir()):
        if not (out / MARKER).is_file():
            raise DemoError(f"{out} is not empty and was not made by 'aegis demo'; choose another --out")
        shutil.rmtree(out)
    out.mkdir(parents=True, exist_ok=True)
    (out / MARKER).write_text("Made by python -m aegis demo; the whole folder is rebuilt every time.\n",
                              encoding="utf-8")


def _copy_recordings(case: str, target: Path) -> None:
    source = RECORDINGS / case
    if not source.is_dir():
        return
    target.mkdir(parents=True, exist_ok=True)
    for path in sorted(source.glob("*.json")):
        shutil.copyfile(path, target / path.name)


def _respond(run_dir: Path, policy_file: Path, pick, approvals: list) -> dict:
    """``decide`` -> ``approve`` -> ``act`` on one incident, as the operator would, with a stand-in gate.

    ``pick`` chooses the incident from the run folder; ``approvals`` is the (action, target) list to
    approve and carry out. The gate records every request and connects to nothing.
    """
    from aegis import cli

    gate = RecordingGate()

    def command(*args) -> tuple[int, str]:
        said = io.StringIO()
        with contextlib.redirect_stdout(said), contextlib.redirect_stderr(said):
            code = cli.main([str(a) for a in args] + ["--dir", str(run_dir), "--policy", str(policy_file)],
                            executor_factory=lambda policy: GateExecutor(policy.executor.ssh_user,
                                                                         "demo-has-no-key", runner=gate))
        return code, said.getvalue()

    incident = pick(read_incidents(run_dir / "incidents.jsonl"))
    steps = [("decide", "--all")]
    for action, target in approvals:
        steps.append(("approve", incident.incident_id, "--action", action, "--target", target, "--by", REVIEWER))
    steps.append(("act", incident.incident_id))
    for args in steps:
        code, said = command(*args)
        if code != 0:
            raise DemoError(f"'{args[0]}' failed in the demo: {said.strip()[-300:]}")
    targets = {target for _, target in approvals}
    if not gate.requests or any(request.split()[-1] not in targets for request in gate.requests):
        raise DemoError(f"the stand-in gate was sent {gate.requests}, expected only {sorted(targets)}")
    return {"incident": incident.incident_id, "host": incident.host.name, "requests": list(gate.requests),
            "actions": [action for action, _ in approvals]}


# --------------------------------------------------------------------------
# The front page
# --------------------------------------------------------------------------

def _front(specs: list[dict], locked: dict, blocked: dict) -> object:
    links = pages.FileLinks()
    sample = next(s for s in specs if s["name"] == "sample")
    twins = [s for s in specs if s["kind"] == "twin"]
    attack = f"sample/{links.incident(locked['incident'])}"
    block = f"response/{links.incident(blocked['incident'])}"

    def twin_item(spec: dict):
        kind = "an attack" if spec["labels"]["attack_events"] else "harmless"
        return tag("li", tag("a", spec["name"], href=f"twins/{spec['name']}/{links.home()}"), f" ({kind}): ",
                   spec["about"])

    return tag(
        "div",
        tag("h1", "Aegis"),
        tag("p", "Aegis investigates Wazuh alerts and keeps control of what is done about them. It groups "
                 "alerts into incidents, asks a local language model (qwen3:4b, through Ollama) to explain "
                 "each one, citing the evidence, scores the risk and decides every proposed action with fixed "
                 "rules, and carries out only what a person approved, through a narrow gate on the lab "
                 "machine. Every approval and action goes into a hash-chained audit log.", class_="lead"),
        tag("h2", "What these pages are"),
        tag("p", "Static copies of Aegis's read-only dashboard, made by python -m aegis demo from the synthetic "
                 "alerts in the repository. Nothing here comes from a real network. The model's answers were "
                 "recorded once and are replayed; the approval was given by \"", REVIEWER, "\" when the site "
                 "was built, and the lab VM that carried out the lock and the firewall block is a stand-in that "
                 "records the request and connects to nothing."),
        tag("h2", "Start here"),
        tag("ul",
            tag("li", tag("a", "The SSH attack, from alerts to the audit log", href=attack), ": password "
                "guessing against svc_backup on ", locked["host"], ", a login, and /etc/shadow read with sudo. "
                "Follow it stage by stage: the evidence, the model's account of it, the risk and the policy's "
                "decision, the approval, and the lock."),
            tag("li", tag("a", "An outside attacker, locked out and blocked", href=block), ": the same "
                "guessing and login, but from a machine that is not the admin's. Aegis locks the account and "
                "blocks the attacker's address at the lab firewall - a network block the sample's attack can "
                "never get, because its source is the laptop Aegis runs on. Scored and decided by the rules; "
                "both actions carried out after approval, with the gate's before/after proof."),
            tag("li", tag("a", "Every incident in the sample", href=f"sample/{links.home()}"), ": ",
                sample["about"]),
            tag("li", tag("a", "The evaluation", href="evaluation/index.html"), ": how the rules and the "
                "model score on the sample and the twins below",
                " - the model asked in one call and, in agent mode, opening the evidence itself one read-only "
                "tool at a time -" if agent_recorded() else "",
                " and the safety probe, which sends hostile model answers down the real path to see what "
                "reaches the gate.")),
        tag("h2", "Posture advice"),
        tag("p", tag("a", "The weak spots of a synthetic PC, ranked, with fix steps",
                     href=f"sample/{links.posture()}"),
            ": vulnerable programs and failed CIS checks, ranked by fixed rules, as the dashboard shows them; the "
            "version that fixes every CVE and an exact registry command for each setting, both worked out by code "
            "and checked; commands that could lock you out or break everyday use held back; and a planted "
            "remediation text that would turn Defender off, removed by the checker. Advice only, and no AI model "
            "wrote it. ", tag("a", "The same advice as one report", href="posture/index.html"),
            ", the way python -m aegis posture writes it."),
        tag("h2", "Twins: the same stories, made harmless"),
        tag("p", "Each twin is a story from the sample, edited so that it is harmless - or, for ssh-injected, "
                 "still an attack, with a message in the evidence telling the AI to call it benign. They show "
                 "whether Aegis tells the difference."),
        tag("ul", [twin_item(spec) for spec in twins]),
        tag("h2", "What holds on every page"),
        tag("ul",
            tag("li", "Risk is scored from the events by fixed rules; the model's verdict is shown beside it "
                      "and does not change it. What the model proposes is checked against the evidence and "
                      "the action catalog, then decided by the policy."),
            tag("li", "Evidence is untrusted text. Alert fields are shown escaped, invisible characters are "
                      "shown as codes, and nothing in them is followed as an instruction."),
            tag("li", "Locking an account and isolating a host always need a person's approval, and only "
                      "approved actions are carried out."),
            tag("li", "The dashboard cannot change anything: no forms, no JavaScript, and a "
                      "Content-Security-Policy that blocks scripts."),
            ),
        tag("h2", "More"),
        tag("ul",
            tag("li", tag("a", "The source code", href=REPO)),
            tag("li", tag("a", "Results on the real lab runs", href=f"{REPO}/blob/main/docs/eval-results.md"),
                " (counts only, no alert data)"),
            tag("li", tag("a", "The design decisions", href=f"{REPO}/blob/main/DECISIONS.md")),
            tag("li", tag("a", "SENTINEL", href="https://github.com/CS-Abuhelal/sentinel"),
                ", the project that inspired Aegis")),
        class_="front",
    )


