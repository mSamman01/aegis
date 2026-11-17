# Aegis - architecture and roadmap

## The pipeline

```
 Wazuh manager (VM)
        |  alerts
        v
 1. INGEST        raw alert  ->  Event (stable event_id, raw kept)        [done]
        v
 2. CORRELATE     Events     ->  Incidents (same process tree / source     [done]
        |                        address / account / rule, within a window)
        v
 3. INVESTIGATE   read-only AI: reads the evidence pack, writes a verdict.   [done]
        |         Every claim must cite events that exist; code checks.
        v
 4. DECIDE        deterministic risk score (from evidence, not from the AI) [done]
        |         + policy engine: allow / needs approval / deny
        v
 5. ACT           fixed action catalog, lab target only, human approval,  [done]
        |         before/after proof
        v
    AUDIT LOG     hash-chained record of every step; can be re-verified [done]

 6. API + dashboard read the results; nothing in the UI can trigger an action.
 7. EVALUATION replays labelled cases and reports accuracy and safety.
```

## Safety rules that never change

1. The model has no tool that changes anything. Its tools only read evidence.
2. The risk score is computed from evidence. The model's verdict is shown to
   the human but does not feed the score.
3. On the real laptop the policy denies every action. Output is advice.
4. An action runs only if it is in the fixed catalog, targets the lab machine,
   and has a recorded human approval for that exact case.
5. Protected accounts and hosts can never be acted on, whatever is approved.
6. Every stage writes to the audit log; a broken hash chain is reported.
7. Nothing is dropped silently, and real alert data never goes to git.

## The lab

| Machine | Role | Resources |
|---------|------|-----------|
| Windows 11 laptop | runs Aegis and Ollama; Wazuh agent 001; advice only | 16 GB RAM, RTX 4050 (6 GB VRAM) |
| Wazuh VM (VirtualBox) | manager + indexer + dashboard, 192.168.56.105 | 6 GB RAM (was 8), 4 cores; indexer heap 1 GB |
| Lab VM `aegis-victim` (agent 002) | Ubuntu Server 24.04 with a Wazuh agent, 192.168.56.107; the only place actions run | 2 GB RAM, 1 core |

Memory budget on the laptop: Windows and apps use about 5-6 GB and the Wazuh
VM is given 8 GB, so with the VM running only 2-3 GB is left. What that means:

* Milestones 1-4 work from an exported alerts file, so the Wazuh VM stays off
  and Ollama has the whole machine.
* Milestones 5-6 need the Wazuh VM, the lab target and Ollama running
  together. For those, lower the Wazuh VM to 6 GB in VirtualBox (4 GB if it is
  still tight) and use a model that fits fully on the GPU, so Ollama needs
  little system memory.
* The lab target is a small VM and not Docker Desktop, which would need WSL2
  and several more GB.

8 GB and 4 cores is comfortable for an all-in-one Wazuh server. At 4-6 GB the
Wazuh dashboard gets slow, but Aegis reads alerts from the manager and does
not need the dashboard open.

## The model

SENTINEL uses qwen3:14b on a 12 GB card; that download is about 9.3 GB and
does not fit in 6 GB of VRAM. Candidates for this laptop:

| Model | Download | On a 6 GB card |
|-------|----------|----------------|
| qwen3:4b | about 2.5 GB | fits fully on the GPU with room for context |
| qwen3:8b | about 5.2 GB | weights barely fit; with context some layers spill to the CPU, so it runs slower |

Measured in milestone 3 (DECISIONS D20-D26): qwen3:4b is the model. qwen3:8b
called every harmless incident suspicious, invented block targets, and ran
four times slower. Thinking mode never finished an answer within its output
allowance. With a small model Aegis leans on deterministic work: code builds
the evidence pack, the model reasons over it, and code checks every citation.

## Milestones

Each milestone ends with something you can run and tests that pass.

**1. Event contract + Wazuh ingest - done.**
`python -m aegis ingest <file>` turns Wazuh alerts into Events.

**2. Correlation - done.**
`python -m aegis correlate` groups Events into Incidents per host: same process
tree, same source address, same account, or the same rule firing again, within
30 minutes. Every link is recorded with its reason, posture findings (SCA,
vulnerabilities) are set aside, and `python -m aegis show <id>` prints an
incident's timeline. In the sample, the SSH brute force, login and sudo are
one incident and the laptop's PowerShell activity is another.

**3. Evidence tools + investigator - done.**
`python -m aegis investigate <id>` builds a deterministic evidence pack for an
incident, asks the local model once for a verdict in a fixed JSON shape, and
checks the answer: findings must cite events that are in the pack, proposed
actions must come from the catalog and name a target from the incident, and
whatever fails is listed as removed. Operator notes are attached by code only
where events match them. Every exchange is recorded and can be replayed;
`compare` scores model setups against labels.
Result with qwen3:4b, instructions v4 and four operator notes, three runs per
incident: 58 of 75 runs on harmless real incidents called benign (77%), and
9 of 9 runs on the synthetic attacks caught. Tool-calling agent mode was not
tried; the single call is the baseline it would have to beat.

**4. Risk score + policy - done.**
`python -m aegis decide <id>` scores an incident 0-100 from eight fixed rules
over its evidence (rule level capped at 15, password guessed, became admin,
credential access, hidden PowerShell command, command interpreter going
online, persistence, critical file changed), each with its reason and
events. Candidate actions - from the risk rules and from the model - go
through `policy/policy.json`: host mode and identity, action switched on,
target present in the incident, target not protected, minimum risk band,
human approval. Same incident, same events, same policy: identical decision.
Result: all 69 real incidents low, every action on the laptop denied; in the
sample the SSH brute force is critical, locking `svc_backup` waits for a
human, and blocking 192.168.56.1 is refused because it is the laptop itself.

**5. Lab target + controlled actions + audit log - done.**
The lab VM (Ubuntu Server 24.04, agent 002 `aegis-victim`) runs `aegis-gate`,
reached over SSH by a key that can run nothing else (D29). `approve` records
a human's sign-off bound to the incident, the policy and the action; `act`
decides again from scratch and runs only approved actions, recording status
before and after; `audit` verifies the hash chain, and `act` will not run on
a broken one. Only `lock_account` is carried out so far.
Result (2026-11-17): a real password-guessing attack on the lab VM - six
failed guesses, a successful login as svc_backup, `sudo cat /etc/shadow` -
scored 100 (critical). Aegis proposed locking svc_backup and refused to block
the source (the laptop, protected). After approval, `act` locked and expired
the account and ended its four running processes (before: password=P,
processes=4; after: password=L, processes=0), and `audit` reported 289
entries with the chain intact. Getting there exposed two real problems, both
fixed: the Wazuh agent's journal reader lost the successful login (D32), and
the risk rule paired the guessing with the administrator's own login (D33).

**6. Live feed + API + dashboard.**
Part 1, read-only dashboard and API - done. `python -m aegis serve --dir
runs\lab` shows each incident stage by stage on http://127.0.0.1:8765/:
ingest, correlation, the AI's verdict (boxed, marked AI-written), the risk
score and policy decision worked out again from the current policy, and the
approvals and actions with before/after proof from the verified audit log.
127.0.0.1 only, GET only, Host header checked, writes nothing (not even the
audit log), no JavaScript, Content-Security-Policy `default-src 'none'`,
invisible characters in evidence shown as codes (D35, D36). Every page of
the three run folders answered and left their files unchanged.
Part 2, live feed - done (2026-11-18). `python -m aegis watch` keeps one SSH
connection to the manager as `aegis-feed`, whose key can run only
`lab/aegis-feed`, a program that only reads alerts.json and its archives
(D37). Each batch goes through the same ingest and correlation as an export;
the position in the manager's file is saved only after the batch is written,
survives the daily rotation, and anything that cannot be read is reported as
a gap. The dashboard shows the feed's state and follows incidents as they
grow (D38). On the real lab the D34 attack arrived as it happened (48
alerts, no gaps), scored 85 (critical), and was approved and locked from
`runs\live`; the lock's own log lines then grew the incident, and the
dashboard carried "done" over to the new version (D39). 298 tests pass.

**7. Evaluation.**
Labelled cases including benign twins of each attack. Report accuracy, false
alarms, citation validity and prohibited actions proposed versus executed.
