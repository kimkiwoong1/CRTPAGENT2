# CRTP Live Session Protocol

How the agent drives a turn-by-turn exam session. Read this when the user says
"시험 시작" / "exam started". Operational assistance only — never write report prose.

## The evidence discipline (why whoami everywhere)
CRTP graders need PROOF of privilege at every transition. A screenshot of an
attack command alone is worth little; it must show WHO you were, WHERE, and WITH
WHAT PRIVS when it worked. So every step pairs with a CONTEXT block:

    hostname
    whoami
    whoami /groups
    whoami /priv
    (ipv4)

Captured automatically by `Crtp-Evidence.ps1`:
    . .\Crtp-Evidence.ps1
    Start-CrtpSession -Target 1 -HostLabel dcorp-std   # starts transcript + context
    Add-CrtpStep -Title "Kerberoast sqlsvc" -Why "svc acct may be weak"
    <run the command>                                   # output lands in transcript
    Show-CrtpContext -Note "after OPTH as sqlsvc"       # prove new privilege
    ...
    Save-CrtpFlag                                       # final flag with context
    Stop-CrtpSession

Transcript files -> Desktop\crtp-evidence\. Screenshots are labeled T<target>.<step>
so they line up 1:1 with the transcript and the evidence_tracker table.

## Screenshot rules (what makes one "report-grade")
- Command AND its full output visible in one shot.
- A CONTEXT banner visible in the same window (who/where/priv).
- For "OS command execution" proof on a target: show `hostname` + `whoami` run
  THROUGH your access (e.g. via winrs/Invoke-Command), not locally.
- Final flag shot: hostname + whoami + `type finalflag.txt` together.
- Before/after on any privilege change (low-priv context, then elevated context).

## The turn loop (how the agent responds each turn)
When the user reports current state, the agent replies with a tight block:

1. SITUATION: restate where they are (host, identity, which of 5 targets).
2. NEXT STEP: the single best next action toward the flag, with the exact command.
3. WHY (1 line): what it should achieve (user re-explains in report themselves).
4. VERIFY: what output means success / failure.
5. SCREENSHOT: the exact label + what must be in frame.
6. THEN: what to report back so the agent picks the next step.

Keep it to ONE primary action per turn. Do not dump the whole chain — react to
real output, because CRTP paths branch on what actually works.

## State the agent tracks across turns
- 5-target table: host | domain | initial access | OS-exec? | admin? | flag/proof
- Current identity + reachable hosts + harvested creds/hashes/tickets
- Trust map + which domain the DC (final flag) lives in
- Open screenshot labels not yet confirmed captured

## Standard micro-checks to request often
- After any new shell:        Show-CrtpContext
- After OPTH / PTT / S4U:      klist ; whoami ; then target access test
- Proof of lateral OS-exec:    Invoke-Command -ComputerName <h> {hostname; whoami}
- Before claiming target done: confirmed OS command ran ON that target, screenshotted

## Hard reminders to surface to the user
- Report body = YOUR words. Agent gives facts/commands; you write the narrative.
- Only TCP 4444 / 8888 open — set payload/listener ports accordingly.
- Explain every command's function in the report (grader requirement).
- Add mitigations + citations per finding for higher score.
