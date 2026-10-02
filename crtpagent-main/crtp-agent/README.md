# crtp-agent

Local analysis assistant for the **CRTP** (Certified Red Team Professional) exam
and lab. It ingests Active Directory data collected with **SOAPHound / BloodHound**
and produces a command-first attack playbook, per-step verification, and a
screenshot/evidence checklist — plus a local-privilege-escalation analyzer for the
host layer.

> **Authorized use only.** CRTP is an open-book, any-tool practical exam in an
> isolated lab. This tool is for that lab / your own authorized environments.
>
> **Report rule:** CRTP forbids AI-generated report content. This tool helps you
> DURING the attack (allowed) and organizes your evidence, but it does **not**
> write the report. The report body must be written by you, in your own words.

## What it does
- Parses SOAPHound/BloodHound JSON (`*_users.json`, `*_computers.json`, …).
- Detects AD attack paths: Kerberoasting, AS-REP roasting, un/constrained & RBCD
  delegation, ACL abuse, GPO abuse (who-can-edit -> linked OU -> affected computers),
  DCSync rights, domain/forest trusts (inter-realm golden command auto-filled with
  real SIDs + SID-filtering state), creds-in-description, high-value group
  membership — ranked by priority toward the flag.
- Analyzes host-local privilege escalation from `whoami /priv`, `whoami /groups`,
  and PowerUp output (SeImpersonate→Potato, SeBackup, local admin, service issues…).
- Emits an evidence tracker + screenshot checklist, and a PowerShell helper that
  captures the whoami/hostname/priv context at every transition.

## Layout
```
parser/
  bh_loader.py       BloodHound JSON loader / normalizer
  analyze.py         AD attack-path detectors (domain layer)
  localpriv.py       local privilege-escalation analyzer (host layer)
  adcs.py            AD CS / ESC analyzer (parses Certify find output)
  main.py            runner -> playbook.md, findings.json, evidence_tracker.md, evidence_plan.md, report_skeleton.md
                     (auto-merges localpriv_findings.json + adcs_findings.json if present)
  Crtp-Evidence.ps1  in-shell context banner + transcript capture
knowledge/
  crtp_playbook.md   technique reference, tool cheatsheet, known gaps
  LIVE_SESSION.md    turn-by-turn operator protocol + screenshot rules
skill/
  crtp-analyst/      Claude Code skill (copy to ~/.claude/skills/ to activate)
input/               put collected JSON here (only sample_*.json is tracked)
output/              generated (gitignored)
```

## Usage
```bash
# 1) AD analysis
python parser/main.py <json_dir>
#   -> output/playbook.md         (prioritized attack plan)
#      output/findings.json       (machine-readable, for Claude to reason over)
#      output/evidence_tracker.md (per-technique checklist + 5-target table)
#      output/evidence_plan.md    (engagement-ordered: recon -> situational awareness -> attack candidates; per-step cmd/verify/proof/screenshot + blank 내 설명/완화)
#      output/report_skeleton.md  (report shape: per-host STEP narrative + mirrored mitigations section)

# 2) host-local privesc (after landing on a box)
python parser/localpriv.py --enum         # prints what to run on the host
python parser/localpriv.py --priv priv.txt --groups groups.txt --powerup pu.txt

# 3) AD CS / ESC (not in BloodHound data — enumerate with Certify, then parse)
python parser/adcs.py --enum              # prints the Certify/Certipy commands
python parser/adcs.py --certify certify_find.txt   # -> output/adcs_findings.json (ESC1/3/4/6)
#   localpriv_findings.json + adcs_findings.json are auto-merged into the next main.py run's plan
```
```powershell
# 3) evidence discipline (load in each shell on the target VM)
. .\parser\Crtp-Evidence.ps1
Start-CrtpSession -Target 1 -HostLabel <host>
```

## Status / gaps
Validated against real SOAPHound v5 output (multi-domain dollarcorp data): loader,
all detectors, and the generated plans confirmed. Covered vs the CRTP course LOs:
Kerberoast/AS-REP, un/constrained & RBCD delegation, ACL abuse, GPO abuse, DCSync,
child->parent (SID history) & forest trusts, local privesc.

**AD CS / ESC** now covered via `parser/adcs.py` (parses `Certify.exe find` output
-> ESC1/ESC2/ESC3/ESC4/ESC6). SOAPHound `--certdump` tends to hang on the PKI cache;
use Certify (or Certipy) instead — that's the standard exam path anyway. Validated
against real Certify output (cross-domain ESC1/ESC3 to the parent forest CA).

Not yet implemented:
- **MSSQL linked-server chains** — host/app layer; feed PowerUpSQL output like the
  localpriv/adcs analyzers do.
- Nested-group/session reachability graph; app-layer footholds (Jenkins etc.).
See `knowledge/crtp_playbook.md` → GAPS.

## Credits / references
Builds on well-known tooling (PowerView, Rubeus, mimikatz, PowerUpSQL, SOAPHound,
BloodHound). Cite the specific sources you actually use in your own report.
