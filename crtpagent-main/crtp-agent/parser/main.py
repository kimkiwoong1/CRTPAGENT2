"""
main.py — CRTP agent entrypoint.

Usage:
    python main.py <input_dir> [--out <output_dir>]

Reads SOAPHound/BloodHound JSON from <input_dir>, analyzes it, and writes:
  - output/playbook.md         : prioritized, command-first attack plan
  - output/findings.json       : machine-readable findings (for Claude to reason over)
  - output/evidence_tracker.md : per-target status + evidence checklist (YOU fill it)

IMPORTANT (exam rule): the report body must be written BY YOU, in your own words.
This tool produces operational aids and an EMPTY scaffold to fill — it does not
write report prose. See evidence_tracker.md header.
"""

from __future__ import annotations
import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from bh_loader import load           # noqa: E402
from analyze import analyze, Finding  # noqa: E402


def _load_extra_findings(out_dir):
    """Reconstruct Finding objects from localpriv.py / adcs.py output, if present."""
    extra = []
    for fname in ("localpriv_findings.json", "adcs_findings.json"):
        path = os.path.join(out_dir, fname)
        if not os.path.exists(path):
            continue
        try:
            with open(path, "r", encoding="utf-8") as fh:
                for d in json.load(fh):
                    extra.append(Finding(**d))
        except Exception:  # noqa — a malformed/old file must not break the run
            pass
    return extra


EXAM = {
    "targets": 5,
    "goal": "5개 대상 서버 전부에서 OS 명령 실행 권한 획득 (관리자 아니어도 됨)",
    "final_flag": r"C:\Users\finadmin\Desktop\finalflag.txt (DC)",
    "ports": "인바운드/아웃바운드 TCP 4444, 8888 만 허용",
    "domains": "다중 도메인 (트러스트 경로 매핑 필수)",
    "time": "환경 24h (실습 12h + 보고서 6h 권장)",
}


def write_playbook(findings, model, out_dir):
    lines = []
    a = lines.append
    a("# CRTP 공격 플레이북 (SOAPHound 데이터 기반)\n")
    a("> 이 파일은 **시험 중 공격 조수용**입니다. 명령어는 인가된 랩에서만 실행하세요.\n")
    a("## 시험 목표 요약")
    for k, v in EXAM.items():
        a(f"- **{k}**: {v}")
    a("")
    a("## 수집 데이터 요약")
    a(f"- 도메인: `{model.domain}`  SID: `{model.domain_sid}`")
    a(f"- users={len(model.users)} groups={len(model.groups)} "
      f"computers={len(model.computers)} domains={len(model.domains)} "
      f"gpos={len(model.gpos)} ous={len(model.ous)}")
    if model.warnings:
        a("- ⚠ warnings: " + "; ".join(model.warnings))
    a("")

    # group findings by CRTP topic
    a("## 우선순위 공격 경로 (priority 낮을수록 먼저)\n")
    for f in findings:
        if f.severity == "INFO" and f.crtp_topic == "meta":
            continue
        a(f"### [{f.severity}] {f.technique}  ·  _{f.crtp_topic}_  (prio {f.priority})")
        a(f"- **대상**: {', '.join(f.targets) if f.targets else '-'}")
        for ev in f.evidence:
            a(f"- **근거**: {ev}")
        if f.commands:
            a("- **명령어**:")
            for tool, cmds in f.commands.items():
                a(f"  - _{tool}_:")
                for c in cmds:
                    a(f"    ```\n    {c}\n    ```")
        if f.verify:
            a("- **확인할 것**:")
            for v in f.verify:
                a(f"  - [ ] {v}")
        if f.screenshots:
            a("- **📸 스크린샷 (보고서 필수)**:")
            for s in f.screenshots:
                a(f"  - [ ] {s}")
        if f.report_notes:
            a(f"- **메모**: {f.report_notes}")
        a("")

    path = os.path.join(out_dir, "playbook.md")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines))
    return path


# ATTACK CANDIDATE phases — surfaced AFTER recon/enumeration, ordered within a
# phase by priority. Keyed by detector fid-prefix (environment-agnostic). These
# are candidates the live situation chooses from, NOT a mandatory 1-2-3 sequence.
# (HV = objective identification; handled earlier under situational awareness.)
PLAN_ATTACK_PHASES = [
    ("3. 자격 접근 후보 — roasting / 평문 자격", ["DESC", "ASREP", "KERB"]),
    ("4. 로컬 권한상승 후보 — 호스트 레이어", ["LPRIV"]),
    ("5. 도메인 권한상승 후보 — ACL / GPO / 위임", ["ACL", "GPO", "RBCD", "CONST", "UNCONST"]),
    ("6. AD CS 권한상승 후보 — ESC1/3/4/6 (교차도메인 가능)", ["ADCS"]),
    ("7. 자격 탈취·지속성 후보 — DCSync", ["DCSYNC"]),
    ("8. 교차 도메인 후보 — Trust", ["TRUST"]),
]


def _fid_prefix(fid: str) -> str:
    return (fid or "").split("-")[0]


def _proof_line(f) -> str:
    """Factual verification bridge (NOT report prose): what success demonstrates."""
    tgt = ", ".join(f.targets[:3]) + (" …" if len(f.targets) > 3 else "") if f.targets else "대상"
    return (f"위 '확인' 항목이 충족되면 → **{f.technique}** 이(가) `{tgt}` 에 대해 "
            f"실제로 성립함을 입증 (심각도 {f.severity}).")


def write_evidence_plan(findings, model, out_dir):
    """Path-ordered evidence scaffold, generated purely from findings.

    Groups findings into attack phases by detector fid-prefix (environment-agnostic)
    and, per finding, emits command / verify / proof / screenshot plus BLANK fields
    the operator fills in their own words (exam rule). No hardcoded lab specifics.
    """
    lines = []
    a = lines.append
    a("# 경로-증거 플랜 (findings 자동 생성)\n")
    a("> ⚠️ **규정**: '🖊 내 설명'·'🛡 완화'는 **본인이 직접** 작성. 이 파일은 "
      "명령/확인/증명/스크린샷 **뼈대만** 제공합니다 (AI 생성 본문 = 실격).")
    a("> 모든 스크린샷은 같은 창에 **`whoami` + 명령 + 출력**이 함께 보이게. 리스너/다운로드는 데이터서 확인된 허용 포트로.\n")
    a(f"- 도메인: `{model.domain}`  SID: `{model.domain_sid}`")
    a(f"- findings: {len([f for f in findings if f.crtp_topic != 'meta'])}개 "
      f"(이 환경 데이터 기준 — 다른 시험 환경이면 그 JSON으로 재생성)\n")

    real = [f for f in findings if not (f.severity == 'INFO' and f.crtp_topic == 'meta')]
    seen = set()

    a("## STEP 0 — 시작: 나 누구 / 어디 / 무슨 권한 (공격 전 상황 파악 먼저)")
    a("- 🛠 명령어: `hostname; whoami; whoami /groups; whoami /priv; ipconfig | findstr IPv4`")
    a("- ✅ 확인: 현재 신원·권한(관리자 여부)·호스트·네트워크")
    a("- 🎯 증명: 공격 시작 시점의 최저 권한 baseline (이후 상승의 before 기준)")
    a("- 📸 스크린샷: `T0.0-baseline` (위 전체 한 화면)")
    a("- 🖊 내 설명: > _시작 권한/위치를 먼저 남기는 이유 (본인 문장)_\n")

    a("## PHASE 0 — 초기 발판 (초기 접근)")
    a("> ⚠ 앱레이어 — **AD 데이터 밖(GAP)**. 환경마다 다름. 특정 앱(예: 특정 CI/웹) 가정 금지.")
    a("- 🛠 닿는 포트/서비스 스캔 → 거기서 진입 (웹/빌드서버/파일공유/기본자격 등)")
    a("- 📸 발판에서 첫 OS 명령 + `whoami` (어느 계정으로 떨어졌는지)")
    a("- 🖊 내 설명: > _어떻게 최초 접근을 얻었는가_\n")

    a("## PHASE 1 — 정찰·열거  (★ 보고서의 큰 축 — 각 열거도 스크린샷+설명 남길 것)")
    a("> CRTP는 보고서 비중이 큼. **열거 과정 자체가 점수** — flag를 따도 열거/설명/완화/인용이 "
      "빈약하면 감점·탈락 가능. 아래 E1~E8은 각각 독립 증거 항목으로 남기세요.\n")
    enum_steps = [
        ("E1", "내 권한/신원 확인", ["whoami /all   # groups + privileges + SID"],
         "현재 계정·그룹·권한·SID"),
        ("E2", "도메인 기본 정보", ["Get-Domain", "Get-DomainController", "Get-DomainPolicy"],
         "도메인/DC/정책 파악"),
        ("E3", "유저·그룹·고가치 멤버십", ["Get-DomainUser | select samaccountname,admincount",
         "Get-DomainGroupMember 'Domain Admins' -Recurse"],
         "DA/EA 등 최종 목표 계정 식별"),
        ("E4", "roastable 계정", ["Get-DomainUser -SPN | select samaccountname",
         "Get-DomainUser -PreauthNotRequired"],
         "Kerberoast / AS-REP 후보"),
        ("E5", "위임 설정", ["Get-DomainComputer -Unconstrained",
         "Get-DomainUser -TrustedToAuth",
         "# RBCD: msds-allowedtoactonbehalfofotheridentity 확인"],
         "위임 기반 권한상승 후보"),
        ("E6", "ACL (내가 관련된 것 우선)",
         ["Find-InterestingDomainAcl -ResolveGUIDs | ?{$_.IdentityReferenceName -match '<나>'}"],
         "내가 악용 가능한 ACL 엣지"),
        ("E7", "트러스트 관계", ["Get-DomainTrustMapping", "Get-ForestTrust -ErrorAction SilentlyContinue"],
         "도메인/포레스트 트러스트 + 방향 + SID filtering"),
        ("E8", "대량 수집 → 파서", ["SOAPHound.exe --buildcache -c cache.json",
         "SOAPHound.exe -c cache.json --bhdump --nolaps -o bh",
         "python parser\\main.py bh   # -> 아래 '후보' 자동 생성"],
         "수집 데이터가 아래 후보의 입력"),
    ]
    for lbl, title, cmds, note in enum_steps:
        a(f"### [{lbl}] {title}")
        a("- 🛠 명령어:")
        for c in cmds:
            a(f"    ```\n    {c}\n    ```")
        a(f"- 📸 스크린샷 `{lbl}-enum`: 명령 + 출력 (whoami 컨텍스트 포함되게)")
        a(f"- 🖊 내 설명: > _{note} — 왜 열거했고 무엇을 확인했는가 (본인 문장)_\n")

    a("## PHASE 2 — 상황 인식: 내가 제어하는 것 / 닿는 곳 / 목표")
    a("- 🛠 `whoami /groups` · 내가 ACL 가진 객체: "
      "`Find-InterestingDomainAcl -ResolveGUIDs | ?{$_.IdentityReferenceName -match '<나>'}`")
    a("- 🎯 증명: 현재 위치에서 쓸 수 있는 특권/엣지 파악 → 아래 후보 중 실제 가능한 것 선별")
    hv = [f for f in real if _fid_prefix(f.fid) == "HV"]
    if hv:
        a("- **열거로 식별된 고가치 목표 (최종 수렴점)**:")
        for f in sorted(hv, key=lambda z: z.priority):
            a(f"  - {f.technique}: {', '.join(f.targets) if f.targets else '-'}")
        seen.update(f.fid for f in hv)
    a("- 🖊 내 설명: > _현재 권한에서 어디로 갈 수 있는지_\n")

    a("---\n")
    a("## 공격 후보 (↓ 열거로 나온 후보 — **우선순위順, 순차 필수 아님**. 라이브 결과가 다음 수를 정함)\n")
    for title, prefixes in PLAN_ATTACK_PHASES:
        bucket = [f for f in real if _fid_prefix(f.fid) in prefixes]
        if not bucket:
            continue
        a(f"## PHASE {title}\n")
        for f in sorted(bucket, key=lambda z: (z.priority, z.fid)):
            seen.add(f.fid)
            a(f"### [{f.severity}] {f.technique}  (prio {f.priority})")
            a(f"- **대상**: {', '.join(f.targets) if f.targets else '-'}")
            for ev in f.evidence:
                a(f"- **근거(데이터)**: {ev}")
            if f.commands:
                a("- 🛠 **명령어**:")
                for tool, cmds in f.commands.items():
                    a(f"  - _{tool}_:")
                    for c in cmds:
                        a(f"    ```\n    {c}\n    ```")
            if f.verify:
                a("- ✅ **확인(VERIFY)**:")
                for v in f.verify:
                    a(f"  - [ ] {v}")
            a(f"- 🎯 **증명(PROOF)**: {_proof_line(f)}")
            if f.screenshots:
                a("- 📸 **스크린샷**:")
                for s in f.screenshots:
                    a(f"  - [ ] {s}")
            if f.report_notes:
                a(f"- _참고(사실): {f.report_notes}_")
            a("- 🖊 **내 설명(본인 문장)**: > _이 명령이 무엇을 하고 왜 통했는가_")
            a("- 🛡 **완화 방안(본인 조사·인용)**: > _방어책_\n")

    leftover = [f for f in real if f.fid not in seen]
    if leftover:
        a("## PHASE 기타 (미분류 findings)\n")
        for f in sorted(leftover, key=lambda z: (z.priority, z.fid)):
            a(f"### [{f.severity}] {f.technique} — {', '.join(f.targets) if f.targets else '-'}")
            a(f"- 🎯 증명: {_proof_line(f)}")
            a("- 🖊 내 설명: > _작성_\n")

    # host-layer GAPs — generic, derived from SPNs (no app names hardcoded)
    a("## 호스트 레이어 (데이터 GAP — 각 호스트 수동 열거)")
    a("> SOAPHound/BloodHound 는 app/MSSQL/localpriv 를 못 봄. 아래는 **데이터의 SPN**에서 유추한 열거 후보.\n")
    for c in sorted(model.computers.values(), key=lambda x: (x.p('samaccountname') or '')):
        spns = c.p('serviceprincipalnames') or []
        spns = spns if isinstance(spns, list) else [spns]
        hints = []
        if any('MSSQLSVC' in str(s).upper() for s in spns):
            hints.append("MSSQL → `Get-SQLServerLinkCrawl`/`xp_cmdshell` (링크드서버 체인)")
        if any('HTTP' in str(s).upper() for s in spns):
            hints.append("웹 서비스 → 앱 열거 (기본자격/업로드/RCE)")
        hints.append("localpriv → `python localpriv.py --enum`")
        name = c.p('samaccountname') or c.name
        a(f"- **{name}**: " + " · ".join(hints))
    a("\n> 초기 발판은 특정 앱으로 가정하지 않음 — 닿는 포트/서비스 스캔 후 발견된 것에서 진입.")
    a("> **AD CS (ESC1-15)** 도 BloodHound 밖: `Certify.exe find /vulnerable` → "
      "`python adcs.py --certify out.txt` 로 탐지 (결과는 위 'AD CS 권한상승 후보' phase에 병합).")
    a("> **로컬 privesc**: 박스에서 `python localpriv.py --enum` 후 캡처 → 파싱.")
    a("> **실행(HOW) 명령 레시피** — 자격추출/측면이동/coercion/인증서인증/티켓위조/덤프 등 "
      "'수동' 구간의 바로 칠 명령: `knowledge/execution_cheatsheet.md` 참조.")

    path = os.path.join(out_dir, "evidence_plan.md")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines))
    return path


def write_report_skeleton(findings, model, out_dir):
    """Report-shaped skeleton mirroring a real passing CRTP report:
    host-by-host STEP narrative (section 1) + a mirrored Mitigations section (2).
    Structure/checklists only — the operator writes all prose (exam rule).
    """
    lines = []
    a = lines.append
    a("# CRTP 모의 침투 테스트 보고서 (스켈레톤 — 본문 본인 작성)\n")
    a("> ⚠️ **규정**: 모든 서술·설명은 **본인 문장**으로. 이 파일은 실제 합격 보고서 구조에 맞춘 "
      "**뼈대·체크리스트**만 제공합니다 (AI 생성 본문 = 실격).")
    a("> 구조: 호스트별 STEP 내러티브 + 별도 대응방안 섹션. **실패한 시도도 기록**(실제 과정 = 가점).\n")
    a(f"- 도메인: `{model.domain}`  ·  목표: 5대 서버 OS 명령 실행 + 최종 flag")
    comps = sorted(str(c.p('samaccountname') or c.name) for c in model.computers.values())
    a("- 후보 호스트(열거 산출물): " + ", ".join(comps[:18]) + (" …" if len(comps) > 18 else ""))
    a("- 5대 타깃 상태표 → `evidence_tracker.md` · 단계별 명령/증거 → `evidence_plan.md`\n")

    a("## 1. 상세 모의 침투 테스트 결과\n")
    a("### 1.1 초기 접근 & 도메인 열거 (studvm)")
    a("- **초기 접근 방식**: > _어떻게 최초 발판을 얻었는가 (본인 문장)_")
    a("- **Enumeration #1~#8** (각 명령+출력 스크린샷):")
    a("  - [ ] E1 whoami/신원  [ ] E2 도메인  [ ] E3 유저·그룹·고가치  [ ] E4 roastable")
    a("  - [ ] E5 위임  [ ] E6 ACL  [ ] E7 트러스트  [ ] E8 수집→파서")
    a("- 🖊 설명: > _무엇을 왜 열거했고 어떤 공격면을 식별했는가_\n")

    for i in range(1, 6):
        a(f"### 1.{i+1} <타깃 호스트 {i}>로의 접근 / 측면 이동")
        a("- **대상·도메인**: ______    **초기 벡터**: ______ (roast / ACL / GPO / 위임 / MSSQL / 앱 등)")
        a("- STEP 1. ______    (🛠 명령 / ✅ 결과 / 📸 라벨)")
        a("- STEP 2. ______")
        a("- STEP 3. ______    _(실패도 기록: \"STEP n. …를 시도했으나 …로 실패\")_")
        a("- **OS 명령 실행 증적**: 📸 해당 호스트에서 `hostname; whoami` (내 접근을 통해 실행)")
        a("- 🖊 설명: > _이 호스트를 어떻게·왜 장악했는가_\n")

    a("### 1.7 도메인 / 포레스트 장악 & 최종 Flag")
    a("- 경로 요약: 유저 → (자격/위임/GPO/ACL) → DA → DCSync krbtgt → (SID history/trust) → EA/상위 DC")
    a("- **최종 flag**: `C:\\Users\\finadmin\\Desktop\\finalflag.txt`")
    a("- 📸 **FLAG 샷(필수)**: hostname + whoami + flag 내용 한 화면")
    a("- 🖊 설명: > _최종 경로 요약 (본인 문장)_\n")

    a("## 2. 대응 방안 (Mitigations) — 1장 호스트별 미러링\n")
    a("> 발견마다 **완화책 + 출처 인용**(가점). finding별 완화 초안 → `evidence_plan.md`.")
    a("### 2.1 초기 접근 & 열거")
    a("- 🛡 > _작성 (+ 인용)_")
    for i in range(1, 6):
        a(f"### 2.{i+1} 타깃 호스트 {i}")
        a("- 🛡 > _작성 (+ 인용)_")
    a("### 2.7 도메인 / 포레스트 장악")
    a("- 🛡 > _작성 (+ 인용)_\n")

    a("## 참고 / 인용")
    a("- > _실제 사용한 도구·블로그·강의 명시 (PowerView, Rubeus, mimikatz, SharpGPOAbuse, Certify 등)_")

    path = os.path.join(out_dir, "report_skeleton.md")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines))
    return path


def write_evidence_tracker(findings, model, out_dir):
    lines = []
    a = lines.append
    a("# CRTP 증거 추적 & 보고서 스캐폴드\n")
    a("> ⚠ **규정 경고**: 최종 보고서 본문은 **반드시 본인이 직접** 작성해야 합니다.")
    a("> AI가 생성한 글을 보고서에 넣으면 부정행위로 실격됩니다.")
    a("> 아래 '내 설명' 칸은 **본인 문장으로** 채우세요. 이 파일은 증거 정리용입니다.\n")

    a("## 대상 서버 정복 현황 (5대 전부 OS 명령 실행이 목표)\n")
    a("| # | 호스트 | 도메인 | 초기 접근 방식 | OS 명령 실행? | 로컬/도메인 관리자? | flag/증적 |")
    a("|---|--------|--------|----------------|:-------------:|:-------------------:|-----------|")
    comps = [c for c in model.computers.values()]
    for i in range(1, 6):
        host = ""
        if i <= len(comps):
            host = comps[i-1].p("samaccountname") or comps[i-1].name or ""
        a(f"| {i} | {host} | | | ☐ | | |")
    a("")
    a(f"**최종 flag**: `{EXAM['final_flag']}` — 캡처 후 스크린샷 필수 (호스트명+whoami 함께 보이게)\n")

    a("## 도메인/트러스트 맵 (다중 도메인)\n")
    a("- [ ] `Get-DomainTrustMapping` 실행 후 전체 트러스트 다이어그램 스크린샷")
    a("- [ ] 각 도메인의 DA / EA 그룹 멤버 식별")
    a("- [ ] child → parent 경로 확인 (SID history 사용 여부)\n")

    a("## 기법별 증거 체크리스트\n")
    for f in findings:
        if f.severity == "INFO" and f.crtp_topic == "meta":
            continue
        a(f"### {f.technique} — 대상: {', '.join(f.targets) if f.targets else '-'}")
        a("| 항목 | 상태 |")
        a("|------|:----:|")
        a("| 명령 실행 성공 | ☐ |")
        for s in f.screenshots:
            a(f"| 📸 {s} | ☐ |")
        a("")
        a("**내 설명 (본인 문장으로 — 이 명령이 무엇을 하고 왜 통했는가):**")
        a("> _여기에 직접 작성_\n")
        a("**완화 방안 (본인 조사·인용 포함하면 가점):**")
        a("> _여기에 직접 작성_\n")

    path = os.path.join(out_dir, "evidence_tracker.md")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines))
    return path


def main():
    ap = argparse.ArgumentParser(description="CRTP SOAPHound analyzer")
    ap.add_argument("input_dir", help="dir with *_users.json etc.")
    ap.add_argument("--out", default=None, help="output dir")
    args = ap.parse_args()

    here = os.path.dirname(os.path.abspath(__file__))
    out_dir = args.out or os.path.join(os.path.dirname(here), "output")
    os.makedirs(out_dir, exist_ok=True)

    model = load(args.input_dir)
    findings = analyze(model)

    # Fold in host-layer / AD CS findings from their separate analyzers, if present,
    # so the unified plan/playbook cover local privesc (localpriv.py) and ESC (adcs.py).
    findings += _load_extra_findings(out_dir)
    findings.sort(key=lambda f: (f.priority, f.fid))

    with open(os.path.join(out_dir, "findings.json"), "w", encoding="utf-8") as fh:
        json.dump([f.dict() for f in findings], fh, ensure_ascii=False, indent=2)

    pb = write_playbook(findings, model, out_dir)
    ev = write_evidence_tracker(findings, model, out_dir)
    ep = write_evidence_plan(findings, model, out_dir)
    rs = write_report_skeleton(findings, model, out_dir)

    print(f"[+] domain={model.domain} objects="
          f"{len(model.users)+len(model.computers)+len(model.groups)}")
    print(f"[+] findings={len(findings)}")
    print(f"[+] playbook        -> {pb}")
    print(f"[+] evidence        -> {ev}")
    print(f"[+] evidence_plan   -> {ep}")
    print(f"[+] report_skeleton -> {rs}")
    print(f"[+] findings.json  -> {os.path.join(out_dir, 'findings.json')}")
    for w in model.warnings:
        print("    WARN:", w)


if __name__ == "__main__":
    main()
