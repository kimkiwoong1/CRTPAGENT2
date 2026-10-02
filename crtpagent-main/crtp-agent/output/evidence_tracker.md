# CRTP 증거 추적 & 보고서 스캐폴드

> ⚠ **규정 경고**: 최종 보고서 본문은 **반드시 본인이 직접** 작성해야 합니다.
> AI가 생성한 글을 보고서에 넣으면 부정행위로 실격됩니다.
> 아래 '내 설명' 칸은 **본인 문장으로** 채우세요. 이 파일은 증거 정리용입니다.

## 대상 서버 정복 현황 (5대 전부 OS 명령 실행이 목표)

| # | 호스트 | 도메인 | 초기 접근 방식 | OS 명령 실행? | 로컬/도메인 관리자? | flag/증적 |
|---|--------|--------|----------------|:-------------:|:-------------------:|-----------|
| 1 | DCORP-CI$ | | | ☐ | | |
| 2 | DCORP-STDADMIN$ | | | ☐ | | |
| 3 | DCORP-STD201$ | | | ☐ | | |
| 4 | DCORP-STD202$ | | | ☐ | | |
| 5 | DCORP-STD203$ | | | ☐ | | |

**최종 flag**: `C:\Users\finadmin\Desktop\finalflag.txt (DC)` — 캡처 후 스크린샷 필수 (호스트명+whoami 함께 보이게)

## 도메인/트러스트 맵 (다중 도메인)

- [ ] `Get-DomainTrustMapping` 실행 후 전체 트러스트 다이어그램 스크린샷
- [ ] 각 도메인의 DA / EA 그룹 멤버 식별
- [ ] child → parent 경로 확인 (SID history 사용 여부)

## 기법별 증거 체크리스트

### High-value group: Account Operators — 대상: ACCOUNT OPERATORS@DOLLARCORP.MONEYCORP.LOCAL
| 항목 | 상태 |
|------|:----:|
| 명령 실행 성공 | ☐ |
| 📸 Account Operators 멤버십 확인 화면 | ☐ |

**내 설명 (본인 문장으로 — 이 명령이 무엇을 하고 왜 통했는가):**
> _여기에 직접 작성_

**완화 방안 (본인 조사·인용 포함하면 가점):**
> _여기에 직접 작성_

### High-value group: Administrators — 대상: <unknown>, DOMAIN ADMINS@DOLLARCORP.MONEYCORP.LOCAL, ADMINISTRATOR@DOLLARCORP.MONEYCORP.LOCAL
| 항목 | 상태 |
|------|:----:|
| 명령 실행 성공 | ☐ |
| 📸 Administrators 멤버십 확인 화면 | ☐ |

**내 설명 (본인 문장으로 — 이 명령이 무엇을 하고 왜 통했는가):**
> _여기에 직접 작성_

**완화 방안 (본인 조사·인용 포함하면 가점):**
> _여기에 직접 작성_

### High-value group: Backup Operators — 대상: BACKUP OPERATORS@DOLLARCORP.MONEYCORP.LOCAL
| 항목 | 상태 |
|------|:----:|
| 명령 실행 성공 | ☐ |
| 📸 Backup Operators 멤버십 확인 화면 | ☐ |

**내 설명 (본인 문장으로 — 이 명령이 무엇을 하고 왜 통했는가):**
> _여기에 직접 작성_

**완화 방안 (본인 조사·인용 포함하면 가점):**
> _여기에 직접 작성_

### High-value group: DnsAdmins (typical) — 대상: SRVADMIN@DOLLARCORP.MONEYCORP.LOCAL
| 항목 | 상태 |
|------|:----:|
| 명령 실행 성공 | ☐ |
| 📸 DnsAdmins (typical) 멤버십 확인 화면 | ☐ |

**내 설명 (본인 문장으로 — 이 명령이 무엇을 하고 왜 통했는가):**
> _여기에 직접 작성_

**완화 방안 (본인 조사·인용 포함하면 가점):**
> _여기에 직접 작성_

### High-value group: Domain Admins — 대상: SVCADMIN@DOLLARCORP.MONEYCORP.LOCAL, ADMINISTRATOR@DOLLARCORP.MONEYCORP.LOCAL
| 항목 | 상태 |
|------|:----:|
| 명령 실행 성공 | ☐ |
| 📸 Domain Admins 멤버십 확인 화면 | ☐ |

**내 설명 (본인 문장으로 — 이 명령이 무엇을 하고 왜 통했는가):**
> _여기에 직접 작성_

**완화 방안 (본인 조사·인용 포함하면 가점):**
> _여기에 직접 작성_

### High-value group: Domain Controllers — 대상: DOMAIN CONTROLLERS@DOLLARCORP.MONEYCORP.LOCAL
| 항목 | 상태 |
|------|:----:|
| 명령 실행 성공 | ☐ |
| 📸 Domain Controllers 멤버십 확인 화면 | ☐ |

**내 설명 (본인 문장으로 — 이 명령이 무엇을 하고 왜 통했는가):**
> _여기에 직접 작성_

**완화 방안 (본인 조사·인용 포함하면 가점):**
> _여기에 직접 작성_

### High-value group: Group Policy Creator Owners — 대상: ADMINISTRATOR@DOLLARCORP.MONEYCORP.LOCAL
| 항목 | 상태 |
|------|:----:|
| 명령 실행 성공 | ☐ |
| 📸 Group Policy Creator Owners 멤버십 확인 화면 | ☐ |

**내 설명 (본인 문장으로 — 이 명령이 무엇을 하고 왜 통했는가):**
> _여기에 직접 작성_

**완화 방안 (본인 조사·인용 포함하면 가점):**
> _여기에 직접 작성_

### SeImpersonate -> SYSTEM (Potato) — 대상: <current host>
| 항목 | 상태 |
|------|:----:|
| 명령 실행 성공 | ☐ |
| 📸 whoami /priv 에 SeImpersonatePrivilege 보이는 화면 (escalation 전) | ☐ |
| 📸 exploit 실행 + whoami == SYSTEM 화면 (escalation 후) | ☐ |

**내 설명 (본인 문장으로 — 이 명령이 무엇을 하고 왜 통했는가):**
> _여기에 직접 작성_

**완화 방안 (본인 조사·인용 포함하면 가점):**
> _여기에 직접 작성_

### AD CS ESC1 — template 'ESC1-User' — 대상: ESC1-User @ mcorp-dc.moneycorp.local\moneycorp-MCORP-DC-CA
| 항목 | 상태 |
|------|:----:|
| 명령 실행 성공 | ☐ |
| 📸 Certify find /vulnerable 에 'ESC1-User' ESC1 조건 보이는 화면 | ☐ |
| 📸 ESC1 request 성공 (인증서 발급) 화면 | ☐ |
| 📸 asktgt /ptt 후 klist + 대상 DC 접근 화면 | ☐ |

**내 설명 (본인 문장으로 — 이 명령이 무엇을 하고 왜 통했는가):**
> _여기에 직접 작성_

**완화 방안 (본인 조사·인용 포함하면 가점):**
> _여기에 직접 작성_

### AD CS ESC3 — template 'SmartCardEnrollment-Agent' — 대상: SmartCardEnrollment-Agent @ mcorp-dc.moneycorp.local\moneycorp-MCORP-DC-CA
| 항목 | 상태 |
|------|:----:|
| 명령 실행 성공 | ☐ |
| 📸 Certify find /vulnerable 에 'SmartCardEnrollment-Agent' ESC3 조건 보이는 화면 | ☐ |
| 📸 ESC3 request 성공 (인증서 발급) 화면 | ☐ |
| 📸 asktgt /ptt 후 klist + 대상 DC 접근 화면 | ☐ |

**내 설명 (본인 문장으로 — 이 명령이 무엇을 하고 왜 통했는가):**
> _여기에 직접 작성_

**완화 방안 (본인 조사·인용 포함하면 가점):**
> _여기에 직접 작성_

### DCSync — 대상: S-1-5-21-335606122-960912869-3279953914-498
| 항목 | 상태 |
|------|:----:|
| 명령 실행 성공 | ☐ |
| 📸 S-1-5-21-335606122-960912869-3279953914-498 의 GetChanges/GetChangesAll 권한 확인 (Get-DomainObjectAcl) | ☐ |
| 📸 dcsync 로 krbtgt 해시 덤프 화면 | ☐ |

**내 설명 (본인 문장으로 — 이 명령이 무엇을 하고 왜 통했는가):**
> _여기에 직접 작성_

**완화 방안 (본인 조사·인용 포함하면 가점):**
> _여기에 직접 작성_

### DCSync — 대상: DOMAIN CONTROLLERS@DOLLARCORP.MONEYCORP.LOCAL
| 항목 | 상태 |
|------|:----:|
| 명령 실행 성공 | ☐ |
| 📸 DOMAIN CONTROLLERS@DOLLARCORP.MONEYCORP.LOCAL 의 GetChanges/GetChangesAll 권한 확인 (Get-DomainObjectAcl) | ☐ |
| 📸 dcsync 로 krbtgt 해시 덤프 화면 | ☐ |

**내 설명 (본인 문장으로 — 이 명령이 무엇을 하고 왜 통했는가):**
> _여기에 직접 작성_

**완화 방안 (본인 조사·인용 포함하면 가점):**
> _여기에 직접 작성_

### AD CS ESC6 — CA allows requester-specified SAN (EDITF_ATTRIBUTESUBJECTALTNAME2) — 대상: mcorp-dc.moneycorp.local\moneycorp-MCORP-DC-CA
| 항목 | 상태 |
|------|:----:|
| 명령 실행 성공 | ☐ |
| 📸 Certify find 에서 'mcorp-dc.moneycorp.local\moneycorp-MCORP-DC-CA' UserSpecifiedSAN 표시 화면 | ☐ |
| 📸 altname 지정 request 성공 화면 | ☐ |
| 📸 asktgt /ptt + klist 화면 | ☐ |

**내 설명 (본인 문장으로 — 이 명령이 무엇을 하고 왜 통했는가):**
> _여기에 직접 작성_

**완화 방안 (본인 조사·인용 포함하면 가점):**
> _여기에 직접 작성_

### ACL abuse: Owns — 대상: DNSADMINS@DOLLARCORP.MONEYCORP.LOCAL
| 항목 | 상태 |
|------|:----:|
| 명령 실행 성공 | ☐ |
| 📸 ACL 확인: Get-DomainObjectAcl -Identity DNSADMINS@DOLLARCORP.MONEYCORP.LOCAL 출력 | ☐ |
| 📸 권한 남용 실행 화면 (그룹 추가 / 패스워드 변경 등) | ☐ |
| 📸 남용 후 획득한 접근 증명 화면 | ☐ |

**내 설명 (본인 문장으로 — 이 명령이 무엇을 하고 왜 통했는가):**
> _여기에 직접 작성_

**완화 방안 (본인 조사·인용 포함하면 가점):**
> _여기에 직접 작성_

### GPO abuse: GenericAll over GPO — 대상: DCORP-ADMINSRV.DOLLARCORP.MONEYCORP.LOCAL
| 항목 | 상태 |
|------|:----:|
| 명령 실행 성공 | ☐ |
| 📸 GPO 'APPLOCKER@DOLLARCORP.MONEYCORP.LOCAL' ACL 확인 (Get-DomainGPO / Get-DomainObjectAcl) | ☐ |
| 📸 GPO 수정 / task 추가 화면 | ☐ |
| 📸 영향 호스트에서 권한 획득 화면 | ☐ |

**내 설명 (본인 문장으로 — 이 명령이 무엇을 하고 왜 통했는가):**
> _여기에 직접 작성_

**완화 방안 (본인 조사·인용 포함하면 가점):**
> _여기에 직접 작성_

### GPO abuse: GenericWrite over GPO — 대상: DCORP-ADMINSRV.DOLLARCORP.MONEYCORP.LOCAL
| 항목 | 상태 |
|------|:----:|
| 명령 실행 성공 | ☐ |
| 📸 GPO 'APPLOCKER@DOLLARCORP.MONEYCORP.LOCAL' ACL 확인 (Get-DomainGPO / Get-DomainObjectAcl) | ☐ |
| 📸 GPO 수정 / task 추가 화면 | ☐ |
| 📸 영향 호스트에서 권한 획득 화면 | ☐ |

**내 설명 (본인 문장으로 — 이 명령이 무엇을 하고 왜 통했는가):**
> _여기에 직접 작성_

**완화 방안 (본인 조사·인용 포함하면 가점):**
> _여기에 직접 작성_

### GPO abuse: GenericWrite over GPO — 대상: DCORP-CI.DOLLARCORP.MONEYCORP.LOCAL
| 항목 | 상태 |
|------|:----:|
| 명령 실행 성공 | ☐ |
| 📸 GPO 'DEVOPS POLICY@DOLLARCORP.MONEYCORP.LOCAL' ACL 확인 (Get-DomainGPO / Get-DomainObjectAcl) | ☐ |
| 📸 GPO 수정 / task 추가 화면 | ☐ |
| 📸 영향 호스트에서 권한 획득 화면 | ☐ |

**내 설명 (본인 문장으로 — 이 명령이 무엇을 하고 왜 통했는가):**
> _여기에 직접 작성_

**완화 방안 (본인 조사·인용 포함하면 가점):**
> _여기에 직접 작성_

### GPO abuse: WriteDacl over GPO — 대상: DCORP-CI.DOLLARCORP.MONEYCORP.LOCAL
| 항목 | 상태 |
|------|:----:|
| 명령 실행 성공 | ☐ |
| 📸 GPO 'DEVOPS POLICY@DOLLARCORP.MONEYCORP.LOCAL' ACL 확인 (Get-DomainGPO / Get-DomainObjectAcl) | ☐ |
| 📸 GPO 수정 / task 추가 화면 | ☐ |
| 📸 영향 호스트에서 권한 획득 화면 | ☐ |

**내 설명 (본인 문장으로 — 이 명령이 무엇을 하고 왜 통했는가):**
> _여기에 직접 작성_

**완화 방안 (본인 조사·인용 포함하면 가점):**
> _여기에 직접 작성_

### GPO abuse: WriteOwner over GPO — 대상: DCORP-CI.DOLLARCORP.MONEYCORP.LOCAL
| 항목 | 상태 |
|------|:----:|
| 명령 실행 성공 | ☐ |
| 📸 GPO 'DEVOPS POLICY@DOLLARCORP.MONEYCORP.LOCAL' ACL 확인 (Get-DomainGPO / Get-DomainObjectAcl) | ☐ |
| 📸 GPO 수정 / task 추가 화면 | ☐ |
| 📸 영향 호스트에서 권한 획득 화면 | ☐ |

**내 설명 (본인 문장으로 — 이 명령이 무엇을 하고 왜 통했는가):**
> _여기에 직접 작성_

**완화 방안 (본인 조사·인용 포함하면 가점):**
> _여기에 직접 작성_

### Domain/Forest trust abuse — 대상: EUROCORP.LOCAL
| 항목 | 상태 |
|------|:----:|
| 명령 실행 성공 | ☐ |
| 📸 Get-DomainTrustMapping 출력 | ☐ |
| 📸 위조 티켓으로 대상 도메인 리소스 접근 화면 | ☐ |

**내 설명 (본인 문장으로 — 이 명령이 무엇을 하고 왜 통했는가):**
> _여기에 직접 작성_

**완화 방안 (본인 조사·인용 포함하면 가점):**
> _여기에 직접 작성_

### Domain/Forest trust abuse — 대상: MONEYCORP.LOCAL
| 항목 | 상태 |
|------|:----:|
| 명령 실행 성공 | ☐ |
| 📸 Get-DomainTrustMapping 출력 | ☐ |
| 📸 위조 티켓으로 대상 도메인 리소스 접근 화면 | ☐ |

**내 설명 (본인 문장으로 — 이 명령이 무엇을 하고 왜 통했는가):**
> _여기에 직접 작성_

**완화 방안 (본인 조사·인용 포함하면 가점):**
> _여기에 직접 작성_

### Domain/Forest trust abuse — 대상: US.DOLLARCORP.MONEYCORP.LOCAL
| 항목 | 상태 |
|------|:----:|
| 명령 실행 성공 | ☐ |
| 📸 Get-DomainTrustMapping 출력 | ☐ |
| 📸 위조 티켓으로 대상 도메인 리소스 접근 화면 | ☐ |

**내 설명 (본인 문장으로 — 이 명령이 무엇을 하고 왜 통했는가):**
> _여기에 직접 작성_

**완화 방안 (본인 조사·인용 포함하면 가점):**
> _여기에 직접 작성_

### Unconstrained Delegation abuse — 대상: DCORP-APPSRV$
| 항목 | 상태 |
|------|:----:|
| 명령 실행 성공 | ☐ |
| 📸 DCORP-APPSRV$ Unconstrained delegation 속성 확인 | ☐ |
| 📸 Rubeus monitor 로 캡처된 TGT 화면 | ☐ |
| 📸 PTT 후 특권 접근 확인 (예: DCSync 또는 DC 접근) | ☐ |

**내 설명 (본인 문장으로 — 이 명령이 무엇을 하고 왜 통했는가):**
> _여기에 직접 작성_

**완화 방안 (본인 조사·인용 포함하면 가점):**
> _여기에 직접 작성_

### SeBackup -> read SAM/SYSTEM & sensitive files — 대상: <current host>
| 항목 | 상태 |
|------|:----:|
| 명령 실행 성공 | ☐ |
| 📸 whoami /priv 에 SeBackupPrivilege 보이는 화면 (escalation 전) | ☐ |
| 📸 exploit 실행 + whoami == SYSTEM 화면 (escalation 후) | ☐ |

**내 설명 (본인 문장으로 — 이 명령이 무엇을 하고 왜 통했는가):**
> _여기에 직접 작성_

**완화 방안 (본인 조사·인용 포함하면 가점):**
> _여기에 직접 작성_

### SeDebug -> inject into SYSTEM process / dump lsass — 대상: <current host>
| 항목 | 상태 |
|------|:----:|
| 명령 실행 성공 | ☐ |
| 📸 whoami /priv 에 SeDebugPrivilege 보이는 화면 (escalation 전) | ☐ |
| 📸 exploit 실행 + whoami == SYSTEM 화면 (escalation 후) | ☐ |

**내 설명 (본인 문장으로 — 이 명령이 무엇을 하고 왜 통했는가):**
> _여기에 직접 작성_

**완화 방안 (본인 조사·인용 포함하면 가점):**
> _여기에 직접 작성_

### Kerberoasting — 대상: svcadmin
| 항목 | 상태 |
|------|:----:|
| 명령 실행 성공 | ☐ |
| 📸 svcadmin SPN 확인 (Get-ADUser/setspn 출력) | ☐ |
| 📸 Rubeus kerberoast 해시 추출 화면 | ☐ |
| 📸 hashcat 크랙 성공 (평문 노출) 화면 | ☐ |
| 📸 크랙한 계정으로 인증/권한 확인 화면 | ☐ |

**내 설명 (본인 문장으로 — 이 명령이 무엇을 하고 왜 통했는가):**
> _여기에 직접 작성_

**완화 방안 (본인 조사·인용 포함하면 가점):**
> _여기에 직접 작성_

### AS-REP Roasting — 대상: VPN201user
| 항목 | 상태 |
|------|:----:|
| 명령 실행 성공 | ☐ |
| 📸 VPN201user DoesNotRequirePreAuth 확인 화면 | ☐ |
| 📸 Rubeus asreproast 추출 화면 | ☐ |
| 📸 hashcat 크랙 성공 화면 | ☐ |

**내 설명 (본인 문장으로 — 이 명령이 무엇을 하고 왜 통했는가):**
> _여기에 직접 작성_

**완화 방안 (본인 조사·인용 포함하면 가점):**
> _여기에 직접 작성_

### AS-REP Roasting — 대상: VPN202user
| 항목 | 상태 |
|------|:----:|
| 명령 실행 성공 | ☐ |
| 📸 VPN202user DoesNotRequirePreAuth 확인 화면 | ☐ |
| 📸 Rubeus asreproast 추출 화면 | ☐ |
| 📸 hashcat 크랙 성공 화면 | ☐ |

**내 설명 (본인 문장으로 — 이 명령이 무엇을 하고 왜 통했는가):**
> _여기에 직접 작성_

**완화 방안 (본인 조사·인용 포함하면 가점):**
> _여기에 직접 작성_

### AS-REP Roasting — 대상: VPN203user
| 항목 | 상태 |
|------|:----:|
| 명령 실행 성공 | ☐ |
| 📸 VPN203user DoesNotRequirePreAuth 확인 화면 | ☐ |
| 📸 Rubeus asreproast 추출 화면 | ☐ |
| 📸 hashcat 크랙 성공 화면 | ☐ |

**내 설명 (본인 문장으로 — 이 명령이 무엇을 하고 왜 통했는가):**
> _여기에 직접 작성_

**완화 방안 (본인 조사·인용 포함하면 가점):**
> _여기에 직접 작성_

### AS-REP Roasting — 대상: VPN204user
| 항목 | 상태 |
|------|:----:|
| 명령 실행 성공 | ☐ |
| 📸 VPN204user DoesNotRequirePreAuth 확인 화면 | ☐ |
| 📸 Rubeus asreproast 추출 화면 | ☐ |
| 📸 hashcat 크랙 성공 화면 | ☐ |

**내 설명 (본인 문장으로 — 이 명령이 무엇을 하고 왜 통했는가):**
> _여기에 직접 작성_

**완화 방안 (본인 조사·인용 포함하면 가점):**
> _여기에 직접 작성_

### AS-REP Roasting — 대상: VPN205user
| 항목 | 상태 |
|------|:----:|
| 명령 실행 성공 | ☐ |
| 📸 VPN205user DoesNotRequirePreAuth 확인 화면 | ☐ |
| 📸 Rubeus asreproast 추출 화면 | ☐ |
| 📸 hashcat 크랙 성공 화면 | ☐ |

**내 설명 (본인 문장으로 — 이 명령이 무엇을 하고 왜 통했는가):**
> _여기에 직접 작성_

**완화 방안 (본인 조사·인용 포함하면 가점):**
> _여기에 직접 작성_

### AS-REP Roasting — 대상: VPN206user
| 항목 | 상태 |
|------|:----:|
| 명령 실행 성공 | ☐ |
| 📸 VPN206user DoesNotRequirePreAuth 확인 화면 | ☐ |
| 📸 Rubeus asreproast 추출 화면 | ☐ |
| 📸 hashcat 크랙 성공 화면 | ☐ |

**내 설명 (본인 문장으로 — 이 명령이 무엇을 하고 왜 통했는가):**
> _여기에 직접 작성_

**완화 방안 (본인 조사·인용 포함하면 가점):**
> _여기에 직접 작성_

### AS-REP Roasting — 대상: VPN207user
| 항목 | 상태 |
|------|:----:|
| 명령 실행 성공 | ☐ |
| 📸 VPN207user DoesNotRequirePreAuth 확인 화면 | ☐ |
| 📸 Rubeus asreproast 추출 화면 | ☐ |
| 📸 hashcat 크랙 성공 화면 | ☐ |

**내 설명 (본인 문장으로 — 이 명령이 무엇을 하고 왜 통했는가):**
> _여기에 직접 작성_

**완화 방안 (본인 조사·인용 포함하면 가점):**
> _여기에 직접 작성_

### AS-REP Roasting — 대상: VPN208user
| 항목 | 상태 |
|------|:----:|
| 명령 실행 성공 | ☐ |
| 📸 VPN208user DoesNotRequirePreAuth 확인 화면 | ☐ |
| 📸 Rubeus asreproast 추출 화면 | ☐ |
| 📸 hashcat 크랙 성공 화면 | ☐ |

**내 설명 (본인 문장으로 — 이 명령이 무엇을 하고 왜 통했는가):**
> _여기에 직접 작성_

**완화 방안 (본인 조사·인용 포함하면 가점):**
> _여기에 직접 작성_

### AS-REP Roasting — 대상: VPN209user
| 항목 | 상태 |
|------|:----:|
| 명령 실행 성공 | ☐ |
| 📸 VPN209user DoesNotRequirePreAuth 확인 화면 | ☐ |
| 📸 Rubeus asreproast 추출 화면 | ☐ |
| 📸 hashcat 크랙 성공 화면 | ☐ |

**내 설명 (본인 문장으로 — 이 명령이 무엇을 하고 왜 통했는가):**
> _여기에 직접 작성_

**완화 방안 (본인 조사·인용 포함하면 가점):**
> _여기에 직접 작성_

### AS-REP Roasting — 대상: VPN210user
| 항목 | 상태 |
|------|:----:|
| 명령 실행 성공 | ☐ |
| 📸 VPN210user DoesNotRequirePreAuth 확인 화면 | ☐ |
| 📸 Rubeus asreproast 추출 화면 | ☐ |
| 📸 hashcat 크랙 성공 화면 | ☐ |

**내 설명 (본인 문장으로 — 이 명령이 무엇을 하고 왜 통했는가):**
> _여기에 직접 작성_

**완화 방안 (본인 조사·인용 포함하면 가점):**
> _여기에 직접 작성_

### AS-REP Roasting — 대상: VPN211user
| 항목 | 상태 |
|------|:----:|
| 명령 실행 성공 | ☐ |
| 📸 VPN211user DoesNotRequirePreAuth 확인 화면 | ☐ |
| 📸 Rubeus asreproast 추출 화면 | ☐ |
| 📸 hashcat 크랙 성공 화면 | ☐ |

**내 설명 (본인 문장으로 — 이 명령이 무엇을 하고 왜 통했는가):**
> _여기에 직접 작성_

**완화 방안 (본인 조사·인용 포함하면 가점):**
> _여기에 직접 작성_

### AS-REP Roasting — 대상: VPN212user
| 항목 | 상태 |
|------|:----:|
| 명령 실행 성공 | ☐ |
| 📸 VPN212user DoesNotRequirePreAuth 확인 화면 | ☐ |
| 📸 Rubeus asreproast 추출 화면 | ☐ |
| 📸 hashcat 크랙 성공 화면 | ☐ |

**내 설명 (본인 문장으로 — 이 명령이 무엇을 하고 왜 통했는가):**
> _여기에 직접 작성_

**완화 방안 (본인 조사·인용 포함하면 가점):**
> _여기에 직접 작성_

### AS-REP Roasting — 대상: VPN213user
| 항목 | 상태 |
|------|:----:|
| 명령 실행 성공 | ☐ |
| 📸 VPN213user DoesNotRequirePreAuth 확인 화면 | ☐ |
| 📸 Rubeus asreproast 추출 화면 | ☐ |
| 📸 hashcat 크랙 성공 화면 | ☐ |

**내 설명 (본인 문장으로 — 이 명령이 무엇을 하고 왜 통했는가):**
> _여기에 직접 작성_

**완화 방안 (본인 조사·인용 포함하면 가점):**
> _여기에 직접 작성_

### AS-REP Roasting — 대상: VPN214user
| 항목 | 상태 |
|------|:----:|
| 명령 실행 성공 | ☐ |
| 📸 VPN214user DoesNotRequirePreAuth 확인 화면 | ☐ |
| 📸 Rubeus asreproast 추출 화면 | ☐ |
| 📸 hashcat 크랙 성공 화면 | ☐ |

**내 설명 (본인 문장으로 — 이 명령이 무엇을 하고 왜 통했는가):**
> _여기에 직접 작성_

**완화 방안 (본인 조사·인용 포함하면 가점):**
> _여기에 직접 작성_

### AS-REP Roasting — 대상: VPN215user
| 항목 | 상태 |
|------|:----:|
| 명령 실행 성공 | ☐ |
| 📸 VPN215user DoesNotRequirePreAuth 확인 화면 | ☐ |
| 📸 Rubeus asreproast 추출 화면 | ☐ |
| 📸 hashcat 크랙 성공 화면 | ☐ |

**내 설명 (본인 문장으로 — 이 명령이 무엇을 하고 왜 통했는가):**
> _여기에 직접 작성_

**완화 방안 (본인 조사·인용 포함하면 가점):**
> _여기에 직접 작성_

### AS-REP Roasting — 대상: VPN216user
| 항목 | 상태 |
|------|:----:|
| 명령 실행 성공 | ☐ |
| 📸 VPN216user DoesNotRequirePreAuth 확인 화면 | ☐ |
| 📸 Rubeus asreproast 추출 화면 | ☐ |
| 📸 hashcat 크랙 성공 화면 | ☐ |

**내 설명 (본인 문장으로 — 이 명령이 무엇을 하고 왜 통했는가):**
> _여기에 직접 작성_

**완화 방안 (본인 조사·인용 포함하면 가점):**
> _여기에 직접 작성_

### AS-REP Roasting — 대상: VPN217user
| 항목 | 상태 |
|------|:----:|
| 명령 실행 성공 | ☐ |
| 📸 VPN217user DoesNotRequirePreAuth 확인 화면 | ☐ |
| 📸 Rubeus asreproast 추출 화면 | ☐ |
| 📸 hashcat 크랙 성공 화면 | ☐ |

**내 설명 (본인 문장으로 — 이 명령이 무엇을 하고 왜 통했는가):**
> _여기에 직접 작성_

**완화 방안 (본인 조사·인용 포함하면 가점):**
> _여기에 직접 작성_

### AS-REP Roasting — 대상: VPN218user
| 항목 | 상태 |
|------|:----:|
| 명령 실행 성공 | ☐ |
| 📸 VPN218user DoesNotRequirePreAuth 확인 화면 | ☐ |
| 📸 Rubeus asreproast 추출 화면 | ☐ |
| 📸 hashcat 크랙 성공 화면 | ☐ |

**내 설명 (본인 문장으로 — 이 명령이 무엇을 하고 왜 통했는가):**
> _여기에 직접 작성_

**완화 방안 (본인 조사·인용 포함하면 가점):**
> _여기에 직접 작성_

### AS-REP Roasting — 대상: VPN219user
| 항목 | 상태 |
|------|:----:|
| 명령 실행 성공 | ☐ |
| 📸 VPN219user DoesNotRequirePreAuth 확인 화면 | ☐ |
| 📸 Rubeus asreproast 추출 화면 | ☐ |
| 📸 hashcat 크랙 성공 화면 | ☐ |

**내 설명 (본인 문장으로 — 이 명령이 무엇을 하고 왜 통했는가):**
> _여기에 직접 작성_

**완화 방안 (본인 조사·인용 포함하면 가점):**
> _여기에 직접 작성_

### AS-REP Roasting — 대상: VPN220user
| 항목 | 상태 |
|------|:----:|
| 명령 실행 성공 | ☐ |
| 📸 VPN220user DoesNotRequirePreAuth 확인 화면 | ☐ |
| 📸 Rubeus asreproast 추출 화면 | ☐ |
| 📸 hashcat 크랙 성공 화면 | ☐ |

**내 설명 (본인 문장으로 — 이 명령이 무엇을 하고 왜 통했는가):**
> _여기에 직접 작성_

**완화 방안 (본인 조사·인용 포함하면 가점):**
> _여기에 직접 작성_

### ACL abuse: GenericWrite — 대상: APPLOCKER@DOLLARCORP.MONEYCORP.LOCAL
| 항목 | 상태 |
|------|:----:|
| 명령 실행 성공 | ☐ |
| 📸 ACL 확인: Get-DomainObjectAcl -Identity APPLOCKER@DOLLARCORP.MONEYCORP.LOCAL 출력 | ☐ |
| 📸 권한 남용 실행 화면 (그룹 추가 / 패스워드 변경 등) | ☐ |
| 📸 남용 후 획득한 접근 증명 화면 | ☐ |

**내 설명 (본인 문장으로 — 이 명령이 무엇을 하고 왜 통했는가):**
> _여기에 직접 작성_

**완화 방안 (본인 조사·인용 포함하면 가점):**
> _여기에 직접 작성_

### ACL abuse: GenericWrite — 대상: DCORP-MGMT.DOLLARCORP.MONEYCORP.LOCAL
| 항목 | 상태 |
|------|:----:|
| 명령 실행 성공 | ☐ |
| 📸 ACL 확인: Get-DomainObjectAcl -Identity DCORP-MGMT.DOLLARCORP.MONEYCORP.LOCAL 출력 | ☐ |
| 📸 권한 남용 실행 화면 (그룹 추가 / 패스워드 변경 등) | ☐ |
| 📸 남용 후 획득한 접근 증명 화면 | ☐ |

**내 설명 (본인 문장으로 — 이 명령이 무엇을 하고 왜 통했는가):**
> _여기에 직접 작성_

**완화 방안 (본인 조사·인용 포함하면 가점):**
> _여기에 직접 작성_

### ACL abuse: GenericWrite — 대상: DEVOPS POLICY@DOLLARCORP.MONEYCORP.LOCAL
| 항목 | 상태 |
|------|:----:|
| 명령 실행 성공 | ☐ |
| 📸 ACL 확인: Get-DomainObjectAcl -Identity DEVOPS POLICY@DOLLARCORP.MONEYCORP.LOCAL 출력 | ☐ |
| 📸 권한 남용 실행 화면 (그룹 추가 / 패스워드 변경 등) | ☐ |
| 📸 남용 후 획득한 접근 증명 화면 | ☐ |

**내 설명 (본인 문장으로 — 이 명령이 무엇을 하고 왜 통했는가):**
> _여기에 직접 작성_

**완화 방안 (본인 조사·인용 포함하면 가점):**
> _여기에 직접 작성_

### ACL abuse: Owns — 대상: DNSUPDATEPROXY@DOLLARCORP.MONEYCORP.LOCAL
| 항목 | 상태 |
|------|:----:|
| 명령 실행 성공 | ☐ |
| 📸 ACL 확인: Get-DomainObjectAcl -Identity DNSUPDATEPROXY@DOLLARCORP.MONEYCORP.LOCAL 출력 | ☐ |
| 📸 권한 남용 실행 화면 (그룹 추가 / 패스워드 변경 등) | ☐ |
| 📸 남용 후 획득한 접근 증명 화면 | ☐ |

**내 설명 (본인 문장으로 — 이 명령이 무엇을 하고 왜 통했는가):**
> _여기에 직접 작성_

**완화 방안 (본인 조사·인용 포함하면 가점):**
> _여기에 직접 작성_

### ACL abuse: WriteDacl — 대상: DEVOPS POLICY@DOLLARCORP.MONEYCORP.LOCAL
| 항목 | 상태 |
|------|:----:|
| 명령 실행 성공 | ☐ |
| 📸 ACL 확인: Get-DomainObjectAcl -Identity DEVOPS POLICY@DOLLARCORP.MONEYCORP.LOCAL 출력 | ☐ |
| 📸 권한 남용 실행 화면 (그룹 추가 / 패스워드 변경 등) | ☐ |
| 📸 남용 후 획득한 접근 증명 화면 | ☐ |

**내 설명 (본인 문장으로 — 이 명령이 무엇을 하고 왜 통했는가):**
> _여기에 직접 작성_

**완화 방안 (본인 조사·인용 포함하면 가점):**
> _여기에 직접 작성_

### ACL abuse: WriteDacl — 대상: RAS AND IAS SERVERS ACCESS CHECK@DOLLARCORP.MONEYCORP.LOCAL
| 항목 | 상태 |
|------|:----:|
| 명령 실행 성공 | ☐ |
| 📸 ACL 확인: Get-DomainObjectAcl -Identity RAS AND IAS SERVERS ACCESS CHECK@DOLLARCORP.MONEYCORP.LOCAL 출력 | ☐ |
| 📸 권한 남용 실행 화면 (그룹 추가 / 패스워드 변경 등) | ☐ |
| 📸 남용 후 획득한 접근 증명 화면 | ☐ |

**내 설명 (본인 문장으로 — 이 명령이 무엇을 하고 왜 통했는가):**
> _여기에 직접 작성_

**완화 방안 (본인 조사·인용 포함하면 가점):**
> _여기에 직접 작성_

### ACL abuse: WriteOwner — 대상: DEVOPS POLICY@DOLLARCORP.MONEYCORP.LOCAL
| 항목 | 상태 |
|------|:----:|
| 명령 실행 성공 | ☐ |
| 📸 ACL 확인: Get-DomainObjectAcl -Identity DEVOPS POLICY@DOLLARCORP.MONEYCORP.LOCAL 출력 | ☐ |
| 📸 권한 남용 실행 화면 (그룹 추가 / 패스워드 변경 등) | ☐ |
| 📸 남용 후 획득한 접근 증명 화면 | ☐ |

**내 설명 (본인 문장으로 — 이 명령이 무엇을 하고 왜 통했는가):**
> _여기에 직접 작성_

**완화 방안 (본인 조사·인용 포함하면 가점):**
> _여기에 직접 작성_

### ACL abuse: WriteOwner — 대상: RAS AND IAS SERVERS ACCESS CHECK@DOLLARCORP.MONEYCORP.LOCAL
| 항목 | 상태 |
|------|:----:|
| 명령 실행 성공 | ☐ |
| 📸 ACL 확인: Get-DomainObjectAcl -Identity RAS AND IAS SERVERS ACCESS CHECK@DOLLARCORP.MONEYCORP.LOCAL 출력 | ☐ |
| 📸 권한 남용 실행 화면 (그룹 추가 / 패스워드 변경 등) | ☐ |
| 📸 남용 후 획득한 접근 증명 화면 | ☐ |

**내 설명 (본인 문장으로 — 이 명령이 무엇을 하고 왜 통했는가):**
> _여기에 직접 작성_

**완화 방안 (본인 조사·인용 포함하면 가점):**
> _여기에 직접 작성_

### ACL abuse: GenericAll (bulk — 41 targets) — 대상: CONTROL201USER@DOLLARCORP.MONEYCORP.LOCAL, CONTROL202USER@DOLLARCORP.MONEYCORP.LOCAL, CONTROL203USER@DOLLARCORP.MONEYCORP.LOCAL, CONTROL204USER@DOLLARCORP.MONEYCORP.LOCAL, CONTROL205USER@DOLLARCORP.MONEYCORP.LOCAL, CONTROL206USER@DOLLARCORP.MONEYCORP.LOCAL, CONTROL207USER@DOLLARCORP.MONEYCORP.LOCAL, CONTROL208USER@DOLLARCORP.MONEYCORP.LOCAL, CONTROL209USER@DOLLARCORP.MONEYCORP.LOCAL, CONTROL210USER@DOLLARCORP.MONEYCORP.LOCAL, CONTROL211USER@DOLLARCORP.MONEYCORP.LOCAL, CONTROL212USER@DOLLARCORP.MONEYCORP.LOCAL, CONTROL213USER@DOLLARCORP.MONEYCORP.LOCAL, CONTROL214USER@DOLLARCORP.MONEYCORP.LOCAL, CONTROL215USER@DOLLARCORP.MONEYCORP.LOCAL, CONTROL216USER@DOLLARCORP.MONEYCORP.LOCAL, CONTROL217USER@DOLLARCORP.MONEYCORP.LOCAL, CONTROL218USER@DOLLARCORP.MONEYCORP.LOCAL, CONTROL219USER@DOLLARCORP.MONEYCORP.LOCAL, CONTROL220USER@DOLLARCORP.MONEYCORP.LOCAL, SUPPORT201USER@DOLLARCORP.MONEYCORP.LOCAL, SUPPORT202USER@DOLLARCORP.MONEYCORP.LOCAL, SUPPORT203USER@DOLLARCORP.MONEYCORP.LOCAL, SUPPORT204USER@DOLLARCORP.MONEYCORP.LOCAL, SUPPORT205USER@DOLLARCORP.MONEYCORP.LOCAL, SUPPORT206USER@DOLLARCORP.MONEYCORP.LOCAL, SUPPORT207USER@DOLLARCORP.MONEYCORP.LOCAL, SUPPORT208USER@DOLLARCORP.MONEYCORP.LOCAL, SUPPORT209USER@DOLLARCORP.MONEYCORP.LOCAL, SUPPORT210USER@DOLLARCORP.MONEYCORP.LOCAL, SUPPORT211USER@DOLLARCORP.MONEYCORP.LOCAL, SUPPORT212USER@DOLLARCORP.MONEYCORP.LOCAL, SUPPORT213USER@DOLLARCORP.MONEYCORP.LOCAL, SUPPORT214USER@DOLLARCORP.MONEYCORP.LOCAL, SUPPORT215USER@DOLLARCORP.MONEYCORP.LOCAL, SUPPORT216USER@DOLLARCORP.MONEYCORP.LOCAL, SUPPORT217USER@DOLLARCORP.MONEYCORP.LOCAL, SUPPORT218USER@DOLLARCORP.MONEYCORP.LOCAL, SUPPORT219USER@DOLLARCORP.MONEYCORP.LOCAL, SUPPORT220USER@DOLLARCORP.MONEYCORP.LOCAL, APPLOCKER@DOLLARCORP.MONEYCORP.LOCAL
| 항목 | 상태 |
|------|:----:|
| 명령 실행 성공 | ☐ |
| 📸 ACL 확인 출력 (대표 대상 1개) | ☐ |
| 📸 권한 남용 실행 화면 | ☐ |
| 📸 남용 후 획득 접근 증명 화면 | ☐ |

**내 설명 (본인 문장으로 — 이 명령이 무엇을 하고 왜 통했는가):**
> _여기에 직접 작성_

**완화 방안 (본인 조사·인용 포함하면 가점):**
> _여기에 직접 작성_

### Kerberoasting — 대상: websvc
| 항목 | 상태 |
|------|:----:|
| 명령 실행 성공 | ☐ |
| 📸 websvc SPN 확인 (Get-ADUser/setspn 출력) | ☐ |
| 📸 Rubeus kerberoast 해시 추출 화면 | ☐ |
| 📸 hashcat 크랙 성공 (평문 노출) 화면 | ☐ |
| 📸 크랙한 계정으로 인증/권한 확인 화면 | ☐ |

**내 설명 (본인 문장으로 — 이 명령이 무엇을 하고 왜 통했는가):**
> _여기에 직접 작성_

**완화 방안 (본인 조사·인용 포함하면 가점):**
> _여기에 직접 작성_

### Unconstrained Delegation abuse — 대상: DCORP-DC$
| 항목 | 상태 |
|------|:----:|
| 명령 실행 성공 | ☐ |
| 📸 DCORP-DC$ Unconstrained delegation 속성 확인 | ☐ |
| 📸 Rubeus monitor 로 캡처된 TGT 화면 | ☐ |
| 📸 PTT 후 특권 접근 확인 (예: DCSync 또는 DC 접근) | ☐ |

**내 설명 (본인 문장으로 — 이 명령이 무엇을 하고 왜 통했는가):**
> _여기에 직접 작성_

**완화 방안 (본인 조사·인용 포함하면 가점):**
> _여기에 직접 작성_
