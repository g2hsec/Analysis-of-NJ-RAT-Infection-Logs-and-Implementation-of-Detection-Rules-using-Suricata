# Analysis-of-NJ-RAT-Infection-Logs-and-Implementation-of-Detection-Rules-using-Suricata
NJ RAT 감염 로그 분석 및 Suricata 탐지 규칙 구현 및 시연

> 감염파일 출처 : https://www.joesandbox.com/analysis/844872/0/html

<hr>
# 개요 

1. 분석 목적 : NJ RAT 감염 징후 및 피해사항 추출
2. 분석 대상 : PACAP File
3. RAT 종류 및 버전 : NJ RAT
4. 사용된 분석 도구 : Suricata, Wireshark

# NJ RAT

| 항목       | 내용                                                                 |
|------------|----------------------------------------------------------------------|
| **명칭**   | NJRat (또는 Bladabindi)                                              |
| **분류**   | Remote Access Trojan (RAT)                                           |
| **출시 시점** | 2013년경 공개, 이후 여러 버전 등장                                  |
| **기반 언어** | .NET (VB.NET)                                                      |
| **용도**   | 원격 제어, 키로깅, 파일 다운로드/업로드, 웹캠 접근 등                 |

<br>

# 특징
- 스팸 이메일, USB 전파, 악성 크랙툴, 드라이브 바이 다운로드
- Visual Basic 기반 빌더로 손쉽게 C2 설정 및 악성코드 생성 가능
- 중동 및 남아시아 지역에서 다수 발견
- 교육기관, 정부기관, 중소기업 등 타깃
- 오픈소스로 퍼졌기 때문에 스크립트 키디의 입문용으로도 많이 사용됨
- 토렌트 및 웹하드를 통한 유포

<hr>
