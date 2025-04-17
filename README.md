# Analysis-of-NJ-RAT-Infection-Logs-and-Implementation-of-Detection-Rules-using-Suricata
NJ RAT 감염 로그 분석 및 Suricata 탐지 규칙 구현 및 시연

> 감염파일 출처 : https://www.joesandbox.com/analysis/844872/0/html

<hr>

## 📡 C2 Master 및 Agent 정보 요약

| 항목             | 값 |
|------------------|--------------------------------------------------------|
| Master IP 개수    | 3개 |
| Master IP 목록    | 52.28.247.255, 3.69.115.178, 3.68.171.119, 3.69.157.220 |
| Agent IP 개수     | 1개 |
| Agent IP 목록     | 192.168.2.4 |

---

## 🔄 양자 간 통신 데이터 전송 분석

| 프레임 번호 | 송신지 → 수신지              | 데이터 크기 (Bytes) | 공통 데이터 내용 (Hex/ASCII)                       |
|-------------|-------------------------------|----------------------|---------------------------------------------------|
| #79         | 192.168.2.4 → 52.28.247.255   | 150                  | 4E 4A 2D 52 41 54 (NJ-RAT Signature)              |
| #81         | 192.168.2.4 → 52.28.247.255   | 160                  | C2 명령 초기 패킷 (AES로 암호화된 명령)           |
| #83         | 192.168.2.4 → 52.28.247.255   | 35                   | Beacon 메시지 전송 시도                           |
| #85         | 52.28.247.255 → 192.168.2.4   | 4                    | 확인 응답, AES 암호화된 명령 포함                |
| #93         | 192.168.2.4 → 3.69.115.178    | 150                  | 동일 구조의 패킷, NJRAT 초기 핸드쉐이크           |
| #95         | 192.168.2.4 → 3.69.115.178    | 160                  | 동일한 C2 응답 패턴 (AES or 커스텀 직렬화)       |
| #97         | 3.69.115.178 → 192.168.2.4    | 35                   | 동일 구조의 패킷, NJRAT 초기 핸드쉐이크           |
'''
| #151        | 192.168.2.4 → 3.68.171.119    | 150                  | 동일한 C2 응답 패턴 (AES or 커스텀 직렬화)       |
| #153        | 192.168.2.4 → 3.68.171.119    | 160                  | 동일한 C2 응답 패턴 (AES or 커스텀 직렬화)       |
| #155        | 192.168.2.4 → 3.68.171.119    | 35                   | 동일 구조의 패킷, NJRAT 초기 핸드쉐이크           |
| #157        | 192.168.2.4 → 3.68.171.119    | 15                   | 동일한 C2 응답 패턴 (AES or 커스텀 직렬화)       |
| #159        | 192.168.2.4 → 3.68.171.119    | 35                   | 동일한 C2 응답 패턴 (AES or 커스텀 직렬화)       |
'''
| #203        | 192.168.2.4 → 3.69.157.220    | 130                  | 동일 구조의 패킷, NJRAT 초기 핸드쉐이크           |
| #205        | 192.168.2.4 → 3.69.157.220    | 160                  | 동일한 C2 응답 패턴 (AES or 커스텀 직렬화)       |
| #207        | 192.168.2.4 → 3.69.157.220    | 35                  | 동일한 C2 응답 패턴 (AES or 커스텀 직렬화)       |

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

# 분석

![image](https://github.com/user-attachments/assets/1a5d7670-d05b-4bf0-a4de-73e43c736ee7)

- 해당 패킷을 보게되면 192.168.2.4 내부 사설망 IP 와의 여러 통신시도가 식별됨, 또한 주고받는 데이터의 크기가 일정한 걸 확인할 수 있음.
- 일정하게 나타나는 데이터의 크기는 150, 160, 35, 4, 130 로 확인됨

> 데이터 스트림을 확인하면 아래와 같이 Base64로 인코딩 된 문자열을 확인할 수 있다.

```
146.ll|'|'|SFVTQlBfQzBCNkM3Njc=|'|'|065367|'|'|jones|'|'|23-04-11|'|'||'|'|Win 10 ProSP0 x64|'|'|No|'|'|im523|'|'|..|'|'|UHJvZ3JhbSBNYW5hZ2VyAA==|'|'|156.inf|'|'|SFVTQlANCjYudGNwLmV1Lm5ncm9rLmlvOjE5OTA1DQpEZXNrdG9wDQpnQXRyTzM0b3RlLmV4ZQ0KRmFsc2UNCkZhbHNlDQpGYWxzZQ0KRmFsc2UNCkZhbHNlDQpGYWxzZQ0KRmFsc2UNCkZhbHNl32.act|'|'|UHJvZ3JhbSBNYW5hZ2VyAA==
```
Base64로 인코딩된 값을 복호화 하면 아래와 같은 출력값을 얻게 된다.

```
׎!UM	A}Ӯw68]V}t>?Lz"Program Manager�
y)HUSBP
6.tcp.eu.ngrok.io:19905
Desktop
gAtrO34ote.exe
False
False
False
False
False
False
False
FalsefAɽɅ5�
```

해당 내용을 보면 6.tcp.eu.ngrok.io:19905 와 같은 주소와 포트가 보이며 경로와 파일 그리고 결과값으로 보이는 문자열들이 출력된다.
<br>

![image](https://github.com/user-attachments/assets/fad78d77-6969-4eb9-97a7-ae44e26583ff)

실제 해당 주소를 Virus Total을 통해 확인해보면 Malicious로 출력된다.

1. 52.28.247.255  | ![image](https://github.com/user-attachments/assets/56b1cb75-9bfb-4c19-b445-95a8e5ade8b5)
2. 3.69.115.178 | ![image](https://github.com/user-attachments/assets/09714a73-4e5a-4dab-a483-18d3fb07fad1)
3. 3.68.171.119 | ![image](https://github.com/user-attachments/assets/b79ab7e5-76d0-4edb-9fc9-fa752202e69c)

실제로 3개의 IP전부 Malware IP 로 확인되었다.

![image](https://github.com/user-attachments/assets/d99f6d6a-d54f-4b84-b5b4-48579fb2871f)

- DNS 패킷을 확인해보면 이전에 Base64 디코딩 결과값에서 확인된 Malicious 주소로 질의/응답을 진행한 패킷이 확인된다.

### 4 len packet

![image](https://github.com/user-attachments/assets/d1f75fa5-5b62-4b65-9b8c-e5f67454910d)

4바이트의 데이터는 단순 0d0a 즉, 개행을 나타내는 패킷으로 확인되며、 이는 명령 및 연결 종료로 추정된다。

## 🔍 Packet 1~3 Hex Dump 비교 (150 Byte)

| Offset | Packet 1                                             | Packet 2                                             | Packet 3                                             |
|--------|------------------------------------------------------|------------------------------------------------------|------------------------------------------------------|
| 0000   |<span style="color:red"> 00 0c 29 82 cb 33 ec f4 bb ea 15 88 08 00 45 00       | <span style="color:red">00 0c 29 82 cb 33 ec f4 bb ea 15 88 08 00 45 00       | <span style="color:red">00 0c 29 82 cb 33 ec f4 bb ea 15 88 08 00 45 00       |
| 0010   | 00 be</span> 25 a7 40 00 80 06 e5 ca c0 a8 02 04 34 1c       | 00 be</sapn> 27 93 40 00 80 06 99 03 c0 a8 02 04 03 45       | 00 be</sapn> 27 9b 40 00 80 06 98 fb c0 a8 02 04 03 45       |
| 0020   | f7 ff c2 1f 4d c1 b7 69 4d b1 f1 04 3e b1 50 18       | 73 b2 c2 20 4d c1 c0 0b 02 73 3a 99 76 80 50 18       | 73 b2 c2 21 4d c1 f9 a5 c8 d9 bf 5e 02 0b 50 18       |


---

### 🔹 Packet 4 (160 Byte)

| Offset | Hex Dump |
|--------|----------|
| 0000 | 00 0c 29 82 cb 33 ec f4 bb ea 15 88 08 00 45 00 |
| 0010 | 00 c8 27 94 40 00 80 06 98 c0 c0 a8 02 04 03 45 |
| 0020 | 73 b2 c2 20 4d c1 c0 0b 03 09 3a 99 76 80 50 18 |

---

### 🔹 Packet 5 (160 Byte)

| Offset | Hex Dump |
|--------|----------|
| 0000 | 00 0c 29 82 cb 33 ec f4 bb ea 15 88 08 00 45 00 |
| 0010 | 00 c8 27 9c 40 00 80 06 98 c8 c0 a8 02 04 03 45 |
| 0020 | 73 b2 c2 21 4d c1 f9 a5 c9 6f bf 5e 02 0b 50 18 |

---

### 🔹 Packet 6 (160 Byte)

| Offset | Hex Dump |
|--------|----------|
| 0000 | 00 0c 29 82 cb 33 ec f4 bb ea 15 88 08 00 45 00 |
| 0010 | 00 c8 25 af 40 00 80 06 e5 b8 c0 a8 02 04 34 1c |
| 0020 | f7 ff c2 22 4d c1 9f 92 d1 62 75 c0 a4 cb 50 18 |





