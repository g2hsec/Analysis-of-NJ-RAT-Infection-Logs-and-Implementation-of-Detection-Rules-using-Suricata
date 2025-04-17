# Analysis-of-NJ-RAT-Infection-Logs-and-Implementation-of-Detection-Rules-using-Suricata
NJ RAT 감염 로그 분석 및 Suricata 탐지 규칙 구현 및 시연

> 감염파일 출처 : https://www.joesandbox.com/analysis/844872/0/html

<hr>

## C2 Master 및 Agent 정보 요약

| 항목             | 값 |
|------------------|--------------------------------------------------------|
| Master IP 개수    | 4개 |
| Master IP 목록    | 52.28.247.255, 3.69.115.178, 3.68.171.119, 3.69.157.220 |
| Agent IP 개수     | 1개 |
| Agent IP 목록     | 192.168.2.4 |

---

## 양자 간 통신 데이터 전송 분석

| 프레임 번호 | 송신지 → 수신지              | 데이터 크기 (Bytes) | 공통 데이터 내용 (Hex/ASCII)                       |
|-------------|-------------------------------|----------------------|---------------------------------------------------|
| #79         | 192.168.2.4 → 52.28.247.255   | 150                  | 7c 27 7c 27 7c (NJ-RAT Signature)              |
| #81         | 192.168.2.4 → 52.28.247.255   | 160                  | 7c 27 7c 27 7c                                 |
| #83         | 192.168.2.4 → 52.28.247.255   | 35                   | 33 32 00 61 63 74 7c 27 7c 27 7c               |
| #85         | 52.28.247.255 → 192.168.2.4   | 4                    | 0d 0a 0d 0a                                    |
| #93         | 192.168.2.4 → 3.69.115.178    | 150                  | 7c 27 7c 27 7c                                 |
| #95         | 192.168.2.4 → 3.69.115.178    | 160                  | 7c 27 7c 27 7c                                 |
| #97         | 3.69.115.178 → 192.168.2.4    | 35                   | 33 32 00 61 63 74 7c 27 7c 27 7c               |
'''
| #151        | 192.168.2.4 → 3.68.171.119    | 150                  | 7c 27 7c 27 7c                                 |
| #153        | 192.168.2.4 → 3.68.171.119    | 160                  | 7c 27 7c 27 7c                                 |
| #155        | 192.168.2.4 → 3.68.171.119    | 35                   | 33 32 00 61 63 74 7c 27 7c 27 7c               |
| #157        | 192.168.2.4 → 3.68.171.119    | 15                   | 61 63 74 7c 27 7c 27 7c                        |
| #159        | 192.168.2.4 → 3.68.171.119    | 35                   | 33 32 00 61 63 74 7c 27 7c 27 7c               |
'''
| #203        | 192.168.2.4 → 3.69.157.220    | 130                  | 7c 27 7c 27 7c                                 |
| #205        | 192.168.2.4 → 3.69.157.220    | 160                  | 7c 27 7c 27 7c                                 |
| #207        | 192.168.2.4 → 3.69.157.220    | 35                   | 33 32 00 61 63 74 7c 27 7c 27 7c               |


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

## Packet 1~6 Hex Dump 비교 


| Offset | Packet 1 150 byte                                    | Packet 2  160 byte                                   | Packet 3  35 byte                                    | Packet 4  15 byte                                    |
|--------|------------------------------------------------------|------------------------------------------------------|------------------------------------------------------|------------------------------------------------------|
| 0000   | 31 34 36 00 6c 6c 7c 27 7c 27 7c 53 46 56 54 51       | 31 35 36 00 69 6e 66 7c 27 7c 27 7c 53 46 56 54       | 33 32 00 61 63 74 7c 27 7c 27 7c 55 48 4a 76 5a       |31 32 00 61 63 74 7c 27 7c 27 7c 41 41 3d 3d
| 0010   | 6c 42 66 51 7a 42 43 4e 6b 4d 33 4e 6a 63 3d 7c       | 51 6c 41 4e 43 6a 59 75 64 47 4e 77 4c 6d 56 31       | 33 4a 68 62 53 42 4e 59 57 35 68 5a 32 56 79 41       |
| 0020   | 27 7c 27 7c 30 36 35 33 36 37 7c 27 7c 27 7c 6a       | 4c 6d 35 6e 63 6d 39 72 4c 6d 6c 76 4f 6a 45 35       | 41 3d 3d       |

| Offset | Packet 1 130 byte                                    |
|--------|------------------------------------------------------|
| 0000   | 31 32 36 00 6c 6c 7c 27 7c 27 7c 53 46 56 54 51       | 
| 0010   | 6c 42 66 51 7a 42 43 4e 6b 4d 33 4e 6a 63 3d 7c       |
| 0020   | 27 7c 27 7c 30 36 35 33 36 37 7c 27 7c 27 7c 6a       | 
'''
'''

> 동일 패킷 (시기느처 패킷으로 추정) : 150 Byte, 130 Byte, 160 Byte -> 7c 27 7c 27 7c
> 동일 패킷 (시기느처 패킷으로 추정) : 35 Byte -> 33 32 00 61 63 74 7c 27 7c 27 7c
> 동일 패킷 (시기느처 패킷으로 추정) : 15 Byte -> 61 63 74 7c 27 7c 27 7c
> 동일 패킷 (시기느처 패킷으로 추정) : 4 Byte -> 0d 0a 0d 0a
> 각 Data 크기별 패킷 내용은 동일 

# Suricata Rule

```
alert ip any any -> [23.0.174.98,52.28.247.255,3.69.115.178,3.68.171.119] any (msg:"[ALERT]Njrat C2 Communication with Known Malicious IP"; sid:1000001; rev:1;)
alert dns any any -> any any (msg:"[ALERT]Njrat DNS Query for ngrok.io (Possible C2)"; dns.query; content:"ngrok.io"; nocase; sid:1000002; rev:2;;)
alert tcp any any -> any any (msg:"[ALERT]Njrat connect_toClient[M->A 4Byte]";  dsize:4; flow:to_client; content:"|0d 0a 0d 0a|"; sid: 1000003;rev:3;)
alert tcp any any -> any any (msg:"[ALERT]Njrat connect_toServ[A->M 150, 160, 130Byte]"; flow:to_server; content:"|7c 27 7c 27 7c|"; offset:6; depth:20; sid: 1000004;rev:4;)
alert tcp any any -> any any (msg:"[ALERT]Njrat connect_toServ2[A->M 35Byte]"; flow:to_server; content:"|33 32 00 61 63 74 7c 27 7c 27 7c|"; sid: 1000005;rev:5;)
alert tcp any any -> any any (msg:"[ALERT]Njrat connect_toServ3[A->M 15Byte]"; flow:to_server; content:"|61 63 74 7c 27 7c 27 7c|"; sid: 1000006;rev:6;)
```





