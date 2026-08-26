# 🛡️ SOC Detection Rules

[![License: MIT](https://img.shields.io/badge/License-Educational-blue.svg)]()
[![Last Update](https://img.shields.io/badge/Last%20Update-June%202026-green.svg)]()
[![Rules Count](https://img.shields.io/badge/Rules-3%20CVE-orange.svg)]()

**Автор:** Захарчук Юрий Александрович  
**Роль:** Аналитик SOC 

Репозиторий содержит базу знаний и правила детектирования для аналитиков SOC. Здесь собраны Sigma/XP/Suricata, Sysmon/Auditd-правила, PoC-скрипты и материалы для триажа инцидентов.

---

## 🖥️ Hosts (Lab Environment)

| IP               | Hostname | Role / OS                  | Notes                                      |
| :--------------- | :------- | :-------------------------- | :------------------------------------------ |
| **192.168.0.10**  | `dc01`   | Windows Server — Domain Controller (primary) | Основной DC, источник событий 4624/4662, DRSUAPI |
| **192.168.0.100** | `dc02`   | Windows Server — Domain Controller (secondary) | Вторичный DC / реплика                      |
| **192.168.0.15**  | —        | Windows 10/11 Desktop       | Рабочая станция, точка входа для клиентских атак (PetitPotam, EternalBlue) |
| **192.168.0.30**  | —        | Kali Linux                  | Атакующая машина / хост для PoC и инструментов (Impacket, Responder и т.д.) |

---

## 📋 Information about CVE

| CVE / Technique    | Title                                                           | Description                                                                                                                                                                                                          | Link                                                                                              |
| :----------------- | :-------------------------------------------------------------- | :------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | :------------------------------------------------------------------------------------------------ |
| **CVE-2017-0143**  | Windows SMB Remote Code Execution Vulnerability *(EternalBlue)* | Уязвимость SMBv1 в Windows, позволяющая удалённому атакующему выполнить произвольный код с помощью специально сформированных SMB-пакетов.                                                                            | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2017-0143) · [Detection](./CVE-2017-0143_EternalBlue)  |
| **CVE-2021-36942** | Windows EFS RPC Service Vulnerability *(PetitPotam)*            | Уязвимость EFS RPC позволяет инициировать принудительную аутентификацию Windows-системы. В сочетании с NTLM Relay может использоваться для дальнейшей атаки на инфраструктуру Active Directory.                      | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2021-36942) · [Detection](./CVE-2021-36942_PetitPotam) |
| **CVE-2026-27944** | Nginx UI Vulnerability                                          | Уязвимость Nginx UI, для которой характерным сетевым индикатором в данном наборе правил является обращение к API endpoint `/api/backup`.                                                                             | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-27944) · [Detection](./CVE-2026-27944_Nginx%20UI) |
| **DCSync**         | DCSync / NTDS.dit Dump                                          | Техника получения учетных данных Active Directory посредством злоупотребления механизмом репликации каталога. Для обнаружения используются сетевые признаки DRSUAPI/DRSGetNCChanges и событие Windows Security 4662. | [MITRE T1003.006](https://attack.mitre.org/techniques/T1003/006/) · [Detection](./DCSync)         |

---

## 🔎 Detection

| Attack                          | Detection                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| :------------------------------ | :----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **EternalBlue (CVE-2017-0143)** | **Sysmon Event ID: 3**<br>  └─ Network connection<br><br>**Security Event ID: 4624**<br>  └─ An account was successfully logged on<br><br>**Network IOC**<br>  └─ `Trans2 Response: STATUS_INVALID_PARAMETER (0xc000000d)`                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| **PetitPotam (CVE-2021-36942)** | **Sysmon Event ID: 3**<br>  └─ `Initiated=false → DC:445`<br>  └─ `Initiated=true → Attacker:445`<br><br>**Sysmon Event ID: 18**<br>  └─ `PipeConnected`<br><br>**SMBClient Event ID: 30805**<br>  └─ `0xC00000C3`<br><br>**SMBClient Event ID: 30816**<br>  └─ `0xC00000CC`<br><br>**SMBClient Event ID: 31012**<br>  └─ `GUID {4141...}`<br><br>**SMBClient Event ID: 31013**<br>  └─ `0xC000A000`<br><br>**SMBServer Event ID: 551**<br>  └─ `0xc000006d`<br><br>**Security Event ID: 4624**<br>  └─ `LogonType=3, NULL SID`<br><br>**Network IOC**<br>  └─ `EfsRpcOpenFileRaw`<br>  └─ `WERR_BAD_NETPATH`<br>  └─ `NTLM Negotiate / Challenge / Authenticate`<br>  └─ `SMB TCP/445 (DC as client)` |
| **Nginx UI (CVE-2026-27944)**   | **HTTP Request**<br>  └─ `GET /api/backup`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| **DCSync (T1003.006)**          | **Security Event ID: 4624**<br>  └─ `Logon Type: 3`<br><br>**Security Event ID: 4662**<br>  └─ `ObjectServer: DS`<br>  └─ `AccessMask: 0x100`<br>  └─ `Properties: 1131f6aa-9c07-11d1-f79f-00c04fc2dcd2`<br>    └─ `Replicating Directory Changes All`<br><br>**DRSUAPI**<br>  └─ UUID: `e3514235-4b06-11d1-ab04-00c04fc2dcd2`<br>  └─ `DRSGetNCChanges (Opnum: 3)`                                                                                                                                                                                                                                                                                                                                    |

---

## 🌐 Network Detection

| Attack                          | Network IOC                                                                                                                                                                                                                                                                    |
| :------------------------------ | :----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **EternalBlue (CVE-2017-0143)** | **SMB Trans2 Response**<br>  └─ `NT Status: STATUS_INVALID_PARAMETER (0xc000000d)`                                                                                                                                                                                             |
| **PetitPotam (CVE-2021-36942)** | **EFS RPC**<br>  └─ `EfsRpcOpenFileRaw`<br>  └─ `WERR_BAD_NETPATH`<br><br>**NTLM**<br>  └─ `Negotiate / Challenge / Authenticate`<br><br>**SMB**<br>  └─ `TCP/445 (DC as client)`<br>  └─ `SMB2 Negotiate (Dialect 0x0202)`                                                    |
| **DCSync (T1003.006)**          | **RPC Endpoint Mapper**<br>  └─ `TCP/135`<br><br>**DRSUAPI**<br>  └─ UUID: `e3514235-4b06-11d1-ab04-00c04fc2dcd2`<br>  └─ `DRSGetNCChanges (Opnum: 3)`<br><br>**RPC**<br>  └─ Dynamic RPC port<br>  └─ `Auth Level: Packet Privacy`<br>  └─ Large fragmented DCE/RPC responses |
| **Nginx UI (CVE-2026-27944)**   | **HTTP Request**<br>  └─ `GET /api/backup`                                                                                                                                                                                                                                     |

---

## 💻 Host Detection

| Attack                          | Windows / Linux IOC                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| :------------------------------ | :----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **EternalBlue (CVE-2017-0143)** | **Sysmon Event ID: 3**<br>  └─ Network connection<br><br>**Security Event ID: 4624**<br>  └─ An account was successfully logged on                                                                                                                                                                                                                                                                                                                                                                                              |
| **PetitPotam (CVE-2021-36942)** | **Sysmon Event ID: 3**<br>  └─ `Initiated=false → DC:445`<br>  └─ `Initiated=true → Attacker:445`<br><br>**Sysmon Event ID: 18**<br>  └─ `PipeConnected`<br><br>**SMBClient Event ID: 30805**<br>  └─ `0xC00000C3`<br><br>**SMBClient Event ID: 30816**<br>  └─ `0xC00000CC`<br><br>**SMBClient Event ID: 31012**<br>  └─ `GUID {4141...}`<br><br>**SMBClient Event ID: 31013**<br>  └─ `0xC000A000`<br><br>**SMBServer Event ID: 551**<br>  └─ `0xc000006d`<br><br>**Security Event ID: 4624**<br>  └─ `LogonType=3, NULL SID` |
| **Nginx UI (CVE-2026-27944)**   | **HTTP Request**<br>  └─ `GET /api/backup`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| **DCSync (T1003.006)**          | **Security Event ID: 4624**<br>  └─ `Logon Type: 3`<br><br>**Security Event ID: 4662** — An operation was performed on an object<br>  └─ `ObjectServer: DS`<br>  └─ `AccessMask: 0x100`<br>  └─ `Properties: 1131f6aa-9c07-11d1-f79f-00c04fc2dcd2`<br>    └─ `Replicating Directory Changes All`                                                                                                                                                                                                                                |

---

## 📚 Attack Resources

| Attack                      | Resources                                                                                                                                               |
| :-------------------------- | :------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **Zerologon**               | [Habr — Zerologon](https://habr.com/ru/companies/bizone/articles/526168/)<br>[Habr — Zerologon](https://habr.com/ru/companies/rvision/articles/743142/) |
| **PetitPotam / NTLM Relay** | [Habr — PetitPotam / NTLM Relay](https://habr.com/ru/companies/ussc/articles/688682/)<br>[Hackndo — NTLM Relay](https://en.hackndo.com/ntlm-relay/)     |
| **DCSync**                  | [Habr — DCSync](https://habr.com/ru/companies/rvision/articles/709866/)<br>[Habr — DCSync](https://habr.com/ru/companies/rvision/articles/709942/)      |
| **EternalBlue (MS17-010)**  | [Habr — EternalBlue / MS17-010](https://habr.com/ru/companies/k2tech/articles/892202/)                                                                  |



**© 2026 Захарчук Юрий Александрович** — Все права защищены.  
Данный материал подготовлен для внутреннего использования в SOC и образовательных целях.
