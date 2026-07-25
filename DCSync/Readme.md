# DCSync

## Краткое описание техники:

**DCSync** — техника получения хешей паролей учетных записей Active Directory посредством имитации репликации контроллера домена. Атакующий, обладающий привилегиями **Replicating Directory Changes**, **Replicating Directory Changes All** и при необходимости **Replicating Directory Changes In Filtered Set**, отправляет запросы репликации через протокол **MS-DRSR (Directory Replication Service Remote Protocol)** и получает секретные атрибуты объектов Active Directory, включая NTLM-хеши, Kerberos-ключи и другие учетные данные, без необходимости выполнять код непосредственно на контроллере домена.

### Ссылки на технику:

MITRE ATT&CK (DCSync): [https://attack.mitre.org/techniques/T1003/006/](https://attack.mitre.org/techniques/T1003/006/)

Microsoft MS-DRSR: [https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-drsr/](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-drsr/)

Microsoft Replicating Directory Changes: [https://learn.microsoft.com/en-us/windows/win32/ad/control-access-rights](https://learn.microsoft.com/en-us/windows/win32/ad/control-access-rights)

---

## Описание структуры проекта:

* Правила **Suricata**, предназначенные для обнаружения активности DCSync на сетевом уровне, расположены в файле `suricata.rules`. Детектирование основано на анализе DCE/RPC-трафика протокола **MS-DRSR**, используемого для репликации Active Directory. Правила позволяют выявлять попытки выполнения операций репликации с узлов, не являющихся контроллерами домена.

* Файл, содержащий реализацию атаки (например, скрипт `secretsdump.py`, модуль Mimikatz `lsadump::dcsync` либо иной инструмент), используется исключительно для моделирования DCSync в лабораторной среде и воспроизведения телеметрии, необходимой для разработки и проверки механизмов обнаружения.

* Каталог `triage` содержит журналы событий Windows, сетевые дампы, события Sysmon и данные средств мониторинга, собранные во время выполнения DCSync. Представленные артефакты позволяют проанализировать последовательность действий атакующего, оценить эффективность правил обнаружения и использовать их для последующей валидации детектов.

* Каталог `Sigma_rule` содержит Sigma-правила, предназначенные для выявления различных признаков выполнения DCSync. В правилах используются события Windows Security, журналы Directory Service, Sysmon, а также признаки запуска наиболее распространенных инструментов, используемых для имитации репликации Active Directory.

* Правило `XP_rule_(eXtraction and Processing)` разработано для **MaxPatrol SIEM**. В текущей реализации правило анализирует события Windows Security. Особое внимание уделяется обнаружению событий репликации каталога (например, Event ID **4662** с доступом к объектам репликации Active Directory).

____

## Разбор журнала Windows при успешной эксплуатации.

### Журнал Security (DCSync/triage/windows_logs/Dcsync.evtx)

Первым косвенным индикатором выполнения DCSync является событие 4624 (An account was successfully logged on), фиксирующее успешную сетевую аутентификацию (Logon Type = 3) учетной записи, обладающей правами репликации Active Directory, с нехарактерного для репликации источника. В отличие от легитимной репликации, которая осуществляется исключительно между контроллерами домена, DCSync инициируется с рабочей станции или сервера, не являющегося контроллером домена. Поэтому появление события 4624 с типом входа 3, пакетом аутентификации NTLM (или Kerberos), IP-адресом, не принадлежащим контроллеру домена, и учетной записью, имеющей права Replicating Directory Changes, является важным поводом для дальнейшего расследования.

Ключевым событием для обнаружения DCSync является Event ID 4662 (An operation was performed on an object). Во время выполнения DCSync инструмент (например, Mimikatz или Impacket secretsdump.py) вызывает метод IDL_DRSGetNCChanges протокола MS-DRSR, запрашивая репликацию данных контроллера домена. Для успешного выполнения этой операции учетная запись должна обладать правами Replicating Directory Changes, Replicating Directory Changes All и, при необходимости, Replicating Directory Changes In Filtered Set. Именно использование этих прав отражается в событии 4662.

## Разбор трафика в Wireshark (по файлу DCSync/triage/wireshark.):

