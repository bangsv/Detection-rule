# DCSync

## Краткое описание техники:

**DCSync** — техника получения хешей паролей учетных записей Active Directory посредством имитации репликации контроллера домена. Атакующий, обладающий привилегиями **Replicating Directory Changes**, **Replicating Directory Changes All** и при необходимости **Replicating Directory Changes In Filtered Set**, отправляет запросы репликации через протокол **MS-DRSR (Directory Replication Service Remote Protocol)** и получает секретные атрибуты объектов Active Directory, включая NTLM-хеши, Kerberos-ключи и другие учетные данные, без необходимости выполнять код непосредственно на контроллере домена.

### Ссылки на технику:

MITRE ATT&CK (DCSync): [https://attack.mitre.org/techniques/T1003/006/](https://attack.mitre.org/techniques/T1003/006/)

Microsoft MS-DRSR: [https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-drsr/](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-drsr/)

Microsoft Replicating Directory Changes: [https://learn.microsoft.com/en-us/windows/win32/ad/control-access-rights](https://learn.microsoft.com/en-us/windows/win32/ad/control-access-rights)

R-Vision, DCSync: особенности выполнения атаки и возможные варианты детектирования, Часть 1: https://habr.com/ru/companies/rvision/articles/709866/ (Больше про сетевые моменты)

R-Vision, DCSync: особенности выполнения атаки и возможные варианты детектирования, Часть 2: https://habr.com/ru/companies/rvision/articles/709942/ (Больше про детектирование на хосте)

---

## Описание структуры проекта:

* Правила **Suricata**, предназначенные для обнаружения активности DCSync на сетевом уровне, расположены в файле `suricata.rules`. Детектирование основано на анализе DCE/RPC-трафика протокола **MS-DRSR**, используемого для репликации Active Directory. Правила позволяют выявлять попытки выполнения операций репликации с узлов, не являющихся контроллерами домена.

* Файл, содержащий реализацию атаки (например, скрипт `secretsdump.py`, модуль Mimikatz `lsadump::dcsync` либо иной инструмент), используется исключительно для моделирования DCSync в лабораторной среде и воспроизведения телеметрии, необходимой для разработки и проверки механизмов обнаружения.

* Каталог `triage` содержит журналы событий Windows, сетевые дампы, события Sysmon и данные средств мониторинга, собранные во время выполнения DCSync. Представленные артефакты позволяют проанализировать последовательность действий атакующего, оценить эффективность правил обнаружения и использовать их для последующей валидации детектов. Также в папке wireshark содержится еще один дополнительный Readme.md с выводом команд и скриншотом каждогоо pcap файла. [ССЫЛКА ДЛЯ УДОБСТВА](https://github.com/bangsv/soc-detection-rules/tree/main/DCSync/triage/wireshark)

* Каталог `Sigma_rule` содержит Sigma-правила, предназначенные для выявления различных признаков выполнения DCSync. В правилах используются события Windows Security, журналы Directory Service, Sysmon, а также признаки запуска наиболее распространенных инструментов, используемых для имитации репликации Active Directory.

* Правило `XP_rule_(eXtraction and Processing)` разработано для **MaxPatrol SIEM**. В текущей реализации правило анализирует события Windows Security. Особое внимание уделяется обнаружению событий репликации каталога (например, Event ID **4662** с доступом к объектам репликации Active Directory).

____

## Разбор журнала Windows при успешной эксплуатации.

Также рекомендую прочитать данную статью: https://habr.com/ru/companies/rvision/articles/709942/

### Журнал Security (DCSync/triage/windows_logs/Dcsync.evtx)
<img width="1245" height="941" alt="image" src="https://github.com/user-attachments/assets/48599791-b77a-4185-8cf2-b7bbd581203d" />

Первым косвенным индикатором выполнения DCSync является событие 4624 (An account was successfully logged on), фиксирующее успешную сетевую аутентификацию (Logon Type = 3) учетной записи, обладающей правами репликации Active Directory, с нехарактерного для репликации источника. В отличие от легитимной репликации, которая осуществляется исключительно между контроллерами домена, DCSync инициируется с рабочей станции или сервера, не являющегося контроллером домена. Поэтому появление события 4624 с типом входа 3, пакетом аутентификации NTLM (или Kerberos), IP-адресом, не принадлежащим контроллеру домена, и учетной записью, имеющей права Replicating Directory Changes, является важным поводом для дальнейшего расследования.

<img width="1258" height="944" alt="image" src="https://github.com/user-attachments/assets/e562425d-a5e1-4e67-b71a-a70b767795c1" />

Ключевым событием для обнаружения DCSync является Event ID 4662 (An operation was performed on an object). Во время выполнения DCSync инструмент (например, Mimikatz или Impacket secretsdump.py) вызывает метод IDL_DRSGetNCChanges протокола MS-DRSR, запрашивая репликацию данных контроллера домена. Для успешного выполнения этой операции учетная запись должна обладать правами Replicating Directory Changes, Replicating Directory Changes All и, при необходимости, Replicating Directory Changes In Filtered Set. Именно использование этих прав отражается в событии 4662.

### Детальный разбор полей события 4662 

#### ObjectType: `%{19195a5b-6da0-11d0-afd3-00c04fd930c9}`
 
 Описание: При DCSync-атаке инструмент (Mimikatz, secretsdump) не запрашивает репликацию одного конкретного пользователя (что было бы GUID'ом класса user). Он запрашивает репликацию корневого объекта домена, чтобы получить доступ ко всем объектам внутри него. Наличие именно этого GUID'а указывает на попытку выгрузки данных.

#### AccessMask: 0x100
Описание: `0x100` (или 256 в десятичной системе) соответствует флагу `ADS_RIGHT_DS_CONTROL_ACCESS`. Это право на выполнение "расширенных операций" (Extended Rights). Обычные права чтения/записи имеют другие значения (например, `0x1` для чтения). Репликация является расширенным правом, поэтому этот флаг всегда будет присутствовать.

#### Properties: %%7688 {1131f6aa-9c07-11d1-f79f-00c04fc2dcd2} {19195a5b-6da0-11d0-afd3-00c04fd930c9}
Описание:

- `%%7688` — Это локализованное строковое представление права (в русской Windows это обычно "Репликация изменений каталога", в английской "Replicating Directory Changes"). Оно зависит от языка ОС.

- `{1131f6aa-9c07-11d1-f79f-00c04fc2dcd2}` - Это универсальный, не зависящий от языка GUID расширенного права "Replicating Directory Changes All". Именно это право позволяет читать зашифрованные атрибуты (хэши паролей).

- `{19195a5b-6da0-11d0-afd3-00c04fd930c9}` - GUID класса объекта `domainDNS` (подтверждает, что право применяется ко всему домену).

## Разбор трафика в Wireshark (по файлу DCSync/triage/wireshark/dcsync.pcapng):
Рекомендую к описанию данную статью: https://habr.com/ru/companies/rvision/articles/709866/

### Этап №1. SMB-подключение атакующего к контроллеру домена и NTLM-аутентификация пользователя. Пакеты №4–12.
<img width="1912" height="524" alt="image" src="https://github.com/user-attachments/assets/03f4e849-001b-4d00-8158-47112fdb64e3" />
На первом этапе атакующий устанавливает TCP-соединение с контроллером домена по порту 445/TCP, после чего инициирует процедуру согласования версии протокола SMB.
В пакете SMB2 Negotiate Protocol Request клиент сообщает контроллеру домена список поддерживаемых диалектов SMB (например, SMB 2.0.2, SMB 2.1, SMB 3.x). Контроллер домена выбирает наиболее подходящую версию и возвращает её в ответном пакете. Данный этап является полностью легитимным и выполняется практически любым Windows-клиентом перед началом работы с удалёнными ресурсами.
После согласования версии SMB клиент выполняет процедуру NTLM-аутентификации (Возможна также и Kerberos). Это означает, что дальнейшие RPC-запросы будут выполняться от имени учётной записи svc_replicator. Важно отметить, что успешная NTLM-аутентификация ещё не означает успешный DCSync. На данном этапе подтверждается лишь наличие действительных учётных данных. После завершения аутентификации SMB3 начинает использовать механизм шифрования сообщений (SMB Encryption), поэтому большая часть дальнейшего SMB-трафика становится недоступной для анализа.

### Этап №2. Обращение к RPC Endpoint Mapper. Пакет №50.
<img width="1916" height="923" alt="image" src="https://github.com/user-attachments/assets/8cbc0887-4a1c-4791-967f-ecc64b0a7cc0" />

После успешной аутентификации атакующий обращается к службе RPC Endpoint Mapper, расположенной на порту 135/TCP. Endpoint Mapper представляет собой службу диспетчеризации RPC-интерфейсов. Практически все RPC-службы Windows работают не на фиксированных портах, а используют динамические порты диапазона RPC. Поэтому клиент сначала должен узнать, на каком именно TCP-порту работает необходимый интерфейс.

### Этап №3. EPM. Пакет №53.
<img width="1919" height="619" alt="image" src="https://github.com/user-attachments/assets/459c68cd-a771-4565-bb03-9a26bbd08080" />

В пакете №53 содержится UUID DRSUAPI e3514235-4b06-11d1-ab04-00c04fc2dcd2.  Данный UUID соответствует интерфейсу Directory Replication Service Remote Protocol (MS-DRSR). Именно через этот интерфейс контроллеры домена выполняют репликацию Active Directory.

### Этап №4. Endpoint Mapper возвращает динамический RPC-порт. Пакет №54.
<img width="1918" height="912" alt="image" src="https://github.com/user-attachments/assets/51bff8ce-df4f-4ba0-b041-32f0f73b9c3f" />

В ответ на запрос Endpoint Mapper возвращает клиенту TCP-порт, на котором в данный момент опубликован интерфейс DRSUAPI. В рассматриваемом дампе контроллер домена сообщает: TCP Port: 49158. После получения данной информации клиент закрывает соединение с портом 135 и устанавливает новое соединение уже непосредственно с интерфейсом репликации. Следует обратить внимание, что номер порта 49158 является динамическим. При следующем запуске службы или после перезагрузки контроллера домена данный порт, скорее всего, изменится. Поэтому детектирование DCSync никогда не строится на поиске определённого TCP-порта — используется UUID интерфейса либо вызовы RPC-функций.

### Этап №5. DCERPC Bind к интерфейсу DRSUAPI. Пакет №62.
<img width="1916" height="929" alt="image" src="https://github.com/user-attachments/assets/7ab9e56d-23e9-4c73-87ae-501693adfe4c" />

Получив номер динамического порта, атакующий устанавливает новое TCP-соединение.
Во время Bind клиент сообщает:
UUID интерфейса;
поддерживаемую версию интерфейса;
используемый механизм аутентификации.
В пакете можно увидеть: Interface UUID: e3514235-4b06-11d1-ab04-00c04fc2dcd2, что соответствует интерфейсу Directory Replication Service (DRSUAPI). Также используется: NTLMSSP и Authentication Level: Packet Privacy. Packet Privacy (RPC Authentication Level 6) означает, что после завершения Bind полезная нагрузка RPC будет полностью шифроваться. Поэтому содержимое запросов DRSGetNCChanges в дампе уже недоступно для анализа.

### Этап №6. DRSBind. Пакет №68.
<img width="1918" height="917" alt="image" src="https://github.com/user-attachments/assets/a4020e2a-78e8-4f36-9c4e-71f9a9834e3e" />
После установки RPC-сеанса вызывается первая функция интерфейса DRSUAPI: DRSBind (Opnum: 0). Это обязательный этап любой репликации Active Directory. Во время выполнения DRSBind:
клиент сообщает поддерживаемые возможности протокола;
сервер возвращает контекст соединения (DRS Handle);
согласовываются поддерживаемые версии репликации.
Без успешного выполнения DRSBind никакие дальнейшие функции MS-DRSR вызвать невозможно. Именно после получения DRS Handle начинается полноценный сеанс репликации.

### Этап №7. Получение информации о контроллере домена. Пакет №70.
<img width="1916" height="953" alt="image" src="https://github.com/user-attachments/assets/c79d6271-ff73-46f7-90a1-95b304c1c915" />

После успешного DRSBind клиент вызывает функцию DRSDomainControllerInfo (Opnum: 16). Данная операция используется для получения информации о контроллере домена:
имя контроллера;
имя домена;
параметры службы репликации;
доступные разделы каталога;
сведения о репликационных партнёрах.
Этот этап позволяет клиенту определить, с каким контроллером он работает и какие разделы Active Directory могут быть реплицированы. Данная операция является штатной частью механизма репликации Active Directory.

### Этап №8. Первый запрос DRSGetNCChanges. Пакет №72.
 <img width="1916" height="955" alt="image" src="https://github.com/user-attachments/assets/83cf842d-f018-41c5-ac8b-67dd199bcd61" />
 Следующим этапом выполняется первый вызов DRSGetNCChanges (Opnum: 3). Функция DRSGetNCChanges является основной функцией протокола репликации Active Directory. Именно через неё контроллеры домена получают изменения объектов каталога. Первый ответ имеет небольшой размер: 208 байт. Подобный ответ ещё не свидетельствует о передаче секретных атрибутов. На данном этапе происходит подготовка репликационного контекста.

### Этап №9. Разрешение имени объекта каталога (DRSCrackNames). Пакет №74.
<img width="1914" height="936" alt="image" src="https://github.com/user-attachments/assets/b9748311-2302-4f61-b866-2aa8ac04decd" />
Перед непосредственным получением объекта вызывается функция DRSCrackNames (Opnum: 12). Она используется для преобразования различных форматов имён объектов Active Directory.
Например:
NT4-имя;
UPN;
Distinguished Name;
GUID;
SID.

Контроллер возвращает внутреннее представление имени объекта, которое затем используется функцией DRSGetNCChanges. Из-за использования RPC Packet Privacy содержимое запроса не отображается.

### Этап №10. Успешный DCSync — получение данных репликации. Пакет №76. ❗
<img width="1909" height="514" alt="image" src="https://github.com/user-attachments/assets/505caf4b-a1d5-439b-a532-177a09f39a2d" />

После подготовки контекста выполняется повторный вызов DRSGetNCChanges (Opnum: 3). Именно данный запрос является ключевым этапом атаки. В ответ контроллер домена начинает передавать данные репликации. Ответ разбивается на несколько DCE/RPC-фрагментов. В нашем случае с 77 по 81 пакет. Но также может наблюдаться, что может быть и один TCP пакет с выделяющийся длинной (Например > 1000 lenght). Большой размер ответа является главным сетевым индикатором успешного DCSync. Внутри ответа содержатся репликационные данные объекта Active Directory, включая защищённые атрибуты:
unicodePwd;
supplementalCredentials;
Kerberos Keys;
NT Hash;
LM Hash (если используется);
Password History;
атрибуты учётной записи.
Из-за использования уровня аутентификации Packet Privacy содержимое этих атрибутов зашифровано и не отображается в Wireshark. Однако именно эти данные впоследствии используются такими инструментами, как Mimikatz, Impacket secretsdump.py и другими средствами реализации DCSync.

### Этап №11. Массовая репликация объектов Active Directory. Пакеты №84–157.
<img width="1914" height="932" alt="image" src="https://github.com/user-attachments/assets/0ffe9b5e-2707-474b-981c-71224676853f" />
После успешного получения первого объекта атакующий многократно повторяет последовательность:
DRSCrackNames -> DRSGetNCChanges -> Большой RPC Response. В дампе наблюдаются крупные ответы размером: 2112 байт, 4400 байт, 4864 байт ... 
Каждый подобный ответ соответствует репликации очередного объекта Active Directory. Повторяющиеся вызовы `DRSGetNCChanges` с крупными фрагментированными ответами являются главным сетевым признаком успешного выполнения атаки DCSync.
В отличие от обычной репликации между контроллерами домена, источником данных запросов является не контроллер домена, а рабочая станция 192.168.0.30, использующая учётную запись svc_replicator. Именно сочетание обращения к интерфейсу MS-DRSR, выполнения операции DRSGetNCChanges и получения крупных ответов репликации от не-DC является наиболее надёжным сетевым индикатором успешного выполнения атаки DCSync.

## Разбор трафика в Wireshark (по файлу DCSync/triage/wireshark/dcsync_fail.pcapng):
<img width="1916" height="949" alt="image" src="https://github.com/user-attachments/assets/98f24634-ca80-4862-ab9e-3edd57522de9" />
Для атаки специально выбрана УЗ без прав на репликацию. Шаги идентичные ранее описанным за исключением ответа DC на запрос `DRSGetNCChanges`.

### Отказ в репликации Active Directory. Пакет №67 ❗
<img width="1911" height="911" alt="image" src="https://github.com/user-attachments/assets/480f1479-53a4-4674-9757-7caa5dd555e6" />

Контроллер домена отвечает на запрос `DRSGetNCChanges`, однако размер ответа составляет всего: 208 байт. Ответ не содержит крупных фрагментированных RPC-пакетов, характерных для передачи данных репликации. В успешной атаке DCSync ответ контроллера обычно имеет размер в несколько килобайт и разбивается на несколько DCE/RPC-фрагментов, содержащих репликационные данные объектов Active Directory. В данном случае этого не происходит. Несмотря на успешное выполнение операций `(DRSBind, DRSDomainControllerInfo, DRSCrackNames, DRSGetNCChanges)` контроллер домена не начинает передачу данных каталога. Причиной является отсутствие у пользователя `work.local\ivanov` необходимых привилегий репликации.
Для успешного выполнения DCSync учётная запись должна обладать одним или несколькими расширенными правами:
- Replicating Directory Changes;
- Replicating Directory Changes All;
- Replicating Directory Changes In Filtered Set (в некоторых конфигурациях).


Обычные доменные пользователи такими правами не обладают, поэтому контроллер домена отклоняет запрос на получение репликационных данных.
Из-за использования уровня аутентификации RPC Packet Privacy код ошибки внутри ответа зашифрован и не отображается в Wireshark, однако характер сетевого обмена однозначно показывает, что репликация не была выполнена.

---

## Описание к модулю Mimikatz lsadump::dcsync (...\mimikatz-2.2.0-20220919\mimikatz-2.2.0-20220919\mimikatz\modules\lsadump)

### 1. Список целевых атрибутов 
```c++
LPCSTR kuhl_m_lsadump_dcsync_oids[] = {
szOID_ANSI_name,
szOID_ANSI_sAMAccountName, szOID_ANSI_userPrincipalName, szOID_ANSI_sAMAccountType,
szOID_ANSI_userAccountControl, szOID_ANSI_accountExpires, szOID_ANSI_pwdLastSet,
szOID_ANSI_objectSid, szOID_ANSI_sIDHistory,
szOID_ANSI_unicodePwd, szOID_ANSI_ntPwdHistory, szOID_ANSI_dBCSPwd, szOID_ANSI_lmPwdHistory,  szOID_ANSI_supplementalCredentials,
szOID_ANSI_msFVEKeyPackage, szOID_ANSI_msFVERecoveryGuid, szOID_ANSI_msFVEVolumeGuid, szOID_ANSI_msFVERecoveryPassword,
szOID_ANSI_trustPartner,  szOID_ANSI_trustAuthIncoming, szOID_ANSI_trustAuthOutgoing,
szOID_ANSI_currentValue,
szOID_ANSI_isDeleted,
};
```

Массив kuhl_m_lsadump_dcsync_oids содержит список OID (Object Identifiers) — уникальных идентификаторов атрибутов Active Directory. При выполнении DCSync Mimikatz не запрашивает «всё подряд», а использует протокол MS-DRSR для запроса конкретных критических атрибутов.
Самые важные для атакующего здесь:
* `szOID_ANSI_unicodePwd` - зашифрованный NTLM-хэш пароля.
* `szOID_ANSI_dBCSPwd` - зашифрованный LM-хэш (если включен).
* `szOID_ANSI_ntPwdHistory и lmPwdHistory` - истории предыдущих паролей.
* `szOID_ANSI_supplementalCredentials` - дополнительные учетные данные, включая ключи Kerberos (AES, DES).
* `szOID_ANSI_msFVERecoveryPassword` - пароли восстановления BitLocker.
* `szOID_ANSI_trustAuthIncoming` / `Outgoing` - пароли междоменного доверия.

Указывая эти OID в запросе репликации, Mimikatz заставляет контроллер домена вернуть именно хэши паролей и ключи, а не просто метаданные учётной записи.

### 2. Формирование RPC-запроса и вызов репликации
```c++
// Фрагмент функции kuhl_m_lsadump_dcsync
getChReq.V8.pNC = &dsName;
getChReq.V8.ulFlags = DRS_INIT_SYNC | DRS_WRIT_REP | DRS_NEVER_SYNCED | DRS_FULL_SYNC_NOW | DRS_SYNC_URGENT;
getChReq.V8.cMaxObjects = (allData ? 1000 : 1);
getChReq.V8.cMaxBytes = 0x00a00000; // 10M
getChReq.V8.ulExtendedOp = (allData ? 0 : EXOP_REPL_OBJ);

if(getChReq.V8.pPartialAttrSet = (PARTIAL_ATTR_VECTOR_V1_EXT *) MIDL_user_allocate(...))
{
    // ... заполнение pPartialAttrSet OID-ами из массива выше ...
}

RpcTryExcept
{
    do
    {
        RtlZeroMemory(&getChRep, sizeof(DRS_MSG_GETCHGREPLY));
        drsStatus = IDL_DRSGetNCChanges(hDrs, 8, &getChReq, &dwOutVersion, &getChRep);
        if(drsStatus == 0)
        {
            // ... обработка ответа ...
        }
    } while(getChRep.V6.fMoreData);
    IDL_DRSUnbind(&hDrs);
}
```
Этот блок демонстрирует суть атаки DCSync. Mimikatz устанавливает RPC-соединение с контроллером домена (DC) и формирует структуру запроса `DRS_MSG_GETCHGREQ` (версия 8).
* Флаги `ulFlags` устанавливаются так, чтобы имитировать срочный запрос на полную синхронизацию (`DRS_FULL_SYNC_NOW`, `DRS_SYNC_URGENT`).
* Если указан флаг `allData`, Mimikatz запрашивает репликацию всего домена (до 1000 объектов за раз), иначе — конкретного пользователя (`EXOP_REPL_OBJ`).
* В `pPartialAttrSet` передается массив OID, чтобы DC знал, какие именно атрибуты нужно вернуть.

Затем вызывается ключевая RPC-функция `IDL_DRSGetNCChanges`. Это та самая функция, которую контроллеры домена используют между собой для репликации данных. Поскольку у атакующего есть права на репликацию (например, членство в доменной группе `Domain Admins`, `Administrators` или права `DS-Replication-Get-Changes-All`), контроллер домена «верит» запросу и возвращает запрошенные атрибуты.

Заметка: Именно вызов IDL_DRSGetNCChanges (или DRSUAPI в терминах Windows Event Logs) с нестандартных IP-адресов (не от других DC) является главным индикатором компрометации (IoC).

### 3. Расшифровка хэшей

```c++
BOOL kuhl_m_lsadump_dcsync_decrypt(PBYTE encodedData, DWORD encodedDataSize, DWORD rid, LPCWSTR prefix, BOOL isHistory)
{
DWORD i;
BOOL status = FALSE;
BYTE data[LM_NTLM_HASH_LENGTH];
for(i = 0; i < encodedDataSize; i += LM_NTLM_HASH_LENGTH)
{
	status = NT_SUCCESS(RtlDecryptNtOwfPwdWithIndex(encodedData + i, &rid, data)); // same as RtlDecryptLmOwfPwdWithIndex for LM hash
	if(status)
	{
		if(isHistory)
			kprintf(L"    %s-%2u: ", prefix, i / LM_NTLM_HASH_LENGTH);
		else
			kprintf(L"  Hash %s: ", prefix);
		kull_m_string_wprintf_hex(data, LM_NTLM_HASH_LENGTH, 0);
		kprintf(L"\n");
	}
    // ...
```
Контроллер домена не отправляет хэши паролей в открытом виде по сети — они зашифрованы с использованием алгоритма RC4. Ключом для шифрования выступает RID (Relative Identifier) пользователя — последняя часть его SID. Функция `kuhl_m_lsadump_dcsync_decrypt` получает зашифрованные данные (encodedData) и RID пользователя. С помощью внутренней функции Windows `RtlDecryptNtOwfPwdWithIndex` Mimikatz расшифровывает NT-хэш (и LM-хэш), используя RID в качестве индекса (ключа). После расшифровки хэш выводится в консоль в hex-формате. Именно так DCSync превращает сырые зашифрованные данные репликации в готовые NTLM-хэши для дальнейшего использования (например, для `Pass-the-Hash`).

### 4. Парсинг ответа и извлечение дополнительных данных
```c++
void kuhl_m_lsadump_dcsync_descrUser(SCHEMA_PREFIX_TABLE *prefixTable, ATTRBLOCK *attributes, ATTRTYP *pSuppATT_IntId, DWORD cSuppATT_IntId)
{
// ... вывод базовой информации (sAMAccountName, UPN, UAC) ...

if(kull_m_rpc_drsr_findMonoAttr(prefixTable, attributes, szOID_ANSI_objectSid, &data, NULL))
{
    // ...
    rid = *GetSidSubAuthority(data, *GetSidSubAuthorityCount(data) - 1);
    kprintf(L"Object Relative ID   : %u\n", rid);
    kprintf(L"\nCredentials:\n");
    
    // Извлечение и расшифровка NT и LM хэшей
    if(kull_m_rpc_drsr_findMonoAttr(prefixTable, attributes, szOID_ANSI_unicodePwd, &encodedData, &encodedDataSize))
        kuhl_m_lsadump_dcsync_decrypt(encodedData, encodedDataSize, rid, L"NTLM", FALSE);
    if(kull_m_rpc_drsr_findMonoAttr(prefixTable, attributes, szOID_ANSI_dBCSPwd, &encodedData, &encodedDataSize))
        kuhl_m_lsadump_dcsync_decrypt(encodedData, encodedDataSize, rid, L"LM  ", FALSE);
}

// Извлечение supplementalCredentials (Kerberos keys, WDigest, Cleartext)
if(kull_m_rpc_drsr_findMonoAttr(prefixTable, attributes, szOID_ANSI_supplementalCredentials, &encodedData, &encodedDataSize))
{
    kprintf(L"\nSupplemental Credentials:\n");
    kuhl_m_lsadump_dcsync_descrUserProperties((PUSER_PROPERTIES) encodedData);
}

// Извлечение пароля LAPS
if((cSuppATT_IntId >= 2) && pSuppATT_IntId[0] && pSuppATT_IntId[1])
{
    kprintf(L"LAPS:\n");
    if(kull_m_rpc_drsr_findMonoAttrNoOID(attributes, pSuppATT_IntId[0], &encodedData, &encodedDataSize))
    {
        kprintf(L"  Password   : %.*S\n", encodedDataSize, encodedData);
    }
}
```

После получения ответа от DC (ATTRBLOCK), Mimikatz разбирает его по частям.
  1) Сначала извлекается SID пользователя, из которого вычисляется RID (последняя субавторити). Этот RID тут же используется для вызова функции расшифровки, описанной в пункте 3.
  2) Затем Mimikatz ищет атрибут `supplementalCredentials`. Это бинарный блоб, который содержит структуру `USER_PROPERTIES`. Внутри неё Mimikatz ищет специфические пакеты: `Primary:CLEARTEXT` (если включено обратимое шифрование), `Primary:WDigest` (хэши WDigest), `Primary:Kerberos` и `Primary:Kerberos-Newer-Keys` (ключи Kerberos AES128/AES256). Это критично, так как позволяет атакующему не только получить NTLM-хэш, но и сразу сгенерировать Kerberos-тикеты (Silver Ticket) или использовать AES-ключи для обхода защиты RC4.
  3) В конце проверяется наличие атрибутов `LAPS` (msMcsAdmPwd), и если они найдены, локальный административный пароль выводится в открытом виде.


