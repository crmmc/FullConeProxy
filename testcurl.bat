@echo off
echo traceing %1
:goa
curl %1 --socks5-hostname 127.0.0.1:10805 >NUL 2>NUL || echo %date% %time% -- %1 %errorlevel%>>CURLERRORTIME.log  || echo %date% %time% -- %1 %errorlevel%>>CURLERRORTIME2.log
goto goa