@echo off
:moreonce
curl https://www.baidu.com --socks5-hostname 127.0.0.1:10805 -o NUL >NUL 2>NUL
goto moreonce