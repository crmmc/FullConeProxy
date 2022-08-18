@echo off
go build -ldflags="-w -s" || exit
start FullConeProxy.exe --test --debug
ping -c 1 127.0.1 >NUL
curl --socks5 127.0.0.1:10805 https://www.baidu.com/
pause