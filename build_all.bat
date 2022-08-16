@echo off
set GOARCH=amd64
set GOOS=windows
go build -o myproxy.exe -ldflags="-w -s" || pause
set GOARCH=amd64
set GOOS=linux
go build  -o myproxy -ldflags="-w -s" || pause
upx -9 myproxy*