@echo off
rem go generate

set BUILDDATE=%DATE:~-4%%DATE:~3,2%%DATE:~0,2%

for /F "usebackq delims=" %%a in (`git rev-parse --short HEAD`) do (
     ENDLOCAL
     set COMMIT=%%a
)

set GIT_COMMIT=`git rev-list -1 HEAD)`
set GOOS=windows
go build -ldflags "-X main.builddate=%BUILDDATE% -X main.commit=%COMMIT%" -o adalanche-windows-x64-%BUILDDATE%-%COMMIT%.exe
set GOOS=darwin
go build -ldflags "-X main.builddate=%BUILDDATE% -X main.commit=%COMMIT%" -o adalanche-osx-x64-%BUILDDATE%-%COMMIT%
set GOOS=linux
go build -ldflags "-X main.builddate=%BUILDDATE% -X main.commit=%COMMIT%" -o adalanche-linux-x64-%BUILDDATE%-%COMMIT%
