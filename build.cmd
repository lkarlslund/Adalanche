@echo off

set BUILDDATE=%DATE:~-4%%DATE:~3,2%%DATE:~0,2%

for /F "usebackq delims=" %%a in (`git rev-parse --short HEAD`) do (
     ENDLOCAL
     set COMMIT=%%a
)
set GIT_COMMIT=`git rev-list -1 HEAD)`


set LDFLAGS=-X version.Programname=adalanche -X version.Builddate=%BUILDDATE% -X version.Commit=%COMMIT%
set GOARCH=amd64
set GOOS=windows
go build -ldflags "%LDFLAGS%" -o adalanche-windows-x64-%BUILDDATE%-%COMMIT%.exe ./adalanche
set GOOS=darwin
go build -ldflags "%LDFLAGS%" -o adalanche-osx-x64-%BUILDDATE%-%COMMIT% ./adalanche
set GOOS=linux
go build -ldflags "%LDFLAGS%" -o adalanche-linux-x64-%BUILDDATE%-%COMMIT% ./adalanche

set LDFLAGS=-X version.Programname=adalanche -X version.Builddate=%BUILDDATE% -X version.Commit=%COMMIT%
set GOARCH=386
set GOOS=windows
go build -ldflags "%LDFLAGS%" -o adalanche-collector-windows-386-%BUILDDATE%-%COMMIT%.exe ./collector
