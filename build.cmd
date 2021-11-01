@echo off

set BUILDDATE=%DATE:~-4%%DATE:~3,2%%DATE:~0,2%

for /F "usebackq delims=" %%a in (`git rev-parse --short HEAD`) do (
     ENDLOCAL
     set COMMIT=%%a
)

for /F "usebackq delims=" %%a in (`git describe --tags --exclude latest`) do (
     ENDLOCAL
     set GIT_VERSION=%%a
)

set LDFLAGS=-X version.Program=adalanche -X version.Builddate=%BUILDDATE% -X version.Commit=%COMMIT% -X version.Version=%GIT_VERSION%
set GOARCH=amd64
set GOOS=windows
go build -ldflags "%LDFLAGS%" -o adalanche-windows-x64-%GIT_VERSION%.exe ./adalanche
set GOOS=darwin
go build -ldflags "%LDFLAGS%" -o adalanche-osx-x64-%GIT_VERSION% ./adalanche
set GOOS=linux
go build -ldflags "%LDFLAGS%" -o adalanche-linux-x64-%GIT_VERSION% ./adalanche

set LDFLAGS=-X version.Program=adalanche-collector -X version.Builddate=%BUILDDATE% -X version.Commit=%COMMIT% -X version.Version=%GIT_VERSION%
set GOARCH=386
set GOOS=windows
go build -ldflags "%LDFLAGS%" -o adalanche-collector-windows-386-%GIT_VERSION%.exe ./collector
