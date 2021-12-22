@echo off

set BUILDDATE=%DATE:~-4%%DATE:~3,2%%DATE:~0,2%

for /F "usebackq delims=" %%a in (`git rev-parse --short HEAD`) do set COMMIT=%%a
for /F "usebackq delims=" %%a in (`git describe --tags --exclude latest`) do set VERSION=%%a
for /F "usebackq delims=" %%a in (`git status --porcelain`) do set dirtyfiles="%%a"

if not [%dirtyfiles%] == [] (
  ENDLOCAL
  set VERSION=%VERSION%-local-changes
)

set LDFLAGS=-X github.com/lkarlslund/adalanche/modules/version.Program=adalanche -X github.com/lkarlslund/adalanche/modules/version.Builddate=%BUILDDATE% -X github.com/lkarlslund/adalanche/modules/version.Commit=%COMMIT% -X github.com/lkarlslund/adalanche/modules/version.Version=%VERSION%
set GOARCH=amd64
set GOOS=windows
go build -ldflags "%LDFLAGS%" -o adalanche-windows-x64-%VERSION%.exe ./adalanche
set GOOS=darwin
go build -ldflags "%LDFLAGS%" -o adalanche-osx-x64-%VERSION% ./adalanche
set GOOS=linux
go build -ldflags "%LDFLAGS%" -o adalanche-linux-x64-%VERSION% ./adalanche

set GOARCH=arm64
set GOOS=linux
go build -ldflags "%LDFLAGS%" -o adalanche-linux-arm64-%VERSION% ./adalanche
set GOOS=darwin
go build -ldflags "%LDFLAGS%" -o adalanche-osx-m1-%VERSION% ./adalanche

set LDFLAGS=-X github.com/lkarlslund/adalanche/modules/version.Program=adalanche-collector -X github.com/lkarlslund/adalanche/modules/version.Builddate=%BUILDDATE% -X github.com/lkarlslund/adalanche/modules/version.Commit=%COMMIT% -X github.com/lkarlslund/adalanche/modules/version.Version=%VERSION%
set GOARCH=386
set GOOS=windows
go build -ldflags "%LDFLAGS%" -o adalanche-collector-windows-386-%VERSION%.exe ./collector

