#!/bin/bash

BUILDDATE=`date +%Y%m%d`
COMMIT=`git rev-parse --short HEAD`

EXIT_STATUS=0

LDFLAGS="-X version.Programname=adalanche -X version.Builddate=$BUILDDATE -X version.Commit=$COMMIT"

GOOS=windows GOARCH=amd64 go build -ldflags "$LDFLAGS" -o adalanche-windows-x64-$BUILDDATE-$COMMIT.exe ./adalanche || EXIT_STATUS=$?
GOOS=darwin GOARCH=amd64 go build -ldflags "$LDFLAGS" -o adalanche-osx-x64-$BUILDDATE-$COMMIT ./adalanche || EXIT_STATUS=$?
GOOS=linux GOARCH=amd64 go build -ldflags "$LDFLAGS" -o adalanche-linux-x64-$BUILDDATE-$COMMIT ./adalanche || EXIT_STATUS=$?

LDFLAGS="-X version.Programname=adalanche-collector -X version.Builddate=$BUILDDATE -X version.Commit=$COMMIT"

GOOS=windows GOARCH=386 go build -ldflags "$LDFLAGS" -o adalanche-collector-windows-386-$BUILDDATE-$COMMIT.exe ./collector || EXIT_STATUS=$?

exit $EXIT_STATUS
