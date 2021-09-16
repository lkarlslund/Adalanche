#!/bin/bash

BUILDDATE=`date +%Y%m%d`
COMMIT=`git rev-parse --short HEAD`

EXIT_STATUS=0

GOOS=windows GOARCH=amd64 go build -ldflags "-X main.builddate=$BUILDDATE -X main.commit=$COMMIT" -o adalanche-windows-x64-$BUILDDATE-$COMMIT.exe ./adalanche || EXIT_STATUS=$?
GOOS=darwin GOARCH=amd64 go build -ldflags "-X main.builddate=$BUILDDATE -X main.commit=$COMMIT" -o adalanche-osx-x64-$BUILDDATE-$COMMIT ./adalanche || EXIT_STATUS=$?
GOOS=linux GOARCH=amd64 go build -ldflags "-X main.builddate=$BUILDDATE -X main.commit=$COMMIT" -o adalanche-linux-x64-$BUILDDATE-$COMMIT ./adalanche || EXIT_STATUS=$?

GOOS=windows GOARCH=386 go build -ldflags "-X main.builddate=$BUILDDATE -X main.commit=$COMMIT" -o adalanche-collector-windows-386-$BUILDDATE-$COMMIT.exe ./collector || EXIT_STATUS=$?

exit $EXIT_STATUS
