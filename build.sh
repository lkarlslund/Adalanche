#!/bin/bash

BUILDDATE=`date +%Y%m%d`
COMMIT=`git rev-parse --short HEAD`

GOOS=windows GOARCH=amd64 go build -ldflags "-X main.builddate=$BUILDDATE -X main.commit=$COMMIT" -o adalanche-windows-x64-$BUILDDATE-$COMMIT.exe ./adalanche
GOOS=darwin GOARCH=amd64 go build -ldflags "-X main.builddate=$BUILDDATE -X main.commit=$COMMIT" -o adalanche-osx-x64-$BUILDDATE-$COMMIT ./adalanche
GOOS=linux GOARCH=amd64 go build -ldflags "-X main.builddate=$BUILDDATE -X main.commit=$COMMIT" -o adalanche-linux-x64-$BUILDDATE-$COMMIT ./adalanche

GOOS=windows GOARCH=386 go build -ldflags "-X main.builddate=$BUILDDATE -X main.commit=$COMMIT" -o adalanche-collector-windows-386-$BUILDDATE-$COMMIT.exe ./collector
