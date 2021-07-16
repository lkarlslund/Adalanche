#!/bin/bash

BUILDDATE=`date +%Y%m%d`
COMMIT=`git rev-parse --short HEAD`

GOOS=windows go build -ldflags "-X main.builddate=$BUILDDATE -X main.commit=$COMMIT" -o adalanche-windows-x64-$BUILDDATE-$COMMIT.exe
GOOS=darwin go build -ldflags "-X main.builddate=$BUILDDATE -X main.commit=$COMMIT" -o adalanche-osx-x64-$BUILDDATE-$COMMIT
GOOS=linux go build -ldflags "-X main.builddate=$BUILDDATE -X main.commit=$COMMIT" -o adalanche-linux-x64-$BUILDDATE-$COMMIT
