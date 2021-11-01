#!/bin/bash

BUILDDATE=`date +%Y%m%d`
COMMIT=`git rev-parse --short HEAD`
VERSION=`git describe --tags --exclude latest`

if [ -n "$(git status --porcelain)" ]; then
  VERSION=$VERSION-local-changes
fi

EXIT_STATUS=0

LDFLAGS="-X github.com/lkarlslund/adalanche/modules/version.Program=adalanche -X github.com/lkarlslund/adalanche/modules/version.Builddate=$BUILDDATE -X github.com/lkarlslund/adalanche/modules/version.Commit=$COMMIT -X github.com/lkarlslund/adalanche/modules/version.Version=$VERSION"

GOOS=windows GOARCH=amd64 go build -ldflags "$LDFLAGS" -o adalanche-windows-x64-$VERSION.exe ./adalanche || EXIT_STATUS=$?
GOOS=darwin GOARCH=amd64 go build -ldflags "$LDFLAGS" -o adalanche-osx-x64-$VERSION ./adalanche || EXIT_STATUS=$?
GOOS=linux GOARCH=amd64 go build -ldflags "$LDFLAGS" -o adalanche-linux-x64-$VERSION ./adalanche || EXIT_STATUS=$?

LDFLAGS="-X github.com/lkarlslund/adalanche/modules/version.Program=adalanche-collector -X github.com/lkarlslund/adalanche/modules/version.Builddate=$BUILDDATE -X github.com/lkarlslund/adalanche/modules/version.Commit=$COMMIT -X github.com/lkarlslund/adalanche/modules/version.Version=$VERSION"

GOOS=windows GOARCH=386 go build -ldflags "$LDFLAGS" -o adalanche-collector-windows-386-$VERSION.exe ./collector || EXIT_STATUS=$?

exit $EXIT_STATUS
