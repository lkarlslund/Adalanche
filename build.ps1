function BuildVariants {
  param (
    $ldflags,
    $compileflags,
    $suffix
  )

  $env:GOARCH = "386"
  $env:GOOS = "windows"
  go build -ldflags "$ldflags" -o binaries/adalanche-collector-windows-386-$VERSION$suffix.exe $compileflags ./collector

  $env:GOARCH = "amd64"
  $env:GOOS = "windows"
  go build -ldflags "$ldflags" -o binaries/adalanche-windows-x64-$VERSION$suffix.exe $compileflags ./adalanche
  $env:GOOS = "darwin"
  go build -ldflags "$ldflags" -o binaries/adalanche-osx-x64-$VERSION$suffix $compileflags ./adalanche
  $env:GOOS = "linux"
  go build -ldflags "$ldflags" -o binaries/adalanche-linux-x64-$VERSION$suffix $compileflags ./adalanche

  $env:GOARCH = "arm64"
  $env:GOOS = "windows"
  go build -ldflags "$ldflags" -o binaries/adalanche-windows-arm64-$VERSION$suffix.exe $compileflags ./adalanche
  $env:GOOS = "linux"
  go build -ldflags "$ldflags" -o binaries/adalanche-linux-arm64-$VERSION$suffix $compileflags ./adalanche
  $env:GOOS = "darwin"
  go build -ldflags "$ldflags" -o binaries/adalanche-osx-m1-$VERSION$suffix $compileflags ./adalanche

}

Set-Location $PSScriptRoot

$BUILDDATE = Get-Date -Format "yyyyMMdd"

$COMMIT = git rev-parse --short HEAD
$VERSION = git describe --tags --exclude latest
$DIRTYFILES = git status --porcelain

if ("$DIRTYFILES" -ne "") {
  $VERSION = "$VERSION-local-changes"
}

$LDFLAGS = "-X github.com/lkarlslund/adalanche/modules/version.Program=adalanche -X github.com/lkarlslund/adalanche/modules/version.Builddate=$BUILDDATE -X github.com/lkarlslund/adalanche/modules/version.Commit=$COMMIT -X github.com/lkarlslund/adalanche/modules/version.Version=$VERSION"

# Release
BuildVariants -ldflags "$LDFLAGS -s"
