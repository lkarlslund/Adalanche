function BuildVariants {
  param (
    $ldflags,
    $compileflags,
    $prefix,
    $suffix,
    $arch,
    $os,
    $path
  )

  foreach ($currentarch in $arch) {
    foreach ($currentos in $os) {
      $env:GOARCH = $currentarch
      $env:GOOS = $currentos
      go build -ldflags "$ldflags" -o binaries/$prefix-$currentarch-$currentos-$VERSION$suffix.exe $compileflags $path
      if (Get-Command "cyclonedx-gomod" -ErrorAction SilentlyContinue)
      {
        cyclonedx-gomod app -json -licenses -output binaries/$prefix-$currentarch-$currentos-$VERSION$suffix.bom.json -main $path .
      }
    }
  }
}

Set-Location $PSScriptRoot

$COMMIT = git rev-parse --short HEAD
$VERSION = git describe --tags --exclude latest
$DIRTYFILES = git status --porcelain

if ("$DIRTYFILES" -ne "") {
  $VERSION = "$VERSION-local-changes"
}

$LDFLAGS = "-X github.com/lkarlslund/adalanche/modules/version.Commit=$COMMIT -X github.com/lkarlslund/adalanche/modules/version.Version=$VERSION"

# Release
BuildVariants -ldflags "$LDFLAGS -s" -prefix adalanche-collector-windows -path ./collector -arch @("386") -os @("windows")
BuildVariants -ldflags "$LDFLAGS -s" -prefix adalanche-windows -path ./adalanche -arch @("amd64", "arm64") -os @("windows", "darwin", "linux")
