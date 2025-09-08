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
    if (![string]::IsNullOrWhiteSpace($env:ONLYARCH) -and $env:ONLYARCH -ne $currentarch) {
        continue
    }
    foreach ($currentos in $os) {
      if (![string]::IsNullOrWhiteSpace($env:ONLYOS) -and $env:ONLYOS -ne $currentos) {
        continue
      }

      $env:GOARCH = $currentarch
      $env:GOOS = $currentos
      
      # More sensible naming for x64
      $namearch = $currentarch
      if ($namearch -eq "amd64") {
        $namearch = "x64"
      }

      Write-Output "Building $prefix for $currentos-$namearch..."

      & $BUILDER build -ldflags "$ldflags" -o binaries/$prefix-$currentos-$namearch-$VERSION$suffix @compileflags $path

      if (Get-Command "cyclonedx-gomod" -ErrorAction SilentlyContinue)
      {
        $sbom = "binaries/$prefix-$currentos-$namearch-$VERSION$suffix.bom.json"
        if (!(Test-Path $sbom)) {
        Write-Output "Generating $prefix SBOM for $currentos-$namearch..."
        cyclonedx-gomod app -json -licenses -output $sbom -main $path .
        }
      }
    }
  }
}

Set-Location $PSScriptRoot

$COMMIT = git rev-parse --short HEAD
$VERSION = git describe --tags --exclude latest --exclude devbuild
$DIRTYFILES = git status --porcelain
$BUILDER = "go"

if ("$DIRTYFILES" -ne "") {
  $VERSION = "$VERSION-local-changes"
}

# enable GOEXPERIMENT greenteagc
$env:GOEXPERIMENT = "greenteagc"

$LDFLAGS = "-X github.com/lkarlslund/adalanche/modules/version.Commit=$COMMIT -X github.com/lkarlslund/adalanche/modules/version.Version=$VERSION"

BuildVariants -ldflags "$LDFLAGS -s" -prefix adalanche -path ./adalanche -arch @("amd64", "arm64") -os @("windows") -suffix ".exe"
BuildVariants -ldflags "$LDFLAGS -s" -prefix adalanche -path ./adalanche -arch @("amd64", "arm64") -os @("darwin", "freebsd", "openbsd", "linux")

# Switch to Go with Win7 compatibility and clear cache
if (Get-Command "go-win7" -ErrorAction SilentlyContinue) {
  Write-Output "Switching to go-win7 for Windows collector builds"
  $BUILDER = "go-win7"
  & $BUILDER clean -cache
}

BuildVariants -ldflags "$LDFLAGS -s" -compileflags @("-trimpath", "-tags", "32bit,collector") -prefix adalanche-collector -path ./adalanche -arch @("386") -os @("windows") -suffix ".exe"
BuildVariants -ldflags "$LDFLAGS -s" -compileflags @("-trimpath", "-tags", "collector") -prefix adalanche-collector -path ./adalanche -arch @("amd64") -os @("windows") -suffix ".exe"
