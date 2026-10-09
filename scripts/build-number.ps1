# Prints the build identity: r<commit count>. Local builds append -local, or
# -local-dirty when tracked files are modified, so a local build is never
# mistaken for a release. -Release prints the bare revision, as CI does.
param(
  [switch]$Release
)

$ErrorActionPreference = "Stop"

$count = git -C $PSScriptRoot rev-list --count HEAD
if ($LASTEXITCODE -ne 0) { throw "git rev-list failed" }
$tag = "r$count"

$dirty = git -C $PSScriptRoot status --porcelain --untracked-files=no
if ("$dirty" -ne "") {
  "$tag-local-dirty"
} elseif ($Release -or $env:CI -eq "true") {
  $tag
} else {
  "$tag-local"
}
