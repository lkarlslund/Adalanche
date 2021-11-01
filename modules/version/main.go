package version

import "strings"

var (
	Program    = "adalanche"
	Builddate  = ""
	Commit     = ""
	Version    = ""
	Copyright  = "(c) 2020-2021 Lars Karlslund"
	Disclaimer = "This program comes with ABSOLUTELY NO WARRANTY"
)

func VersionStringShort() string {
	result := Program
	if Version != "" {
		result += " " + Version
		if strings.Contains(Version, "-") {
			result += " (non-release)"
		}
	}
	if Commit != "" && !strings.Contains(Version, Commit) {
		result += " (commit " + Commit + ")"
	}
	return result
}

func VersionString() string {
	result := VersionStringShort()

	if Builddate != "" {
		result += " built " + Builddate
	}
	result += ", " + Copyright + ", " + Disclaimer
	return result
}
