package version

import "strings"

var (
	Program    = "adalanche"
	Builddate  = ""
	Commit     = ""
	Version    = ""
	Copyright  = "(c) 2020-2022 Lars Karlslund"
	Disclaimer = "This program comes with ABSOLUTELY NO WARRANTY"
)

func ProgramVersionShort() string {
	return Program + " " + VersionStringShort()
}

func VersionStringShort() string {
	result := ""
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
	result := ProgramVersionShort()

	if Builddate != "" {
		result += " built " + Builddate
	}
	result += ", " + Copyright + ", " + Disclaimer
	return result
}
