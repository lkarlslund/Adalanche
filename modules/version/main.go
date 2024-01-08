package version

import (
	"strings"
)

var (
	Program    = "Adalanche Open Source"
	Commit     = ""
	Version    = ""
	Copyright  = "(c) 2020-2024 Lars Karlslund"
	Disclaimer = "This program comes with ABSOLUTELY NO WARRANTY"
)

func ProgramVersionShort() string {
	return strings.Trim(Program+" "+VersionStringShort(), " ")
}

func VersionStringShort() string {
	result := ""
	if Version != "" {
		result += Version
		if strings.Contains(Version, "-") {
			result += " (non-release)"
		}
	}
	if Commit != "" && !strings.Contains(Version, Commit) {
		result += " (commit " + Commit + ")"
	}
	if result == "" {
		result = "(unknown build)"
	}
	return result
}

func VersionString() string {
	result := ProgramVersionShort()

	result += ", " + Copyright + ", " + Disclaimer
	return result
}
