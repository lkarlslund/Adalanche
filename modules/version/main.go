package version

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
	}
	if Commit != "" {
		result += " (commit " + Commit + ")"
	}
	return result
}

func VersionString() string {
	result := Program
	if Version != "" {
		result += " " + Version
	}
	if Commit != "" {
		result += " (commit " + Commit + ")"
	}

	if Builddate != "" {
		result += " built " + Builddate
	}
	result += ", " + Copyright + ", " + Disclaimer
	return result
}
