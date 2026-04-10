package mcpserver

import (
	"fmt"
	"strings"
)

type redactor struct {
	profile string
}

func newRedactor(profile string) (redactor, error) {
	switch strings.ToLower(strings.TrimSpace(profile)) {
	case "", "strict":
		return redactor{profile: "strict"}, nil
	default:
		return redactor{}, fmt.Errorf("unsupported MCP redaction profile %q", profile)
	}
}

func (r redactor) mask(attribute string, values []string) ([]string, bool) {
	if r.profile != "strict" {
		return nil, false
	}

	name := strings.ToLower(attribute)
	switch name {
	case "unicodepwd", "userpassword", "supplementalcredentials", "nthash", "lmpwdhistory", "ntpwdhistory", "msds-managedpassword", "msds-managedpasswordid":
		return []string{"<redacted>"}, true
	}
	for _, fragment := range []string{"password", "secret", "credential", "hash"} {
		if strings.Contains(name, fragment) {
			return []string{"<redacted>"}, true
		}
	}
	return values, false
}
