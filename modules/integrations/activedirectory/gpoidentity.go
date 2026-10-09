package activedirectory

import (
	"strings"

	"github.com/lkarlslund/adalanche/modules/engine"
)

// GPOIdentity is a group policy's identity: the DNS name of its domain and
// its GUID, as "example.test/{31B2F340-016D-11D2-945F-00C04FB984F9}". The
// directory object, the SYSVOL collection and machines' policy results each
// name a GPO differently; all of them reduce to this.
var GPOIdentity = engine.NewAttribute("gpoIdentity").Flag(engine.Single, engine.Merge)

// GPOIdentityFromPath reads the identity from a SYSVOL path,
// \\server\SYSVOL\<domain>\Policies\{GUID}[\...], whatever the server and
// case. It returns "" for other paths.
func GPOIdentityFromPath(path string) string {
	parts := strings.Split(strings.TrimLeft(strings.ReplaceAll(path, "/", `\`), `\`), `\`)
	for i := 0; i+3 < len(parts); i++ {
		if strings.EqualFold(parts[i], "sysvol") && strings.EqualFold(parts[i+2], "policies") {
			return gpoIdentity(parts[i+1], parts[i+3])
		}
	}
	return ""
}

// GPOIdentityFromDN reads the identity from a GPO's distinguished name,
// CN={GUID},CN=Policies,CN=System,DC=example,DC=test. It returns "" for other
// names.
func GPOIdentityFromDN(dn string) string {
	parts := strings.Split(dn, ",")
	if len(parts) < 4 || !strings.EqualFold(parts[1], "CN=Policies") || !strings.EqualFold(parts[2], "CN=System") {
		return ""
	}
	name, found := strings.CutPrefix(strings.ToUpper(parts[0]), "CN=")
	if !found {
		return ""
	}
	var domain []string
	for _, p := range parts[3:] {
		label, found := strings.CutPrefix(strings.ToUpper(p), "DC=")
		if !found {
			return ""
		}
		domain = append(domain, label)
	}
	return gpoIdentity(strings.Join(domain, "."), name)
}

func gpoIdentity(domain, guid string) string {
	if domain == "" || len(guid) != 38 || guid[0] != '{' || guid[37] != '}' {
		return ""
	}
	return strings.ToLower(domain) + "/" + strings.ToUpper(guid)
}
