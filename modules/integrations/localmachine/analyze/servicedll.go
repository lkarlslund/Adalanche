package analyze

import (
	"encoding/base64"
	"encoding/json"
	"fmt"

	"github.com/lkarlslund/adalanche/modules/engine"
	"github.com/lkarlslund/adalanche/modules/integrations/activedirectory"
	lm "github.com/lkarlslund/adalanche/modules/integrations/localmachine"
	"github.com/lkarlslund/adalanche/modules/windowssecurity"
)

// EdgeModifyServiceDLL: the account can write a shared service's Parameters
// registry key, where its ServiceDll is named, so it can run its own DLL as
// the service account (usually LocalSystem) the next time the service starts.
var EdgeModifyServiceDLL = engine.NewEdge("ModifyServiceDLL").Tag("Pivot").Describe("Can change a service's ServiceDll by writing its Parameters registry key, running code as the service account")

// serviceDLLPermissions is the owner and DACL of one service's Parameters key.
type serviceDLLPermissions struct {
	owner string
	dacl  []byte
}

// serviceDLLSecurity returns, per service name, the owner and DACL of the
// Parameters key that holds a shared service's ServiceDll.
func serviceDLLSecurity(a *lm.Assessment) map[string]serviceDLLPermissions {
	out := map[string]serviceDLLPermissions{}
	for _, raw := range a.Categories["service-payloads"].Records {
		var r struct {
			Kind          string
			Name          string
			Payload       string
			RegistryOwner string
			RegistryDACL  string
		}
		if json.Unmarshal(raw, &r) != nil || r.Kind != "service-dll" || r.Name == "" {
			continue
		}
		if r.Payload == "" {
			continue // no ServiceDll value, so nothing to hijack
		}
		dacl, err := base64.StdEncoding.DecodeString(r.RegistryDACL)
		if err != nil {
			dacl = nil
		}
		out[r.Name] = serviceDLLPermissions{owner: r.RegistryOwner, dacl: dacl}
	}
	return out
}

func importServiceDLLHijack(tx *engine.Tx, scope MachineScope, service engine.TxNode, name string, perm serviceDLLPermissions) {
	if !service.Valid() {
		return
	}
	if perm.owner != "" {
		if sid, err := windowssecurity.ParseStringSID(perm.owner); err == nil {
			tx.EdgeBecause(scope.Principal(sid), service, EdgeRegistryOwns, Collected("service "+name+" Parameters key owner"))
		}
	}
	if len(perm.dacl) == 0 {
		return
	}
	acl, err := engine.ParseACL(perm.dacl)
	if err != nil {
		return
	}
	for index, entry := range acl.Entries {
		if entry.Type != engine.ACETYPE_ACCESS_ALLOWED || entry.ACEFlags&engine.ACEFLAG_INHERIT_ONLY_ACE != 0 {
			continue
		}
		principal := scope.Principal(entry.SID)
		cause := Collected(fmt.Sprintf("service %v Parameters key ACE %d", name, index))
		if entry.Mask&engine.KEY_SET_VALUE != 0 {
			tx.EdgeBecause(principal, service, EdgeModifyServiceDLL, cause)
		}
		if entry.Mask&engine.RIGHT_WRITE_DACL != 0 {
			tx.EdgeBecause(principal, service, EdgeRegistryModifyDACL, cause)
		}
		if entry.Mask&engine.RIGHT_WRITE_OWNER != 0 {
			tx.EdgeBecause(principal, service, activedirectory.EdgeTakeOwnership, cause)
		}
	}
}
