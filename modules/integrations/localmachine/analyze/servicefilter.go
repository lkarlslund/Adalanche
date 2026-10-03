package analyze

import (
	"strings"

	"github.com/lkarlslund/adalanche/modules/engine"
	"github.com/lkarlslund/adalanche/modules/integrations/localmachine"
	"github.com/lkarlslund/adalanche/modules/windowssecurity"
)

// adminEquivalent reports whether a principal already controls the machine,
// so rights it holds over the machine's own objects add no attack path.
type adminEquivalent func(windowssecurity.SID) bool

var trustedInstallerSID = windowssecurity.ServiceNameToServiceSID("TrustedInstaller")

// machineAdmins returns the machine's admin-equivalent principals: the local
// Administrators group and SYSTEM, and TrustedInstaller when the collection
// shows that only those can control the TrustedInstaller service. Windows
// owns its own binaries and service settings through TrustedInstaller.
func machineAdmins(services []localmachine.Service) adminEquivalent {
	withTrustedInstaller := func(sid windowssecurity.SID) bool {
		return localAdministratorSID(sid) || sid == trustedInstallerSID
	}
	for _, service := range services {
		// TrustedInstaller owns its own service; that gives no one else
		// control, so its service is judged with it counted.
		if strings.EqualFold(service.Name, "TrustedInstaller") && serviceAdminOnly(service, withTrustedInstaller) {
			return withTrustedInstaller
		}
	}
	return localAdministratorSID
}

// serviceAdminOnly reports whether the collected data shows that only
// admin-equivalent principals can change the service, its settings or its
// executable. It suppresses redundant service graph objects, not inventory
// or collection outcomes. Only data we have is acted on: a field that was
// not collected is not evaluated (it gives the graph no edges either), and
// one that was collected but cannot be read keeps the service.
func serviceAdminOnly(service localmachine.Service, admin adminEquivalent) bool {
	for _, owner := range []string{service.ImageExecutableOwner, service.RegistryOwner} {
		if owner == "" {
			continue
		}
		sid, err := windowssecurity.ParseStringSID(owner)
		if err != nil || !admin(sid) {
			return false
		}
	}
	if len(service.ImageExecutableDACL) > 0 {
		file, err := engine.ParseACL(service.ImageExecutableDACL)
		if err != nil || !adminOnlyServiceACL(file, engine.FILE_WRITE_DATA|engine.FILE_APPEND_DATA, admin) {
			return false
		}
	}
	if len(service.RegistryDACL) > 0 {
		registry, err := engine.ParseACL(service.RegistryDACL)
		if err != nil || !adminOnlyServiceACL(registry, engine.KEY_SET_VALUE|engine.KEY_CREATE_SUB_KEYS, admin) {
			return false
		}
	}
	if len(service.SecurityDescriptor) > 0 {
		sd, err := engine.ParseSecurityDescriptor(service.SecurityDescriptor)
		if err != nil || sd.Control&engine.CONTROLFLAG_DACL_PRESENT == 0 || sd.DACL.Revision == 0 || !admin(sd.Owner) {
			return false
		}
		if !adminOnlyServiceACL(sd.DACL, engine.SERVICE_CHANGE_CONFIG, admin) {
			return false
		}
	}
	return true
}

func localAdministratorSID(sid windowssecurity.SID) bool {
	return sid == windowssecurity.AdministratorsSID || sid == windowssecurity.SystemSID
}

func adminOnlyServiceACL(acl engine.ACL, specificWrites engine.Mask, admin adminEquivalent) bool {
	// Raw generic bits are used here; engine.RIGHT_GENERIC_* are directory mappings.
	writes := specificWrites | engine.RIGHT_WRITE_DACL | engine.RIGHT_WRITE_OWNER | engine.RIGHT_DELETE | engine.Mask(0x40000000|0x10000000)
	for _, ace := range acl.Entries {
		if ace.ACEFlags&engine.ACEFLAG_INHERIT_ONLY_ACE != 0 {
			continue
		}
		switch ace.Type {
		case engine.ACETYPE_ACCESS_DENIED, engine.ACETYPE_ACCESS_DENIED_OBJECT:
			// Do not infer effective access or cancel a grant using a deny ACE.
			continue
		case engine.ACETYPE_ACCESS_ALLOWED:
			if ace.Mask&writes != 0 && !admin(ace.SID) {
				return false
			}
		default:
			// Conditional and object-specific grants need a fuller access check.
			return false
		}
	}
	return true
}

// serviceStartName names a service start type.
func serviceStartName(start int) string {
	switch start {
	case 0:
		return "boot"
	case 1:
		return "system"
	case 2:
		return "automatic"
	case 3:
		return "manual"
	case 4:
		return "disabled"
	}
	return "unknown"
}
