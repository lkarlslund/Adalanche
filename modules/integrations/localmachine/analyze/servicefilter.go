package analyze

import (
	"github.com/lkarlslund/adalanche/modules/engine"
	"github.com/lkarlslund/adalanche/modules/integrations/localmachine"
	"github.com/lkarlslund/adalanche/modules/windowssecurity"
)

// serviceAdminOnly suppresses redundant service graph objects, not inventory or
// collection outcomes. Incomplete data is not evidence of an admin-only service.
func serviceAdminOnly(service localmachine.Service) bool {
	for _, owner := range []string{service.ImageExecutableOwner, service.RegistryOwner} {
		sid, err := windowssecurity.ParseStringSID(owner)
		if err != nil || !localAdministratorSID(sid) {
			return false
		}
	}
	file, err := engine.ParseACL(service.ImageExecutableDACL)
	if err != nil || !adminOnlyServiceACL(file, engine.FILE_WRITE_DATA|engine.FILE_APPEND_DATA) {
		return false
	}
	registry, err := engine.ParseACL(service.RegistryDACL)
	if err != nil || !adminOnlyServiceACL(registry, engine.KEY_SET_VALUE|engine.KEY_CREATE_SUB_KEYS) {
		return false
	}
	sd, err := engine.ParseSecurityDescriptor(service.SecurityDescriptor)
	if err != nil || sd.Control&engine.CONTROLFLAG_DACL_PRESENT == 0 || sd.DACL.Revision == 0 || !localAdministratorSID(sd.Owner) {
		return false
	}
	return adminOnlyServiceACL(sd.DACL, engine.SERVICE_CHANGE_CONFIG)
}

func localAdministratorSID(sid windowssecurity.SID) bool {
	return sid == windowssecurity.AdministratorsSID || sid == windowssecurity.SystemSID
}

func adminOnlyServiceACL(acl engine.ACL, specificWrites engine.Mask) bool {
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
			if ace.Mask&writes != 0 && !localAdministratorSID(ace.SID) {
				return false
			}
		default:
			// Conditional and object-specific grants need a fuller access check.
			return false
		}
	}
	return true
}
