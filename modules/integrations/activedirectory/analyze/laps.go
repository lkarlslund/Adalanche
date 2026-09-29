package analyze

import (
	"github.com/gofrs/uuid/v5"
	"github.com/lkarlslund/adalanche/modules/engine"
	"github.com/lkarlslund/adalanche/modules/integrations/activedirectory"
	"github.com/lkarlslund/adalanche/modules/ui"
)

func addLAPSv2Edges(ao *engine.IndexedGraph) {
	// Find LAPS or return
	var lapsV2PasswordGUID uuid.UUID
	var lapsV2EncryptedPasswordGUID uuid.UUID

	if lapsobject, found := ao.FindTwo(engine.Name, engine.NV("ms-LAPS-Password"),
		engine.ObjectClass, engine.NV("attributeSchema")); found {
		if objectGUID, ok := lapsobject.OneAttrRaw(activedirectory.SchemaIDGUID).(uuid.UUID); ok {
			ui.Debug().Msg("Detected LAPS schema extension GUID")
			lapsV2PasswordGUID = objectGUID
		} else {
			ui.Error().Msgf("Could not read LAPS schema extension GUID from %v", lapsobject.DN())
		}
	}
	if lapsobject, found := ao.FindTwo(engine.Name, engine.NV("ms-LAPS-EncryptedPassword"),
		engine.ObjectClass, engine.NV("attributeSchema")); found {
		if objectGUID, ok := lapsobject.OneAttrRaw(activedirectory.SchemaIDGUID).(uuid.UUID); ok {
			ui.Debug().Msg("Detected LAPS schema extension GUID")
			lapsV2EncryptedPasswordGUID = objectGUID
		} else {
			ui.Error().Msgf("Could not read LAPS schema extension GUID from %v", lapsobject.DN())
		}
	}

	if lapsV2PasswordGUID.IsNil() && lapsV2EncryptedPasswordGUID.IsNil() {
		ui.Debug().Msg("LAPS v2 schema not detected, skipping analysis")
		return
	}

	ao.Iterate(func(o *engine.Node) bool {
		// Only for computers
		if o.Type() != engine.NodeTypeComputer {
			return true
		}

		// ... that has LAPS installed
		if !o.HasAttr(activedirectory.MSLAPSPasswordExpirationTime) {
			return true
		}

		// Analyze ACL
		sd, err := o.SecurityDescriptor()
		if err != nil {
			return true
		}

		// Link to the machine object
		machinesid := o.SID()
		if machinesid.IsBlank() {
			ui.Fatal().Msgf("Computer account %v has no objectSID", o.DN())
		}
		machine, found := ao.Find(DomainJoinedSID, engine.NV(machinesid))
		if !found {
			ui.Error().Msgf("Could not locate machine for domain SID %v while processing LAPS v2", machinesid)
			return true
		}
		machine.Tag("laps")

		for index, acl := range sd.DACL.Entries {
			// Plaintext access is evaluated independently. An encrypted-attribute
			// grant alone does not prove the trustee can decrypt the password.
			if !lapsV2PasswordGUID.IsNil() && sd.DACL.IsObjectClassAccessAllowed(index, o, engine.RIGHT_DS_CONTROL_ACCESS, lapsV2PasswordGUID, ao) {
				ao.EdgeTo(ao.FindOrAddAdjacentSID(acl.SID, o), machine, activedirectory.EdgeReadLAPSPassword)
			}
			if !lapsV2EncryptedPasswordGUID.IsNil() && sd.DACL.IsObjectClassAccessAllowed(index, o, engine.RIGHT_DS_CONTROL_ACCESS, lapsV2EncryptedPasswordGUID, ao) {
				ao.EdgeTo(ao.FindOrAddAdjacentSID(acl.SID, o), machine, activedirectory.EdgeReadEncryptedLAPSPassword)
			}
			if sd.DACL.IsObjectClassAccessAllowed(index, o, engine.RIGHT_DS_CONTROL_ACCESS, msLAPSEncryptedPasswordAttributesGUID, ao) {
				ao.EdgeTo(ao.FindOrAddAdjacentSID(acl.SID, o), machine, activedirectory.EdgeReadEncryptedLAPSPassword)
			}
		}
		return true
	})
}
