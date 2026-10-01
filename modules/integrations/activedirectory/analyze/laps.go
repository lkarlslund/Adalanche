package analyze

import (
	"github.com/gofrs/uuid/v5"
	"github.com/lkarlslund/adalanche/modules/engine"
	"github.com/lkarlslund/adalanche/modules/integrations/activedirectory"
	"github.com/lkarlslund/adalanche/modules/ui"
)

// lapsSchemaGUID returns the schemaIDGUID of a Windows LAPS attribute, found
// by its schema object name (cn), or nil if the schema lacks it.
func lapsSchemaGUID(ao *engine.IndexedGraph, cn string) uuid.UUID {
	lapsobject, found := ao.FindTwo(engine.Name, engine.NV(cn), engine.ObjectClass, engine.NV("attributeSchema"))
	if !found {
		return uuid.Nil
	}
	guid, ok := lapsobject.OneAttrRaw(activedirectory.SchemaIDGUID).(uuid.UUID)
	if !ok {
		ui.Error().Msgf("Could not read LAPS schema extension GUID from %v", lapsobject.DN())
		return uuid.Nil
	}
	return guid
}

func addLAPSv2Edges(ao *engine.IndexedGraph) {
	passwordGUID := lapsSchemaGUID(ao, "ms-LAPS-Password")
	encryptedGUID := lapsSchemaGUID(ao, "ms-LAPS-EncryptedPassword")
	dsrmGUID := lapsSchemaGUID(ao, "ms-LAPS-EncryptedDSRMPassword")
	if passwordGUID.IsNil() && encryptedGUID.IsNil() && dsrmGUID.IsNil() {
		ui.Debug().Msg("LAPS v2 schema not detected, skipping analysis")
		return
	}

	// The password attributes are confidential, so reading them takes both
	// read and control access rights (MS-ADTS 3.1.1.4.4).
	type grant struct {
		attribute uuid.UUID
		edge      engine.Edge
		forDC     bool
	}
	var grants []grant
	for _, g := range []grant{
		// Plaintext access is evaluated independently. An encrypted-attribute
		// grant alone does not prove the trustee can decrypt the password.
		{passwordGUID, activedirectory.EdgeReadLAPSPassword, false},
		{encryptedGUID, activedirectory.EdgeReadEncryptedLAPSPassword, false},
		{msLAPSEncryptedPasswordAttributesGUID, activedirectory.EdgeReadEncryptedLAPSPassword, false},
		// Domain controllers back up their DSRM password instead.
		{dsrmGUID, activedirectory.EdgeReadEncryptedLAPSPassword, true},
	} {
		if !g.attribute.IsNil() {
			grants = append(grants, g)
		}
	}
	rights := make(map[uuid.UUID]engine.Mask, len(grants))
	for _, g := range grants {
		rights[g.attribute] = AttributeReadRights(ao, g.attribute, true)
	}

	ao.Iterate(func(o *engine.Node) bool {
		// Only computers that have Windows LAPS
		if o.Type() != engine.NodeTypeComputer || !o.HasAttr(activedirectory.MSLAPSPasswordExpirationTime) {
			return true
		}
		sd, err := o.SecurityDescriptor()
		if err != nil {
			return true
		}
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

		uac, _ := o.AttrInt(activedirectory.UserAccountControl)
		isDC := uac&engine.UAC_SERVER_TRUST_ACCOUNT != 0
		for _, g := range grants {
			if g.forDC != isDC {
				continue
			}
			for _, sid := range PrincipalsGranted(sd, o, rights[g.attribute], g.attribute, ao) {
				ao.EdgeTo(aceTrustee(ao, sd, sid, o), machine, g.edge)
			}
		}
		return true
	})
}
