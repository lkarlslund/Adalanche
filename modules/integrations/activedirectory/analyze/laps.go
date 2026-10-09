package analyze

import (
	"github.com/gofrs/uuid/v5"
	"github.com/lkarlslund/adalanche/modules/engine"
	"github.com/lkarlslund/adalanche/modules/integrations/activedirectory"
	"github.com/lkarlslund/adalanche/modules/ui"
)

// lapsSchemaGUID returns the schemaIDGUID of a Windows LAPS attribute, found
// by its schema object name (cn) in the schema of o's dump, or nil if the
// schema lacks it.
func lapsSchemaGUID(ao engine.GraphReader, o *engine.Node, cn string) uuid.UUID {
	lapsobject, found := schemaObjectTwo(ao, o, engine.Name, engine.NV(cn), engine.ObjectClass, engine.NV("attributeSchema"))
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

// lapsv2Grant is an attribute whose read access gives an edge.
type lapsv2Grant struct {
	name      string // the schema attribute
	attribute uuid.UUID
	edge      engine.Edge
	forDC     bool
	rights    engine.Mask
}

// lapsv2Grants returns the Windows LAPS grants in the schema of o's dump, or
// none if that schema lacks Windows LAPS.
func lapsv2Grants(tx *engine.Tx, o *engine.Node) []lapsv2Grant {
	passwordGUID := lapsSchemaGUID(tx, o, "ms-LAPS-Password")
	encryptedGUID := lapsSchemaGUID(tx, o, "ms-LAPS-EncryptedPassword")
	dsrmGUID := lapsSchemaGUID(tx, o, "ms-LAPS-EncryptedDSRMPassword")
	if passwordGUID.IsNil() && encryptedGUID.IsNil() && dsrmGUID.IsNil() {
		ui.Debug().Msg("LAPS v2 schema not detected, skipping analysis")
		return nil
	}

	// The password attributes are confidential, so reading them takes both
	// read and control access rights (MS-ADTS 3.1.1.4.4).
	var grants []lapsv2Grant
	for _, g := range []lapsv2Grant{
		// Plaintext access is evaluated independently. An encrypted-attribute
		// grant alone does not prove the trustee can decrypt the password.
		{name: "ms-LAPS-Password", attribute: passwordGUID, edge: activedirectory.EdgeReadLAPSPassword},
		{name: "ms-LAPS-EncryptedPassword", attribute: encryptedGUID, edge: activedirectory.EdgeReadEncryptedLAPSPassword},
		{name: "ms-LAPS-Encrypted-Password-Attributes property set", attribute: msLAPSEncryptedPasswordAttributesGUID, edge: activedirectory.EdgeReadEncryptedLAPSPassword},
		// Domain controllers back up their DSRM password instead.
		{name: "ms-LAPS-EncryptedDSRMPassword", attribute: dsrmGUID, edge: activedirectory.EdgeReadEncryptedLAPSPassword, forDC: true},
	} {
		if !g.attribute.IsNil() {
			g.rights = AttributeReadRights(tx, o, g.attribute, true)
			grants = append(grants, g)
		}
	}
	return grants
}

func addLAPSv2Edges(tx *engine.Tx) {
	grantsFor := newPerDump(func(o *engine.Node) []lapsv2Grant { return lapsv2Grants(tx, o) })

	tx.Iterate(func(o *engine.Node) bool {
		// Only computers that have Windows LAPS
		if o.Type() != engine.NodeTypeComputer || !o.HasAttr(activedirectory.MSLAPSPasswordExpirationTime) {
			return true
		}
		grants := grantsFor.For(o)
		if len(grants) == 0 {
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
		machines := MachinesForComputer(tx, machinesid)
		if len(machines) == 0 {
			ui.Error().Msgf("Could not locate machine for domain SID %v while processing LAPS v2", machinesid)
			return true
		}
		for _, machine := range machines {
			tx.Node(machine).Tag("laps")
		}

		uac, _ := o.AttrInt(activedirectory.UserAccountControl)
		isDC := uac&engine.UAC_SERVER_TRUST_ACCOUNT != 0
		for _, g := range grants {
			if g.forDC != isDC {
				continue
			}
			for _, sid := range PrincipalsGranted(sd, o, g.rights, g.attribute, tx) {
				trustee := aceTrustee(tx, sd, sid, o)
				for _, machine := range machines {
					tx.EdgeBecause(trustee, machine, g.edge, RightsCause(o, "read "+g.name))
				}
			}
		}
		return true
	})
}
