package analyze

import (
	"testing"

	"github.com/gofrs/uuid/v5"
	"github.com/lkarlslund/adalanche/modules/engine"
	"github.com/lkarlslund/adalanche/modules/integrations/activedirectory"
)

func TestLAPSv2EncryptedAccessDoesNotImplyDecryption(t *testing.T) {
	plainGUID := uuid.Must(uuid.FromString("c576124b-743e-4c14-95c8-8f3198376c09"))
	encryptedGUID := uuid.Must(uuid.FromString("a593f5bb-97e8-4410-8826-2ff2199f7252"))
	readerSID := mustSID(t, "S-1-5-21-1-2-3-1001")
	computerSID := mustSID(t, "S-1-5-21-1-2-3-1002")
	// The LAPS password attributes are confidential: reading needs both rights.
	readControl := engine.Mask(engine.RIGHT_DS_READ_PROPERTY | engine.RIGHT_DS_CONTROL_ACCESS)
	for _, tt := range []struct {
		name                         string
		grant                        uuid.UUID
		mask                         engine.Mask
		plainSchema, encryptedSchema bool
		wantPlain, wantEncrypted     bool
	}{
		{"plaintext attribute", plainGUID, readControl, true, true, true, false},
		{"encrypted attribute", encryptedGUID, readControl, true, true, false, true},
		{"encrypted property set", msLAPSEncryptedPasswordAttributesGUID, readControl, true, true, false, true},
		{"read property only", encryptedGUID, engine.RIGHT_DS_READ_PROPERTY, true, true, false, false},
		{"control access only", plainGUID, engine.RIGHT_DS_CONTROL_ACCESS, true, true, false, false},
		{"plaintext schema absent", encryptedGUID, readControl, false, true, false, true},
		{"encrypted schema absent", plainGUID, readControl, true, false, true, false},
		{"schema absent", uuid.Nil, readControl, false, false, false, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			reader := engine.NewNode(engine.ObjectSid, engine.NV(readerSID))
			machine := engine.NewNode(engine.Type, ObjectTypeMachine.ValueString(), DomainJoinedSID, engine.NV(computerSID))
			computer := engine.NewNode(engine.Type, engine.NodeTypeComputer.ValueString(), engine.ObjectSid, engine.NV(computerSID), activedirectory.MSLAPSPasswordExpirationTime, int64(1), engine.NTSecurityDescriptor, engine.NV(securityDescriptorWithACEs(allowACE(readerSID, tt.mask, tt.grant))))
			graph := newADTestGraph(reader, machine, computer)
			if tt.plainSchema {
				graph.Add(engine.NewNode(engine.Name, "ms-LAPS-Password", engine.ObjectClass, "attributeSchema", engine.SchemaIDGUID, engine.NV(plainGUID)))
			}
			if tt.encryptedSchema {
				graph.Add(engine.NewNode(engine.Name, "ms-LAPS-EncryptedPassword", engine.ObjectClass, "attributeSchema", engine.SchemaIDGUID, engine.NV(encryptedGUID), engine.AttributeSecurityGUID, engine.NV(msLAPSEncryptedPasswordAttributesGUID)))
			}
			addLAPSv2Edges(graph)
			for edge, want := range map[engine.Edge]bool{activedirectory.EdgeReadLAPSPassword: tt.wantPlain, activedirectory.EdgeReadEncryptedLAPSPassword: tt.wantEncrypted} {
				if want {
					requireEdgeSet(t, graph, reader, machine, edge)
				} else {
					requireNoEdgeSet(t, graph, reader, machine, edge)
				}
			}
		})
	}
	if p := activedirectory.EdgeReadEncryptedLAPSPassword.Probability(nil, nil, nil); p != 0 {
		t.Fatalf("encrypted password access probability = %d, want 0", p)
	}
}

func TestLAPSv2DSRMPasswordOnDomainControllers(t *testing.T) {
	plainGUID := uuid.Must(uuid.FromString("c576124b-743e-4c14-95c8-8f3198376c09"))
	dsrmGUID := uuid.Must(uuid.FromString("cdd04f4c-6e7d-4d5d-8f2e-5f9d8b2e4c11"))
	readerSID := mustSID(t, "S-1-5-21-1-2-3-1001")
	readControl := engine.Mask(engine.RIGHT_DS_READ_PROPERTY | engine.RIGHT_DS_CONTROL_ACCESS)
	for _, tt := range []struct {
		name                string
		uac                 int64
		grant               uuid.UUID
		wantPlain, wantDSRM bool
	}{
		{"domain controller DSRM password", engine.UAC_SERVER_TRUST_ACCOUNT, dsrmGUID, false, true},
		{"domain controller plaintext grant", engine.UAC_SERVER_TRUST_ACCOUNT, plainGUID, false, false},
		{"member computer DSRM grant", engine.UAC_WORKSTATION_TRUST_ACCOUNT, dsrmGUID, false, false},
		{"member computer plaintext", engine.UAC_WORKSTATION_TRUST_ACCOUNT, plainGUID, true, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			computerSID := mustSID(t, "S-1-5-21-1-2-3-1002")
			reader := engine.NewNode(engine.ObjectSid, engine.NV(readerSID))
			machine := engine.NewNode(engine.Type, ObjectTypeMachine.ValueString(), DomainJoinedSID, engine.NV(computerSID))
			computer := engine.NewNode(engine.Type, engine.NodeTypeComputer.ValueString(), engine.ObjectSid, engine.NV(computerSID),
				activedirectory.UserAccountControl, tt.uac, activedirectory.MSLAPSPasswordExpirationTime, int64(1),
				engine.NTSecurityDescriptor, engine.NV(securityDescriptorWithACEs(allowACE(readerSID, readControl, tt.grant))))
			graph := newADTestGraph(reader, machine, computer,
				engine.NewNode(engine.Name, "ms-LAPS-Password", engine.ObjectClass, "attributeSchema", engine.SchemaIDGUID, engine.NV(plainGUID)),
				engine.NewNode(engine.Name, "ms-LAPS-EncryptedDSRMPassword", engine.ObjectClass, "attributeSchema", engine.SchemaIDGUID, engine.NV(dsrmGUID)))
			addLAPSv2Edges(graph)
			for edge, want := range map[engine.Edge]bool{activedirectory.EdgeReadLAPSPassword: tt.wantPlain, activedirectory.EdgeReadEncryptedLAPSPassword: tt.wantDSRM} {
				if want {
					requireEdgeSet(t, graph, reader, machine, edge)
				} else {
					requireNoEdgeSet(t, graph, reader, machine, edge)
				}
			}
		})
	}
}

func TestAttributeReadRightsFollowSchema(t *testing.T) {
	guid := uuid.Must(uuid.FromString("c576124b-743e-4c14-95c8-8f3198376c09"))
	readControl := engine.Mask(engine.RIGHT_DS_READ_PROPERTY | engine.RIGHT_DS_CONTROL_ACCESS)
	for _, tt := range []struct {
		name     string
		schema   []any
		fallback bool
		want     engine.Mask
	}{
		{"confidential in schema", []any{engine.SchemaIDGUID, engine.NV(guid), activedirectory.SearchFlags, int64(904)}, false, readControl},
		{"not confidential in schema", []any{engine.SchemaIDGUID, engine.NV(guid), activedirectory.SearchFlags, int64(1)}, true, engine.RIGHT_DS_READ_PROPERTY},
		{"no search flags uses fallback", []any{engine.SchemaIDGUID, engine.NV(guid)}, true, readControl},
		{"no schema uses fallback", nil, false, engine.RIGHT_DS_READ_PROPERTY},
	} {
		t.Run(tt.name, func(t *testing.T) {
			graph := newADTestGraph()
			if tt.schema != nil {
				graph.Add(engine.NewNode(tt.schema...))
			}
			if got := AttributeReadRights(graph, guid, tt.fallback); got != tt.want {
				t.Fatalf("got %#x, want %#x", got, tt.want)
			}
		})
	}
}
