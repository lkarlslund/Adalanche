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
	for _, tt := range []struct {
		name                         string
		grant                        uuid.UUID
		mask                         engine.Mask
		plainSchema, encryptedSchema bool
		wantPlain, wantEncrypted     bool
	}{
		{"plaintext attribute", plainGUID, engine.RIGHT_DS_CONTROL_ACCESS, true, true, true, false},
		{"encrypted attribute", encryptedGUID, engine.RIGHT_DS_CONTROL_ACCESS, true, true, false, true},
		{"encrypted property set", msLAPSEncryptedPasswordAttributesGUID, engine.RIGHT_DS_CONTROL_ACCESS, true, true, false, true},
		{"read property only", encryptedGUID, engine.RIGHT_DS_READ_PROPERTY, true, true, false, false},
		{"plaintext schema absent", encryptedGUID, engine.RIGHT_DS_CONTROL_ACCESS, false, true, false, true},
		{"encrypted schema absent", plainGUID, engine.RIGHT_DS_CONTROL_ACCESS, true, false, true, false},
		{"schema absent", uuid.Nil, engine.RIGHT_DS_CONTROL_ACCESS, false, false, false, false},
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
