package attrs_test

import (
	"testing"

	"github.com/lkarlslund/adalanche/modules/engine"
	"github.com/lkarlslund/adalanche/modules/engine/enginetest"
	"github.com/lkarlslund/adalanche/modules/integrations/attrs"
	"github.com/lkarlslund/adalanche/modules/windowssecurity"
)

func sid(t *testing.T, s string) windowssecurity.SID {
	t.Helper()
	v, err := windowssecurity.ParseStringSID(s)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

// A machine is keyed by its domain computer SID, over its own (clone-prone)
// local objectSid; a non-domain machine falls back to objectSid.
func TestMachineKeyedByDomainJoinedSID(t *testing.T) {
	domainSID := sid(t, "S-1-5-21-10-20-30-1105")
	localSID := sid(t, "S-1-5-21-99-98-97-1001")

	machine := engine.NewNode(engine.Type, engine.NV("Machine"),
		attrs.DomainJoinedSID, engine.NV(domainSID), engine.ObjectSid, engine.NV(localSID))
	if got, want := engine.NodeKey(machine), "domainJoinedSID="+domainSID.String(); got != want {
		t.Errorf("machine key %q, want %q", got, want)
	}

	standalone := engine.NewNode(engine.Type, engine.NV("Machine"), engine.ObjectSid, engine.NV(localSID))
	if got, want := engine.NodeKey(standalone), "objectSid="+localSID.String(); got != want {
		t.Errorf("non-domain machine key %q, want %q", got, want)
	}

	g := enginetest.NewGraph(machine)
	nodes, err := g.FindByKey("domainJoinedSID=" + domainSID.String())
	if err != nil || nodes.Len() != 1 || nodes.First() != machine {
		t.Fatalf("FindByKey: %v nodes, err %v", nodes.Len(), err)
	}
}
