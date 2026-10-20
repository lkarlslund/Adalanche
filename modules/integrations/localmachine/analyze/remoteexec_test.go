package analyze

import (
	"encoding/binary"
	"encoding/json"
	"testing"
	"time"

	"github.com/lkarlslund/adalanche/modules/engine"
	"github.com/lkarlslund/adalanche/modules/engine/enginetest"
	ad "github.com/lkarlslund/adalanche/modules/integrations/activedirectory/analyze"
	lm "github.com/lkarlslund/adalanche/modules/integrations/localmachine"
	"github.com/lkarlslund/adalanche/modules/windowssecurity"
)

// selfRelativeSD wraps a DACL in a minimal self-relative security descriptor.
func selfRelativeSD(dacl []byte) []byte {
	sd := make([]byte, 20)
	sd[0] = 1                                          // revision
	binary.LittleEndian.PutUint16(sd[2:], 0x8004)      // self-relative + DACL present
	binary.LittleEndian.PutUint32(sd[16:], uint32(20)) // DACL offset
	return append(sd, dacl...)
}

func remoteExecAssessment(t *testing.T, category string, records ...map[string]any) *lm.Assessment {
	t.Helper()
	var raws []json.RawMessage
	for _, r := range records {
		raw, err := json.Marshal(r)
		if err != nil {
			t.Fatal(err)
		}
		raws = append(raws, raw)
	}
	c := lm.AssessmentCapture{Records: raws}
	c.Result.Status = "collected"
	return &lm.Assessment{Version: lm.AssessmentVersion, Captured: time.Now().UTC(), Categories: map[string]lm.AssessmentCapture{category: c}}
}

func edgeFromSIDTo(t *testing.T, g *engine.IndexedGraph, sid windowssecurity.SID, to *engine.Node, edge engine.Edge) bool {
	t.Helper()
	found := false
	g.IterateEdges(to, engine.In, func(from *engine.Node, edges engine.EdgeBitmap) bool {
		if from.SID() == sid && edges.IsSet(edge) {
			found = true
			return false
		}
		return true
	})
	return found
}

func TestImportDCOMRights(t *testing.T) {
	user := windowssecurity.MustParseStringSID("S-1-5-21-1-2-3-1120")
	g := engine.NewIndexedGraph()
	machine := engine.NewNode(engine.Name, "WS01", engine.DistinguishedName, "WS01")
	enginetest.Add(g, machine)

	a := remoteExecAssessment(t, "dcom-security",
		map[string]any{"Value": "DefaultLaunchPermission", "SecurityDescriptor": selfRelativeSD(allowACL(user, 0x10))}, // remote activate
		map[string]any{"Value": "DefaultAccessPermission", "SecurityDescriptor": selfRelativeSD(allowACL(user, 0x10))}, // access only, ignored
	)
	runTx(g, func(tx *engine.Tx) { importDCOMRights(tx, tx.Node(machine), a) })

	if !edgeFromSIDTo(t, g, user, machine, EdgeLocalDCOMRights) {
		t.Error("remote DCOM launch permission should give a DCOMRights edge")
	}

	// Access permission alone must not: build a graph with only that record.
	g2 := engine.NewIndexedGraph()
	m2 := engine.NewNode(engine.Name, "WS02", engine.DistinguishedName, "WS02")
	enginetest.Add(g2, m2)
	a2 := remoteExecAssessment(t, "dcom-security", map[string]any{"Value": "DefaultAccessPermission", "SecurityDescriptor": selfRelativeSD(allowACL(user, 0x10))})
	runTx(g2, func(tx *engine.Tx) { importDCOMRights(tx, tx.Node(m2), a2) })
	if edgeFromSIDTo(t, g2, user, m2, EdgeLocalDCOMRights) {
		t.Error("access permission alone must not give a DCOMRights edge")
	}
}

func TestImportRemoteEndpoints(t *testing.T) {
	user := "S-1-5-21-1-2-3-1121"
	runAs := windowssecurity.MustParseStringSID("S-1-5-21-1-2-3-1122")
	g := engine.NewIndexedGraph()
	machine := engine.NewNode(engine.Name, "WS01", engine.DistinguishedName, "WS01")
	enginetest.Add(g, machine)

	a := remoteExecAssessment(t, "remote-endpoints",
		map[string]any{"Name": "microsoft.powershell", "RunAsUser": runAs.String(),
			"SecurityDescriptorSddl": "O:BAG:BAD:P(A;;GA;;;" + user + ")(A;;GA;;;BA)"},
	)
	runTx(g, func(tx *engine.Tx) { importRemoteEndpoints(tx, tx.Node(machine), a) })

	if !edgeFromSIDTo(t, g, windowssecurity.MustParseStringSID(user), machine, EdgeRemotePowerShell) {
		t.Error("an account with GA on the endpoint should get a RemotePowerShell edge")
	}
	// Running the endpoint as a fixed account also acts as that account.
	runAsNode, found := g.Find(engine.ObjectSid, engine.NVSID(runAs))
	if !found {
		t.Fatal("RunAs account node not created")
	}
	if !edgeFromSIDTo(t, g, windowssecurity.MustParseStringSID(user), runAsNode, ad.EdgeAuthenticatesAs) {
		t.Error("RunAs account should get an AuthenticatesAs edge")
	}
	// Built-in Administrators is already privileged and should be skipped.
	if edgeFromSIDTo(t, g, windowssecurity.MustParseStringSID("S-1-5-32-544"), machine, EdgeRemotePowerShell) {
		t.Error("Administrators should not get a RemotePowerShell edge")
	}
}
