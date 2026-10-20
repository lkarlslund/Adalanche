package analyze

import (
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"testing"
	"time"

	"github.com/lkarlslund/adalanche/modules/engine"
	"github.com/lkarlslund/adalanche/modules/engine/enginetest"
	"github.com/lkarlslund/adalanche/modules/integrations/activedirectory"
	lm "github.com/lkarlslund/adalanche/modules/integrations/localmachine"
	"github.com/lkarlslund/adalanche/modules/windowssecurity"
)

// allowACL builds a self-relative ACL with one ACCESS_ALLOWED ACE.
func allowACL(sid windowssecurity.SID, mask uint32) []byte {
	// windowssecurity.SID stores the identifier authority and subauthorities
	// without the leading revision and count, which a binary SID needs.
	stored := []byte(sid)
	raw := append([]byte{1, byte((len(stored) - 6) / 4)}, stored...)
	ace := make([]byte, 8+len(raw))
	ace[0] = 0 // ACCESS_ALLOWED
	binary.LittleEndian.PutUint16(ace[2:], uint16(len(ace)))
	binary.LittleEndian.PutUint32(ace[4:], mask)
	copy(ace[8:], raw)
	acl := make([]byte, 8+len(ace))
	acl[0] = 2 // revision
	binary.LittleEndian.PutUint16(acl[2:], uint16(len(acl)))
	binary.LittleEndian.PutUint16(acl[4:], 1)
	copy(acl[8:], ace)
	return acl
}

func serviceDLLAssessment(t *testing.T, records ...map[string]any) *lm.Assessment {
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
	return &lm.Assessment{Version: lm.AssessmentVersion, Captured: time.Now().UTC(), Categories: map[string]lm.AssessmentCapture{"service-payloads": c}}
}

func TestServiceDLLHijack(t *testing.T) {
	user := windowssecurity.MustParseStringSID("S-1-5-21-1-2-3-1107")
	dacl := base64.StdEncoding.EncodeToString(allowACL(user, engine.KEY_SET_VALUE))

	a := serviceDLLAssessment(t,
		// A writable Parameters key with a ServiceDll: hijackable.
		map[string]any{"Kind": "service-dll", "Name": "SharedSvc", "Payload": `%SystemRoot%\System32\shared.dll`, "RegistryDACL": json.RawMessage(`"` + dacl + `"`)},
		// Same permissions but no ServiceDll: not hijackable.
		map[string]any{"Kind": "service-dll", "Name": "PlainSvc", "Payload": "", "RegistryDACL": json.RawMessage(`"` + dacl + `"`)},
	)
	perms := serviceDLLSecurity(a)
	if _, ok := perms["SharedSvc"]; !ok {
		t.Fatal("SharedSvc should be present")
	}
	if _, ok := perms["PlainSvc"]; ok {
		t.Fatal("a service without a ServiceDll must not be hijackable")
	}

	g := engine.NewIndexedGraph()
	machine := engine.NewNode(engine.Name, "WS01", engine.DistinguishedName, "WS01")
	enginetest.Add(g, machine)
	var service *engine.Node
	runTx(g, func(tx *engine.Tx) {
		scope := NewMachineScope(tx, tx.Node(machine), lm.Info{Machine: lm.Machine{Name: "WS01", LocalSID: "S-1-5-21-1-2-3"}})
		svc := tx.AddNew(activedirectory.Name, "SharedSvc", engine.DataSource, "WS01", engine.Type, "Service")
		svc.ChildOf(tx.Node(machine))
		service = svc.Node()
		importServiceDLLHijack(tx, scope, svc, "SharedSvc", perms["SharedSvc"])
	})

	found := false
	g.IterateEdges(service, engine.In, func(from *engine.Node, edges engine.EdgeBitmap) bool {
		if edges.IsSet(EdgeModifyServiceDLL) && from.SID() == user {
			found = true
			return false
		}
		return true
	})
	if !found {
		t.Error("expected a ModifyServiceDLL edge from the writer to the service")
	}
}
