package analyze

import (
	"encoding/json"
	"testing"

	"github.com/lkarlslund/adalanche/modules/engine"
	"github.com/lkarlslund/adalanche/modules/engine/enginetest"
	lm "github.com/lkarlslund/adalanche/modules/integrations/localmachine"
	"github.com/lkarlslund/adalanche/modules/windowssecurity"
)

func jsonRecords(t *testing.T, records ...map[string]any) []json.RawMessage {
	t.Helper()
	var raws []json.RawMessage
	for _, r := range records {
		raw, err := json.Marshal(r)
		if err != nil {
			t.Fatal(err)
		}
		raws = append(raws, raw)
	}
	return raws
}

func TestImportLiveSessions(t *testing.T) {
	domainUser := "S-1-5-21-1-2-3-1130"
	g := engine.NewIndexedGraph()
	machine := engine.NewNode(engine.Name, "WS01", engine.DistinguishedName, "WS01")
	enginetest.Add(g, machine)

	a := &lm.Assessment{Version: lm.AssessmentVersion, Categories: map[string]lm.AssessmentCapture{
		"current-sessions": {Records: jsonRecords(t,
			map[string]any{"Kind": "coverage"},                    // skipped
			map[string]any{"SID": "S-1-5-18"},                     // SYSTEM, skipped
			map[string]any{"SID": "S-1-5-90-0-1", "LogonType": 2}, // virtual account, skipped
			map[string]any{"SID": domainUser, "LogonType": 2},     // followed
		)},
		"process-identities": {Records: jsonRecords(t,
			map[string]any{"SID": domainUser, "Name": "powershell.exe"}, // same account, deduped
			map[string]any{"SID": "S-1-5-19"},                           // LOCAL SERVICE, skipped
		)},
	}}
	runTx(g, func(tx *engine.Tx) {
		if err := importLiveSessions(tx, tx.Node(machine), a); err != nil {
			t.Fatal(err)
		}
	})

	var observed int
	g.IterateEdges(machine, engine.Out, func(to *engine.Node, edges engine.EdgeBitmap) bool {
		if edges.IsSet(EdgeSessionObserved) {
			observed++
			if to.SID() != windowssecurity.MustParseStringSID(domainUser) {
				t.Errorf("edge to unexpected SID %s", to.SID())
			}
		}
		return true
	})
	if observed != 1 {
		t.Errorf("expected one SessionObserved edge (deduped), got %d", observed)
	}
}
