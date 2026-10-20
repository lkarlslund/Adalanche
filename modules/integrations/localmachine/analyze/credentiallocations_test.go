package analyze

import (
	"testing"

	"github.com/lkarlslund/adalanche/modules/engine"
	"github.com/lkarlslund/adalanche/modules/engine/enginetest"
	lm "github.com/lkarlslund/adalanche/modules/integrations/localmachine"
	"github.com/lkarlslund/adalanche/modules/windowssecurity"
)

func TestImportCredentialLocations(t *testing.T) {
	user := "S-1-5-21-1-2-3-1140"
	g := engine.NewIndexedGraph()
	machine := engine.NewNode(engine.Name, "WS01", engine.DistinguishedName, "WS01")
	enginetest.Add(g, machine)

	a := &lm.Assessment{Version: lm.AssessmentVersion, Categories: map[string]lm.AssessmentCapture{
		"credential-locations": {Records: jsonRecords(t,
			map[string]any{"Path": `C:\...\SYSTEM\Credentials`, "UserSID": "S-1-5-18"}, // SYSTEM, skipped
			map[string]any{"Path": `C:\Users\a\...\Credentials`, "UserSID": user},
			map[string]any{"Path": `C:\Users\a\...\Vault`, "UserSID": user}, // same user, deduped
		)},
	}}
	runTx(g, func(tx *engine.Tx) {
		if err := importCredentialLocations(tx, tx.Node(machine), a); err != nil {
			t.Fatal(err)
		}
	})

	var edges int
	g.IterateEdges(machine, engine.Out, func(to *engine.Node, e engine.EdgeBitmap) bool {
		if e.IsSet(EdgeStoredCredentials) {
			edges++
			if to.SID() != windowssecurity.MustParseStringSID(user) {
				t.Errorf("unexpected credential-holder SID %s", to.SID())
			}
		}
		return true
	})
	if edges != 1 {
		t.Errorf("expected one deduped StoredCredentials edge, got %d", edges)
	}
}
