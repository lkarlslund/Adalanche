package analyze

import (
	"testing"

	"github.com/lkarlslund/adalanche/modules/engine"
	"github.com/lkarlslund/adalanche/modules/engine/enginetest"
	lm "github.com/lkarlslund/adalanche/modules/integrations/localmachine"
	"github.com/lkarlslund/adalanche/modules/windowssecurity"
)

func TestImportTaskFolders(t *testing.T) {
	odd := "S-1-5-21-1-2-3-1150" // a specific principal with full control: a finding
	g := engine.NewIndexedGraph()
	machine := engine.NewNode(engine.Name, "WS01", engine.DistinguishedName, "WS01")
	enginetest.Add(g, machine)

	// The default-looking ACE for Authenticated Users (write, not full) plus a
	// full-control ACE for a specific account.
	sddl := "O:BAG:BAD:P(A;CI;FW;;;AU)(A;CI;FA;;;BA)(A;CI;FA;;;" + odd + ")"
	a := &lm.Assessment{Version: lm.AssessmentVersion, Categories: map[string]lm.AssessmentCapture{
		"task-payloads": {Records: jsonRecords(t,
			map[string]any{"Kind": "task-folder", "Path": `\`, "SDDL": sddl},
			map[string]any{"Kind": "task-principal", "Path": `\Some Task`}, // ignored
		)},
	}}
	runTx(g, func(tx *engine.Tx) {
		if err := importTaskFolders(tx, tx.Node(machine), a); err != nil {
			t.Fatal(err)
		}
	})

	if !edgeFromSIDTo(t, g, windowssecurity.MustParseStringSID(odd), machine, EdgeTaskFolderControl) {
		t.Error("a specific principal with full control should get a TaskFolderControl edge")
	}
	// Authenticated Users (write only, and a broad group) must not.
	if edgeFromSIDTo(t, g, windowssecurity.MustParseStringSID("S-1-5-11"), machine, EdgeTaskFolderControl) {
		t.Error("Authenticated Users must not get a TaskFolderControl edge")
	}
	// Administrators has full control but is a broad trustee: skipped.
	if edgeFromSIDTo(t, g, windowssecurity.MustParseStringSID("S-1-5-32-544"), machine, EdgeTaskFolderControl) {
		t.Error("Administrators must not get a TaskFolderControl edge")
	}
}
