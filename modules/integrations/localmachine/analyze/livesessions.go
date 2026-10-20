package analyze

import (
	"encoding/json"

	"github.com/lkarlslund/adalanche/modules/engine"
	"github.com/lkarlslund/adalanche/modules/integrations/activedirectory"
	lm "github.com/lkarlslund/adalanche/modules/integrations/localmachine"
	"github.com/lkarlslund/adalanche/modules/windowssecurity"
)

// EdgeSessionObserved: the account had a logon session or a running process on
// the machine when it was captured. The collector states this is not proof
// that credentials are recoverable, but it is a fresher, snapshot view of who
// uses the machine than the logon event history, so it is a credential-theft
// target worth following.
var EdgeSessionObserved = engine.NewEdge("SessionObserved").RegisterProbabilityCalculator(activedirectory.OnlyIfTargetAccountEnabled(activedirectory.FixedProbability(70))).Tag("Pivot").Describe("Had a logon session or running process on the machine at capture time")

// importLiveSessions turns the current-sessions and process-identities
// snapshots into one SessionObserved edge per account. Only real domain
// accounts (users and computers) are followed; the machine's own SYSTEM,
// service and virtual accounts are always present and are not pivots.
func importLiveSessions(tx *engine.Tx, machine engine.TxNode, a *lm.Assessment) error {
	seen := map[windowssecurity.SID]bool{}
	edge := func(sidString, detail string) {
		sid, err := windowssecurity.ParseStringSID(sidString)
		if err != nil || sid.Component(2) != 21 || seen[sid] {
			return
		}
		seen[sid] = true
		tx.EdgeBecause(machine, tx.FindOrAddAdjacentSID(sid, machine), EdgeSessionObserved, Collected(detail))
	}
	for _, raw := range a.Categories["current-sessions"].Records {
		var r struct {
			Kind string
			SID  string
		}
		if json.Unmarshal(raw, &r) == nil && r.Kind != "coverage" && r.SID != "" {
			edge(r.SID, "logon session at capture")
		}
	}
	for _, raw := range a.Categories["process-identities"].Records {
		var r struct {
			Kind string
			SID  string
		}
		if json.Unmarshal(raw, &r) == nil && r.Kind != "coverage" && r.SID != "" {
			edge(r.SID, "running process at capture")
		}
	}
	return nil
}

func init() {
	RegisterAssessmentImporter(importLiveSessions)
}
