package analyze

import (
	"encoding/json"

	"github.com/lkarlslund/adalanche/modules/engine"
	"github.com/lkarlslund/adalanche/modules/integrations/activedirectory"
	lm "github.com/lkarlslund/adalanche/modules/integrations/localmachine"
	"github.com/lkarlslund/adalanche/modules/windowssecurity"
)

// EdgeStoredCredentials: the machine holds a credential store (DPAPI,
// Credential Manager, vaults) belonging to the account, so controlling the
// machine is a route to that account's stored secrets.
var EdgeStoredCredentials = engine.NewEdge("StoredCredentials").RegisterProbabilityCalculator(activedirectory.OnlyIfTargetAccountEnabled(activedirectory.FixedProbability(50))).Tag("Pivot").Describe("The machine holds a credential store belonging to the account")

func importCredentialLocations(tx *engine.Tx, machine engine.TxNode, a *lm.Assessment) error {
	seen := map[windowssecurity.SID]bool{}
	for _, raw := range a.Categories["credential-locations"].Records {
		var r struct {
			Path    string
			UserSID string
		}
		if json.Unmarshal(raw, &r) != nil || r.UserSID == "" {
			continue
		}
		sid, err := windowssecurity.ParseStringSID(r.UserSID)
		if err != nil || sid.Component(2) != 21 || seen[sid] {
			continue
		}
		seen[sid] = true
		tx.EdgeBecause(machine, tx.FindOrAddAdjacentSID(sid, machine), EdgeStoredCredentials, Collected("stored credential location"))
	}
	return nil
}

func init() {
	RegisterAssessmentImporter(importCredentialLocations)
}
