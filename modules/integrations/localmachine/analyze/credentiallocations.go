package analyze

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/lkarlslund/adalanche/modules/engine"
	"github.com/lkarlslund/adalanche/modules/integrations/activedirectory"
	lm "github.com/lkarlslund/adalanche/modules/integrations/localmachine"
	"github.com/lkarlslund/adalanche/modules/windowssecurity"
)

var (
	// EdgeHasProfile: the account has a user profile on the machine, so it
	// logged on there interactively at some point. That is worth knowing
	// (an admin account with profiles on workstations has been exposed
	// there), but a profile holds nothing that hands the account to whoever
	// controls the machine, so routes do not follow it.
	EdgeHasProfile = engine.NewEdge("HasProfile").Tag("Informative").RegisterFixedProbability(0).SetDefault(false, false, false).
			Describe("The account has a user profile on the machine: it logged on there interactively at some point")

	// EdgeStoredCredentials: the account saved secrets on the machine, in
	// Credential Manager or a vault. They are encrypted with the account's
	// DPAPI keys, so controlling the machine alone does not open them: that
	// also takes the account's password, the domain's DPAPI backup key, or
	// the account logging on while the machine is controlled.
	EdgeStoredCredentials = engine.NewEdge("StoredCredentials").RegisterProbabilityCalculator(activedirectory.OnlyIfTargetAccountEnabled(activedirectory.FixedProbability(10))).Tag("Pivot").
				Describe("The account saved credentials on the machine (Credential Manager or vault); opening them takes its DPAPI keys")
)

// importCredentialLocations turns the credential-locations capture into a
// HasProfile edge for every domain account with a profile on the machine,
// and a StoredCredentials edge where it saved credentials there. Captures
// from collectors that did not count the files only show the profiles.
func importCredentialLocations(tx *engine.Tx, machine engine.TxNode, a *lm.Assessment) error {
	type account struct {
		profile profileTimes
		saved   int
	}
	accounts := map[windowssecurity.SID]*account{}
	var order []windowssecurity.SID
	for _, raw := range a.Categories["credential-locations"].Records {
		var r struct {
			Kind    string
			UserSID string
			Files   int
			profileTimes
		}
		if json.Unmarshal(raw, &r) != nil || r.UserSID == "" {
			continue
		}
		sid, err := windowssecurity.ParseStringSID(r.UserSID)
		if err != nil || sid.Component(2) != 21 {
			continue
		}
		acc := accounts[sid]
		if acc == nil {
			acc = &account{}
			accounts[sid] = acc
			order = append(order, sid)
		}
		switch r.Kind {
		case "profile":
			acc.profile = r.profileTimes
		case "credentials", "vault":
			acc.saved += r.Files
		}
	}
	for _, sid := range order {
		acc := accounts[sid]
		target := tx.FindOrAddAdjacentSID(sid, machine)
		tx.EdgeBecause(machine, target, EdgeHasProfile, Collected(acc.profile.detail()))
		if acc.saved > 0 {
			tx.EdgeBecause(machine, target, EdgeStoredCredentials, Collected(fmt.Sprintf("%d saved credentials", acc.saved)))
		}
	}
	return nil
}

// profileTimes are what the collector found about when a profile was used.
type profileTimes struct {
	LastLoaded     time.Time // the profile's own record of being loaded and unloaded
	LastUnloaded   time.Time
	NTUserModified time.Time // the user's registry hive, written while loaded
	ProfileCreated time.Time // the profile folder, made at the first logon
}

// lastUsed is when the profile was last in use, from the profile's own times
// where Windows keeps them; the hive's time is only a fallback, as other
// tools can write it too. fromHive says the fallback was used.
func (p profileTimes) lastUsed() (last time.Time, fromHive bool) {
	last = p.LastLoaded
	if p.LastUnloaded.After(last) {
		last = p.LastUnloaded
	}
	if last.IsZero() && !p.NTUserModified.IsZero() {
		return p.NTUserModified, true
	}
	return last, false
}

func (p profileTimes) detail() string {
	detail := "user profile"
	if !p.ProfileCreated.IsZero() {
		detail += ", first used " + day(p.ProfileCreated)
	}
	if last, fromHive := p.lastUsed(); !last.IsZero() {
		detail += ", last used " + day(last)
		if fromHive {
			detail += " (NTUSER.DAT written)"
		}
	}
	return detail
}

func day(t time.Time) string { return t.UTC().Format("2006-01-02") }

func init() {
	RegisterAssessmentImporter(importCredentialLocations)
}
