package analyze

import (
	"strings"
	"testing"

	"github.com/lkarlslund/adalanche/modules/engine"
	"github.com/lkarlslund/adalanche/modules/engine/enginetest"
	lm "github.com/lkarlslund/adalanche/modules/integrations/localmachine"
)

// importLocations imports credential-locations records for one machine and
// returns, per target SID, the edges from the machine and their sources.
func importLocations(t *testing.T, records ...map[string]any) (map[string]engine.EdgeBitmap, map[string][]string) {
	t.Helper()
	g := engine.NewIndexedGraph()
	machine := engine.NewNode(engine.Name, "WS01", engine.DistinguishedName, "WS01")
	enginetest.Add(g, machine)
	a := &lm.Assessment{Version: lm.AssessmentVersion, Categories: map[string]lm.AssessmentCapture{
		"credential-locations": {Records: jsonRecords(t, records...)},
	}}
	runTx(g, func(tx *engine.Tx) {
		if err := importCredentialLocations(tx, tx.Node(machine), a); err != nil {
			t.Fatal(err)
		}
	})
	edges := map[string]engine.EdgeBitmap{}
	details := map[string][]string{}
	g.IterateEdges(machine, engine.Out, func(to *engine.Node, e engine.EdgeBitmap) bool {
		edges[to.SID().String()] = e
		for _, s := range g.EdgeSources(machine, to) {
			details[to.SID().String()] = append(details[to.SID().String()], s.Edge.String()+": "+s.Source.Detail)
		}
		return true
	})
	return edges, details
}

// A profile only shows the account logged on; it is not a route to it.
func TestProfilesAreNotRoutes(t *testing.T) {
	const user = "S-1-5-21-1-2-3-1140"
	// As collectors before file counting reported them: one record per
	// location, nothing about what is in it.
	edges, _ := importLocations(t,
		map[string]any{"Path": `C:\Windows\system32\config\systemprofile\AppData\Roaming\Microsoft\Credentials`, "UserSID": "S-1-5-18"},
		map[string]any{"Path": `C:\Users\a\AppData\Roaming\Microsoft\Credentials`, "UserSID": user},
		map[string]any{"Path": `C:\Users\a\AppData\Local\Microsoft\Vault`, "UserSID": user},
	)
	if len(edges) != 1 {
		t.Fatalf("edges to %v accounts, want the one domain account", len(edges))
	}
	e := edges[user]
	if !e.IsSet(EdgeHasProfile) || e.IsSet(EdgeStoredCredentials) {
		t.Errorf("edges %v, want HasProfile alone", e.StringSlice())
	}
	if EdgeHasProfile.DefaultF() || EdgeHasProfile.DefaultM() || EdgeHasProfile.DefaultL() || EdgeHasProfile.HasTag("Pivot") {
		t.Error("HasProfile is followed by default or is a pivot")
	}
}

// Saved credentials, counted by the collector, are a (weak) route; empty
// credential folders and DPAPI master keys, which every profile has, are not.
func TestCountedCredentialLocations(t *testing.T) {
	const saver, nosaver = "S-1-5-21-1-2-3-1140", "S-1-5-21-1-2-3-1141"
	edges, details := importLocations(t,
		map[string]any{"Kind": "profile", "UserSID": saver, "LastLoaded": "2024-01-02T03:04:05Z"},
		map[string]any{"Kind": "credentials", "UserSID": saver, "Exists": true, "Files": 2},
		map[string]any{"Kind": "vault", "UserSID": saver, "Exists": true, "Files": 1},
		map[string]any{"Kind": "dpapi-keys", "UserSID": saver, "Exists": true, "Files": 3},
		map[string]any{"Kind": "profile", "UserSID": nosaver},
		map[string]any{"Kind": "credentials", "UserSID": nosaver, "Exists": true, "Files": 0},
		map[string]any{"Kind": "vault", "UserSID": nosaver, "Exists": false, "Files": 0},
		map[string]any{"Kind": "dpapi-keys", "UserSID": nosaver, "Exists": true, "Files": 2},
	)
	if e := edges[saver]; !e.IsSet(EdgeHasProfile) || !e.IsSet(EdgeStoredCredentials) {
		t.Errorf("account with saved credentials: %v", e.StringSlice())
	}
	if e := edges[nosaver]; !e.IsSet(EdgeHasProfile) || e.IsSet(EdgeStoredCredentials) {
		t.Errorf("account without saved credentials: %v", e.StringSlice())
	}
	joined := strings.Join(details[saver], "; ")
	if !strings.Contains(joined, "last used 2024-01-02") || !strings.Contains(joined, "3 saved credentials") {
		t.Errorf("sources: %v", joined)
	}
}

// Last use comes from the profile's own load and unload times, the later of
// the two; the hive's time is a fallback, marked as such, as other tools can
// write the hive too. First use is when the profile folder was made.
func TestProfileTimes(t *testing.T) {
	const user = "S-1-5-21-1-2-3-1140"
	for _, c := range []struct {
		name   string
		record map[string]any
		want   string
	}{
		{"load and unload", map[string]any{"LastLoaded": "2024-03-01T08:00:00Z", "LastUnloaded": "2024-03-02T17:00:00Z", "NTUserModified": "2025-01-01T00:00:00Z", "ProfileCreated": "2021-06-01T09:00:00Z"},
			"user profile, first used 2021-06-01, last used 2024-03-02"},
		{"hive only", map[string]any{"NTUserModified": "2019-05-05T10:00:00Z"},
			"user profile, last used 2019-05-05 (NTUSER.DAT written)"},
		{"nothing known", map[string]any{},
			"user profile"},
	} {
		record := map[string]any{"Kind": "profile", "UserSID": user}
		for k, v := range c.record {
			record[k] = v
		}
		_, details := importLocations(t, record)
		if got := details[user]; len(got) != 1 || got[0] != "HasProfile: "+c.want {
			t.Errorf("%v: %v, want %q", c.name, got, c.want)
		}
	}
}
