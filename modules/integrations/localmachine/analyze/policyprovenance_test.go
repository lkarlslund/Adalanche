package analyze

import (
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/lkarlslund/adalanche/modules/engine"
	"github.com/lkarlslund/adalanche/modules/integrations/activedirectory"
	lm "github.com/lkarlslund/adalanche/modules/integrations/localmachine"
)

func provenanceInfo(t *testing.T, records ...map[string]any) lm.Info {
	t.Helper()
	var raws []json.RawMessage
	for _, r := range records {
		raw, err := json.Marshal(r)
		if err != nil {
			t.Fatal(err)
		}
		raws = append(raws, raw)
	}
	data, err := json.Marshal(lm.Assessment{
		Version:    lm.AssessmentVersion,
		Captured:   time.Now().UTC(),
		Categories: map[string]lm.AssessmentCapture{"policy-provenance": {Records: raws}},
	})
	if err != nil {
		t.Fatal(err)
	}
	return lm.Info{AssessmentData: string(data)}
}

func rsopGPO(guid, path string, enabled, denied, allowed bool) map[string]any {
	return map[string]any{"Class": "RSOP_GPO", "Scope": "machine", "guidName": guid, "name": "Policy " + guid,
		"fileSystemPath": path, "enabled": enabled, "accessDenied": denied, "filterAllowed": allowed}
}

const sysvol = `\\example.test\SysVol\example.test\Policies\`

func TestImportPolicyProvenance(t *testing.T) {
	g := engine.NewIndexedGraph()
	machine := engine.NewNode(engine.Name, "WS01")
	g.Add(machine)
	importPolicyProvenance(g, machine, provenanceInfo(t,
		map[string]any{"Class": "MachineSite", "DynamicSiteName": "Discovered", "SiteName": "Override"},
		rsopGPO("{A}", sysvol+`{A}\Machine`, true, false, true),
		rsopGPO("{B}", sysvol+`{B}`, true, true, true),
		rsopGPO("{C}", sysvol+`{C}`, true, false, false),
		rsopGPO("{D}", sysvol+`{D}`, false, false, true),
		rsopGPO("LocalGPO", `C:\Windows\System32\GroupPolicy\Machine`, true, false, true),
		map[string]any{"Class": "RSOP_GPO", "Scope": "user", "guidName": "{E}", "fileSystemPath": sysvol + `{E}`, "enabled": true, "filterAllowed": true},
	))

	if got := machine.OneAttrString(lm.ADSite); got != "Override" {
		t.Errorf("site %q, want the administrator override", got)
	}
	if !machine.HasAttr(lm.GPOResultsCollected) {
		t.Error("collected results not recorded")
	}
	var linked []string
	g.Edges(machine, engine.In).Iterate(func(gpo *engine.Node, eb engine.EdgeBitmap) bool {
		if eb.IsSet(activedirectory.EdgeAffectedByGPO) {
			linked = append(linked, gpo.OneAttrString(activedirectory.GPCFileSysPath))
		}
		return true
	})
	if len(linked) != 1 || linked[0] != sysvol+`{A}` {
		t.Fatalf("linked %v, want only %v", linked, sysvol+`{A}`)
	}

	// No policy results at all: inference stays in charge.
	other := engine.NewNode(engine.Name, "WS02")
	g.Add(other)
	importPolicyProvenance(g, other, provenanceInfo(t, map[string]any{"Class": "MachineSite", "DynamicSiteName": "Discovered"}))
	if other.HasAttr(lm.GPOResultsCollected) || other.OneAttrString(lm.ADSite) != "Discovered" {
		t.Error("site only collection handled wrongly")
	}
}

// The GPO node made at import must fold into the directory's GPO object in
// whichever order the graphs are merged, keeping the directory's attributes.
func TestReportedGPOMergesIntoDirectoryGPO(t *testing.T) {
	for _, localFirst := range []bool{false, true} {
		t.Run(fmt.Sprintf("local graph larger: %v", localFirst), func(t *testing.T) {
			dn := "CN={A},CN=Policies,CN=System,DC=example,DC=test"
			ad := engine.NewIndexedGraph()
			ad.Add(engine.NewNode(engine.DistinguishedName, dn, engine.DataSource, "EXAMPLE",
				activedirectory.GPCFileSysPath, `\\EXAMPLE.TEST\sysvol\example.test\Policies\{A}`,
				activedirectory.GPLink, "kept"))

			local := engine.NewIndexedGraph()
			machine := engine.NewNode(engine.Name, "WS01", engine.DataSource, "WS01")
			local.Add(machine)
			importPolicyProvenance(local, machine, provenanceInfo(t, rsopGPO("{A}", sysvol+`{A}\Machine`, true, false, true)))

			filler, other := ad, local
			if localFirst {
				filler, other = local, ad
			}
			for i := 0; i < 5+other.Order(); i++ {
				filler.Add(engine.NewNode(engine.Name, fmt.Sprintf("filler %d", i), engine.DataSource, "FILLER"))
			}

			merged, err := engine.MergeGraphs([]*engine.IndexedGraph{ad, local})
			if err != nil {
				t.Fatal(err)
			}
			gpos, _ := merged.FindMulti(activedirectory.GPCFileSysPath, engine.NV(sysvol+`{A}`))
			if gpos.Len() != 1 {
				t.Fatalf("%d GPO nodes after merge, want 1", gpos.Len())
			}
			gpo := gpos.First()
			if gpo.DN() != dn || gpo.OneAttrString(activedirectory.GPLink) != "kept" {
				t.Fatal("the directory's GPO object lost its attributes")
			}
			edges, found := merged.GetEdge(gpo, machine)
			if !found || !edges.IsSet(activedirectory.EdgeAffectedByGPO) {
				t.Fatal("the reported GPO edge did not survive the merge")
			}
		})
	}
}
