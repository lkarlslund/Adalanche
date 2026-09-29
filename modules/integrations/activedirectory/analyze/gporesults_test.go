package analyze

import (
	"encoding/json"
	"testing"

	"github.com/lkarlslund/adalanche/modules/basedata"
	"github.com/lkarlslund/adalanche/modules/engine"
	"github.com/lkarlslund/adalanche/modules/integrations/activedirectory"
)

func TestPolicyAcquisitionResultsReachGraph(t *testing.T) {
	g := newADTestGraph()
	info := activedirectory.GPOdump{GPOinfo: activedirectory.GPOinfo{
		Path: "/synthetic", CollectionResults: basedata.CollectionResults{"enumeration": {Status: basedata.CollectionAccessDenied}},
		Files: []activedirectory.GPOfileinfo{{RelativePath: "/file", CollectionResults: basedata.CollectionResults{"contents": {Status: basedata.CollectionAccessDenied}}}},
	}}
	if err := ImportGPOInfo(info, g); err != nil {
		t.Fatal(err)
	}
	var count int
	g.IterateStable(func(node *engine.Node) bool {
		if node.HasAttr(GPOCollectionResults) {
			var result struct{ Results basedata.CollectionResults }
			if err := json.Unmarshal([]byte(node.OneAttrString(GPOCollectionResults)), &result); err != nil {
				t.Fatal(err)
			}
			for _, status := range result.Results {
				if status.Status != basedata.CollectionAccessDenied {
					t.Fatal("acquisition failure lost")
				}
			}
			count++
		}
		return true
	})
	if count != 2 {
		t.Fatalf("got %d acquisition records, want policy and file", count)
	}
}
