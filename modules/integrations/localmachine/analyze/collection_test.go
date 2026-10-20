package analyze

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/lkarlslund/adalanche/modules/basedata"
	"github.com/lkarlslund/adalanche/modules/engine"
	"github.com/lkarlslund/adalanche/modules/integrations/localmachine"
)

func TestImportRetainsCollectionSettingsWithoutTaskPayloads(t *testing.T) {
	g := engine.NewIndexedGraph()
	info := localmachine.Info{
		Machine:           localmachine.Machine{Name: "synthetic", LocalSID: "S-1-5-21-1-2-3"},
		RegistryData:      localmachine.RegistryData{"zero": uint64(0)},
		CollectionResults: basedata.CollectionResults{"registry/value/denied": {Status: basedata.CollectionAccessDenied, ErrorCode: "errno:5"}},
	}
	info.Tasks = []localmachine.RegisteredTask{{Definition: localmachine.TaskDefinition{XMLText: "synthetic-secret-marker"}}}
	node, err := importMachine(g, info)
	if err != nil {
		t.Fatal(err)
	}
	raw := node.OneAttrString(localmachine.CollectedSettings)
	if strings.Contains(raw, "synthetic-secret-marker") {
		t.Fatal("copied task payload into settings")
	}
	var settings localmachine.CollectionSettings
	if err := json.Unmarshal([]byte(raw), &settings); err != nil {
		t.Fatal(err)
	}
	if settings.CollectionResults["registry/value/denied"].Status != basedata.CollectionAccessDenied {
		t.Fatal("lost acquisition outcome")
	}
	info.CollectionResults["registry/value/denied"] = basedata.CollectionResult{Status: basedata.CollectionCollected}
	if raw != node.OneAttrString(localmachine.CollectedSettings) {
		t.Fatal("retained mutable caller state")
	}
}

func TestImportHandsAssessmentToImportersWithoutRetainingIt(t *testing.T) {
	var seen []string
	RegisterAssessmentImporter(func(_ *engine.Tx, _ engine.TxNode, a *localmachine.Assessment) error {
		if records := a.Categories["synthetic-category"].Records; len(records) > 0 {
			seen = append(seen, string(records[0]))
		}
		return nil
	})
	assessment, err := json.Marshal(localmachine.Assessment{
		Version:    localmachine.AssessmentVersion,
		Captured:   time.Now().UTC(),
		Categories: map[string]localmachine.AssessmentCapture{"synthetic-category": {Records: []json.RawMessage{json.RawMessage(`"synthetic-assessment-marker"`)}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	g := engine.NewIndexedGraph()
	node, err := importMachine(g, localmachine.Info{
		Machine:        localmachine.Machine{Name: "synthetic", LocalSID: "S-1-5-21-1-2-3"},
		AssessmentData: string(assessment),
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(seen) != 1 || seen[0] != `"synthetic-assessment-marker"` {
		t.Fatalf("importer saw %q", seen)
	}
	if strings.Contains(node.OneAttrString(localmachine.CollectedSettings), "synthetic-assessment-marker") {
		t.Fatal("assessment retained in collected settings")
	}
}
