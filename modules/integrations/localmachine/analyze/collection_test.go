package analyze

import (
	"encoding/json"
	"strings"
	"testing"

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
	node, err := ImportCollectorInfo(g, info)
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
	other := engine.NewNode()
	if err := importCollectionSettings(other, localmachine.Info{RegistryData: localmachine.RegistryData{"zero": uint64(1)}}); err != nil {
		t.Fatal(err)
	}
	node.Absorb(other)
	if node.Attr(localmachine.CollectedSettings).Len() != 2 {
		t.Fatal("merge discarded a capture")
	}
}
