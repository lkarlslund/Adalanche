package analyze

import (
	"slices"
	"testing"
	"time"

	"github.com/lkarlslund/adalanche/modules/engine"
	"github.com/lkarlslund/adalanche/modules/engine/enginetest"
	adanalyze "github.com/lkarlslund/adalanche/modules/integrations/activedirectory/analyze"
	"github.com/lkarlslund/adalanche/modules/integrations/attrs"
	lm "github.com/lkarlslund/adalanche/modules/integrations/localmachine"
	"github.com/lkarlslund/adalanche/modules/windowssecurity"
)

const sharedAccount = "S-1-5-21-900-901-902-1101"

func collectionGraph(t *testing.T, at time.Time, uuid string) (*engine.IndexedGraph, *engine.Node) {
	t.Helper()
	g := engine.NewIndexedGraph()
	info := syntheticMachine("WS01", "S-1-5-21-111-222-333", sharedAccount)
	info.Collected = at
	info.Machine.SMBIOSUUID = uuid
	machine, err := importMachine(g, info)
	if err != nil {
		t.Fatal(err)
	}
	return g, machine
}

// The machine the directory knows for the account, as the AD processors
// make it before the merge.
func directoryGraph() *engine.IndexedGraph {
	g := engine.NewIndexedGraph()
	sid := engine.NVSID(windowssecurity.MustParseStringSID(sharedAccount))
	enginetest.AddNew(g, engine.Type, adanalyze.ObjectTypeMachine.ValueString(), engine.Name, "WS01",
		adanalyze.DomainJoinedSID, sid, attrs.PrimaryMachineFor, sid)
	return g
}

func TestCollectionsClaimingOneAccountAreKeptAndTagged(t *testing.T) {
	base := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	newest, current := collectionGraph(t, base.Add(48*time.Hour), "UUID-A")
	older, superseded := collectionGraph(t, base.Add(24*time.Hour), "UUID-A")
	cloneG, clone := collectionGraph(t, base, "UUID-B")
	unknownG, unknown := collectionGraph(t, base.Add(-24*time.Hour), "")
	directory := directoryGraph()

	graphs := []*engine.IndexedGraph{directory, unknownG, cloneG, older, newest}
	if err := chooseCurrentCollections(graphs); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		node *engine.Node
		tag  string
	}{{current, TagCollectionCurrent}, {superseded, TagCollectionSuperseded}, {clone, TagCollectionClone}, {unknown, TagCollectionUnresolved}} {
		if !c.node.HasTag(TagComputerAccountShared) || !c.node.HasTag(c.tag) {
			t.Errorf("collection should be tagged %v", c.tag)
		}
	}
	if !current.HasAttr(attrs.PrimaryMachineFor) || superseded.HasAttr(attrs.PrimaryMachineFor) {
		t.Error("only the newest collection should stand for the account")
	}

	// The same machines come out whatever order the graphs are merged in.
	count := func(order []*engine.IndexedGraph) (machines int, mergedWithDirectory bool) {
		merged := enginetest.Load(order...)
		for _, m := range adanalyze.MachinesForComputer(merged, windowssecurity.MustParseStringSID(sharedAccount)) {
			machines++
			if m.HasTag(TagCollectionCurrent) && m.OneAttrString(engine.Name) == "WS01" {
				mergedWithDirectory = true
			}
		}
		return
	}
	for _, order := range [][]*engine.IndexedGraph{graphs, {newest, older, cloneG, unknownG, directory}} {
		machines, merged := count(slices.Clone(order))
		if machines != 4 || !merged {
			t.Fatalf("got %v machines (current merged with the directory's: %v), want 4 with the current one merged", machines, merged)
		}
	}
}

func TestSingleCollectionMergesWithTheDirectoryMachine(t *testing.T) {
	g, machine := collectionGraph(t, time.Now(), "")
	directory := directoryGraph()
	if err := chooseCurrentCollections([]*engine.IndexedGraph{g, directory}); err != nil {
		t.Fatal(err)
	}
	if machine.HasTag(TagComputerAccountShared) {
		t.Error("a lone collection is tagged as sharing its account")
	}
	merged := enginetest.Load(directory, g)
	machines := adanalyze.MachinesForComputer(merged, windowssecurity.MustParseStringSID(sharedAccount))
	if len(machines) != 1 || !machines[0].HasAttr(lm.CollectedSettings) || machines[0].OneAttrString(engine.Name) != "WS01" {
		t.Fatalf("got %v machines, want the collection merged with the directory's machine", len(machines))
	}
}
