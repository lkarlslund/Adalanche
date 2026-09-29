package engine

import "testing"

func TestNodeIDAssignment(t *testing.T) {
	a, b := NewNode(), NewNode()
	if a.ID() == InvalidNodeID || b.ID() == InvalidNodeID || a.ID() == b.ID() {
		t.Fatalf("ids %v and %v", a.ID(), b.ID())
	}
	var unassigned Node
	if unassigned.ID() != InvalidNodeID {
		t.Fatal("a node not created through NewNode has an ID")
	}
}

func TestLookupNodeByID(t *testing.T) {
	first, second := NewIndexedGraph(), NewIndexedGraph()
	node := NewNode()
	first.Add(node)
	second.Add(node)
	for _, g := range []*IndexedGraph{first, second} {
		if found, ok := g.LookupNodeByID(node.ID()); !ok || found != node {
			t.Fatal("node not found by ID in a graph containing it")
		}
	}
	if _, ok := first.LookupNodeByID(InvalidNodeID); ok {
		t.Fatal("the invalid ID resolved to a node")
	}
	if _, ok := first.LookupNodeByID(NewNode().ID()); ok {
		t.Fatal("a node outside the graph was found")
	}
	var unassigned Node
	first.Add(&unassigned)
	if _, ok := first.LookupNodeByID(InvalidNodeID); ok {
		t.Fatal("a node without an ID was registered under the invalid ID")
	}
}

func TestMergeKeepsTargetID(t *testing.T) {
	mergeOn := NewAttribute("test-merge-key").Flag(Merge)
	g := NewIndexedGraph()
	target := NewNode(mergeOn, NV("shared"))
	g.Add(target)
	targetID := target.ID()

	source := NewNode(mergeOn, NV("shared"), Name, NV("from source"))
	sourceID := source.ID()
	mergedTo, merged := g.Merge([]Attribute{mergeOn}, nil, source)
	if !merged || mergedTo != target {
		t.Fatal("source was not merged into the target")
	}
	if target.ID() != targetID {
		t.Fatalf("target ID changed from %v to %v", targetID, target.ID())
	}
	if found, ok := g.LookupNodeByID(targetID); !ok || found != target {
		t.Fatal("target not found by its ID after the merge")
	}
	if _, ok := g.LookupNodeByID(sourceID); ok {
		t.Fatal("the absorbed source is reachable by its ID")
	}
	if target.OneAttrString(Name) != "from source" {
		t.Fatal("source attributes were not absorbed")
	}
}
