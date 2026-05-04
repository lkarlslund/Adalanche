package engine

import (
	"fmt"
	"sync"
	"testing"
)

func TestIndexedGraphAddAndLookup(t *testing.T) {
	node := testNamedNode("Alpha", DisplayName, "Alpha Node")
	graph := testGraph(node)

	if !graph.Contains(node) {
		t.Fatal("expected graph to contain added node")
	}
	if graph.Order() != 1 {
		t.Fatalf("expected order 1, got %d", graph.Order())
	}

	index, found := graph.NodeToIndex(node)
	if !found {
		t.Fatal("expected node index")
	}
	if foundNode, ok := graph.IndexToNode(index); !ok || foundNode != node {
		t.Fatal("expected index to resolve back to node")
	}
	if foundNode, ok := graph.LookupNodeByID(node.ID()); !ok || foundNode != node {
		t.Fatal("expected lookup by node ID to resolve node")
	}
}

func TestIndexedGraphAddNewAppliesDefaultsAndIndexes(t *testing.T) {
	graph := NewIndexedGraph()
	graph.AddDefaultFlex(DataSource, "loader")

	node := graph.AddNew(Name, "Alpha")

	if got := node.OneAttrString(DataSource); got != "loader" {
		t.Fatalf("expected default datasource, got %q", got)
	}

	index := graph.GetIndex(DataSource)
	nodes, found := index.Lookup(NV("loader"))
	if !found || nodes.Len() != 1 || nodes.First() != node {
		t.Fatal("expected default value to be indexed")
	}
}

func TestIndexedGraphGetIndexAndMultiIndex(t *testing.T) {
	alpha := testNode(Name, "Alpha", SAMAccountName, "ALPHA")
	graph := testGraph(alpha)

	nameIndex := graph.GetIndex(Name)
	nodes, found := nameIndex.Lookup(NV("alpha"))
	if !found || nodes.Len() != 1 || nodes.First() != alpha {
		t.Fatal("expected case-insensitive string index lookup to resolve node")
	}

	multiForward := graph.GetMultiIndex(Name, SAMAccountName)
	multiReverse := graph.GetMultiIndex(SAMAccountName, Name)
	if multiForward != multiReverse {
		t.Fatal("expected multi-index lookup order to be normalized")
	}

	nodes, found = multiForward.Lookup(NV("alpha"), NV("alpha"))
	if !found || nodes.Len() != 1 || nodes.First() != alpha {
		t.Fatal("expected multi-index lookup to resolve node")
	}
}

func TestIndexedGraphMergeMovesRelationshipsAndValues(t *testing.T) {
	parent := testNamedNode("Parent")
	target := testNode(Name, "Shared", DisplayName, "Target")
	source := testNode(Name, "Shared", Description, "Source description")
	child := testNamedNode("Child")

	source.ChildOf(parent)
	source.Adopt(child)

	graph := testGraph(parent, target, source, child)
	mergedTo, merged := graph.Merge([]Attribute{Name}, nil, source)
	if !merged {
		t.Fatal("expected merge to happen")
	}
	if mergedTo != target {
		t.Fatal("expected merge target to be returned")
	}
	if got := target.OneAttrString(DisplayName); got != "Target" {
		t.Fatalf("expected target display name to remain, got %q", got)
	}
	if got := target.OneAttrString(Description); got != "Source description" {
		t.Fatalf("expected merged description, got %q", got)
	}
	if target.Parent() != parent {
		t.Fatal("expected merged node to inherit source parent")
	}
	if child.Parent() != target {
		t.Fatal("expected child to be reparented to merge target")
	}
}

func TestIndexedGraphConcurrentAddRelaxedAndIndexReads(t *testing.T) {
	graph := NewIndexedGraph()

	var writers sync.WaitGroup
	for worker := range 8 {
		writers.Add(1)
		go func(worker int) {
			defer writers.Done()
			for i := range 100 {
				graph.AddRelaxed(testNode(
					Name, fmt.Sprintf("node-%d-%d", worker, i),
					SAMAccountName, fmt.Sprintf("NODE-%d-%d", worker, i),
				))
				_ = graph.GetIndex(Name)
				_ = graph.GetMultiIndex(Name, SAMAccountName)
			}
		}(worker)
	}
	writers.Wait()

	if graph.Order() != 800 {
		t.Fatalf("expected 800 nodes, got %d", graph.Order())
	}

	index := graph.GetIndex(Name)
	nodes, found := index.Lookup(NV("node-3-42"))
	if !found || nodes.Len() != 1 {
		t.Fatal("expected indexed lookup after concurrent population")
	}
}
