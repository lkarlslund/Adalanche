package engine

import (
	"fmt"
	"maps"
	"slices"
	"sync"
	"testing"
)

func collectNodeNames(iterator func(func(*Node) bool)) []string {
	names := make([]string, 0, 64)
	iterator(func(node *Node) bool {
		names = append(names, node.OneAttrString(Name))
		return true
	})
	slices.Sort(names)
	return names
}

func collectParallelNodeNames(iterator func(func(*Node) bool, int)) []string {
	names := make([]string, 0, 64)
	seen := make(map[string]struct{})
	var mu sync.Mutex

	iterator(func(node *Node) bool {
		name := node.OneAttrString(Name)
		mu.Lock()
		if _, found := seen[name]; !found {
			seen[name] = struct{}{}
			names = append(names, name)
		}
		mu.Unlock()
		return true
	}, 4)
	slices.Sort(names)
	return names
}

func compareGraphValuesByID(t *testing.T, got, want map[*Node]int) {
	t.Helper()

	gotByID := make(map[NodeID]int, len(got))
	for node, value := range got {
		gotByID[node.ID()] = value
	}

	wantByID := make(map[NodeID]int, len(want))
	for node, value := range want {
		wantByID[node.ID()] = value
	}

	if !maps.Equal(gotByID, wantByID) {
		t.Fatalf("graph values mismatch:\n got: %#v\nwant: %#v", gotByID, wantByID)
	}
}

func collectOutgoingEdges(iterator func(*Node, EdgeDirection, func(*Node, EdgeBitmap) bool), source *Node) []string {
	edges := make([]string, 0, 16)
	iterator(source, Out, func(target *Node, ebm EdgeBitmap) bool {
		edges = append(edges, fmt.Sprintf("%s->%s:%v", source.OneAttrString(Name), target.OneAttrString(Name), ebm.Edges()))
		return true
	})
	slices.Sort(edges)
	return edges
}

func TestSyntheticGraphGeneratorIsDeterministic(t *testing.T) {
	cfg := mediumSyntheticGraphConfig()

	first := buildSyntheticGraph(cfg)
	second := buildSyntheticGraph(cfg)

	if got, want := collectNodeNames(first.Iterate), collectNodeNames(second.Iterate); !slices.Equal(got, want) {
		t.Fatalf("node names differ:\n got: %#v\nwant: %#v", got, want)
	}

	for _, graph := range []*IndexedGraph{first, second} {
		if graph.Size() == 0 {
			t.Fatal("expected synthetic graph to contain edges")
		}
	}
	if first.Size() != second.Size() {
		t.Fatalf("expected deterministic edge count, got %d and %d", first.Size(), second.Size())
	}
}

func TestFrozenGraphIterateMatchesIndexedGraphIterate(t *testing.T) {
	graph := buildSyntheticGraph(mediumSyntheticGraphConfig())
	view := graph.freeze()

	got := collectNodeNames(view.Iterate)
	want := collectNodeNames(graph.Iterate)
	if !slices.Equal(got, want) {
		t.Fatalf("frozen iterate mismatch:\n got: %#v\nwant: %#v", got, want)
	}
}

func TestFrozenGraphIterateParallelMatchesIndexedGraphIterate(t *testing.T) {
	graph := buildSyntheticGraph(mediumSyntheticGraphConfig())
	view := graph.freeze()

	got := collectParallelNodeNames(view.IterateParallel)
	want := collectNodeNames(graph.Iterate)
	if !slices.Equal(got, want) {
		t.Fatalf("frozen iterate parallel mismatch:\n got: %#v\nwant: %#v", got, want)
	}
}

func TestFrozenGraphIterateEdgesMatchesIndexedGraph(t *testing.T) {
	graph := buildSyntheticGraph(smallSyntheticGraphConfig())
	view := graph.freeze()

	var source *Node
	graph.Iterate(func(node *Node) bool {
		source = node
		return false
	})
	if source == nil {
		t.Fatal("expected source node")
	}

	got := collectOutgoingEdges(view.IterateEdges, source)
	want := collectOutgoingEdges(graph.IterateEdges, source)
	if !slices.Equal(got, want) {
		t.Fatalf("frozen edge iteration mismatch:\n got: %#v\nwant: %#v", got, want)
	}
}

func TestFrozenGraphSnapshotIsStableAfterEdgeMutation(t *testing.T) {
	edge := testEdge("snapshot-edge")
	from := testNamedNode("from")
	to := testNamedNode("to")
	other := testNamedNode("other")
	graph := testGraph(from, to, other)
	graph.edgeToEx(from, to, edge, true)

	view := graph.freeze()
	graph.edgeToEx(from, other, edge, true)

	got := collectOutgoingEdges(view.IterateEdges, from)
	want := []string{fmt.Sprintf("from->to:%v", EdgeBitmap{}.Set(edge).Edges())}
	if !slices.Equal(got, want) {
		t.Fatalf("expected frozen snapshot to remain stable:\n got: %#v\nwant: %#v", got, want)
	}
}

func TestCalculateGraphValuesMatchesFrozenGraph(t *testing.T) {
	graph := buildSyntheticGraph(smallSyntheticGraphConfig())
	matchEdges := EdgeBitmap{}.
		Set(testEdge("synthetic-member")).
		Set(testEdge("synthetic-admin"))

	got := CalculateGraphValues(graph, matchEdges, 0, "indexed synthetic", func(node *Node) int {
		return len(node.OneAttrString(Name)) % 7
	})
	want := CalculateGraphValues(graph.freeze(), matchEdges, 0, "frozen synthetic", func(node *Node) int {
		return len(node.OneAttrString(Name)) % 7
	})

	compareGraphValuesByID(t, got, want)
}

func TestCalculateGraphValuesPropagatesSCCSuccessorScores(t *testing.T) {
	edge := testEdge("graph-values")
	matchEdges := EdgeBitmap{}.Set(edge)

	a1 := testNamedNode("a1")
	a2 := testNamedNode("a2")
	b1 := testNamedNode("b1")
	b2 := testNamedNode("b2")

	graph := testGraph(a1, a2, b1, b2)
	graph.edgeToEx(a1, a2, edge, true)
	graph.edgeToEx(a2, a1, edge, true)
	graph.edgeToEx(b1, b2, edge, true)
	graph.edgeToEx(b2, b1, edge, true)
	graph.edgeToEx(a1, b1, edge, true)

	values := CalculateGraphValues(graph, matchEdges, 0, "scc propagation", func(*Node) int {
		return 1
	})

	if got := values[b1]; got != 2 {
		t.Fatalf("expected successor SCC score 2 for b1, got %d", got)
	}
	if got := values[b2]; got != 2 {
		t.Fatalf("expected successor SCC score 2 for b2, got %d", got)
	}
	if got := values[a1]; got != 8 {
		t.Fatalf("expected upstream SCC score 8 for a1, got %d", got)
	}
	if got := values[a2]; got != 8 {
		t.Fatalf("expected upstream SCC score 8 for a2, got %d", got)
	}
}
