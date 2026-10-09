package engine

import (
	"context"
	"slices"
	"sync"
	"testing"
)

func TestIndexesBelongToGraph(t *testing.T) {
	a, b, c := testNamedNode("a"), testNamedNode("b"), testNamedNode("c")
	g := testGraph(a, b, c)
	edge := testEdge("graph-local-index")
	g.edgeToEx(a, b, edge, true)
	view := g.freeze()
	temporary := testGraph(c, a) // Different positions; b is not a member.
	temporary.edgeToEx(c, a, edge, true)
	for node, want := range map[*Node]NodeIndex{a: 0, b: 1, c: 2} {
		if got, found := g.nodeToIndex(node); !found || got != want {
			t.Fatalf("main graph: %s index %d, found %t, want %d", node.Label(), got, found, want)
		}
	}
	if _, found := temporary.nodeToIndex(b); found {
		t.Fatal("foreign node accepted by temporary graph")
	}
	var targets []*Node
	view.IterateEdges(a, Out, func(target *Node, _ EdgeBitmap) bool {
		targets = append(targets, target)
		return true
	})
	if !slices.Equal(targets, []*Node{b}) {
		t.Fatal("temporary graph changed frozen adjacency lookup")
	}
	// Reusing pointers concurrently must not write graph-local state into nodes.
	var wg sync.WaitGroup
	for range 4 {
		wg.Go(func() {
			for range 20 {
				other := testGraph(c, b, a)
				if got, _ := other.nodeToIndex(a); got != 2 {
					t.Error("wrong temporary graph index")
				}
				view.IterateEdges(a, Out, func(target *Node, _ EdgeBitmap) bool {
					if target != b {
						t.Error("wrong frozen target")
					}
					return true
				})
			}
		})
	}
	wg.Wait()
}

func TestImpactResultsStayBoundToSnapshot(t *testing.T) {
	a, b, c := testNamedNode("a"), testNamedNode("b"), testNamedNode("c")
	g := testGraph(a, b, c)
	edge := testEdge("impact-snapshot")
	g.edgeToEx(a, b, edge, true)
	result, err := calculateImpact(context.Background(), g.freeze(), ImpactOptions{
		Edges: EdgeBitmap{}.Set(edge), RequiredProbability: 100, Categories: 1, Workers: 4,
		Classify: func(*Node) int { return 0 },
	})
	if err != nil {
		t.Fatal(err)
	}
	_ = testGraph(c, b, a)
	extra := testNamedNode("added after snapshot")
	g.add(extra)
	if result.Counts(extra) != nil {
		t.Fatal("result accepted a node added after analysis")
	}
	want := map[*Node]uint32{a: 2, b: 1, c: 1}
	for node, count := range want {
		if got := result.Counts(node); len(got) != 1 || got[0] != count {
			t.Fatalf("%s: counts %v, want %d", node.Label(), got, count)
		}
	}
	var mu sync.Mutex
	visited := make(map[*Node]int)
	result.IterateParallel(func(node *Node, counts []uint32) {
		mu.Lock()
		defer mu.Unlock()
		visited[node]++
		if len(counts) != 1 || counts[0] != want[node] {
			t.Errorf("snapshot iteration: %s counts %v", node.Label(), counts)
		}
	})
	if len(visited) != len(want) {
		t.Fatalf("visited %d nodes, want %d", len(visited), len(want))
	}
	for _, count := range visited {
		if count != 1 {
			t.Fatal("snapshot node visited more than once")
		}
	}
}
