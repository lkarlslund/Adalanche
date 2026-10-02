package engine

import (
	"slices"
	"testing"
)

func TestRankedAdjacencyIsOrderedAndFollowsChanges(t *testing.T) {
	edge := NewEdge("CanonicalTestEdge")
	build := func(names ...string) (*IndexedGraph, map[string]*Node) {
		g := NewIndexedGraph()
		nodes := map[string]*Node{}
		for _, name := range names {
			nodes[name] = NewNode(Name, name)
			g.add(nodes[name])
		}
		return g, nodes
	}
	labels := func(g *IndexedGraph, r *RankedAdjacency, from *Node) []string {
		i, _ := g.NodeIndexOf(from)
		var out []string
		for _, e := range r.Neighbors[Out][i] {
			out = append(out, g.NodeAt(e.Target).Label())
		}
		return out
	}

	for _, order := range [][]string{{"hub", "c", "a", "b"}, {"b", "a", "hub", "c"}} {
		g, n := build(order...)
		for _, target := range []string{"c", "a", "b"} {
			g.edgeTo(n["hub"], n[target], edge)
		}
		if got := labels(g, g.RankedAdjacency(), n["hub"]); !slices.Equal(got, []string{"a", "b", "c"}) {
			t.Fatalf("built in order %v: neighbours %v, want [a b c]", order, got)
		}

		first := g.RankedAdjacency()
		if g.RankedAdjacency() != first {
			t.Fatal("unchanged graph rebuilt its adjacency")
		}
		extra := NewNode(Name, "0first")
		g.add(extra)
		g.edgeTo(n["hub"], extra, edge)
		if got := labels(g, g.RankedAdjacency(), n["hub"]); !slices.Equal(got, []string{"0first", "a", "b", "c"}) {
			t.Fatalf("after adding a node and edge: neighbours %v", got)
		}
	}
}
