package engine

import (
	"slices"
	"testing"
)

func tagsOn(g *IndexedGraph, from, to *Node) []EdgeTag {
	tags := g.EdgeTags(from, to)
	slices.SortFunc(tags, func(a, b EdgeTag) int {
		if a.Edge != b.Edge {
			return int(a.Edge) - int(b.Edge)
		}
		if a.Tag < b.Tag {
			return -1
		}
		if a.Tag > b.Tag {
			return 1
		}
		return 0
	})
	return tags
}

// A tag is on one edge type, or on the pair; searches ask which of the
// pair's edge types carry a tag.
func TestEdgeTagsOnTypesAndPairs(t *testing.T) {
	g := NewIndexedGraph()
	first, second := testEdge("tags first"), testEdge("tags second")
	tx := g.Begin("write")
	a, b := tx.AddNew(Name, "a"), tx.AddNew(Name, "b")
	tx.EdgeTo(a, b, first)
	tx.EdgeTo(a, b, second)
	tx.TagEdge(a, b, first, "accepted")
	tx.TagEdge(a, b, AnyEdgeType, "reviewed")
	tx.TagEdge(a, b, first, "accepted") // again
	commitTx(t, tx)

	want := []EdgeTag{{first, "accepted"}, {AnyEdgeType, "reviewed"}}
	if first > AnyEdgeType {
		want[0], want[1] = want[1], want[0]
	}
	if got := tagsOn(g, a.Node(), b.Node()); !slices.Equal(got, want) {
		t.Fatalf("tags %+v, want %+v", got, want)
	}

	ai, _ := g.NodeIndexOf(a.Node())
	bi, _ := g.NodeIndexOf(b.Node())
	present := EdgeBitmap{}.Set(first).Set(second)
	accepted, _ := g.LookupEdgeTag("accepted")
	reviewed, _ := g.LookupEdgeTag("reviewed")
	if got := g.EdgeTypesTagged(ai, bi, accepted, present); got != (EdgeBitmap{}.Set(first)) {
		t.Errorf("accepted on %v, want the first type only", got.StringSlice())
	}
	if got := g.EdgeTypesTagged(ai, bi, reviewed, present); got != present {
		t.Errorf("reviewed on %v, want every type (it is on the pair)", got.StringSlice())
	}
	if _, found := g.LookupEdgeTag("never used"); found {
		t.Error("an unused tag name has a number")
	}
	if !g.HasEdgeTags() {
		t.Error("graph says it has no edge tags")
	}

	untag := g.Begin("untag")
	untag.UntagEdge(a.Node(), b.Node(), first, "accepted")
	commitTx(t, untag)
	if got := tagsOn(g, a.Node(), b.Node()); !slices.Equal(got, []EdgeTag{{AnyEdgeType, "reviewed"}}) {
		t.Errorf("after untagging: %+v", got)
	}
}

// Tags only go on edges the graph has, and go with them: a type's tags when
// the pair loses the type, the pair's when it loses its last edge.
func TestEdgeTagsFollowTheirEdges(t *testing.T) {
	g := NewIndexedGraph()
	first, second := testEdge("tags first"), testEdge("tags second")
	tx := g.Begin("write")
	a, b, c := tx.AddNew(Name, "a"), tx.AddNew(Name, "b"), tx.AddNew(Name, "c")
	tx.EdgeTo(a, b, first)
	tx.EdgeTo(a, b, second)
	tx.TagEdge(a, b, first, "on first")
	tx.TagEdge(a, b, AnyEdgeType, "on pair")
	tx.TagEdge(a, c, first, "no such edge")
	tx.TagEdge(a, c, AnyEdgeType, "no such pair")
	tx.TagEdge(b, a, first, "wrong way round")
	commitTx(t, tx)
	if tags := g.EdgeTags(a.Node(), c.Node()); len(tags) != 0 {
		t.Errorf("tags on missing edges: %+v", tags)
	}
	if tags := g.EdgeTags(b.Node(), a.Node()); len(tags) != 0 {
		t.Errorf("tags on a missing direction: %+v", tags)
	}

	clear := g.Begin("clear first")
	clear.EdgeClear(a.Node(), b.Node(), first)
	commitTx(t, clear)
	if got := tagsOn(g, a.Node(), b.Node()); !slices.Equal(got, []EdgeTag{{AnyEdgeType, "on pair"}}) {
		t.Errorf("after clearing the first type: %+v", got)
	}
	clear = g.Begin("clear second")
	clear.EdgeClear(a.Node(), b.Node(), second)
	commitTx(t, clear)
	if got := g.EdgeTags(a.Node(), b.Node()); len(got) != 0 {
		t.Errorf("after clearing every type: %+v", got)
	}
}

// Machine collections commit on their own path; tags staged there are kept.
func TestCollectionCommitsKeepEdgeTags(t *testing.T) {
	g := NewAnalysisGraph()
	edge := testEdge("tags first")
	tx := NewLoadTarget(g, "loader").BeginCollection("collection")
	machine, account := tx.AddNew(Name, "machine"), tx.AddNew(Name, "account")
	tx.EdgeTo(account, machine, edge)
	tx.TagEdge(account, machine, edge, "collected")
	commitTx(t, tx)
	if got := g.EdgeTags(account.Node(), machine.Node()); !slices.Equal(got, []EdgeTag{{edge, "collected"}}) {
		t.Fatalf("got %+v", got)
	}
}

// When nodes are folded, tags move with their edges.
func TestCompactionMovesEdgeTags(t *testing.T) {
	g := NewIndexedGraph()
	edge := testEdge("tags first")
	tx := g.Begin("write")
	reference, real, target := tx.AddNew(Name, "reference"), tx.AddNew(Name, "real"), tx.AddNew(Name, "target")
	tx.EdgeTo(reference, target, edge)
	tx.TagEdge(reference, target, edge, "moves")
	commitTx(t, tx)

	g.compact(map[*Node]*Node{reference.Node(): real.Node()})
	if got := g.EdgeTags(real.Node(), target.Node()); !slices.Equal(got, []EdgeTag{{edge, "moves"}}) {
		t.Fatalf("got %+v", got)
	}
}

// Tags staged in forked transactions are kept when the forks are joined,
// also where a fork's edge merges into one the parent already has.
func TestForkedTransactionsKeepEdgeTags(t *testing.T) {
	g := NewIndexedGraph()
	edge := testEdge("tags first")
	setup := g.Begin("setup")
	a, b := setup.AddNew(Name, "a"), setup.AddNew(Name, "b")
	commitTx(t, setup)

	tx := g.Begin("forks")
	tx.EdgeTo(a.Node(), b.Node(), edge)
	forks := tx.Fork(2)
	forks[0].TagEdge(a.Node(), b.Node(), edge, "one")
	forks[1].TagEdge(a.Node(), b.Node(), AnyEdgeType, "two")
	tx.Join(forks)
	commitTx(t, tx)
	if got := g.EdgeTags(a.Node(), b.Node()); len(got) != 2 {
		t.Fatalf("got %+v, want both tags", got)
	}
}
