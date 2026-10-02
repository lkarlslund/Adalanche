package engine

import (
	"fmt"
	"slices"
	"sync"
	"testing"

	"github.com/lkarlslund/adalanche/modules/windowssecurity"
)

// Two loaders state things about the same nodes. Whichever commits first,
// the graph ends up the same: each commit resolves identities among its own
// loader's nodes, staged lookups do not see the other loader, and when
// loading finishes the two become one node with the union of their values
// and parent claims are applied in an order taken from content.
func TestLoadCommitsInAnyOrderGiveTheSameGraph(t *testing.T) {
	edge := testEdge("load")
	snapshot := func(firstA bool) []string {
		g := NewAnalysisGraph()
		targetA, targetB := NewLoadTarget(g, "A"), NewLoadTarget(g, "B")

		a := targetA.Begin("A")
		x, _ := a.FindOrAdd(DistinguishedName, NV("CN=x,DC=test"), Description, "from A")
		x.Set(ObjectClass, NV("top"), NV("a-class")).Tag("seen-by-a")
		folderA := a.AddNew(Name, "folder A")
		x.ChildOf(folderA)
		a.EdgeTo(folderA, x, edge)

		b := targetB.Begin("B")
		if _, found := b.Find(DistinguishedName, NV("CN=x,DC=test")); found {
			t.Fatal("a load transaction saw another loader's node")
		}
		y, _ := b.FindOrAdd(DistinguishedName, NV("CN=x,DC=test"))
		y.Set(ObjectClass, NV("b-class")).Tag("seen-by-b")
		folderB := b.AddNew(Name, "folder B")
		y.ChildOf(folderB)

		first, second := a, b
		if !firstA {
			first, second = b, a
		}
		for _, tx := range []*Tx{first, second} {
			if err := tx.Commit(); err != nil {
				t.Fatal(err)
			}
		}
		if err := g.FinishLoading(); err != nil {
			t.Fatal(err)
		}

		nodes, _ := g.FindMulti(DistinguishedName, NV("CN=x,DC=test"))
		if nodes.Len() != 1 {
			t.Fatalf("got %v nodes for one identity", nodes.Len())
		}
		n := nodes.First()
		var out []string
		for _, attr := range []Attribute{Description, ObjectClass, Tag, DataLoader} {
			out = append(out, fmt.Sprint(attr.String(), n.Attr(attr).StringSlice()))
		}
		parent := "none"
		if n.Parent() != nil {
			parent = n.Parent().Label()
		}
		out = append(out, "parent "+parent)
		var edges []string
		g.IterateEdges(n, In, func(source *Node, eb EdgeBitmap) bool {
			edges = append(edges, source.Label()+" "+fmt.Sprint(eb.IsSet(edge)))
			return true
		})
		slices.Sort(edges)
		return append(out, edges...)
	}
	ab, ba := snapshot(true), snapshot(false)
	if !slices.Equal(ab, ba) {
		t.Fatalf("commit order changed the graph:\n%v\n%v", ab, ba)
	}
	t.Log(ab)
}

// A before-merge processor sees its own loader's node for a SID, even when
// another loader's reference for the same SID and domain came first.
func TestScopedSIDLookupIgnoresOtherLoaders(t *testing.T) {
	sid := windowssecurity.AuthenticatedUsersSID
	g := NewAnalysisGraph()
	g.add(NewNode(ObjectSid, NVSID(sid), DomainContext, "DC=a", DataLoader, "Group Policy"))
	own := NewNode(ObjectSid, NVSID(sid), DomainContext, "DC=a", DataSource, "A", DataLoader, "Active Directory")
	g.add(own)
	user := NewNode(Name, "user", DomainContext, "DC=a", DataSource, "A", DataLoader, "Active Directory")
	g.add(user)

	tx := g.Begin("processor")
	tx.scopeTo("Active Directory")
	if found, ok := tx.FindAdjacentSID(sid, user); !ok || found != own {
		t.Fatal("scoped lookup did not find the loader's own node")
	}
	if h, existed := tx.FindOrAddAdjacentSIDFound(sid, user); !existed || h.Node() != own {
		t.Fatal("scoped find-or-add did not find the loader's own node")
	}
}

// Two machine collections from different machines with the same name keep
// their own builtin groups: a collection's identities stay within it.
func TestCollectionsKeepTheirOwnIdentities(t *testing.T) {
	g := NewAnalysisGraph()
	target := NewLoadTarget(g, "Local Machine")
	machineSID := windowssecurity.MustParseStringSID("S-1-5-21-1-2-3")
	for range 2 {
		tx := target.BeginCollection("collection")
		machine := tx.AddNew(Type, NodeTypeMachine.ValueString(), ObjectSid, NVSID(machineSID), DataSource, "WS01")
		tx.FindOrAddAdjacentSID(windowssecurity.AdministratorsSID, machine)
		if err := tx.Commit(); err != nil {
			t.Fatal(err)
		}
	}
	if admins, _ := g.FindMulti(ObjectSid, NVSID(windowssecurity.AdministratorsSID)); admins.Len() != 2 {
		t.Fatalf("got %v Administrators nodes, want one per collection", admins.Len())
	}
}

// A load commit that replaces a value keeps the index in place: the node is
// taken off the old value and found by the new one.
func TestLoadCommitReplacingAValueKeepsTheIndex(t *testing.T) {
	g := NewAnalysisGraph()
	target := NewLoadTarget(g, "A")
	g.FindMulti(Description, NV("anything")) // builds the index

	tx := target.Begin("A")
	x, _ := tx.FindOrAdd(DistinguishedName, NV("CN=x,DC=test"))
	x.Set(Description, NV("old"))
	x.Set(Description, NV("new"))
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if g.indexes[Description] == nil {
		t.Fatal("the commit dropped the index")
	}
	if nodes, _ := g.FindMulti(Description, NV("old")); nodes.Len() != 0 {
		t.Fatalf("found %v nodes by the replaced value", nodes.Len())
	}
	if nodes, _ := g.FindMulti(Description, NV("new")); nodes.Len() != 1 {
		t.Fatalf("found %v nodes by the new value", nodes.Len())
	}
}

// Concurrent lookups of a missing index share one build instead of each
// scanning the whole graph.
func TestConcurrentLookupsBuildAMissingIndexOnce(t *testing.T) {
	g := NewAnalysisGraph()
	tx := g.Begin("nodes")
	for i := range 1000 {
		tx.AddNew(Description, fmt.Sprint("node ", i%10))
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	indexes := make([]*Index, 16)
	multi := make([]*MultiIndex, 16)
	var wg sync.WaitGroup
	for i := range indexes {
		wg.Go(func() {
			indexes[i] = g.GetIndex(Description)
			multi[i] = g.GetMultiIndex(Description, Name)
		})
	}
	wg.Wait()
	for i := range indexes {
		if indexes[i] != indexes[0] || multi[i] != multi[0] {
			t.Fatal("concurrent lookups got different indexes")
		}
	}
	if nodes, _ := g.FindMulti(Description, NV("node 3")); nodes.Len() != 100 {
		t.Fatalf("found %v nodes, want 100", nodes.Len())
	}
}

// Loaders place nodes under their root through parent claims, so a root's
// children only show once loading finishes: a root with claimed children
// stays, one with none is removed.
func TestLoaderRootsKeepClaimedChildren(t *testing.T) {
	g := NewAnalysisGraph()
	used, unused := NewLoadTarget(g, "used"), NewLoadTarget(g, "unused")

	tx := used.BeginCollection("collection")
	child := tx.AddNew(Name, "child")
	child.ChildOf(used.Root())
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	tx = unused.Begin("nothing placed")
	elsewhere := tx.AddNew(Name, "elsewhere")
	elsewhere.ChildOf(g.Root())
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if err := g.FinishLoading(); err != nil {
		t.Fatal(err)
	}

	if !g.Contains(used.Root()) || child.Node().Parent() != used.Root() {
		t.Fatal("the root of a loader that placed a node under it was lost")
	}
	if g.Contains(unused.Root()) {
		t.Fatal("the root of a loader that placed nothing under it was kept")
	}
	if elsewhere.Node().Parent() != g.Root() {
		t.Fatal("a node placed elsewhere lost its parent")
	}
}

// A large index is built on several workers; each key still lists its
// nodes in graph order.
func TestParallelIndexBuildKeepsGraphOrder(t *testing.T) {
	g := NewIndexedGraph()
	tx := g.Begin("nodes")
	for i := range 70000 {
		tx.AddNew(Description, fmt.Sprint("value ", i%97), Name, fmt.Sprint("name ", i%13))
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	position := map[*Node]int{}
	for i, n := range g.nodes {
		position[n] = i
	}
	check := func(nodes NodeSlice, want int) {
		t.Helper()
		if nodes.Len() != want {
			t.Fatalf("got %v nodes, want %v", nodes.Len(), want)
		}
		last := -1
		nodes.Iterate(func(n *Node) bool {
			if position[n] <= last {
				t.Fatal("nodes are not in graph order")
			}
			last = position[n]
			return true
		})
	}
	nodes, _ := g.FindMulti(Description, NV("value 5"))
	check(nodes, 722)
	both, _ := g.FindTwoMulti(Description, NV("value 5"), Name, NV("name 5"))
	check(both, 56)
}
