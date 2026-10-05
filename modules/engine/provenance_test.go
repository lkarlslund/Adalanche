package engine

import (
	"fmt"
	"testing"
)

var (
	testSourcePolicy  = NewSourceKind("Test policy")
	testSourceListing = NewSourceKind("Test listing")
)

func commitTx(t *testing.T, tx *Tx) {
	t.Helper()
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
}

func TestEdgeBecauseRecordsEveryCause(t *testing.T) {
	g := NewIndexedGraph()
	edge := testEdge("provenance")
	tx := g.Begin("write")
	member, machine, policy := tx.AddNew(Name, "member"), tx.AddNew(Name, "machine"), tx.AddNew(Name, "policy")
	tx.EdgeBecause(member, machine, edge, Source{testSourcePolicy, policy, "setting"})
	tx.EdgeBecause(member, machine, edge, Source{testSourceListing, machine, "local group"})
	tx.EdgeBecause(member, machine, edge, Source{testSourcePolicy, policy, "setting"}) // same cause again
	commitTx(t, tx)

	sources := g.EdgeSources(member.Node(), machine.Node())
	if len(sources) != 2 {
		t.Fatalf("got %v causes, want 2", len(sources))
	}
	if s := sources[0]; s.Edge != edge || s.Source.Kind != testSourcePolicy || s.Source.About != policy.Node() || s.Source.Detail != "setting" {
		t.Fatalf("first cause %+v", s)
	}
	if s := sources[1]; s.Source.Kind != testSourceListing || s.Source.About != machine.Node() {
		t.Fatalf("second cause %+v", s)
	}
	if edges, _ := g.GetEdge(member.Node(), machine.Node()); !edges.IsSet(edge) {
		t.Fatal("the edge itself is missing")
	}
}

// Causes belong to edge types; clearing the edge drops them.
func TestClearingAnEdgeDropsItsCauses(t *testing.T) {
	g := NewIndexedGraph()
	edge := testEdge("provenance")
	tx := g.Begin("write")
	a, b := tx.AddNew(Name, "a"), tx.AddNew(Name, "b")
	tx.EdgeBecause(a, b, edge, Source{Kind: testSourcePolicy, Detail: "granted"})
	commitTx(t, tx)

	clear := g.Begin("clear")
	clear.EdgeClear(a.Node(), b.Node(), edge)
	commitTx(t, clear)
	if sources := g.EdgeSources(a.Node(), b.Node()); len(sources) != 0 {
		t.Fatalf("cleared edge kept %v causes", len(sources))
	}
}

// A machine collection commits on its own path; its causes are kept too,
// including causes about nodes the collection itself added.
func TestCollectionCommitsKeepCauses(t *testing.T) {
	g := NewAnalysisGraph()
	edge := testEdge("provenance")
	tx := NewLoadTarget(g, "loader").BeginCollection("collection")
	machine := tx.AddNew(Name, "machine")
	account := tx.AddNew(Name, "account")
	tx.EdgeBecause(account, machine, edge, Source{testSourceListing, machine, "local group"})
	commitTx(t, tx)
	sources := g.EdgeSources(account.Node(), machine.Node())
	if len(sources) != 1 || sources[0].Source.About != machine.Node() {
		t.Fatalf("got %+v", sources)
	}
}

func TestForkedTransactionsKeepCauses(t *testing.T) {
	g := NewIndexedGraph()
	edge := testEdge("provenance")
	setup := g.Begin("setup")
	a, b := setup.AddNew(Name, "a"), setup.AddNew(Name, "b")
	commitTx(t, setup)

	tx := g.Begin("forks")
	forks := tx.Fork(2)
	forks[0].EdgeBecause(a.Node(), b.Node(), edge, Source{Kind: testSourcePolicy, Detail: "one"})
	forks[1].EdgeBecause(a.Node(), b.Node(), edge, Source{Kind: testSourceListing, Detail: "two"})
	tx.Join(forks)
	commitTx(t, tx)
	if sources := g.EdgeSources(a.Node(), b.Node()); len(sources) != 2 {
		t.Fatalf("got %v causes, want 2", len(sources))
	}
}

// When nodes are folded, their causes move with their edges, and causes
// about a folded node name the node it was folded into.
func TestCompactionMovesCauses(t *testing.T) {
	g := NewIndexedGraph()
	edge := testEdge("provenance")
	tx := g.Begin("write")
	reference, real, target, policy, realPolicy := tx.AddNew(Name, "reference"), tx.AddNew(Name, "real"), tx.AddNew(Name, "target"), tx.AddNew(Name, "policy"), tx.AddNew(Name, "real policy")
	tx.EdgeBecause(reference, target, edge, Source{testSourcePolicy, policy, "setting"})
	commitTx(t, tx)

	g.compact(map[*Node]*Node{reference.Node(): real.Node(), policy.Node(): realPolicy.Node()})
	sources := g.EdgeSources(real.Node(), target.Node())
	if len(sources) != 1 || sources[0].Source.About != realPolicy.Node() || sources[0].Source.Detail != "setting" {
		t.Fatalf("got %+v", sources)
	}
}

// A bitmap write records the cause for every edge type in it.
func TestSetEdgeBecauseRecordsEachEdgeType(t *testing.T) {
	g := NewIndexedGraph()
	first, second := testEdge("provenance"), testEdge("provenance second")
	tx := g.Begin("write")
	a, b := tx.AddNew(Name, "a"), tx.AddNew(Name, "b")
	tx.SetEdgeBecause(a, b, EdgeBitmap{}.Set(first).Set(second), Source{Kind: testSourcePolicy, Detail: "ACE 3"})
	commitTx(t, tx)
	sources := g.EdgeSources(a.Node(), b.Node())
	if len(sources) != 2 || sources[0].Source.Detail != "ACE 3" || sources[1].Source.Detail != "ACE 3" || sources[0].Edge == sources[1].Edge {
		t.Fatalf("got %+v", sources)
	}
}

// Large batches of causes are applied on several workers; each is kept.
func TestManyCausesAreAllKept(t *testing.T) {
	g := NewIndexedGraph()
	edge := testEdge("provenance")
	setup := g.Begin("nodes")
	nodes := make([]TxNode, 300)
	for i := range nodes {
		nodes[i] = setup.AddNew(Name, fmt.Sprint("node ", i))
	}
	commitTx(t, setup)
	tx := g.Begin("causes")
	pairs := 0
	for i := range nodes {
		for j := range nodes {
			if i != j && pairs < parallelEdgeMutations+1000 {
				tx.EdgeBecause(nodes[i].Node(), nodes[j].Node(), edge, Source{Kind: testSourcePolicy, Detail: fmt.Sprint("rule ", (i+j)%7)})
				pairs++
			}
		}
	}
	commitTx(t, tx)
	recorded := 0
	for i := range nodes {
		for j := range nodes {
			if i != j {
				recorded += len(g.EdgeSources(nodes[i].Node(), nodes[j].Node()))
			}
		}
	}
	if recorded != pairs {
		t.Fatalf("recorded %v causes for %v edges", recorded, pairs)
	}
}
